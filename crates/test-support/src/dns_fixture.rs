//! Deterministic DNS-over-TCP fixture and DNS client used by acceptance tests.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;

const DNS_HEADER_LEN: usize = 12;
const MAX_DNS_MESSAGE: usize = 4096;

/// DNS address record type used by [`query_dns`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    /// IPv4 address record.
    A,
    /// IPv6 address record.
    Aaaa,
}

impl DnsRecordType {
    const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

/// Minimal DNS-over-TCP server returning one fixed A or AAAA answer.
pub struct TcpDnsFixture {
    address: SocketAddr,
    queries: Arc<AtomicU64>,
    task: JoinHandle<()>,
}

impl TcpDnsFixture {
    /// Bind an ephemeral TCP port on `bind_ip` and answer with `answer`.
    ///
    /// # Errors
    /// Propagates listener bind failures.
    pub async fn start_on(bind_ip: IpAddr, answer: IpAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::new(bind_ip, 0)).await?;
        let address = listener.local_addr()?;
        let queries = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&queries);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let counter = Arc::clone(&counter);
                tokio::spawn(async move {
                    let _ = serve_connection(stream, answer, counter).await;
                });
            }
        });
        Ok(Self {
            address,
            queries,
            task,
        })
    }

    /// Listening address for an Xray `tcp://` nameserver URL.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Number of syntactically valid questions received.
    #[must_use]
    pub fn query_count(&self) -> u64 {
        self.queries.load(Ordering::Relaxed)
    }
}

impl Drop for TcpDnsFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_connection(
    mut stream: TcpStream,
    answer: IpAddr,
    queries: Arc<AtomicU64>,
) -> io::Result<()> {
    loop {
        let mut length = [0_u8; 2];
        match stream.read_exact(&mut length).await {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        }
        let length = usize::from(u16::from_be_bytes(length));
        if !(DNS_HEADER_LEN..=MAX_DNS_MESSAGE).contains(&length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS query length is outside the fixture limit",
            ));
        }
        let mut request = vec![0_u8; length];
        stream.read_exact(&mut request).await?;
        let response = response_for(&request, answer)?;
        queries.fetch_add(1, Ordering::Relaxed);
        stream
            .write_all(
                &u16::try_from(response.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            )
            .await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}

fn response_for(request: &[u8], answer: IpAddr) -> io::Result<Vec<u8>> {
    if request.len() < DNS_HEADER_LEN || u16::from_be_bytes([request[4], request[5]]) != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture accepts exactly one DNS question",
        ));
    }
    let question_end = question_end(request)?;
    let query_type = u16::from_be_bytes([request[question_end - 4], request[question_end - 3]]);
    let record_matches = matches!(
        (query_type, answer),
        (1, IpAddr::V4(_)) | (28, IpAddr::V6(_))
    );

    let mut response = Vec::with_capacity(request.len() + 32);
    response.extend_from_slice(&request[..2]);
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&u16::from(record_matches).to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&request[DNS_HEADER_LEN..question_end]);
    if record_matches {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&query_type.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        match answer {
            IpAddr::V4(address) => {
                response.extend_from_slice(&4_u16.to_be_bytes());
                response.extend_from_slice(&address.octets());
            }
            IpAddr::V6(address) => {
                response.extend_from_slice(&16_u16.to_be_bytes());
                response.extend_from_slice(&address.octets());
            }
        }
    }
    Ok(response)
}

fn question_end(message: &[u8]) -> io::Result<usize> {
    let mut offset = DNS_HEADER_LEN;
    loop {
        let Some(&length) = message.get(offset) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated DNS question name",
            ));
        };
        offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 || offset + usize::from(length) > message.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid DNS question label",
            ));
        }
        offset += usize::from(length);
    }
    let end = offset + 4;
    if end > message.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated DNS question type",
        ));
    }
    Ok(end)
}

/// Ask a UDP DNS listener for one A or AAAA record.
///
/// This is intentionally independent of Xray's DNS codec: it serialises and
/// parses the wire format directly so an Xray listener is tested end to end.
///
/// # Errors
/// Reports socket errors and malformed or empty DNS replies.
pub async fn query_dns(
    server: SocketAddr,
    name: &str,
    record_type: DnsRecordType,
) -> io::Result<IpAddr> {
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    let query = encode_query(name, record_type)?;
    socket.send_to(&query, server).await?;
    let mut response = [0_u8; MAX_DNS_MESSAGE];
    let (length, source) = socket.recv_from(&mut response).await?;
    if source != server {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response came from an unexpected address",
        ));
    }
    parse_answer(&response[..length], record_type)
}

fn encode_query(name: &str, record_type: DnsRecordType) -> io::Result<Vec<u8>> {
    let mut query = vec![0x58, 0x54, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS name is empty or too long",
        ));
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS labels must contain 1..=63 ASCII bytes",
            ));
        }
        query.push(u8::try_from(label.len()).unwrap_or(63));
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&record_type.code().to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    Ok(query)
}

fn parse_answer(message: &[u8], expected: DnsRecordType) -> io::Result<IpAddr> {
    if message.len() < DNS_HEADER_LEN
        || message[..2] != [0x58, 0x54]
        || message[3] & 0x0f != 0
        || u16::from_be_bytes([message[6], message[7]]) == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS reply is malformed, failed, or has no answer",
        ));
    }
    let question_end = question_end(message)?;
    let answer = message
        .get(question_end..)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "DNS answer is truncated"))?;
    if answer.len() < 12 || answer[..2] != [0xc0, 0x0c] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "fixture DNS answer name is malformed",
        ));
    }
    let answer_type = u16::from_be_bytes([answer[2], answer[3]]);
    let data_len = usize::from(u16::from_be_bytes([answer[10], answer[11]]));
    let data = answer.get(12..12 + data_len).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "DNS record data is truncated")
    })?;
    match (expected, answer_type, data) {
        (DnsRecordType::A, 1, [a, b, c, d]) => {
            Ok(IpAddr::V4(std::net::Ipv4Addr::new(*a, *b, *c, *d)))
        }
        (DnsRecordType::Aaaa, 28, bytes) if bytes.len() == 16 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(bytes);
            Ok(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS reply does not contain the requested record type",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn fixture_answers_a_and_aaaa_queries_over_real_dns_wire_format() {
        let ipv4 = TcpDnsFixture::start_on(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
        )
        .await
        .expect("IPv4 fixture");
        let ipv6 = TcpDnsFixture::start_on(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("2001:db8::7".parse().expect("IPv6 answer")),
        )
        .await;

        // The public helper speaks UDP, while the fixture intentionally speaks
        // TCP because that is what exercises Xray's routed DNS dispatcher. A
        // direct unit check of the fixture uses a tiny TCP exchange instead.
        async fn exchange(server: SocketAddr, query_type: DnsRecordType) -> IpAddr {
            let query = encode_query("fixture.test", query_type).expect("query");
            let mut stream = TcpStream::connect(server).await.expect("connect");
            stream
                .write_all(&u16::try_from(query.len()).unwrap_or(u16::MAX).to_be_bytes())
                .await
                .expect("length");
            stream.write_all(&query).await.expect("query body");
            let mut length = [0_u8; 2];
            stream.read_exact(&mut length).await.expect("reply length");
            let mut reply = vec![0_u8; usize::from(u16::from_be_bytes(length))];
            stream.read_exact(&mut reply).await.expect("reply");
            parse_answer(&reply, query_type).expect("answer")
        }

        assert_eq!(
            exchange(ipv4.address(), DnsRecordType::A).await,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))
        );
        assert_eq!(ipv4.query_count(), 1);

        match ipv6 {
            Ok(ipv6) => {
                assert_eq!(
                    exchange(ipv6.address(), DnsRecordType::Aaaa).await,
                    IpAddr::V6("2001:db8::7".parse().expect("IPv6 answer"))
                );
                assert_eq!(ipv6.query_count(), 1);
            }
            Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {}
            Err(error) => panic!("IPv6 fixture: {error}"),
        }

        tokio::time::timeout(
            Duration::from_millis(20),
            query_dns(ipv4.address(), "fixture.test", DnsRecordType::A),
        )
        .await
        .expect_err("a TCP-only fixture must not answer UDP");
    }
}
