use std::collections::BTreeMap;

use xraytui_domain::NodeSource;
use xraytui_import::{ExportFidelity, ShareOptions, export_share_link, parse_many, parse_uri};

const LINKS: &str = include_str!("fixtures/cross-client-links.txt");

#[test]
fn mature_client_fixture_corpus_survives_import_export_reimport() {
    let imported = parse_many(LINKS, NodeSource::Manual);
    assert!(imported.rejected.is_empty(), "{:?}", imported.rejected);
    assert!(
        imported.unsupported.is_empty(),
        "{:?}",
        imported.unsupported
    );
    assert_eq!(imported.nodes.len(), 8);

    for original in imported.nodes {
        let export = export_share_link(&original, ShareOptions::default())
            .unwrap_or_else(|error| panic!("{}: {error}", original.summary()));
        assert_ne!(export.fidelity, ExportFidelity::Lossy, "{:?}", export.notes);
        let round_tripped = parse_uri(export.link.expose())
            .expect("exported link parses")
            .into_node()
            .expect("exported link remains executable");
        assert_eq!(
            original.canonical_identity(),
            round_tripped.canonical_identity(),
            "{} -> {}",
            original.summary(),
            round_tripped.summary()
        );
    }
}

#[test]
fn fixture_set_covers_distinct_mainstream_protocol_families() {
    let imported = parse_many(LINKS, NodeSource::Manual);
    let counts = imported
        .nodes
        .iter()
        .fold(BTreeMap::new(), |mut counts, node| {
            *counts
                .entry(node.protocol.xray_protocol())
                .or_insert(0usize) += 1;
            counts
        });
    for protocol in [
        "vless",
        "vmess",
        "trojan",
        "shadowsocks",
        "wireguard",
        "hysteria",
        "socks",
    ] {
        assert!(
            counts.contains_key(protocol),
            "missing {protocol}: {counts:?}"
        );
    }
}
