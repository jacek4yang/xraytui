//! QR code rendering and decoding.
//!
//! A QR code containing a share link **is** the credential — anyone who
//! photographs the terminal gains proxy access. Callers are expected to print the
//! warning in [`SECRET_WARNING`] before displaying one; the rendering functions
//! themselves take a plain `&str` because the caller has already decided to
//! reveal it.

use std::path::Path;

use qrcode::{EcLevel, QrCode};

/// One-line warning to print before showing a QR code that carries credentials.
pub const SECRET_WARNING: &str =
    "This QR code grants access to the proxy. Treat it like a password: do not \
     photograph it, screen-share it, or paste it where others can see.";

/// Largest payload a QR code can hold (version 40, low error correction).
pub const MAX_QR_BYTES: usize = 2953;

/// Modules of quiet zone required on each side by the specification.
const QUIET_ZONE: usize = 4;

/// Why a QR operation failed.
#[derive(Debug, thiserror::Error)]
pub enum QrError {
    /// The payload exceeds what any QR version can hold.
    #[error("payload is {size} bytes, over the {MAX_QR_BYTES} byte QR capacity")]
    TooLarge {
        /// Size of the offending payload.
        size: usize,
    },
    /// The payload was empty.
    #[error("payload is empty")]
    Empty,
    /// The encoder refused the payload.
    #[error("could not encode QR code: {0}")]
    Encode(String),
    /// Writing or reading the image failed.
    #[error("{path}: {source}")]
    Io {
        /// Path involved.
        path: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The image could not be decoded as an image at all.
    #[error("{path}: not a readable image ({reason})")]
    Image {
        /// Path involved.
        path: String,
        /// Why.
        reason: String,
    },
    /// The image held no readable QR code.
    #[error("{path}: no QR code found in the image")]
    NoCode {
        /// Path involved.
        path: String,
    },
    /// The requested scale was zero or absurd.
    #[error("scale must be between 1 and 64")]
    BadScale,
}

fn encode(data: &str) -> Result<QrCode, QrError> {
    if data.is_empty() {
        return Err(QrError::Empty);
    }
    if data.len() > MAX_QR_BYTES {
        return Err(QrError::TooLarge { size: data.len() });
    }
    // Low error correction maximises capacity, which matters because REALITY
    // links with a long public key and short id are close to the limit.
    QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L)
        .map_err(|error| QrError::Encode(error.to_string()))
}

/// Render a QR code for a terminal using Unicode half blocks.
///
/// Two module rows are packed into one character cell, so the result is roughly
/// square in a normal terminal font and fits an 80x24 window for typical share
/// links. Dark modules are rendered as foreground blocks on the default
/// background, which scans correctly in both light and dark colour schemes
/// **provided the terminal's default background is light**; for dark terminals
/// use [`render_terminal_inverted`].
///
/// # Errors
/// Returns [`QrError`] for empty or oversized payloads.
pub fn render_terminal(data: &str) -> Result<String, QrError> {
    render_blocks(data, false)
}

/// As [`render_terminal`], with dark and light modules swapped.
///
/// Scanners require a light quiet zone and light background. On a dark terminal
/// the inverted rendering is the one that scans.
///
/// # Errors
/// Returns [`QrError`] for empty or oversized payloads.
pub fn render_terminal_inverted(data: &str) -> Result<String, QrError> {
    render_blocks(data, true)
}

fn render_blocks(data: &str, invert: bool) -> Result<String, QrError> {
    let code = encode(data)?;
    let modules: Vec<bool> = code.to_colors().iter().map(|c| *c == qrcode::Color::Dark).collect();
    let width = code.width();

    let padded_width = width + QUIET_ZONE * 2;
    let padded_height = width + QUIET_ZONE * 2;

    // `dark(x, y)` is the module colour after inversion and quiet-zone padding.
    let dark = |x: usize, y: usize| -> bool {
        if x < QUIET_ZONE || y < QUIET_ZONE || x >= QUIET_ZONE + width || y >= QUIET_ZONE + width {
            return invert;
        }
        let index = (y - QUIET_ZONE) * width + (x - QUIET_ZONE);
        let value = modules.get(index).copied().unwrap_or(false);
        value != invert
    };

    // Each output line covers two module rows: the upper half block is the top
    // row, the lower half block the bottom row.
    let mut out = String::with_capacity(padded_width * padded_height / 2 + padded_height);
    let mut y = 0;
    while y < padded_height {
        for x in 0..padded_width {
            let top = dark(x, y);
            let bottom = if y + 1 < padded_height { dark(x, y + 1) } else { invert };
            out.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    Ok(out)
}

/// Write a QR code to a PNG file.
///
/// The file is created with mode 0600: a PNG of a share link is as sensitive as
/// the link itself.
///
/// # Errors
/// Returns [`QrError`] for bad payloads, bad scales, and I/O failures.
pub fn render_png(data: &str, path: &Path, scale: u32) -> Result<(), QrError> {
    if scale == 0 || scale > 64 {
        return Err(QrError::BadScale);
    }
    let code = encode(data)?;
    // `qrcode`'s image renderer is behind an optional feature that pulls a
    // second copy of `image`; rasterising the module grid directly avoids that
    // and keeps full control over the quiet zone and pixel scale.
    let width = code.width();
    let modules: Vec<bool> = code.to_colors().iter().map(|c| *c == qrcode::Color::Dark).collect();
    let padded = width + QUIET_ZONE * 2;
    let side = u32::try_from(padded).unwrap_or(u32::MAX).saturating_mul(scale);

    let mut buffer = image::GrayImage::from_pixel(side, side, image::Luma([255_u8]));
    for (index, dark) in modules.iter().enumerate() {
        if !dark {
            continue;
        }
        let module_x = index % width + QUIET_ZONE;
        let module_y = index / width + QUIET_ZONE;
        for dy in 0..scale {
            for dx in 0..scale {
                let x = u32::try_from(module_x).unwrap_or(0).saturating_mul(scale) + dx;
                let y = u32::try_from(module_y).unwrap_or(0).saturating_mul(scale) + dy;
                if x < side && y < side {
                    buffer.put_pixel(x, y, image::Luma([0_u8]));
                }
            }
        }
    }

    create_private_file(path)?;
    buffer.save(path).map_err(|error| QrError::Image {
        path: path.display().to_string(),
        reason: error.to_string(),
    })
}

/// Create (or truncate) `path` with mode 0600 before the encoder writes to it.
fn create_private_file(path: &Path) -> Result<(), QrError> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map(|_| ())
        .map_err(|source| QrError::Io { path: path.display().to_string(), source })
}

/// Decode every QR code found in a PNG (or any image the `image` crate reads).
///
/// # Errors
/// Returns [`QrError::NoCode`] when the image holds no readable code.
pub fn decode_png(path: &Path) -> Result<Vec<String>, QrError> {
    let image = image::open(path).map_err(|error| QrError::Image {
        path: path.display().to_string(),
        reason: error.to_string(),
    })?;
    let luma = image.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(luma);
    let grids = prepared.detect_grids();
    let mut out = Vec::new();
    for grid in grids {
        if let Ok((_meta, content)) = grid.decode() {
            out.push(content);
        }
    }
    if out.is_empty() {
        return Err(QrError::NoCode { path: path.display().to_string() });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "vless://11111111-2222-3333-4444-555555555555@example.com:443\
                        ?type=ws&path=%2Fray&security=tls&sni=cdn.example.com#HK%2001";

    #[test]
    fn terminal_rendering_uses_only_block_characters() {
        let rendered = render_terminal(LINK).expect("render");
        for ch in rendered.chars() {
            assert!(
                matches!(ch, '█' | '▀' | '▄' | ' ' | '\n'),
                "unexpected character {ch:?} in terminal QR"
            );
        }
        assert!(rendered.lines().count() > 8);
    }

    #[test]
    fn terminal_rendering_includes_a_quiet_zone() {
        let rendered = render_terminal("x").expect("render");
        let first = rendered.lines().next().expect("a line");
        // The first two module rows are entirely quiet zone, so the first output
        // line must be blank.
        assert!(first.chars().all(|c| c == ' '), "{first:?}");
        for line in rendered.lines() {
            assert!(line.starts_with("    "), "missing left quiet zone: {line:?}");
        }
    }

    #[test]
    fn inverted_rendering_differs_and_is_still_blocks_only() {
        let normal = render_terminal(LINK).expect("render");
        let inverted = render_terminal_inverted(LINK).expect("render");
        assert_ne!(normal, inverted);
        for ch in inverted.chars() {
            assert!(matches!(ch, '█' | '▀' | '▄' | ' ' | '\n'));
        }
    }

    #[test]
    fn empty_and_oversized_payloads_are_refused() {
        assert!(matches!(render_terminal(""), Err(QrError::Empty)));
        let huge = "x".repeat(MAX_QR_BYTES + 1);
        assert!(matches!(render_terminal(&huge), Err(QrError::TooLarge { .. })));
    }

    #[test]
    fn png_round_trips_through_the_decoder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.png");
        render_png(LINK, &path, 8).expect("render");
        let decoded = decode_png(&path).expect("decode");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded.first().map(String::as_str), Some(LINK));
    }

    #[test]
    fn png_files_are_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.png");
        render_png("x", &path, 4).expect("render");
        let mode = std::fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn bad_scale_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.png");
        assert!(matches!(render_png("x", &path, 0), Err(QrError::BadScale)));
        assert!(matches!(render_png("x", &path, 65), Err(QrError::BadScale)));
    }

    #[test]
    fn decoding_a_non_image_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("not-an-image.png");
        std::fs::write(&path, b"definitely not a png").expect("write");
        assert!(matches!(decode_png(&path), Err(QrError::Image { .. })));
    }

    #[test]
    fn decoding_an_image_without_a_code_reports_no_code() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("blank.png");
        let blank = image::GrayImage::from_pixel(64, 64, image::Luma([255_u8]));
        blank.save(&path).expect("save");
        assert!(matches!(decode_png(&path), Err(QrError::NoCode { .. })));
    }

    #[test]
    fn a_long_reality_link_still_fits() {
        let long = format!(
            "vless://11111111-2222-3333-4444-555555555555@some.rather.long.hostname.example.com:443\
             ?security=reality&pbk={}&sid=0123456789abcdef&spx=%2F&fp=chrome&type=grpc\
             &serviceName=AVeryLongGunServiceName#{}",
            "A".repeat(43),
            "Node%20Name%20With%20Spaces"
        );
        render_terminal(&long).expect("must fit");
    }
}
