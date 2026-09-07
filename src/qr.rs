//! QR capture: decoding a Tier-A pack carrier from a still image.
//!
//! The officer's terminal story (seam S1): the carrier is a QR code on
//! the product; `unidpp verify --image photo.png` decodes the QR's
//! content and hands it to the normal verify pipeline — the pack text
//! (hex/base64) directly, or an explicit pointer when the QR carries a
//! resolver URI instead of the pack itself.
//!
//! Decoding is [`rqrr`] (pure Rust) over a luminance grid loaded from
//! a PNG via the [`png`] crate; camera capture is deliberately not a
//! dependency of this crate (frame capture drags platform media
//! stacks with it) — `--camera` states the path instead of silently
//! pretending.

use rqrr::PreparedImage;

use crate::encoding::auto_decode;

/// A QR's decoded content, classified: pack text, or a resolver URI
/// (explicitly surfaced — fetching is `resolve`'s job, not the
/// verifier's).
#[derive(Debug)]
pub enum QrContent {
    /// Pack bytes + the encoding they decoded from.
    Pack(Vec<u8>, crate::encoding::Encoding),
    /// A URI the QR carries (resolve it with `unidpp resolve`, then
    /// verify what comes back).
    Uri(String),
}

impl QrContent {
    /// Human-facing label.
    pub fn label(&self) -> &'static str {
        match self {
            QrContent::Pack(..) => "pack",
            QrContent::Uri(_) => "resolver-uri",
        }
    }
}

/// Decode the first QR code found in a PNG image. Grayscale images
/// load directly; colour images are folded to luminance
/// (Rec. 601) — QR's black/white modules survive the fold.
pub fn decode_png(path: &std::path::Path) -> Result<QrContent, String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let decoder = png::Decoder::new(std::io::BufReader::new(file));
    let mut reader = decoder
        .read_info()
        .map_err(|e| format!("{}: not a PNG ({e})", path.display()))?;
    let mut buffer = vec![0u8; reader.output_buffer_size()];
    let output = reader
        .next_frame(&mut buffer)
        .map_err(|e| format!("{}: PNG decode failed ({e})", path.display()))?;
    buffer.truncate(output.buffer_size());
    let grid = luminance_grid(&buffer, output.color_type);
    let width = output.width as usize;
    let height = output.height as usize;
    let mut image =
        PreparedImage::prepare_from_greyscale(width, height, |x, y| grid[y * width + x]);
    let mut grids = image.detect_grids();
    let grid = grids
        .first_mut()
        .ok_or_else(|| format!("{}: no QR code found in the image", path.display()))?;
    let (_meta, text) = grid
        .decode()
        .map_err(|e| format!("{}: QR decode failed ({e:?})", path.display()))?;
    classify(text)
}

/// Fold decoded PNG bytes into an 8-bit luminance grid.
fn luminance_grid(buffer: &[u8], color: png::ColorType) -> Vec<u8> {
    match color {
        png::ColorType::Grayscale | png::ColorType::GrayscaleAlpha => {
            let channels = if color == png::ColorType::GrayscaleAlpha {
                2
            } else {
                1
            };
            buffer
                .chunks(channels)
                .map(|pixel| pixel[0])
                .collect::<Vec<u8>>()
        }
        png::ColorType::Rgb | png::ColorType::Rgba => {
            let channels = if color == png::ColorType::Rgba { 4 } else { 3 };
            buffer
                .chunks(channels)
                .map(|pixel| {
                    let (r, g, b) = (pixel[0] as u32, pixel[1] as u32, pixel[2] as u32);
                    ((299 * r + 587 * g + 114 * b) / 1000) as u8
                })
                .collect::<Vec<u8>>()
        }
        png::ColorType::Indexed => buffer.to_vec(),
    }
}

/// Classify QR text: pack encodings decode; URIs point at the
/// resolver; anything else is refused with the reason.
fn classify(text: String) -> Result<QrContent, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("the QR code carries no content".to_string());
    }
    if let Some(uri) = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
    {
        return Ok(QrContent::Uri(format!("https://{uri}")));
    }
    if trimmed.starts_with("urn:") {
        return Ok(QrContent::Uri(trimmed.to_string()));
    }
    match auto_decode(trimmed) {
        Ok((bytes, encoding)) => Ok(QrContent::Pack(bytes, encoding)),
        Err(why) => Err(format!(
            "the QR content is neither a pack encoding (hex/base64) nor a resolver URI: {why}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::hex_encode;

    /// Render bytes as a QR PNG (grayscale, 8px modules, 4-module
    /// quiet zone) — the generator mirrors what a label printer
    /// produces and what the decoder must read back.
    fn qr_png(content: &str, path: &std::path::Path) {
        let code = qrcode::QrCode::new(content.as_bytes()).expect("qr encode");
        let modules = code.width();
        let scale = 8usize;
        let quiet = 4usize;
        let size = (modules + 2 * quiet) * scale;
        let mut pixels = vec![255u8; size * size];
        for row in 0..modules {
            for column in 0..modules {
                if code[(column, row)] == qrcode::Color::Dark {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let x = (quiet + column) * scale + dx;
                            let y = (quiet + row) * scale + dy;
                            pixels[y * size + x] = 0;
                        }
                    }
                }
            }
        }
        let file = std::fs::File::create(path).unwrap();
        let mut encoder =
            png::Encoder::new(std::io::BufWriter::new(file), size as u32, size as u32);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().unwrap();
        writer.write_image_data(&pixels).unwrap();
    }

    fn temp_path(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("unidpp-cli-qr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn generated_qr_png_decodes_to_the_pack_bytes() {
        let payload: Vec<u8> = (0..=200u8).cycle().take(300).collect();
        let text = hex_encode(&payload);
        let path = temp_path("pack.png");
        qr_png(&text, &path);
        match decode_png(&path).unwrap() {
            QrContent::Pack(bytes, encoding) => {
                assert_eq!(bytes, payload);
                assert_eq!(encoding.as_str(), "hex");
            }
            other => panic!("expected pack content, got {}", other.label()),
        }
    }

    #[test]
    fn base64_content_and_resolver_uris_are_classified() {
        let payload = b"the quick brown fox jumps over the lazy dog".to_vec();
        let text = crate::encoding::base64_encode(&payload);
        let path = temp_path("pack-b64.png");
        qr_png(&text, &path);
        match decode_png(&path).unwrap() {
            QrContent::Pack(bytes, encoding) => {
                assert_eq!(bytes, payload);
                assert_eq!(encoding.as_str(), "base64");
            }
            other => panic!("expected pack content, got {}", other.label()),
        }

        let uri = "https://resolver.unidpp.org/r/urn:unidpp:passport:e8-1";
        let path = temp_path("uri.png");
        qr_png(uri, &path);
        match decode_png(&path).unwrap() {
            QrContent::Uri(decoded) => assert_eq!(decoded, uri),
            other => panic!("expected uri content, got {}", other.label()),
        }
    }

    #[test]
    fn undecodable_content_and_missing_images_fail_with_reasons() {
        let path = temp_path("junk.png");
        qr_png("this is neither a pack nor a uri!", &path);
        let err = decode_png(&path).unwrap_err();
        assert!(err.contains("neither a pack encoding"), "{err}");

        let path = temp_path("blank.png");
        let size = 64usize;
        let file = std::fs::File::create(&path).unwrap();
        let mut encoder =
            png::Encoder::new(std::io::BufWriter::new(file), size as u32, size as u32);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Eight);
        encoder
            .write_header()
            .unwrap()
            .write_image_data(&vec![255u8; size * size])
            .unwrap();
        let err = decode_png(&path).unwrap_err();
        assert!(err.contains("no QR code"), "{err}");

        let err = decode_png(std::path::Path::new("/nonexistent/qr.png")).unwrap_err();
        assert!(err.contains("cannot open"), "{err}");
    }
}
