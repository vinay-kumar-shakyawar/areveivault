//! Local QR decoding (for 2FA setup screenshots). Images never leave the device.

use crate::{Error, Result};

const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;
const MAX_DIMENSION: u32 = 4096;

pub fn decode(image_bytes: &[u8]) -> Result<Vec<String>> {
    if image_bytes.len() > MAX_IMAGE_BYTES {
        return Err(Error::Invalid("image too large".into()));
    }
    let img = image::load_from_memory(image_bytes).map_err(|_| Error::Invalid("unsupported image".into()))?;
    if img.width() > MAX_DIMENSION || img.height() > MAX_DIMENSION {
        return Err(Error::Invalid("image dimensions too large".into()));
    }
    let mut prepared = rqrr::PreparedImage::prepare(img.to_luma8());
    let found: Vec<String> = prepared
        .detect_grids()
        .into_iter()
        .filter_map(|g| g.decode().ok().map(|(_, content)| content))
        .collect();
    if found.is_empty() {
        return Err(Error::NotFound("no QR code found in image".into()));
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        assert!(decode(b"not an image").is_err());
    }

    #[test]
    fn blank_image_has_no_qr() {
        let img = image::GrayImage::from_pixel(64, 64, image::Luma([255]));
        let mut png = Vec::new();
        image::DynamicImage::ImageLuma8(img)
            .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        assert!(matches!(decode(&png), Err(Error::NotFound(_))));
    }
}
