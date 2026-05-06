// crates/domain/src/images.rs
//
// Centralized avatar / image handling for KLLDAP 7.0+
//
// DESIGN PRINCIPLES:
// - Single source of truth for all avatar creation and validation.
// - Avatar struct ALWAYS contains valid JPEG bytes (≤512×512, ≤512 KiB).
// - process_avatar_input is the ONLY way to create a new Avatar from untrusted input.
// - validate_stored_avatar_bytes is defensive (accepts legacy data + current JPEGs).
// - All errors are clear and actionable.
// - PNG/BMP/JPEG input → always converted to optimized JPEG on write.

use base64::engine::general_purpose;
use base64::Engine;
use image::{codecs::jpeg::JpegEncoder, ImageFormat, ImageReader};
use std::io::Cursor;

pub const MAX_AVATAR_SIZE: u32 = 512;
pub const TARGET_AVATAR_SIZE: u32 = MAX_AVATAR_SIZE;
pub const JPEG_QUALITY: u8 = 82;
pub const MAX_AVATAR_JPEG_SIZE: usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvatarError {
    WrongDimensions { width: u32, height: u32 },
    UnsupportedFormat,
    TooLarge { size: usize },
    InvalidImage(String),
}

impl std::fmt::Display for AvatarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AvatarError::WrongDimensions { width, height } => {
                write!(f, "Avatar must be at most {}x{} pixels (got {}x{})",
                    TARGET_AVATAR_SIZE, TARGET_AVATAR_SIZE, width, height)
            }
            AvatarError::UnsupportedFormat => {
                write!(f, "Unsupported image format. Only JPEG, PNG, or BMP allowed.")
            }
            AvatarError::TooLarge { size } => {
                write!(f, "Avatar too large ({} bytes > {} KiB limit)",
                    size, MAX_AVATAR_JPEG_SIZE / 1024)
            }
            AvatarError::InvalidImage(msg) => write!(f, "Invalid or corrupted image data: {}", msg),
        }
    }
}

impl std::error::Error for AvatarError {}

/// THE single entry point for creating Avatars from user input (GraphQL, LDAP, etc.).
///
/// Guarantees:
/// - Output is always valid JPEG (even if input was PNG/BMP).
/// - Output respects size and dimension limits.
/// - Never stores raw PNG/BMP in the database.
pub fn process_avatar_input(input: &[u8]) -> Result<Vec<u8>, AvatarError> {
    if input.is_empty() {
        return Ok(vec![]);
    }

    let reader = ImageReader::new(Cursor::new(input))
    .with_guessed_format()
    .map_err(|e| {
        tracing::error!(target: "avatar_debug", "guessed_format FAILED: {}", e);
        AvatarError::InvalidImage(e.to_string())
    })?;

    let format = reader.format().ok_or_else(|| {
        tracing::error!(target: "avatar_debug", "format() returned None");
        AvatarError::UnsupportedFormat
    })?;

    if !matches!(format, ImageFormat::Jpeg | ImageFormat::Png | ImageFormat::Bmp) {
        tracing::error!(target: "avatar_debug", "Unsupported format: {:?}", format);
        return Err(AvatarError::UnsupportedFormat);
    }

    let max_input_size = if format == ImageFormat::Bmp {
        2 * 1024 * 1024
    } else {
        MAX_AVATAR_JPEG_SIZE   // 512 KiB for JPEG, PNG
    };

    if input.len() > max_input_size {
        return Err(AvatarError::TooLarge { size: input.len() });
    }

    let img = reader
        .decode()
        .map_err(|e| AvatarError::InvalidImage(e.to_string()))?;

    if img.width() > TARGET_AVATAR_SIZE || img.height() > TARGET_AVATAR_SIZE {
        tracing::warn!(
            target: "avatar_debug",
            "REJECTED: image {}x{} exceeds {}x{} limit",
            img.width(),
            img.height(),
            TARGET_AVATAR_SIZE,
            TARGET_AVATAR_SIZE
        );
        return Err(AvatarError::WrongDimensions {
            width: img.width(),
            height: img.height(),
        });
    }

    let mut jpeg_bytes = Vec::with_capacity(128 * 1024);
    let mut encoder = JpegEncoder::new_with_quality(&mut jpeg_bytes, JPEG_QUALITY);
    encoder.encode_image(&img)
        .map_err(|e| AvatarError::InvalidImage(e.to_string()))?;

    if jpeg_bytes.len() > MAX_AVATAR_JPEG_SIZE {
        return Err(AvatarError::TooLarge { size: jpeg_bytes.len() });
    }

    Ok(jpeg_bytes)
}

/// Converts stored avatar bytes (always JPEG) to GraphQL base64.
pub fn avatar_to_graphql_base64(jpeg_bytes: &[u8]) -> String {
    if jpeg_bytes.is_empty() {
        return String::new();
    }
    general_purpose::STANDARD.encode(jpeg_bytes)
}

/// Defense-in-depth validation for data coming FROM the database.
/// Accepts:
/// - Valid JPEG (current format)
/// - Valid input formats (for legacy data that may still be PNG/BMP)
/// - Never fails on legacy data — lets the read path re-process if needed.
pub fn validate_stored_avatar_bytes(bytes: &[u8]) -> Result<(), AvatarError> {
    if bytes.is_empty() {
        return Ok(());
    }
    if bytes.len() > MAX_AVATAR_JPEG_SIZE {
        return Err(AvatarError::TooLarge { size: bytes.len() });
    }

    // Accept current JPEGs
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xD8 {
        return Ok(());
    }

    // Accept legacy PNG/BMP (will be re-processed on read if needed)
    if bytes.len() >= 4 {
        let is_png = bytes.starts_with(&[0x89, 0x50, 0x4E, 0x47]);
        let is_bmp = bytes.starts_with(&[0x42, 0x4D]);
        if is_png || is_bmp {
            return Ok(());
        }
    }

    Err(AvatarError::InvalidImage(
        "Stored avatar is not a valid JPEG, PNG, or BMP".to_string(),
    ))
}

pub fn is_valid_avatar_dimensions(width: u32, height: u32) -> bool {
    width <= TARGET_AVATAR_SIZE && height <= TARGET_AVATAR_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb, RgbImage};

    fn make_test_jpeg(size: u32) -> Vec<u8> {
        let img: RgbImage = ImageBuffer::from_fn(size, size, |x, y| {
            if (x + y) % 2 == 0 { Rgb([0, 0, 0]) } else { Rgb([255, 255, 255]) }
        });
        let mut buf = Vec::new();
        img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Jpeg).unwrap();
        buf
    }

    fn make_test_png(size: u32) -> Vec<u8> {
        let img: RgbImage = ImageBuffer::from_fn(size, size, |x, y| {
            Rgb([(x % 256) as u8, (y % 256) as u8, 128])
        });
        let mut buf = Vec::new();
        img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png).unwrap();
        buf
    }

    #[test]
    fn test_valid_512_jpeg_passes() {
        let jpeg = make_test_jpeg(512);
        let result = process_avatar_input(&jpeg);
        assert!(result.is_ok());
        let out = result.unwrap();
        assert!(!out.is_empty());
        assert!(out.len() < MAX_AVATAR_JPEG_SIZE);
        assert_eq!(&out[0..2], &[0xFF, 0xD8]);
    }

    #[test]
    fn test_png_converts_to_jpeg() {
        let png = make_test_png(512);
        let result = process_avatar_input(&png);
        assert!(result.is_ok());
        let out = result.unwrap();
        assert_eq!(&out[0..2], &[0xFF, 0xD8]);
    }

    #[test]
    fn test_wrong_size_rejected() {
        let jpeg = make_test_jpeg(256);
        let err = process_avatar_input(&jpeg).unwrap_err();
        match err {
            AvatarError::WrongDimensions { width, height } => {
                assert_eq!(width, 256);
                assert_eq!(height, 256);
            }
            _ => panic!("Expected WrongDimensions"),
        }
    }

    #[test]
    fn test_unsupported_format_rejected() {
        let gif = vec![0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x21, 0xF9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x4C, 0x01, 0x00, 0x3B];
        let err = process_avatar_input(&gif).unwrap_err();
        assert!(matches!(err, AvatarError::UnsupportedFormat));
    }

    #[test]
    fn test_empty_input_returns_empty() {
        let result = process_avatar_input(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_validate_stored_accepts_jpeg_and_png() {
        let jpeg = make_test_jpeg(512);
        assert!(validate_stored_avatar_bytes(&jpeg).is_ok());

        let png = make_test_png(512);
        assert!(validate_stored_avatar_bytes(&png).is_ok());
    }
}
