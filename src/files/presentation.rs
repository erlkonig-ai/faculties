//! Bounded, derived views of stored bytes. Nothing here changes the stored file.
//!
//! Images have a fixed 16,384-pixel side limit and a 128 MiB decoded-surface
//! limit, independent of the requested output dimensions. The same allocation
//! allowance is passed to the codec; codec scratch limits are best-effort, not
//! a process-wide memory guarantee. Conversion presents the first image/frame
//! and does not preserve container metadata. An accepted original is returned
//! byte-for-byte after validating its first image. JPEG conversion is lossy and
//! drops alpha; request PNG when transparency must survive.

use std::io::{self, Cursor, Seek, SeekFrom, Write};

use anybytes::Bytes;
use anyhow::{bail, ensure, Context, Result};
use image::{imageops::FilterType, DynamicImage, ImageDecoder, ImageFormat, ImageReader, Limits};

use crate::out::Part;

const MAX_IMAGE_DIMENSION: u32 = 16_384;
const MAX_IMAGE_BYTES: u64 = 128 * 1024 * 1024;
const RAW_GET_HINT: &str = "use get to retrieve the original bytes";

/// Formats and limits for one displayed result, not for storage or raw export.
///
/// `accept` is an unordered set of exact MIME types, `type/*`, or `*` (`*/*`
/// also accepts everything). Matching is case-insensitive and ignores input
/// MIME parameters. Quality values and parameters in accept entries are not
/// supported. PNG is preferred to JPEG when conversion is necessary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewOptions {
    pub accept: Vec<String>,
    pub max_bytes: usize,
    pub max_dimension: Option<u32>,
}

impl Default for ViewOptions {
    fn default() -> Self {
        Self {
            accept: ["text/*", "image/png", "image/jpeg", "audio/*"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            max_bytes: 4 * 1024 * 1024,
            max_dimension: None,
        }
    }
}

impl ViewOptions {
    /// Validate recipient constraints before opening storage or acquiring bytes.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.max_bytes > 0, "max_bytes must be greater than zero");
        ensure!(
            self.max_dimension != Some(0),
            "max_dimension must be greater than zero"
        );
        Accept::new(&self.accept)?;
        Ok(())
    }
}

/// Present bytes without changing their stored representation.
///
/// Text must be valid UTF-8 and fit exactly: it is never truncated. Audio is
/// passthrough only. Image conversion performs at most one resize and one encode;
/// an output that cannot fit is an error, not an implicit quality-reduction loop.
pub fn present(bytes: Bytes, mime_type: &str, options: &ViewOptions) -> Result<Part> {
    options.validate()?;
    let accept = Accept::new(&options.accept)?;
    let mime: mime::Mime = mime_type.trim().parse().context("invalid file MIME type")?;
    ensure!(
        !mime.essence_str().contains('*'),
        "file MIME type cannot contain a wildcard"
    );
    let essence = mime.essence_str();
    match mime.type_().as_str() {
        "text" => {
            ensure!(
                accept.matches(essence),
                "{essence} is not accepted; {RAW_GET_HINT}"
            );
            ensure!(
                bytes.len() <= options.max_bytes,
                "text is {} bytes, exceeding max_bytes ({}); {RAW_GET_HINT}",
                bytes.len(),
                options.max_bytes
            );
            let text = std::str::from_utf8(bytes.as_ref())
                .with_context(|| format!("text is not UTF-8; {RAW_GET_HINT}"))?;
            Ok(Part::Text {
                text: text.to_owned(),
            })
        }
        "image" => present_image(bytes, essence, options, &accept),
        "audio" => {
            ensure!(
                accept.matches(essence),
                "{essence} is not accepted; audio conversion is not supported; {RAW_GET_HINT}"
            );
            if essence == "audio/l16" {
                let rate = mime
                    .get_param("rate")
                    .context(
                        "audio/L16 needs a sample rate; stored MIME essence cannot recover it",
                    )?
                    .as_str()
                    .parse::<u32>()
                    .context("invalid audio/L16 sample rate")?;
                ensure!(rate > 0, "audio/L16 sample rate must be positive");
                let channels = mime
                    .get_param("channels")
                    .map(|value| value.as_str().parse::<u32>())
                    .transpose()
                    .context("invalid audio/L16 channels")?
                    .unwrap_or(1);
                ensure!(channels > 0, "audio/L16 channels must be positive");
                ensure!(
                    (bytes.len() as u64) % (2 * u64::from(channels)) == 0,
                    "audio/L16 payload has an incomplete sample frame"
                );
            }
            ensure!(
                bytes.len() <= options.max_bytes,
                "audio is {} bytes, exceeding max_bytes ({}); audio conversion is not supported; {RAW_GET_HINT}",
                bytes.len(),
                options.max_bytes
            );
            Ok(Part::Audio {
                bytes,
                // Parameters can describe a raw audio rate/channel layout.
                mime_type: mime_type.trim().to_owned(),
            })
        }
        _ => bail!("cannot present {essence}; {RAW_GET_HINT}"),
    }
}

struct Accept(Vec<String>);

impl Accept {
    fn new(values: &[String]) -> Result<Self> {
        ensure!(
            !values.is_empty(),
            "accept must contain at least one MIME type"
        );
        let mut patterns = Vec::with_capacity(values.len());
        for value in values {
            let pattern = value.trim().to_ascii_lowercase();
            if pattern != "*" && pattern != "*/*" {
                let parsed: mime::Mime = pattern
                    .parse()
                    .with_context(|| format!("invalid accept entry {value:?}"))?;
                ensure!(
                    parsed.params().next().is_none(),
                    "accept entry {value:?} must not contain MIME parameters or quality values"
                );
                ensure!(
                    !pattern.contains('*')
                        || (parsed.type_() != mime::STAR
                            && parsed.subtype() == mime::STAR
                            && pattern.ends_with("/*")
                            && !pattern[..pattern.len() - 2].contains('*')),
                    "accept entry {value:?} must be an exact MIME type, type/*, or *"
                );
            }
            patterns.push(pattern);
        }
        Ok(Self(patterns))
    }

    fn matches(&self, mime_type: &str) -> bool {
        self.0.iter().any(|pattern| {
            pattern == "*"
                || pattern == "*/*"
                || pattern == mime_type
                || pattern.strip_suffix("/*").is_some_and(|kind| {
                    mime_type
                        .split_once('/')
                        .is_some_and(|(actual, _)| kind == actual)
                })
        })
    }
}

fn image_limits() -> Limits {
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(MAX_IMAGE_BYTES);
    limits
}

fn present_image(
    bytes: Bytes,
    mime_type: &str,
    options: &ViewOptions,
    accept: &Accept,
) -> Result<Part> {
    // Bound encoded input too: a tiny pixel surface need not imply a small
    // container or metadata payload. This is separate from the output budget.
    ensure!(
        bytes.len() as u64 <= MAX_IMAGE_BYTES,
        "encoded image exceeds the {MAX_IMAGE_BYTES}-byte safety limit; {RAW_GET_HINT}"
    );
    let declared = ImageFormat::from_mime_type(mime_type)
        .with_context(|| format!("unsupported image MIME type {mime_type}; {RAW_GET_HINT}"))?;
    let format = image::guess_format(bytes.as_ref())
        .with_context(|| format!("image format is unrecognized or corrupt; {RAW_GET_HINT}"))?;
    ensure!(
        format == declared,
        "image bytes are {}, not the declared {mime_type}; {RAW_GET_HINT}",
        format.to_mime_type()
    );

    let mut limits = image_limits();
    let mut reader = ImageReader::with_format(Cursor::new(bytes.as_ref()), format);
    reader.limits(limits.clone());
    let mut decoder = reader.into_decoder().with_context(|| {
        format!("cannot decode {mime_type} within image safety limits; {RAW_GET_HINT}")
    })?;
    let (width, height) = decoder.dimensions();
    ensure!(width > 0 && height > 0, "image dimensions must be nonzero");
    limits
        .check_dimensions(width, height)
        .context("image dimensions exceed safety limit")?;
    // Budget at least RGBA8 surface space, even for grayscale images, because
    // conversion may expand their channels. Check before allocating pixels.
    let expanded_bytes = u64::from(width) * u64::from(height) * 4;
    ensure!(
        decoder.total_bytes().max(expanded_bytes) <= MAX_IMAGE_BYTES,
        "decoded image exceeds the {MAX_IMAGE_BYTES}-byte surface safety limit; {RAW_GET_HINT}"
    );
    // Match ImageReader::decode's accounting: the output surface and codec's
    // allocation allowance share the budget instead of each receiving it.
    limits
        .reserve(decoder.total_bytes())
        .context("decoded image exceeds allocation limit")?;
    decoder
        .set_limits(limits)
        .context("image decoder cannot honor safety limits")?;
    let mut image = DynamicImage::from_decoder(decoder).with_context(|| {
        format!("image is corrupt or exceeds decoder safety limits; {RAW_GET_HINT}")
    })?;

    let actual_mime = format.to_mime_type();
    let resize = options
        .max_dimension
        .filter(|&edge| width > edge || height > edge);
    if accept.matches(actual_mime) && bytes.len() <= options.max_bytes && resize.is_none() {
        return Ok(Part::Image {
            bytes,
            mime_type: actual_mime.to_owned(),
        });
    }

    let target = if accept.matches("image/png") {
        ImageFormat::Png
    } else if accept.matches("image/jpeg") {
        ImageFormat::Jpeg
    } else {
        bail!(
            "image needs conversion but neither image/png nor image/jpeg is accepted; {RAW_GET_HINT}"
        );
    };
    if let Some(edge) = resize {
        image = image.resize(edge, edge, FilterType::Triangle);
    }
    if target == ImageFormat::Jpeg {
        image = DynamicImage::ImageRgb8(image.into_rgb8());
    }
    let mut output = LimitedWriter {
        inner: Cursor::new(Vec::new()),
        max_bytes: options.max_bytes,
    };
    image.write_to(&mut output, target).with_context(|| {
        format!(
            "cannot encode {} within max_bytes ({}); {RAW_GET_HINT}",
            target.to_mime_type(),
            options.max_bytes
        )
    })?;
    Ok(Part::Image {
        bytes: Bytes::from(output.inner.into_inner()),
        mime_type: target.to_mime_type().to_owned(),
    })
}

/// Stop an encoder before its output buffer grows past the caller's budget.
struct LimitedWriter {
    inner: Cursor<Vec<u8>>,
    max_bytes: usize,
}

impl Write for LimitedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self
            .inner
            .position()
            .checked_add(buf.len() as u64)
            .is_none_or(|end| end > self.max_bytes as u64)
        {
            return Err(io::Error::other("encoded image exceeds max_bytes"));
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Seek for LimitedWriter {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{Rgb, RgbImage};

    fn encoded(format: ImageFormat, width: u32, height: u32) -> Bytes {
        let image =
            DynamicImage::ImageRgb8(RgbImage::from_pixel(width, height, Rgb([20, 80, 160])));
        let mut output = Cursor::new(Vec::new());
        image.write_to(&mut output, format).unwrap();
        Bytes::from(output.into_inner())
    }

    fn only(accept: &str) -> ViewOptions {
        ViewOptions {
            accept: vec![accept.into()],
            ..ViewOptions::default()
        }
    }

    fn image_part(part: Part) -> (Bytes, String) {
        match part {
            Part::Image { bytes, mime_type } => (bytes, mime_type),
            other => panic!("expected image, got {other:?}"),
        }
    }

    #[test]
    fn default_options_are_explicit() {
        let options = ViewOptions::default();
        assert_eq!(
            options.accept,
            ["text/*", "image/png", "image/jpeg", "audio/*"]
        );
        assert_eq!(options.max_bytes, 4 * 1024 * 1024);
        assert_eq!(options.max_dimension, None);
    }

    #[test]
    fn accepted_png_preserves_original_shared_bytes() {
        let original = encoded(ImageFormat::Png, 3, 2);
        let options = ViewOptions {
            max_bytes: original.len(),
            max_dimension: Some(3),
            ..ViewOptions::default()
        };
        let (bytes, mime) = image_part(present(original.clone(), "image/png", &options).unwrap());
        assert_eq!(mime, "image/png");
        assert_eq!(bytes, original);
        assert_eq!(bytes.as_ptr(), original.as_ptr());
    }

    #[test]
    fn bmp_converts_to_png_without_changing_source() {
        let original = encoded(ImageFormat::Bmp, 32, 16);
        let original_copy = original.clone();
        let (bytes, mime) =
            image_part(present(original.clone(), "image/bmp", &ViewOptions::default()).unwrap());
        assert_eq!(mime, "image/png");
        assert_eq!(
            image::guess_format(bytes.as_ref()).unwrap(),
            ImageFormat::Png
        );
        assert_eq!(image::load_from_memory(bytes.as_ref()).unwrap().width(), 32);
        assert_eq!(original, original_copy);
        assert_ne!(bytes, original);
    }

    #[test]
    fn output_budget_does_not_reject_a_larger_convertible_source() {
        let original = encoded(ImageFormat::Bmp, 32, 16);
        let (converted, _) =
            image_part(present(original.clone(), "image/bmp", &ViewOptions::default()).unwrap());
        assert!(converted.len() < original.len());
        let options = ViewOptions {
            max_bytes: converted.len(),
            ..ViewOptions::default()
        };
        let (again, _) = image_part(present(original, "image/bmp", &options).unwrap());
        assert_eq!(again, converted);
    }

    #[test]
    fn resizing_preserves_aspect_and_does_not_upscale() {
        let original = encoded(ImageFormat::Png, 12, 4);
        let options = ViewOptions {
            max_dimension: Some(6),
            ..ViewOptions::default()
        };
        let (small, _) = image_part(present(original.clone(), "image/png", &options).unwrap());
        let decoded = image::load_from_memory(small.as_ref()).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (6, 2));
        let options = ViewOptions {
            max_dimension: Some(100),
            ..options
        };
        let (same, _) = image_part(present(original.clone(), "image/png", &options).unwrap());
        assert_eq!(same.as_ptr(), original.as_ptr());
    }

    #[test]
    fn jpeg_only_is_a_real_conversion_and_png_has_priority() {
        let original = encoded(ImageFormat::Bmp, 2, 2);
        let (jpeg, mime) =
            image_part(present(original.clone(), "image/bmp", &only("image/jpeg")).unwrap());
        assert_eq!(mime, "image/jpeg");
        assert_eq!(
            image::guess_format(jpeg.as_ref()).unwrap(),
            ImageFormat::Jpeg
        );
        let options = ViewOptions {
            accept: vec!["image/jpeg".into(), "image/png".into()],
            ..ViewOptions::default()
        };
        let (_, mime) = image_part(present(original, "image/bmp", &options).unwrap());
        assert_eq!(mime, "image/png");
    }

    #[test]
    fn tiny_budget_fails_instead_of_truncating_encoded_image() {
        let options = ViewOptions {
            max_bytes: 1,
            ..ViewOptions::default()
        };
        let error = present(encoded(ImageFormat::Png, 2, 2), "image/png", &options).unwrap_err();
        assert!(error.to_string().contains("max_bytes"));
    }

    #[test]
    fn target_rejection_is_honest_even_when_original_type_is_accepted() {
        let original = encoded(ImageFormat::Bmp, 3, 2);
        assert!(present(original.clone(), "image/bmp", &only("audio/*")).is_err());
        let (same, mime) =
            image_part(present(original.clone(), "image/bmp", &only("image/bmp")).unwrap());
        assert_eq!(same.as_ptr(), original.as_ptr());
        assert_eq!(mime, "image/bmp");
        let options = ViewOptions {
            max_dimension: Some(1),
            ..only("image/bmp")
        };
        assert!(present(original, "image/bmp", &options)
            .unwrap_err()
            .to_string()
            .contains("neither image/png nor image/jpeg"));
    }

    #[test]
    fn corrupt_or_mislabeled_images_are_not_passed_through() {
        let png = encoded(ImageFormat::Png, 2, 2);
        assert!(present(png.clone(), "image/jpeg", &ViewOptions::default()).is_err());
        assert!(present(
            Bytes::from(png[..33].to_vec()),
            "image/png",
            &ViewOptions::default()
        )
        .is_err());
        assert!(present(
            Bytes::from(b"not an image".to_vec()),
            "image/png",
            &ViewOptions::default()
        )
        .is_err());
        let error = present(
            Bytes::from(b"<svg/>".to_vec()),
            "image/svg+xml",
            &only("image/*"),
        )
        .unwrap_err();
        assert!(error.to_string().contains(RAW_GET_HINT));
    }

    #[test]
    fn huge_header_is_rejected_even_when_tiny_output_is_requested() {
        let mut bytes = encoded(ImageFormat::Bmp, 2, 2).to_vec();
        // BMP BITMAPINFOHEADER stores signed width and height at offsets 18/22.
        bytes[18..22].copy_from_slice(&(MAX_IMAGE_DIMENSION as i32 + 1).to_le_bytes());
        bytes[22..26].copy_from_slice(&1_i32.to_le_bytes());
        let options = ViewOptions {
            max_dimension: Some(1),
            ..ViewOptions::default()
        };
        let error = present(Bytes::from(bytes), "image/bmp", &options).unwrap_err();
        assert!(format!("{error:#}").contains("limit"));
    }

    #[test]
    fn decoded_surface_limit_is_checked_before_pixels_are_allocated() {
        let mut bytes = encoded(ImageFormat::Bmp, 2, 2).to_vec();
        bytes[18..22].copy_from_slice(&8192_i32.to_le_bytes());
        bytes[22..26].copy_from_slice(&8192_i32.to_le_bytes());
        let error = present(Bytes::from(bytes), "image/bmp", &ViewOptions::default()).unwrap_err();
        assert!(format!("{error:#}").contains("surface safety limit"));
    }

    #[test]
    fn text_is_exact_utf8_with_a_byte_not_character_budget() {
        let bytes = Bytes::from("hé\n".as_bytes().to_vec());
        let options = ViewOptions {
            max_bytes: bytes.len(),
            ..only(" TEXT/* ")
        };
        assert_eq!(
            present(bytes.clone(), "Text/Plain; charset=utf-8", &options).unwrap(),
            Part::Text {
                text: "hé\n".into()
            }
        );
        let options = ViewOptions {
            max_bytes: 3,
            ..options
        };
        assert!(present(bytes, "text/plain", &options).is_err());
        assert!(present(
            Bytes::from(vec![0xff]),
            "text/plain",
            &ViewOptions::default()
        )
        .is_err());
        assert!(present(Bytes::from(b"ok".to_vec()), "text/plain", &only("image/*")).is_err());
    }

    #[test]
    fn audio_is_passthrough_only_and_keeps_format_parameters() {
        let original = Bytes::from(vec![0_u8, 1, 2, 3]);
        let mime = "audio/L16; rate=16000; channels=1";
        let Part::Audio { bytes, mime_type } =
            present(original.clone(), mime, &ViewOptions::default()).unwrap()
        else {
            panic!("expected audio")
        };
        assert_eq!(bytes.as_ptr(), original.as_ptr());
        assert_eq!(mime_type, mime);
        let error = present(original.clone(), "audio/wav", &only("audio/pcm")).unwrap_err();
        assert!(error
            .to_string()
            .contains("audio conversion is not supported"));
        let options = ViewOptions {
            max_bytes: 3,
            ..ViewOptions::default()
        };
        assert!(present(original, mime, &options).is_err());
    }

    #[test]
    fn raw_pcm_requires_rate_and_complete_frames() {
        for mime in [
            "audio/L16",
            "audio/L16;rate=0",
            "audio/L16;rate=bad",
            "audio/L16;rate=16000;channels=0",
        ] {
            assert!(
                present(Bytes::from(vec![0_u8, 1]), mime, &ViewOptions::default()).is_err(),
                "{mime}"
            );
        }
        assert!(present(
            Bytes::from(vec![0_u8]),
            "audio/L16;rate=16000",
            &ViewOptions::default()
        )
        .is_err());
    }

    #[test]
    fn simple_accept_patterns_match_without_prefix_confusion() {
        for pattern in ["*", "*/*", "text/*", "TEXT/PLAIN"] {
            assert!(present(
                Bytes::from(b"ok".to_vec()),
                "text/plain; charset=utf-8",
                &only(pattern)
            )
            .is_ok());
        }
        assert!(!Accept::new(&["image/*".into()])
            .unwrap()
            .matches("imageish/png"));
        assert!(!Accept::new(&["text/plain".into()])
            .unwrap()
            .matches("text/html"));
    }

    #[test]
    fn invalid_options_and_unknown_types_fail_clearly() {
        for options in [
            ViewOptions {
                max_bytes: 0,
                ..ViewOptions::default()
            },
            ViewOptions {
                max_dimension: Some(0),
                ..ViewOptions::default()
            },
            ViewOptions {
                accept: vec![],
                ..ViewOptions::default()
            },
            only(""),
            only("image"),
            only("*/png"),
            only("image/p*"),
            only("image/png;q=0.8"),
        ] {
            assert!(
                present(Bytes::from(b"ok".to_vec()), "text/plain", &options).is_err(),
                "{options:?}"
            );
        }
        for mime in ["application/octet-stream", "application/x-mystery"] {
            let error = present(Bytes::from(vec![0, 1]), mime, &only("*")).unwrap_err();
            assert!(error.to_string().contains(RAW_GET_HINT));
        }
        assert!(present(Bytes::from(vec![0]), "not a mime", &only("*")).is_err());
        assert!(present(Bytes::from(vec![0]), "text/*", &only("*")).is_err());
    }

    #[test]
    fn limited_encoder_writer_cannot_seek_past_its_budget_then_write() {
        let mut writer = LimitedWriter {
            inner: Cursor::new(Vec::new()),
            max_bytes: 4,
        };
        writer.write_all(&[1, 2, 3, 4]).unwrap();
        assert!(writer.write_all(&[5]).is_err());
        writer.seek(SeekFrom::Start(100)).unwrap();
        assert!(writer.write_all(&[6]).is_err());
        assert_eq!(writer.inner.into_inner(), [1, 2, 3, 4]);
    }
}
