//! Incremental, frontend-neutral faculty output.
//!
//! A handler pushes native content to the frontend as it becomes available.
//! There is no stored result, transport encoding, or endpoint selection here.
//! A finite frontend may explicitly collect parts; a long-lived frontend can
//! deliver each part without retaining the preceding output.
//!
//! This interface is synchronous: a slow emitter holds up the handler, and an
//! emitter error is returned to it immediately. Blocking CLI transport belongs
//! in the emitter. An asynchronous frontend such as MCP must invoke synchronous
//! handlers at its blocking-work boundary, constructing [`Out`] there, rather
//! than block a shared async executor. No runtime or queue is supplied here.

use anybytes::Bytes;
use anyhow::Result;

/// One ordered emission, with resident media bytes rather than an encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Part {
    /// Exact UTF-8 text; no separator is added by the output interface.
    Text { text: String },
    /// An image and its declared media type. Cloning shares its byte storage.
    Image { bytes: Bytes, mime_type: String },
    /// An audio clip and its declared media type. Cloning shares its storage.
    Audio { bytes: Bytes, mime_type: String },
    /// An exact binary export, not a request to display or play its contents.
    /// The URI identifies the exported value; transports carry resident bytes.
    /// CLI exports stay on stdout even when perception uses DRIVE_ENDPOINT;
    /// MCP exports are file resources, never sensory input.
    Blob {
        bytes: Bytes,
        mime_type: String,
        uri: String,
    },
}

/// A borrowed synchronous emitter, with no implicit buffering.
///
/// Handlers propagate emission errors with `?`. Previously accepted parts are
/// not rolled back, retried, or rerouted. The frontend decides what acceptance
/// means for its transport; it does not imply remote processing or durability.
/// An emitter can report cancellation at an emission, but this interface does
/// not interrupt a handler that is computing or waiting without emitting.
pub struct Out<'a> {
    emit: &'a mut dyn FnMut(Part) -> Result<()>,
}

impl<'a> Out<'a> {
    pub fn new(emit: &'a mut dyn FnMut(Part) -> Result<()>) -> Self {
        Self { emit }
    }

    /// Deliver one part before returning; any backpressure or error is direct.
    pub fn emit(&mut self, part: Part) -> Result<()> {
        (self.emit)(part)
    }

    /// Emit text exactly, including any newlines supplied by the handler.
    pub fn text(&mut self, text: impl Into<String>) -> Result<()> {
        self.emit(Part::Text { text: text.into() })
    }

    /// Emit text followed by one newline, including for an empty line.
    pub fn line(&mut self, line: impl Into<String>) -> Result<()> {
        let mut text = line.into();
        text.push('\n');
        self.text(text)
    }

    pub fn image(&mut self, bytes: impl Into<Bytes>, mime_type: impl Into<String>) -> Result<()> {
        self.emit(Part::Image {
            bytes: bytes.into(),
            mime_type: mime_type.into(),
        })
    }

    pub fn audio(&mut self, bytes: impl Into<Bytes>, mime_type: impl Into<String>) -> Result<()> {
        self.emit(Part::Audio {
            bytes: bytes.into(),
            mime_type: mime_type.into(),
        })
    }

    /// Export bytes without interpreting them as text or a displayed modality.
    pub fn blob(
        &mut self,
        bytes: impl Into<Bytes>,
        mime_type: impl Into<String>,
        uri: impl Into<String>,
    ) -> Result<()> {
        self.emit(Part::Blob {
            bytes: bytes.into(),
            mime_type: mime_type.into(),
            uri: uri.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_mixed_order_exact_text_and_line_endings() {
        let image = Bytes::from(vec![0_u8, 0xff]);
        let audio = Bytes::from(vec![1_u8, 2, 3]);
        let mut parts = Vec::new();
        {
            let mut collect = |part| {
                parts.push(part);
                Ok(())
            };
            let mut output = Out::new(&mut collect);
            output.line("first").unwrap();
            output.image(image.clone(), "image/png").unwrap();
            output.text("between").unwrap();
            output.audio(audio.clone(), "audio/wav").unwrap();
            output.line("").unwrap();
            output.line("last\n").unwrap();
        }
        assert_eq!(
            parts,
            [
                Part::Text {
                    text: "first\n".into()
                },
                Part::Image {
                    bytes: image.clone(),
                    mime_type: "image/png".into()
                },
                Part::Text {
                    text: "between".into()
                },
                Part::Audio {
                    bytes: audio.clone(),
                    mime_type: "audio/wav".into()
                },
                Part::Text { text: "\n".into() },
                Part::Text {
                    text: "last\n\n".into()
                },
            ]
        );
        let Part::Image { bytes, .. } = &parts[1] else {
            panic!("expected image")
        };
        assert_eq!(bytes.as_ptr(), image.as_ptr(), "image storage is shared");
        let Part::Audio { bytes, .. } = &parts[3] else {
            panic!("expected audio")
        };
        assert_eq!(bytes.as_ptr(), audio.as_ptr(), "audio storage is shared");
    }

    #[test]
    fn no_output_and_an_explicit_empty_text_part_remain_distinct() {
        let mut parts = Vec::new();
        {
            let mut collect = |part| {
                parts.push(part);
                Ok(())
            };
            let _output = Out::new(&mut collect);
        }
        assert!(parts.is_empty());
        {
            let mut collect = |part| {
                parts.push(part);
                Ok(())
            };
            Out::new(&mut collect).text("").unwrap();
        }
        assert_eq!(
            parts,
            [Part::Text {
                text: String::new()
            }]
        );
    }
}
