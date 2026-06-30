//! Liora's self-image domain attributes — the labels her self-image dataset
//! hangs on `mary::dataset` Samples.
//!
//! These are deliberately SEPARATE from the generic `mary::dataset` schema: that
//! namespace is modality-blind and domain-free, knowing nothing about any one
//! dataset's labels. The "open schema" pattern is exactly this — a consumer
//! extends the model by minting its *own* typed attributes and hanging them on
//! the shared Sample entities, never by forking the generic library.
//!
//! `style` and `expression` are real typed attributes (not a generic key→value
//! annotation): each is its own minted id with its own value schema, so "every
//! sample in this style" or "every joyful expression" is a single one-pattern
//! query, and content-addressed dedup still applies. Both are short labels, so
//! `ShortString` inline values (no blob).

use triblespace::prelude::inlineencodings::ShortString;
use triblespace::prelude::*;

attributes! {
    /// The visual/aesthetic style label of a self-image sample (e.g.
    /// "portrait", "watercolour", "line-art"). Minted 2026-06-30 (trible genid).
    "C60D8DCFD7ECA4B0A975C8656327A17F" as style: ShortString;
    /// The emotional expression label of a self-image sample (e.g. "joyful",
    /// "pensive", "serene"). Minted 2026-06-30 (trible genid).
    "813627529BC29E76938ADC06ACD4F9F8" as expression: ShortString;
}
