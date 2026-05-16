//! Gauge schema: re-exports the subset of wiki attributes that the gauge
//! faculty reads when computing research quality metrics.
//!
//! Gauge is a read-only lens on wiki tag metadata — it does not define
//! its own attribute IDs. Keeping this module here lets downstream
//! consumers of the gauge faculty mirror the same attribute view.

pub const WIKI_BRANCH_NAME: &str = "wiki";

pub mod wiki {
    use triblespace::prelude::*;
    attributes! {
        "EBFC56D50B748E38A14F5FC768F1B9C1" as fragment: inlineencodings::GenId;
        "78BABEF1792531A2E51A372D96FE5F3E" as title: inlineencodings::Handle<blobencodings::LongString>;
        "DEAFB7E307DF72389AD95A850F24BAA5" as links_to: inlineencodings::GenId;
    }
}
