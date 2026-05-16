//! Wiki schema: fragments, content, links, file references, and tag vocabulary.
//!
//! Used by `wiki.rs` (the faculty CLI) and by viewers that render wiki
//! fragments from a pile (the GORBIE wiki viewer widget, playground
//! dashboard, etc.).

use triblespace::macros::id_hex;
use triblespace::prelude::*;

pub const WIKI_BRANCH_NAME: &str = "wiki";

pub const KIND_VERSION_ID: Id = id_hex!("1AA0310347EDFED7874E8BFECC6438CF");

pub const TAG_ARCHIVED_ID: Id = id_hex!("480CB6A663C709478A26A8B49F366C3F");

pub const TAG_SPECS: [(Id, &str); 9] = [
    (KIND_VERSION_ID, "version"),
    (id_hex!("1A7FB717FBFCA81CA3AA7D3D186ACC8F"), "hypothesis"),
    (id_hex!("72CE6B03E39A8AAC37BC0C4015ED54E2"), "critique"),
    (id_hex!("243AE22C5E020F61EBBC8C0481BF05A4"), "finding"),
    (id_hex!("8871C1709EBFCDD2588369003D3964DE"), "paper"),
    (id_hex!("7D58EBA4E1E4A1EF868C3C4A58AEC22E"), "source"),
    (id_hex!("C86BCF906D270403A0A2083BB95B3552"), "concept"),
    (id_hex!("F8172CC4E495817AB52D2920199EF4BD"), "experiment"),
    (TAG_ARCHIVED_ID, "archived"),
];

pub mod attrs {
    use super::*;
    attributes! {
        "EBFC56D50B748E38A14F5FC768F1B9C1" as fragment: inlineencodings::GenId;
        "6DBBE746B7DD7A4793CA098AB882F553" as content: inlineencodings::Handle<blobencodings::LongString>;
        "78BABEF1792531A2E51A372D96FE5F3E" as title: inlineencodings::Handle<blobencodings::LongString>;
        "DEAFB7E307DF72389AD95A850F24BAA5" as links_to: inlineencodings::GenId;
        // Content-hash reference: `files:<64-char-blake3>` points to file bytes directly.
        "C61CA2F2A70103FD79E97C2F88B854D8" as references_file_content: inlineencodings::Handle<blobencodings::RawBytes>;
        // File-entity reference: `files:<32-char-id>` points to a file entity with metadata.
        "C98FE0EF9151F196D8F7D816ABBBCC49" as references_file: inlineencodings::GenId;
    }
}
