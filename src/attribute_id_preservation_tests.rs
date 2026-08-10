//! Attribute identity regression checks.
//!
//! A quoted id followed by bare `as` is an *anchor* in the current
//! `attributes!` macro: the encoding participates in the resulting id. The
//! faculties predate that distinction, so their published literals must use
//! the explicitly pinned `unsafe as` form to keep addressing existing facts.

fn assert_id(path: &str, got: String, expected: &str) {
    assert_eq!(
        got, expected,
        "{path} no longer resolves to its published id"
    );
}

#[test]
fn durable_faculty_attributes_keep_their_published_ids() {
    assert_id(
        "wiki::fragment",
        format!("{:X}", crate::schemas::wiki::attrs::fragment.id()),
        "EBFC56D50B748E38A14F5FC768F1B9C1",
    );
    assert_id(
        "files::content",
        format!("{:X}", crate::schemas::files::file::content.id()),
        "C1E3A12230595280F22ABEB8733D082C",
    );
    assert_id(
        "relations::alias",
        format!("{:X}", crate::schemas::relations::relations::alias.id()),
        "8F162B593D390E1424394DBF6883A72C",
    );
    assert_id(
        "relations::group::member",
        format!("{:X}", crate::schemas::relations::group::member.id()),
        "EF5B6F8429FA30D503BA8B8F3ABD5FD9",
    );
    assert_id(
        "message::to",
        format!("{:X}", crate::schemas::message::local::to.id()),
        "95D58D3E68A43979F8AA51415541414C",
    );
    assert_id(
        "compass::title",
        format!("{:X}", crate::schemas::compass::board::title.id()),
        "EE18CEC15C18438A2FAB670E2E46E00C",
    );
    assert_id(
        "mail::from",
        format!("{:X}", crate::schemas::mail::mail::from.id()),
        "CFAEF6367467548E6799AA8AE9E971C8",
    );
}

/// Coverage is deliberately source-level: a declaration omitted from the
/// representative equality checks above must still be unable to slip back to
/// the encoding-derived anchored form unnoticed.
#[test]
fn no_published_literal_uses_bare_as() {
    fn walk(dir: &std::path::Path, unswept: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("read source directory") {
            let path = entry.expect("source entry").path();
            if path.is_dir() {
                walk(&path, unswept);
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }

            let source = std::fs::read_to_string(&path).expect("read Rust source");
            for (line_index, line) in source.lines().enumerate() {
                let trimmed = line.trim_start();
                let bytes = trimmed.as_bytes();
                if bytes.len() <= 34 || bytes[0] != b'"' || bytes[33] != b'"' {
                    continue;
                }
                let literal_is_upper_hex = bytes[1..33]
                    .iter()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase());
                if literal_is_upper_hex && trimmed[34..].trim_start().starts_with("as ") {
                    unswept.push(format!(
                        "{}:{}: {}",
                        path.display(),
                        line_index + 1,
                        trimmed
                    ));
                }
            }
        }
    }

    let mut unswept = Vec::new();
    walk(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut unswept,
    );
    assert!(
        unswept.is_empty(),
        "{} published attribute declaration(s) use bare `as` and therefore no longer resolve to their literal id:\n{}",
        unswept.len(),
        unswept.join("\n")
    );
}
