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
    assert_id(
        "planner::cancellation::event",
        format!("{:X}", crate::schemas::planner::cancellation::event.id()),
        "123D7A7CC84D0E95EE51298021213B46",
    );
    assert_id(
        "triage::exec::attempt",
        format!("{:X}", crate::schemas::triage::exec::attempt.id()),
        "79474B948670C7D0322C309EB65219F8",
    );
    assert_id(
        "triage::model_chat::attempt",
        format!("{:X}", crate::schemas::triage::model_chat::attempt.id()),
        "8CAEF4617646F8C9E90BC9A3ED3D0496",
    );
    for (path, got, expected) in [
        (
            "habit::label",
            format!("{:X}", crate::schemas::habit::attrs::label.id()),
            "4AB58053472C4163C39C9A4047F8111E",
        ),
        (
            "habit::nudge",
            format!("{:X}", crate::schemas::habit::attrs::nudge.id()),
            "1E82BD7E8EFEA00FD3FAB3ECEFD0BA33",
        ),
        (
            "habit::condition",
            format!("{:X}", crate::schemas::habit::attrs::condition.id()),
            "134ECC925E8547B46AF67D6DC29B5F5C",
        ),
        (
            "habit::of",
            format!("{:X}", crate::schemas::habit::attrs::of.id()),
            "F00FAA4B44DB1E79E36055410B476C42",
        ),
        (
            "habit::state",
            format!("{:X}", crate::schemas::habit::attrs::state.id()),
            "5C1E4BD13E8FA4633F286CD5B33BCAC7",
        ),
    ] {
        assert_id(path, got, expected);
    }
}

#[test]
fn relations_snapshot_algebra_keeps_its_minted_ids() {
    use crate::schemas::relations::{group, identity, lifecycle, profile};

    for (path, got, expected) in [
        (
            "relations::profile::of",
            format!("{:X}", profile::of.id()),
            "6BB0306AA13B62F7E5490AEB255430E3",
        ),
        (
            "relations::profile::alias",
            format!("{:X}", profile::alias.id()),
            "8663728605F1212E3B454D0E7F09FB76",
        ),
        (
            "relations::profile::affinity",
            format!("{:X}", profile::affinity.id()),
            "96101F2E1A20978BEBD12BB97D6E84F6",
        ),
        (
            "relations::profile::teams_user_id",
            format!("{:X}", profile::teams_user_id.id()),
            "9DBA8FAEF649E33919BC708F943F0C2D",
        ),
        (
            "relations::profile::email",
            format!("{:X}", profile::email.id()),
            "962F91429CE0432204B12E9A041E56A8",
        ),
        (
            "relations::profile::phone",
            format!("{:X}", profile::phone.id()),
            "140A6AAD3F1845694F33B00D97B9AF40",
        ),
        (
            "relations::profile::first_name",
            format!("{:X}", profile::first_name.id()),
            "F0AD0BBFAC4C4C899637573DC965622E",
        ),
        (
            "relations::profile::last_name",
            format!("{:X}", profile::last_name.id()),
            "764DD765142B3F4725B614BD3B9118EC",
        ),
        (
            "relations::profile::display_name",
            format!("{:X}", profile::display_name.id()),
            "DC0916CB5F640984EFE359A33105CA9A",
        ),
        (
            "relations::profile::company",
            format!("{:X}", profile::company.id()),
            "E3D486BD7C9C088D908DF1B9E1F4D925",
        ),
        (
            "relations::profile::position",
            format!("{:X}", profile::position.id()),
            "173B771D35FEE90B83F2731DD3C59EF8",
        ),
        (
            "relations::profile::profile_url",
            format!("{:X}", profile::profile_url.id()),
            "5A71C103E026FC1AC01E35EDAC274A5C",
        ),
        (
            "relations::lifecycle::of",
            format!("{:X}", lifecycle::of.id()),
            "36E4966DA6704AA84C44A3E4E8DEB70F",
        ),
        (
            "relations::lifecycle::retired",
            format!("{:X}", lifecycle::retired.id()),
            "639BD621C86B6B6C39F08D6E97026988",
        ),
        (
            "relations::group::member",
            format!("{:X}", group::member.id()),
            "EF5B6F8429FA30D503BA8B8F3ABD5FD9",
        ),
        (
            "relations::group::snapshot_of",
            format!("{:X}", group::snapshot_of.id()),
            "D944552B560826095BCEAFDAACE6DF66",
        ),
        (
            "relations::identity::low",
            format!("{:X}", identity::low.id()),
            "31B34A0C3B2129DA19ECEF84961E92EC",
        ),
        (
            "relations::identity::high",
            format!("{:X}", identity::high.id()),
            "86B8EF9DA613C443C27A1A9519222CBE",
        ),
        (
            "relations::identity::same",
            format!("{:X}", identity::same.id()),
            "EFBE40002918177DCBAAEC2D20D223FD",
        ),
    ] {
        assert_id(path, got, expected);
    }

    for (path, got, expected) in [
        (
            "relations::DEFAULT_SCOPE_ID",
            format!("{:X}", crate::schemas::relations::DEFAULT_SCOPE_ID),
            "A36AB53B3F9B4D52AC6BD473C1F8C4F1",
        ),
        (
            "relations::KIND_PERSON_PROFILE",
            format!("{:X}", crate::schemas::relations::KIND_PERSON_PROFILE),
            "BEFF639D71F2AF70BC01E0DBE99C0304",
        ),
        (
            "relations::KIND_PERSON_LIFECYCLE",
            format!("{:X}", crate::schemas::relations::KIND_PERSON_LIFECYCLE),
            "717DCED8539A871037AFFC7893F6FF9F",
        ),
        (
            "relations::KIND_GROUP_SNAPSHOT",
            format!("{:X}", crate::schemas::relations::KIND_GROUP_SNAPSHOT),
            "A42E379E89D2F3A52EEA7A40771B51BF",
        ),
        (
            "relations::KIND_IDENTITY_VERDICT",
            format!("{:X}", crate::schemas::relations::KIND_IDENTITY_VERDICT),
            "4BEAD16C2FDBBDEB7BA37B464594E1CE",
        ),
    ] {
        assert_id(path, got, expected);
    }
}

/// Coverage is deliberately source-level and workspace-wide: a declaration
/// omitted from the representative equality checks above must still be unable
/// to slip back to the encoding-derived anchored form unnoticed. New schemas
/// that deliberately use the safe `(anchor, encoding)` identity form are
/// admitted only by an exact declaration allowlist, rather than by exempting
/// their whole file or crate.
#[test]
fn no_published_workspace_literal_uses_bare_as() {
    fn is_deliberate_anchor(path: &std::path::Path, declaration: &str) -> bool {
        let Some(path) = path.to_str() else {
            return false;
        };
        [
            (
                "schemas/orient.rs",
                "\"3CD5AAC437782247E0AE445D199B92E9\" as persona: inlineencodings::GenId;",
            ),
            (
                "schemas/orient.rs",
                "\"55D805540D0E44B2779FC5116BB66B3F\" as view: inlineencodings::Handle<blobencodings::LongString>;",
            ),
            (
                "schemas/posture.rs",
                "\"26F75BC480669978650F99B11480D168\" as scan_document: inlineencodings::GenId;",
            ),
            (
                "schemas/posture.rs",
                "\"952559B264EA4F07812CE79D13D70166\" as scan_finding: inlineencodings::GenId;",
            ),
            (
                "schemas/posture.rs",
                "\"4A79C0B54AF4B8AE50B9D2CEDAA05D48\" as scan_omission: inlineencodings::GenId;",
            ),
            (
                "schemas/wiki.rs",
                "\"FF2DD2D2E71E8CD4AC45C0667FECAF4A\" as revision: inlineencodings::GenId;",
            ),
            (
                "schemas/discord.rs",
                "\"4B9C024EDD627A4E8786E01B196FDF16\" as pub message: GenId;",
            ),
            (
                "schemas/discord.rs",
                "\"CE2A12E5A260253138C86DD2D15654C7\" as pub user: GenId;",
            ),
            (
                "schemas/discord.rs",
                "\"A37BBC85528AF14B6C20280886B7A537\" as pub receipt_after_exclusive: U256BE;",
            ),
            (
                "schemas/discord.rs",
                "\"8B9F2C90AB42911696E17F49974CD28B\" as pub receipt_through_inclusive: U256BE;",
            ),
            (
                "schemas/headspace.rs",
                "\"DAE53BDA7C5D7878AF846490BF3DC62F\" as cognition_scope: GenId;",
            ),
            (
                "schemas/headspace.rs",
                "\"740B82A5C35A7577171627F01F13A1BA\" as model_secret_version: GenId;",
            ),
            (
                "schemas/headspace.rs",
                "\"7B2CAEA05A9B7247E86916E13372EDF1\" as tavily_secret_version: GenId;",
            ),
            (
                "schemas/headspace.rs",
                "\"05C8F916018E3E4DDAD5D5F2DBE148B2\" as exa_secret_version: GenId;",
            ),
            (
                "schemas/teams.rs",
                "\"35CED3BE8703D51670F55A0A7D7379A2\" as pub auth_client_id: Handle<LongString>;",
            ),
            (
                "schemas/teams.rs",
                "\"70B7AD9A1FE24A186F6E45DF979AE4C1\" as pub auth_user_id: Handle<LongString>;",
            ),
            (
                "schemas/teams.rs",
                "\"3EE1F37036587FA6F678B66474747C50\" as pub auth_scopes: Handle<LongString>;",
            ),
            (
                "schemas/teams.rs",
                "\"16BCD72691DE40244513D2D2276C6E6C\" as pub auth_client_secret_version: GenId;",
            ),
            (
                "schemas/teams.rs",
                "\"32B44CCD1C4C95B87F263BFA39909404\" as pub auth_delegated_token_version: GenId;",
            ),
        ]
        .iter()
        .any(|(suffix, expected)| path.ends_with(suffix) && declaration == *expected)
    }

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
                if literal_is_upper_hex
                    && trimmed[34..].trim_start().starts_with("as ")
                    && !is_deliberate_anchor(&path, trimmed)
                {
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

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut unswept = Vec::new();
    for source_root in ["src", "faculties-secrets/src"] {
        walk(&root.join(source_root), &mut unswept);
    }
    assert!(
        unswept.is_empty(),
        "{} published attribute declaration(s) use bare `as` and therefore no longer resolve to their literal id:\n{}",
        unswept.len(),
        unswept.join("\n")
    );
}
