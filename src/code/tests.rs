//! Open-world contract for the Code projections.
//!
//! These are the tests that keep the catalogue from quietly becoming a
//! validating loader. Every one of them asserts that something this reader
//! cannot model is INERT or SKIPPED, never an error.

use triblespace::core::metadata;

use super::*;
use crate::schemas::code::{attrs, KIND_ITEM};

fn fixture() -> (TribleSet, Id, Id, Id) {
    let extracted = extract::Extracted {
        doc: Some("a module".to_owned()),
        items: vec![extract::ExtractedItem {
            kind: crate::schemas::code::ItemKind::Fn,
            name: Some("force_step_kernel".to_owned()),
            tokens: "pub fn force_step_kernel ( ) { }".to_owned(),
            signature: "pub fn force_step_kernel()".to_owned(),
            doc: Some("One integration step of the force-directed layout, on GPU.".to_owned()),
            visibility: crate::schemas::code::Visibility::Public,
            mentions: ["cubecl".to_owned(), "cubecl::wgpu".to_owned()]
                .into_iter()
                .collect(),
            span: (380, 0, 402, 1),
            parent: None,
        }],
        ..extract::Extracted::default()
    };
    let (fragment, unit) = unit_fragment(
        "faculties",
        "src/widgets/wiki.rs",
        Language::Rust,
        b"// fixture",
        &extracted,
    );
    let scan_core = scan_core(text_handle("faculties"), text_handle("336a8765"));
    let scan = scan_core.root().expect("scan root");

    let mut facts = TribleSet::new();
    facts += fragment.facts().clone();
    facts += scan_core.facts().clone();
    facts += scan_holds(scan, unit).facts().clone();

    let item = find!(
        item: Id,
        pattern!(&facts, [{ ?item @ metadata::tag: &KIND_ITEM }])
    )
    .next()
    .expect("one item");
    (facts, scan, unit, item)
}

#[test]
fn an_exact_identifier_is_a_constant_term_in_the_pattern() {
    let (facts, scan, _, item) = fixture();
    let found = definitions_in_scan(&facts, scan, text_handle("force_step_kernel"));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].item, item);
    assert_eq!(span_parts(found[0].range).0, 380);
}

#[test]
fn an_absent_identifier_yields_no_rows_and_that_is_the_answer() {
    let (facts, scan, _, _) = fixture();
    assert!(definitions_in_scan(&facts, scan, text_handle("LearnerBuilder")).is_empty());
    assert!(usages_in_scan(&facts, scan, text_handle("burn::train")).is_empty());
}

#[test]
fn a_full_joined_path_is_queryable_exactly() {
    let (facts, scan, _, _) = fixture();
    assert_eq!(
        usages_in_scan(&facts, scan, text_handle("cubecl::wgpu")).len(),
        1
    );
    assert_eq!(usages_in_scan(&facts, scan, text_handle("cubecl")).len(), 1);
}

#[test]
fn an_unmodelled_fact_on_an_item_is_inert() {
    let (mut facts, scan, _, item) = fixture();
    // An attribute from some other faculty, asserted on our item.
    facts += entity! { ExclusiveId::force_ref(&item) @
        metadata::description: text_handle("something this reader does not model"),
    };
    assert_eq!(
        definitions_in_scan(&facts, scan, text_handle("force_step_kernel")).len(),
        1
    );
    assert_eq!(item_row(&facts, item).len(), 1);
}

#[test]
fn an_item_with_two_names_yields_two_complete_tuples_and_no_error() {
    let (mut facts, scan, _, item) = fixture();
    facts += entity! { ExclusiveId::force_ref(&item) @
        metadata::name: text_handle("fdeb_step_kernel"),
    };
    // Both names resolve. Nothing bails on the second: the schema language
    // cannot express cardinality, and re-imposing it here would invent a
    // constraint the substrate deliberately refuses.
    assert_eq!(
        definitions_in_scan(&facts, scan, text_handle("force_step_kernel")).len(),
        1
    );
    assert_eq!(
        definitions_in_scan(&facts, scan, text_handle("fdeb_step_kernel")).len(),
        1
    );
    assert_eq!(item_names(&facts, item).len(), 2);
}

#[test]
fn an_item_whose_kind_is_unknown_to_this_reader_is_skipped_not_rejected() {
    let (mut facts, scan, unit, _) = fixture();
    // A future extractor's vocabulary, in the same collection.
    let newer = entity! { _ @
        metadata::tag: &KIND_ITEM,
        attrs::source_tokens: text_handle("impl Trait for Type { }"),
    };
    let newer_item = newer.root().expect("root");
    facts += newer.facts().clone();
    facts += entity! { ExclusiveId::force_ref(&newer_item) @
        attrs::kind: "coroutine",
        attrs::visibility: "pub",
        metadata::name: text_handle("resume"),
    };
    let range: SpanValue = (1_u64, 0_u64, 2_u64, 0_u64).to_inline();
    let placement = placement_core(unit, newer_item, range);
    facts += placement.facts().clone();

    // The row is reachable by name, because a name is a name.
    assert_eq!(
        definitions_in_scan(&facts, scan, text_handle("resume")).len(),
        1
    );
    // Its KIND does not inhabit this reader's result type — and that is a
    // skip, not an error. It is what lets two generations of this faculty read
    // one pile through a cutover.
    assert!(item_row(&facts, newer_item).is_empty());
}

#[test]
fn byte_identical_declarations_in_two_files_are_one_item_with_two_placements() {
    let declaration = extract::ExtractedItem {
        kind: crate::schemas::code::ItemKind::Fn,
        name: Some("arc_points".to_owned()),
        tokens: "fn arc_points ( ) -> u8 { 1 }".to_owned(),
        signature: "fn arc_points() -> u8".to_owned(),
        doc: None,
        visibility: crate::schemas::code::Visibility::Private,
        mentions: ["u8".to_owned()].into_iter().collect(),
        span: (237, 0, 240, 1),
        parent: None,
    };
    let here = extract::Extracted {
        items: vec![declaration.clone()],
        ..extract::Extracted::default()
    };
    let there = extract::Extracted {
        items: vec![extract::ExtractedItem {
            span: (497, 0, 500, 1),
            ..declaration
        }],
        ..extract::Extracted::default()
    };

    let (left, left_unit) =
        unit_fragment("GORBIE", "src/widgets/mesh.rs", Language::Rust, b"a", &here);
    let (right, right_unit) = unit_fragment(
        "GORBIE",
        "src/widgets/lattice.rs",
        Language::Rust,
        b"b",
        &there,
    );
    assert_ne!(left_unit, right_unit);

    let scan_core = scan_core(text_handle("GORBIE"), text_handle("24bea0ac"));
    let scan = scan_core.root().expect("scan root");
    let mut facts = TribleSet::new();
    facts += left.facts().clone();
    facts += right.facts().clone();
    facts += scan_core.facts().clone();
    facts += scan_holds(scan, left_unit).facts().clone();
    facts += scan_holds(scan, right_unit).facts().clone();

    let items: Vec<Id> = find!(
        item: Id,
        pattern!(&facts, [{ ?item @ metadata::tag: &KIND_ITEM }])
    )
    .collect();
    // ONE item. The pile's content addressing IS the clone detector: no hash
    // attribute, no hashing pass, no comparison.
    assert_eq!(items.len(), 1);

    let pairs = duplicate_placements_in_scan(&facts, scan);
    let distinct: std::collections::BTreeSet<(Id, Id)> = pairs
        .iter()
        .filter(|(_, left, right, _, _)| left != right)
        .map(|(_, left, right, _, _)| {
            if left < right {
                (*left, *right)
            } else {
                (*right, *left)
            }
        })
        .collect();
    assert_eq!(distinct.len(), 1);
}

#[test]
fn a_unit_re_ingested_unchanged_produces_the_same_entities() {
    let extracted = extract::Extracted {
        doc: Some("prose".to_owned()),
        ..extract::Extracted::default()
    };
    let (first, first_unit) = unit_fragment(
        "faculties",
        "src/lib.rs",
        Language::Rust,
        b"content",
        &extracted,
    );
    let (second, second_unit) = unit_fragment(
        "faculties",
        "src/lib.rs",
        Language::Rust,
        b"content",
        &extracted,
    );
    assert_eq!(first_unit, second_unit);
    assert_eq!(first.facts(), second.facts());
}

#[test]
fn a_moved_file_is_a_different_unit_but_the_same_items() {
    let extracted = extract::Extracted {
        items: vec![extract::ExtractedItem {
            kind: crate::schemas::code::ItemKind::Fn,
            name: Some("f".to_owned()),
            tokens: "fn f ( ) { }".to_owned(),
            signature: "fn f()".to_owned(),
            doc: None,
            visibility: crate::schemas::code::Visibility::Private,
            mentions: Default::default(),
            span: (1, 0, 1, 12),
            parent: None,
        }],
        ..extract::Extracted::default()
    };
    let (here, here_unit) = unit_fragment(
        "faculties",
        "src/a.rs",
        Language::Rust,
        b"fn f() {}",
        &extracted,
    );
    let (there, there_unit) = unit_fragment(
        "faculties",
        "src/b.rs",
        Language::Rust,
        b"fn f() {}",
        &extracted,
    );
    assert_ne!(here_unit, there_unit);

    let item_of = |fragment: &Fragment| -> Id {
        find!(
            item: Id,
            pattern!(fragment.facts(), [{ ?item @ metadata::tag: &KIND_ITEM }])
        )
        .next()
        .expect("one item")
    };
    // Moving a file re-mints its unit and leaves the declaration's identity
    // alone, because an item is its tokens and nothing else.
    assert_eq!(item_of(&here), item_of(&there));
}

#[test]
fn a_scan_core_carries_no_clock_so_two_machines_converge() {
    let left = scan_core(text_handle("faculties"), text_handle("336a8765"));
    let right = scan_core(text_handle("faculties"), text_handle("336a8765"));
    assert_eq!(left.root(), right.root());

    let scan = left.root().expect("root");
    let early = scan_annotation(
        scan,
        crate::clock::point(hifitime::Epoch::from_tai_seconds(1.0)).unwrap(),
        "head",
    );
    let late = scan_annotation(
        scan,
        crate::clock::point(hifitime::Epoch::from_tai_seconds(9.0)).unwrap(),
        "head",
    );
    // Two observation times on ONE scan entity. No cardinality is imposed on
    // them, and neither one wins.
    let mut facts = TribleSet::new();
    facts += early.facts().clone();
    facts += late.facts().clone();
    assert_eq!(
        find!(
            at: IntervalValue,
            pattern!(&facts, [{ scan @ metadata::created_at: ?at }])
        )
        .count(),
        2
    );
}

#[test]
fn an_unparseable_unit_is_held_with_its_complaint_and_no_items() {
    let extracted = extract::extract("fn broken( {", Language::Rust);
    let (fragment, unit) = unit_fragment(
        "faculties",
        "src/broken.rs",
        Language::Rust,
        b"fn broken( {",
        &extracted,
    );
    let facts = fragment.facts().clone();
    // The unit exists, it is searchable, and the gap is visible rather than
    // silent. Refusing the file would have made it invisible instead.
    assert_eq!(
        find!(
            error: TextHandle,
            pattern!(&facts, [{ unit @ attrs::parse_error: ?error }])
        )
        .count(),
        1
    );
    assert!(find!(
        item: Id,
        pattern!(&facts, [{ ?item @ metadata::tag: &KIND_ITEM }])
    )
    .next()
    .is_none());
}

#[test]
fn swapping_a_derived_id_for_a_fresh_one_breaks_only_idempotence() {
    // The mechanical test CLAUDE.md prescribes. Nothing in this module
    // validates or recomputes an entity id in order to look something up, so a
    // fresh id produces a second, distinct item — which is duplication, not an
    // error, and exactly the physics two-generals hands us.
    let extracted = extract::Extracted {
        items: vec![extract::ExtractedItem {
            kind: crate::schemas::code::ItemKind::Fn,
            name: Some("f".to_owned()),
            tokens: "fn f ( ) { }".to_owned(),
            signature: "fn f()".to_owned(),
            doc: None,
            visibility: crate::schemas::code::Visibility::Private,
            mentions: Default::default(),
            span: (1, 0, 1, 12),
            parent: None,
        }],
        ..extract::Extracted::default()
    };
    let (fragment, unit) = unit_fragment(
        "faculties",
        "src/a.rs",
        Language::Rust,
        b"fn f() {}",
        &extracted,
    );
    let mut facts = fragment.facts().clone();

    let stranger = Id::new([0x5A; 16]).expect("non-nil");
    facts += entity! { ExclusiveId::force_ref(&stranger) @
        metadata::tag: &KIND_ITEM,
        attrs::source_tokens: text_handle("fn f ( ) { }"),
        metadata::name: text_handle("f"),
    };
    let range: SpanValue = (9_u64, 0_u64, 9_u64, 12_u64).to_inline();
    facts += placement_core(unit, stranger, range).facts().clone();

    let scan_core = scan_core(text_handle("faculties"), text_handle("deadbeef"));
    let scan = scan_core.root().expect("root");
    facts += scan_core.facts().clone();
    facts += scan_holds(scan, unit).facts().clone();

    // Both are found; nothing errors; only the dedup is lost.
    assert_eq!(definitions_in_scan(&facts, scan, text_handle("f")).len(), 2);
}
