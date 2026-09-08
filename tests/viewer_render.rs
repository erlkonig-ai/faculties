//! Explicit graphics smoke test: no model weights, live pile or audio/camera devices.
//! Run only with a reserved graphics host and an outer process deadline.
#![cfg(feature = "widgets")]

use faculties::relations::{ProfileInput, Relations};
use faculties::status::Status;
use faculties::storage::initialize_signer;
use faculties::viewer::{CaptureOptions, Target, Viewer};
use std::time::Duration;

#[test]
#[ignore = "requires an explicitly reserved native graphics runtime"]
fn resident_capture_renders_a_temporary_status_pile_without_export_files() {
    let directory = tempfile::tempdir().unwrap();
    let pile = directory.path().join("capture.pile");
    let key = directory.path().join("explicit.key");
    std::fs::File::create(&pile).unwrap();
    initialize_signer(&pile, Some(&key)).unwrap();
    let relations = Relations::new(pile.clone(), Some(key.clone()));
    let person = relations
        .add(
            ProfileInput {
                label: "Capture fixture".into(),
                ..Default::default()
            },
            None,
            &[],
        )
        .unwrap();
    Status::new(pile.clone(), Some(key.clone()))
        .set(
            &format!("{:x}", person.person),
            "Native capture is rendering",
        )
        .unwrap();
    let entries = || {
        let mut names = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        names
    };
    let before = entries();
    let options = CaptureOptions {
        scale: 0.5,
        settle_timeout: Duration::from_millis(500),
        max_images: 2,
        max_bytes: 1024 * 1024,
    };
    let mut pages = Vec::new();
    let summary = Viewer::new(pile, Some(key))
        .capture_with(Target::Status, &options, |page| {
            pages.push(page);
            Ok(())
        })
        .unwrap();
    assert_eq!(summary.images, 2);
    assert_eq!(
        summary.bytes,
        pages.iter().map(|page| page.png.len()).sum::<usize>()
    );
    assert_eq!(entries(), before, "resident capture created an export file");
    for (index, page) in pages.iter().enumerate() {
        assert_eq!(page.card_index, index);
        assert_eq!((page.page_index, page.page_count), (0, 1));
        let decoded = image::load_from_memory(page.png.as_ref())
            .unwrap()
            .into_rgba8();
        assert_eq!(decoded.dimensions(), (page.width, page.height));
        assert!(page.width > 0 && page.height > 0);
        let first = decoded.get_pixel(0, 0);
        assert!(
            decoded.pixels().any(|pixel| pixel != first),
            "flat capture page"
        );
    }
}
