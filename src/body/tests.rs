use crate::body as body_model;
use crate::schemas::body::intent;
#[cfg(test)]
fn latest_intent_jit<P>(space: &P) -> Option<(i128, Id, TextHandle)>
where
    P: TriblePattern,
{
    let mut best: Option<(i128, Id, TextHandle)> = None;
    for (intent_id, handle, created) in find!(
        (i: Id, h: TextHandle, t: Inline<inlineencodings::NsTAIInterval>),
        pattern!(space, [{
            ?i @
                metadata::tag: KIND_INTENT,
                intent::text: ?h,
                metadata::created_at: ?t,
        }])
    ) {
        let candidate = (interval_key(created), intent_id);
        if best
            .as_ref()
            .is_none_or(|(time, id, _)| candidate > (*time, *id))
        {
            best = Some((candidate.0, candidate.1, handle));
        }
    }

    best
}

use std::fs::{self, File};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::storage::initialize_signer;

use super::*;

static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "faculties-body-live-{}-{serial}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn at_unix(seconds: f64) -> Inline<inlineencodings::NsTAIInterval> {
    let epoch = Epoch::from_unix_seconds(seconds);
    (epoch, epoch).try_to_inline().unwrap()
}

#[test]
fn equal_time_intents_coexist_and_higher_event_id_wins() {
    let directory = TestDirectory::new();
    let pile = directory.0.join("body.pile");
    let key = directory.0.join("body.key");
    File::create(&pile).unwrap();
    initialize_signer(&pile, Some(&key)).unwrap();
    let storage = BodyStorage {
        pile: &pile,
        key: Some(&key),
    };

    let created = at_unix(1_750_000_000.0);
    let first = intent_fragment("first", created);
    let second = intent_fragment("second", created);
    let first_id = first.root().unwrap();
    let second_id = second.root().unwrap();
    storage.publish(second).unwrap();
    storage.publish(first).unwrap();

    let mut capture = Fragment::empty();
    let pose = capture.put::<blobencodings::UTF8String, _>("{}".to_owned());
    capture += entity! {
        metadata::tag: &KIND_CAPTURE,
        metadata::created_at: at_unix(1_760_000_000.0),
        capture::modality: "touch",
        capture::pose: pose,
    };
    storage.publish(capture).unwrap();

    storage
        .with_indexed_view(|snapshot| {
            let intents: Vec<Id> = find!(
                (i: Id),
                pattern!(snapshot.facts(), [{ ?i @ metadata::tag: KIND_INTENT }])
            )
            .map(|(id,)| id)
            .collect();
            assert_eq!(intents.len(), 2);

            let (_, jit_id, jit_handle) =
                latest_intent_jit(snapshot.facts()).expect("JIT latest intent");
            let selected = latest_intent(snapshot)?.expect("maintained latest intent");
            let selected_id = selected.id;
            let selected_text = selected.text;
            let expected_id = first_id.max(second_id);
            let expected_text = if expected_id == first_id {
                "first"
            } else {
                "second"
            };
            assert_eq!(jit_id, expected_id);
            assert_eq!(selected_id, expected_id);
            assert_eq!(
                body_model::decode_intent(snapshot.facts(), selected_id)?.text,
                jit_handle
            );
            assert_eq!(selected_text, expected_text);
            Ok(())
        })
        .unwrap();
}

#[test]
fn indexed_snapshots_are_attached_to_their_exact_cover() {
    let directory = TestDirectory::new();
    let pile_path = directory.0.join("body.pile");
    let key = directory.0.join("body.key");
    File::create(&pile_path).unwrap();
    initialize_signer(&pile_path, Some(&key)).unwrap();
    let signer = load_signer(&pile_path, Some(&key)).unwrap();
    let mut pile = open_pile_strict(&pile_path).unwrap();

    let first = intent_fragment("first", at_unix(1_750_000_000.0));
    let first_id = first.root().unwrap();
    let collection = open_configured(&mut pile, DEFAULT_SCOPE_ID, signer.verifying_key()).unwrap();
    pile.commit(collection, &signer, first).unwrap();
    let before = pollster::block_on(body_model::materialize_indexed_collection(
        &mut pile, &signer,
    ))
    .unwrap();
    assert_eq!(
        body_model::latest_intent(before.facts(), before.intent_register())
            .unwrap()
            .unwrap()
            .id,
        first_id
    );

    let second = intent_fragment("second", at_unix(1_760_000_000.0));
    let second_id = second.root().unwrap();
    pile.commit(collection, &signer, second).unwrap();
    let after = pollster::block_on(body_model::materialize_indexed_collection(
        &mut pile, &signer,
    ))
    .unwrap();

    assert_eq!(
        body_model::latest_intent(before.facts(), before.intent_register())
            .unwrap()
            .unwrap()
            .id,
        first_id,
        "the older snapshot must not borrow a later cover's register"
    );
    assert_eq!(
        body_model::latest_intent(after.facts(), after.intent_register())
            .unwrap()
            .unwrap()
            .id,
        second_id
    );
    pile.close().unwrap();
}
