//! Explicit import from the resident legacy mixed-persona receipt projection.
//!
//! This copies historical observations, not an attention baseline. It neither
//! maintains the legacy view nor claims that its resident cover is complete.

use super::*;

pub(super) async fn import(
    pile: &mut FacultyStore,
    signer: &SigningKey,
    legacy_persona: &str,
) -> Result<usize> {
    let legacy = OrientSource::open(
        pile,
        signer,
        crate::schemas::orient::DEFAULT_SCOPE_ID,
        "Legacy Orient",
    )
    .await?;
    let relations = OrientSource::open(pile, signer, RELATIONS_SCOPE_ID, "Relations").await?;
    let snapshot = pile.snapshot().context("freeze legacy receipt import")?;
    let relations = relations.observe(&snapshot)?;
    let persona = resolve_resident_persona(relations.view(), &snapshot, legacy_persona)
        .context("resolve legacy receipt persona from resident Relations")?;
    let legacy = legacy.observe(&snapshot)?;
    let facts = legacy.view();
    let mut fragment = Fragment::empty();
    let mut events = BTreeSet::new();
    for (receipt, event) in find!(
        (receipt: Id, event: Id),
        pattern!(facts, [{
            ?receipt @
            metadata::tag: &KIND_PRESENTED,
            presentation::persona: &persona,
            presentation::event: ?event,
        }])
    ) {
        // The existing subject is opaque. Preserve its observed facts, without
        // reconstructing an intrinsic ID or inventing an import timestamp.
        fragment += entity! { ExclusiveId::force_ref(&receipt) @
            metadata::tag: &KIND_PRESENTED,
            presentation::event: &event,
            metadata::created_at*: find!(
                created: IntervalValue,
                pattern!(facts, [{ receipt @ metadata::created_at: ?created }])
            ),
        };
        events.insert(event);
    }
    if events.is_empty() {
        return Ok(0);
    }

    let destination = ReceiptSource::register(pile, signer)?;
    require_presentation_write(&pile.snapshot()?, destination.source, signer)?;
    pile.commit(destination.source, signer, fragment)
        .context("commit imported legacy receipt facts")?;
    Ok(events.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        store: FacultyStore,
        signer: SigningKey,
        legacy: OrientSource,
        relations: OrientSource,
        destination: ReceiptSource,
        _directory: tempfile::TempDir,
    }

    impl Fixture {
        async fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("receipt-import.pile");
            std::fs::File::create(&path).unwrap();
            let signer = SigningKey::from_bytes(&[79; 32]);
            let mut store = open_store(&path).unwrap();
            let legacy = OrientSource::open(
                &mut store,
                &signer,
                crate::schemas::orient::DEFAULT_SCOPE_ID,
                "Legacy Orient",
            )
            .await
            .unwrap();
            let relations =
                OrientSource::open(&mut store, &signer, RELATIONS_SCOPE_ID, "Relations")
                    .await
                    .unwrap();
            let destination = ReceiptSource::register(&mut store, &signer).unwrap();
            Self {
                store,
                signer,
                legacy,
                relations,
                destination,
                _directory: directory,
            }
        }

        async fn publish_legacy(&mut self, facts: Fragment) {
            self.store
                .commit(self.legacy.source, &self.signer, facts)
                .unwrap();
            self.legacy
                .maintain(&mut self.store, &self.signer)
                .await
                .unwrap();
        }

        fn imported(&mut self) -> TribleSet {
            self.store
                .snapshot()
                .unwrap()
                .collection(self.destination.source)
                .unwrap()
                .view::<TribleSet>()
                .unwrap()
        }
    }

    #[test]
    fn import_selects_one_persona_and_preserves_opaque_receipts_and_timestamps() {
        pollster::block_on(async {
            let mut f = Fixture::new().await;
            let persona = fucid();
            let other_persona = fucid();
            let receipt = fucid();
            let duplicate_event_receipt = fucid();
            let undated_receipt = fucid();
            let foreign_receipt = fucid();
            let event = fucid();
            let second_event = fucid();
            let foreign_event = fucid();
            let extra_tag = fucid();
            let times = [
                clock::point(Epoch::from_unix_seconds(1_700_000_000.0)).unwrap(),
                clock::point(Epoch::from_unix_seconds(1_700_000_010.0)).unwrap(),
            ];
            let (person, _, _) = relations::person_fragment(
                *persona,
                relations::ProfileInput {
                    label: "Legacy reader".to_owned(),
                    aliases: vec!["legacy-alias".to_owned()],
                    ..Default::default()
                },
            )
            .unwrap();
            f.store
                .commit(f.relations.source, &f.signer, person)
                .unwrap();
            f.relations.maintain(&mut f.store, &f.signer).await.unwrap();
            let legacy = entity! { &receipt @
                metadata::tag*: [&KIND_PRESENTED, &*extra_tag],
                presentation::persona: &persona,
                presentation::event: &event,
                metadata::created_at*: times,
            } + entity! { &duplicate_event_receipt @
                metadata::tag: &KIND_PRESENTED,
                presentation::persona: &persona,
                presentation::event: &event,
            } + entity! { &undated_receipt @
                metadata::tag: &KIND_PRESENTED,
                presentation::persona: &persona,
                presentation::event: &second_event,
            } + entity! { &foreign_receipt @
                metadata::tag: &KIND_PRESENTED,
                presentation::persona: &other_persona,
                presentation::event: &foreign_event,
                metadata::created_at*: times,
            };
            f.publish_legacy(legacy.clone()).await;
            let legacy_before = f
                .store
                .snapshot()
                .unwrap()
                .collection(f.legacy.source)
                .unwrap()
                .view::<TribleSet>()
                .unwrap();

            assert_eq!(
                import(&mut f.store, &f.signer, "legacy-alias")
                    .await
                    .unwrap(),
                2
            );
            let expected = entity! { &receipt @
                metadata::tag: &KIND_PRESENTED,
                presentation::event: &event,
                metadata::created_at*: times,
            } + entity! { &duplicate_event_receipt @
                metadata::tag: &KIND_PRESENTED,
                presentation::event: &event,
            } + entity! { &undated_receipt @
                metadata::tag: &KIND_PRESENTED,
                presentation::event: &second_event,
            };
            assert_eq!(&f.imported(), expected.facts());
            let after = f.store.snapshot().unwrap();
            assert_eq!(
                after
                    .collection(f.legacy.source)
                    .unwrap()
                    .view::<TribleSet>()
                    .unwrap(),
                legacy_before,
            );
            assert!(
                after
                    .collection(f.destination.rank9)
                    .unwrap()
                    .cover()
                    .is_empty(),
                "import publishes only source facts; maintenance stays explicit"
            );
            assert!(!exists!(pattern!(expected.facts(), [{
                undated_receipt @ metadata::created_at: _?created
            }])));
        });
    }

    #[test]
    fn import_replay_has_the_same_commit_without_a_new_timestamp() {
        pollster::block_on(async {
            let mut f = Fixture::new().await;
            let persona = fucid();
            let receipt = fucid();
            let event = fucid();
            f.publish_legacy(entity! { &receipt @
                metadata::tag: &KIND_PRESENTED,
                presentation::persona: &persona,
                presentation::event: &event,
            })
            .await;
            let selector = fmt_id(*persona);
            assert_eq!(import(&mut f.store, &f.signer, &selector).await.unwrap(), 1);
            let once = f.imported();
            let before = f.store.snapshot().unwrap();
            assert_eq!(import(&mut f.store, &f.signer, &selector).await.unwrap(), 1);
            assert_eq!(f.imported(), once);
            assert!(f
                .store
                .snapshot()
                .unwrap()
                .changes_since(&before)
                .is_empty());
        });
    }

    #[test]
    fn empty_resident_selection_does_not_commit_or_maintain() {
        pollster::block_on(async {
            let mut f = Fixture::new().await;
            let persona = fucid();
            let receipt = fucid();
            let event = fucid();
            // A source member without its resident legacy projection is not
            // permission to invent a complete historical import or a baseline.
            f.store
                .commit(
                    f.legacy.source,
                    &f.signer,
                    entity! { &receipt @
                        metadata::tag: &KIND_PRESENTED,
                        presentation::persona: &persona,
                        presentation::event: &event,
                    },
                )
                .unwrap();
            let before = f.store.snapshot().unwrap();
            assert_eq!(
                import(&mut f.store, &f.signer, &fmt_id(*persona))
                    .await
                    .unwrap(),
                0
            );
            assert!(f.imported().is_empty());
            assert!(f
                .store
                .snapshot()
                .unwrap()
                .changes_since(&before)
                .is_empty());
        });
    }
}
