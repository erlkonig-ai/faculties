//! Resident-only health input with admitted foreground maintenance.
//! No host activation or blob acquisition is part of this path.
//!
//! The maintained targets remain the query sources. The values built below
//! are just one report's output and attention IDs, never a second health store.

use super::*;
use crate::schemas::swarm_health::{self as schema, attrs};
use triblespace::core::collection::descriptor;

pub(super) struct HealthSources {
    health: OrientSource,
    latest: Collection<LwwRegisterBlob>,
    relations: OrientSource,
    presentations: ReceiptSource,
    max_age: Duration,
    // The prefix before successful health upkeep and an optional receipt
    // attempt, not its final query snapshot: an append racing upkeep must
    // remain changed on the next poll.
    maintained_view: Option<(ed25519_dalek::VerifyingKey, FacultySnapshot)>,
    // A failed receipt attempt is not a freshness claim. Retain its note with
    // that input/signer so unchanged polls report it without repeating upkeep.
    receipt_maintenance_note: Option<String>,
    // One process-local observation, not another persisted health model. The
    // cached views and watermark belong to exactly the same sampled prefix.
    poll_view: Option<(FacultySnapshot, HealthObservation)>,
    #[cfg(test)]
    poll_observations: usize,
    #[cfg(test)]
    maintenance_passes: std::cell::Cell<usize>,
}

impl HealthSources {
    pub(super) fn open(
        pile: &mut FacultyStore,
        signer: &SigningKey,
        max_age: Duration,
    ) -> Result<Self> {
        let mut local = pile.store();
        let mut open = |scope, label| {
            let source = open_configured(&mut *local, scope, signer.verifying_key())?;
            OrientSource::register(&mut *local, source, label)
        };
        let health = open(schema::DEFAULT_SCOPE_ID, "Swarm health")?;
        let relations = open(RELATIONS_SCOPE_ID, "Relations")?;
        let presentations = ReceiptSource::register(&mut *local, signer)?;
        let policy = health.source.policy(&local.snapshot()?)?;
        let latest = local.derive::<LwwRegisterBlob>(
            health.source,
            (attrs::node.id(), metadata::created_at.id()),
            policy,
        )?;
        drop(local);
        Ok(Self {
            health,
            latest,
            relations,
            presentations,
            max_age,
            maintained_view: None,
            receipt_maintenance_note: None,
            poll_view: None,
            #[cfg(test)]
            poll_observations: 0,
            #[cfg(test)]
            maintenance_passes: std::cell::Cell::new(0),
        })
    }

    fn maintain(&self, pile: &FacultyStore, signer: &SigningKey) -> Result<Option<String>> {
        #[cfg(test)]
        self.maintenance_passes
            .set(self.maintenance_passes.get() + 1);
        let mut local = pile.store();
        // Pile acquisition is immediately resident-only. Run these local
        // mapping futures to completion without yielding a Peer store guard
        // across network I/O or re-entering a Peer operation.
        pollster::block_on(async {
            let snapshot = local.snapshot()?;
            for source in [&self.health, &self.relations] {
                if !source.can_maintain(&snapshot, signer)? {
                    continue;
                }
                drop(local.maintain(source.succinct, signer).await?);
                drop(local.maintain(source.rank9, signer).await?);
            }
            if self
                .latest
                .writer_is_admitted(&snapshot, signer.verifying_key())?
            {
                drop(local.maintain(self.latest, signer).await?);
            }
            // As on the ordinary Orient path, receipt freshness avoids a
            // repeat but is not a precondition of reporting resident health.
            // Only this optional projection is best effort; health, Relations
            // and latest-target failures above still propagate unchanged.
            let receipt_result: Result<()> = async {
                if self
                    .presentations
                    .ids
                    .writer_is_admitted(&snapshot, signer.verifying_key())
                    .context("check Orient receipt membership WRITE admission")?
                {
                    drop(
                        local
                            .maintain(self.presentations.ids, signer)
                            .await
                            .context("maintain Orient receipt membership set")?,
                    );
                }
                Ok(())
            }
            .await;
            Ok(receipt_result.err().map(|error| {
                format!(
                    "note: Orient receipt membership not refreshed ({error:#}); a recent event may repeat"
                )
            }))
        })
    }

    pub(super) fn observe(
        &self,
        pile: &mut FacultyStore,
        signer: &SigningKey,
    ) -> Result<HealthObservation> {
        // Baseline/show select health, not presentation freshness. Poll has an
        // Out through which it reports an optional receipt-attempt failure.
        let _receipt_note = self.maintain(pile, signer)?;
        let now = clock::now()?;
        self.at(pile.snapshot()?, now)
    }

    fn maintain_if_changed(
        &mut self,
        pile: &mut FacultyStore,
        signer: &SigningKey,
    ) -> Result<bool> {
        let before = pile.snapshot()?;
        let subject = signer.verifying_key();
        if self
            .maintained_view
            .as_ref()
            .is_some_and(|(prior_subject, prior)| {
                *prior_subject == subject && before.changes_since(prior).is_empty()
            })
        {
            return Ok(false);
        }
        let receipt_note = self.maintain(pile, signer)?;
        // Our own publications can cause one extra quiet upkeep. Advancing to
        // a post-upkeep snapshot instead could silently cover a concurrent
        // append to a source whose mapping has already run.
        self.maintained_view = Some((subject, before));
        self.receipt_maintenance_note = receipt_note;
        Ok(true)
    }

    /// Health is delivered before any ordinary source or payload acquisition.
    /// An unresolved resident persona leaves the normal resolution path intact.
    pub(super) fn poll(
        &mut self,
        pile: &mut FacultyStore,
        signer: &SigningKey,
        input: &str,
        peek: bool,
        output: &mut Out<'_>,
    ) -> Result<(bool, Option<Epoch>)> {
        self.maintain_if_changed(pile, signer)?;
        if let Some(note) = &self.receipt_maintenance_note {
            output.line(note)?;
        }
        let now = clock::now()?;
        let sampled = pile.snapshot()?;
        self.refresh_poll_view(sampled, now)?;
        let (_, observation) = self
            .poll_view
            .as_ref()
            .expect("poll selected a health view");
        let report = observation.report();
        if report.attention.is_empty() {
            return Ok((false, report.next_change));
        }
        let persona = match observation.persona(input) {
            Ok(persona) => persona,
            Err(error) if is_payload_pending(&error) || is_persona_not_found(&error) => {
                return Ok((false, report.next_change));
            }
            Err(error) => return Err(error),
        };
        let news = observation.news(persona, &report);
        let fired = matches!(news, News::Report { .. });
        apply_prepared_news(pile, signer, peek, &news, "", output)?;
        Ok((fired, report.next_change))
    }

    fn refresh_poll_view(&mut self, sampled: FacultySnapshot, now: Epoch) -> Result<()> {
        let probe = RefreshProbe::begin(
            "health",
            &sampled,
            self.poll_view.as_ref().map(|(watermark, _)| watermark),
            None,
        );
        let changed = self
            .poll_view
            .as_ref()
            .map_or(true, |(_, observation)| !observation.is_current(&sampled));
        if changed {
            let observation = self.at(sampled.clone(), now);
            if let Some(probe) = &probe {
                if let Ok(current) = &observation {
                    let previous = self.poll_view.as_ref().map(|(_, observation)| observation);
                    trace_refresh_line(format_args!(
                        "event=baseline refresh={} scope=health baseline={}",
                        probe.id,
                        if previous.is_some() {
                            "previous_observation"
                        } else {
                            "absent"
                        },
                    ));
                    probe.fact("Swarm health", previous.map(|p| &p.facts), &current.facts);
                    probe.fact(
                        "Relations",
                        previous.map(|p| &p.relations),
                        &current.relations,
                    );
                    probe.cover(
                        "Orient receipts",
                        previous.map(|p| p.presentations.collection.cover()),
                        current.presentations.collection.cover(),
                    );
                    probe.cover(
                        "Swarm health latest",
                        previous.map(|p| p.latest_collection.cover()),
                        current.latest_collection.cover(),
                    );
                }
                probe.finish(if observation.is_ok() {
                    "ready"
                } else {
                    "error"
                });
            }
            let observation = observation?;
            self.poll_view = Some((sampled, observation));
            #[cfg(test)]
            {
                self.poll_observations += 1;
            }
        } else {
            // Unrelated appends and time alone leave these target views valid.
            // Refresh the payload reader and health evaluation time so newly
            // resident labels, expiry and clock rollback need no reattachment.
            let observation = &mut self
                .poll_view
                .as_mut()
                .expect("an unchanged poll has a selected health view")
                .1;
            observation.snapshot = sampled;
            observation.evaluated_at = now;
            if let Some(probe) = &probe {
                probe.finish("retained");
            }
        }
        Ok(())
    }

    fn at(&self, snapshot: FacultySnapshot, now: Epoch) -> Result<HealthObservation> {
        let facts = self.health.observe(&snapshot)?;
        let latest_collection = trace_refresh_call("Swarm health latest", "attach", || {
            snapshot.collection(self.latest)
        })?;
        let latest_index = trace_refresh_call("Swarm health latest", "view", || {
            latest_collection.view::<LwwIndex>()
        })?;
        let latest = trace_refresh_call("Swarm health latest", "query", || latest_index.query())?;
        let relations = self.relations.observe(&snapshot)?;
        let presentations = self.presentations.observe(&snapshot)?;
        Ok(HealthObservation {
            snapshot,
            evaluated_at: now,
            facts,
            latest,
            latest_collection,
            relations,
            presentations,
            max_age: self.max_age,
        })
    }
}

pub(super) fn until(deadline: Option<Epoch>, now: Epoch) -> Option<Duration> {
    deadline.map(|deadline| {
        let ns = (deadline - now).total_nanoseconds().max(0);
        Duration::from_nanos(ns.min(u64::MAX as i128) as u64)
    })
}

/// The reader's freshness deadline, not a retry timeout. Dropping ordinary reads at
/// this boundary lets the caller refresh local health before trying them again.
pub(super) async fn deadline(deadline: Option<Epoch>) -> Result<()> {
    match until(deadline, clock::now()?) {
        Some(delay) => tokio::time::sleep(delay).await,
        None => std::future::pending::<()>().await,
    }
    Ok(())
}

pub(super) struct HealthObservation {
    snapshot: FacultySnapshot,
    // Health freshness is evaluated at this explicit application time, not a
    // property of the immutable storage observation.
    evaluated_at: Epoch,
    facts: OrientFact,
    latest: LwwQuery,
    latest_collection: CollectionSnapshot<FacultySnapshot, LwwRegisterBlob>,
    relations: OrientFact,
    presentations: ReceiptObservation,
    max_age: Duration,
}

pub(super) struct HealthReport {
    pub(super) text: String,
    pub(super) attention: AttentionView,
    pub(super) next_change: Option<Epoch>,
}

impl HealthObservation {
    fn is_current(&self, snapshot: &FacultySnapshot) -> bool {
        self.facts.is_current(snapshot)
            && self.latest_collection.is_current(snapshot)
            && self.relations.is_current(snapshot)
            && self.presentations.is_current(snapshot)
    }

    pub(super) fn report(&self) -> HealthReport {
        render_health(
            self.facts.view(),
            &self.latest,
            &self.snapshot,
            self.evaluated_at,
            self.max_age,
        )
    }

    pub(super) fn persona(&self, input: &str) -> Result<Id> {
        resolve_resident_persona(self.relations.view(), &self.snapshot, input)
    }

    pub(super) fn news(&self, _persona: Id, report: &HealthReport) -> News {
        let pending = report.attention.pending(self.presentations.view());
        if pending.is_empty() {
            return News::Quiet;
        }
        use std::fmt::Write as _;
        let mut text = String::new();
        // Wait/poll are an attention channel, not a health dashboard. Each
        // reason already identifies the changed subject and actionable state;
        // the complete resident snapshot remains available through `show`.
        let mut collection_groups: BTreeMap<CollectionSyncGroup, Vec<&AttentionEvent>> =
            BTreeMap::new();
        for event in pending.events.values() {
            match event {
                AttentionEvent::Health {
                    collection_group: Some(group),
                    ..
                } => collection_groups
                    .entry(group.clone())
                    .or_default()
                    .push(event),
                _ => writeln!(text, "News: {}", event.reason()).unwrap(),
            }
        }
        for (group, events) in collection_groups {
            if events.len() == 1 {
                writeln!(text, "News: {}", events[0].reason()).unwrap();
            } else {
                writeln!(text, "News: {}", group.reason(events.len())).unwrap();
            }
        }
        News::Report {
            text,
            events: pending.ids().collect(),
        }
    }
}

fn component_name(component: Id) -> Option<&'static str> {
    match component {
        schema::HOST => Some("event loop"),
        schema::STORE => Some("serving snapshot"),
        schema::COLLECTION => Some("collection sync"),
        schema::DHT => Some("DHT publication"),
        _ => None,
    }
}

fn state_name(component: Id, state: Id) -> &'static str {
    match state {
        schema::CURRENT if component == schema::COLLECTION => {
            "converged at observed pairwise roots"
        }
        schema::CURRENT => "current",
        schema::PROGRESSING => "catching up",
        schema::STALLED => "stalled",
        _ => "unknown",
    }
}

fn attention_state_name(component: Id, state: Id) -> &'static str {
    match state {
        schema::UNKNOWN if component == schema::COLLECTION => {
            "pairwise-root comparison unavailable beyond progress grace"
        }
        schema::STALLED if component == schema::COLLECTION => {
            "pairwise roots remain divergent without observed progress beyond grace"
        }
        _ => state_name(component, state),
    }
}

fn collection_label(
    snapshot: &FacultySnapshot,
    handle: Inline<inlineencodings::Handle<SimpleArchive>>,
) -> String {
    let encoded = hex::encode(handle.raw);
    let prefix = &encoded[..12];
    let name = BlobStoreGet::get::<TribleSet, SimpleArchive>(snapshot, handle)
        .ok()
        .and_then(|facts| descriptor::name(&facts).ok().flatten())
        .and_then(|name| {
            BlobStoreGet::get::<View<str>, blobencodings::UTF8String>(snapshot, name).ok()
        });
    match name {
        Some(name) => format!("{} [{prefix}]", &*name),
        None => format!("[{prefix}]"),
    }
}

/// Query the current report and its conditions directly from maintained facts.
/// Missing/unknown rows do not invalidate other reports or invent a green bit.
fn render_health(
    facts: &FactArchive,
    latest: &LwwQuery,
    snapshot: &FacultySnapshot,
    now: Epoch,
    max_age: Duration,
) -> HealthReport {
    use std::fmt::Write as _;

    let now_key = now.to_tai_duration().total_nanoseconds();
    let mut text = String::from("\nSwarm health (local observations):\n");
    let mut attention = AttentionView::default();
    let mut next_change: Option<Epoch> = None;
    let mut observed = false;
    for (report, node, session, endpoint, created) in find!(
        (report: Id, node: Id, session: Id, endpoint: ed25519_dalek::VerifyingKey,
         created: (Epoch, Epoch)),
        and!(latest.has(report), pattern!(facts, [
            { ?report @ metadata::tag: &schema::KIND_REPORT, attrs::node: ?node,
              attrs::session: ?session, metadata::created_at: ?created },
            { ?node @ attrs::endpoint: ?endpoint },
        ]))
    ) {
        observed = true;
        let endpoint = hex::encode(endpoint.to_bytes());
        let observer = &endpoint[..12];
        let age = format_age(now_key, created.1.to_tai_duration().total_nanoseconds());
        let stale_at =
            created.1 + hifitime::Duration::from_total_nanoseconds(max_age.as_nanos() as i128);
        let fresh = created.1 <= now && now < stale_at;
        let timing = if now < created.1 {
            "unknown (sample is in the future)"
        } else if !fresh {
            "unknown (report too old)"
        } else {
            "fresh"
        };
        writeln!(text, "- observer [{observer}], sample {age} ago: {timing}").unwrap();
        if fresh {
            next_change = Some(next_change.map_or(stale_at, |seen| seen.min(stale_at)));
        } else if now < created.1 {
            next_change = Some(next_change.map_or(created.1, |seen| seen.min(created.1)));
        } else {
            attention.insert(AttentionEvent::Health {
                event: report,
                detail: format!("observer [{observer}] report exceeds reader maximum age; current health unknown (last sample {age} ago)"),
                collection_group: None,
            });
        }
        let mut conditions = BTreeSet::new();
        for (condition, component, state) in find!(
            (condition: Id, component: Id, state: Id),
            pattern!(facts, [
                { report @ attrs::condition: ?condition },
                { ?condition @ metadata::tag: &schema::KIND_CONDITION,
                  metadata::tag: ?component, attrs::node: &node, attrs::session: &session,
                  attrs::state: ?state },
            ])
        ) {
            let Some(component_name) = component_name(component) else {
                continue;
            };
            let mut collections: Vec<String> = find!(
                collection: Inline<inlineencodings::Handle<SimpleArchive>>,
                pattern!(facts, [{ condition @ attrs::collection: ?collection }])
            )
            .map(|collection| collection_label(snapshot, collection))
            .collect();
            collections.sort();
            let mut peers: Vec<String> = find!(
                peer: ed25519_dalek::VerifyingKey,
                pattern!(facts, [{ condition @ attrs::peer: ?peer }])
            )
            .map(|peer| hex::encode(peer.to_bytes())[..12].to_owned())
            .collect();
            peers.sort();
            let collection_scope = collections
                .iter()
                .map(|collection| format!(" {collection}"))
                .collect::<String>();
            let peer_scope = peers
                .iter()
                .map(|peer| format!(" via [{peer}]"))
                .collect::<String>();
            let scope = format!("{collection_scope}{peer_scope}");
            let detail = format!("{component_name}{scope}: {}", state_name(component, state));
            conditions.insert(detail.clone());
            // Recovery is retained in the append-only health report, but it is
            // normal daemon exhaust: only an active alert asks the agent to act.
            if fresh
                && exists!(pattern!(facts, [{ condition @ metadata::tag: &schema::KIND_ALERT }]))
            {
                attention.insert(AttentionEvent::Health {
                    event: condition,
                    detail: format!(
                        "observer [{observer}] {component_name}{scope}: {}",
                        attention_state_name(component, state)
                    ),
                    collection_group: if component == schema::COLLECTION && collections.len() == 1 {
                        let issue = match state {
                            schema::UNKNOWN => Some(CollectionSyncIssue::ComparisonUnavailable),
                            schema::STALLED => Some(CollectionSyncIssue::DivergenceStalled),
                            _ => None,
                        };
                        issue.map(|issue| CollectionSyncGroup {
                            observer: observer.to_owned(),
                            peer_scope,
                            issue,
                        })
                    } else {
                        None
                    },
                });
            }
        }
        if conditions.is_empty() {
            writeln!(text, "  scope not observed in this report").unwrap();
        }
        for condition in conditions {
            writeln!(
                text,
                "  {condition}{}",
                if fresh { "" } else { " (last sample only)" }
            )
            .unwrap();
        }
    }
    if !observed {
        text.push_str("- not observed / not configured; no health conclusion\n");
    } else {
        text.push_str("  Scope is the reported observer/peer/collection pairs, not the whole swarm.\n  DHT publication and record convergence do not prove blob availability.\n");
    }
    HealthReport {
        text,
        attention,
        next_change,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schema::{Component, Condition, Recorder, State};
    use triblespace::core::blob::Blob;
    use triblespace::core::collection::{
        records::empty_metadata_handle, CollectionCommit, CollectionRecord, CollectionStore,
    };
    use triblespace::core::repo::{BlobStorePut, WantRead};

    struct Fixture {
        store: FacultyStore,
        sources: HealthSources,
        signer: SigningKey,
        _directory: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("health.pile");
            std::fs::File::create(&path).unwrap();
            // Test-only author, never a live transport or pile identity.
            let signer = SigningKey::from_bytes(&[71; 32]);
            let mut store = open_store(&path).unwrap();
            let sources =
                HealthSources::open(&mut store, &signer, Duration::from_secs(60)).unwrap();
            Self {
                store,
                sources,
                signer,
                _directory: directory,
            }
        }

        fn publish(&mut self, facts: Fragment) {
            self.store
                .commit(self.sources.health.source, &self.signer, facts)
                .unwrap();
        }

        fn observe_at(&mut self, at: Epoch) -> HealthObservation {
            assert!(self
                .sources
                .maintain(&self.store, &self.signer)
                .unwrap()
                .is_none());
            self.sources.at(self.store.snapshot().unwrap(), at).unwrap()
        }

        fn malformed_member(&mut self, source: Collection<SimpleArchive>) -> CollectionCommit {
            // Resident and content-valid as a blob, but not a SimpleArchive.
            // A missing member alone can be skipped by resident source support
            // and would not establish the upkeep-failure boundary.
            let blob = Blob::<SimpleArchive>::new(Bytes::from(vec![0xff]));
            let handle = self.store.put::<SimpleArchive, _>(blob).unwrap();
            let commit = CollectionCommit::sign(
                &self.signer,
                source.handle(),
                inlineencodings::Handle::<SimpleArchive>::to_hash(handle),
                empty_metadata_handle(),
            );
            self.store.insert(CollectionRecord::Commit(commit)).unwrap();
            assert!(self
                .store
                .snapshot()
                .unwrap()
                .contains_blob(handle)
                .unwrap());
            commit
        }
    }

    fn condition(state: State, alert: bool) -> Condition {
        Condition {
            component: Component::Collection,
            collection: None,
            peer: None,
            state,
            alert,
        }
    }

    fn at(seconds: f64) -> Epoch {
        Epoch::from_unix_seconds(1_700_000_000.0 + seconds)
    }

    #[test]
    fn health_reader_keeps_resident_input_when_source_grows_without_images() {
        let mut f = Fixture::new();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        let first = recorder
            .record(at(0.0), [condition(State::Current, false)])
            .unwrap();
        let first_id = first.root().unwrap();
        f.publish(first);
        f.observe_at(at(1.0));
        let second = recorder
            .record(at(2.0), [condition(State::Stalled, true)])
            .unwrap();
        f.publish(second);

        let reader_key = SigningKey::from_bytes(&[73; 32]);
        // Keep receipt publication local while health and Relations are
        // external, read-only input for this signing principal.
        f.sources.presentations = {
            let mut local = f.store.store();
            ReceiptSource::register(&mut *local, &reader_key).unwrap()
        };
        let before = f.store.snapshot().unwrap();
        let records: Vec<_> = before.records().unwrap().map(Result::unwrap).collect();
        assert!(!f.sources.health.can_maintain(&before, &reader_key).unwrap());
        let observed = f.sources.observe(&mut f.store, &reader_key).unwrap();
        let reports = find!(
            report: Id,
            pattern!(observed.facts.view(), [{ ?report @ metadata::tag: &schema::KIND_REPORT }])
        )
        .collect::<BTreeSet<_>>();
        assert_eq!(reports, BTreeSet::from([first_id]));
        assert_eq!(
            f.store
                .snapshot()
                .unwrap()
                .records()
                .unwrap()
                .map(Result::unwrap)
                .collect::<Vec<_>>(),
            records,
            "health-first reads must not require WRITE on remote inputs",
        );
        assert!(observed.presentations.view().is_empty());
        assert!(observed.snapshot.wants().unwrap().next().is_none());
    }

    #[test]
    fn health_reads_with_write_authority_maintain_before_observing() {
        let mut f = Fixture::new();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        let first = recorder
            .record(at(0.0), [condition(State::Current, false)])
            .unwrap();
        let first_id = first.root().unwrap();
        f.publish(first);

        let before = f.store.snapshot().unwrap();
        assert!(f.sources.health.can_maintain(&before, &f.signer).unwrap());
        assert!(f
            .sources
            .latest
            .writer_is_admitted(&before, f.signer.verifying_key())
            .unwrap());
        let ready = f.sources.observe(&mut f.store, &f.signer).unwrap();
        assert!(exists!(pattern!(ready.facts.view(), [
            { first_id @ metadata::tag: &schema::KIND_REPORT }
        ])));
        assert!(ready.latest.contains(first_id));
        assert!(f
            .sources
            .at(before.clone(), at(1.0))
            .unwrap()
            .facts
            .collection
            .cover()
            .is_empty());

        let second = recorder
            .record(at(2.0), [condition(State::Stalled, true)])
            .unwrap();
        let second_id = second.root().unwrap();
        f.publish(second);
        let observed = f.sources.observe(&mut f.store, &f.signer).unwrap();
        let reports: BTreeSet<_> = find!(
            report: Id,
            pattern!(observed.facts.view(), [{ ?report @ metadata::tag: &schema::KIND_REPORT }])
        )
        .collect();
        assert_eq!(reports, BTreeSet::from([first_id, second_id]));
        assert!(observed.latest.contains(second_id));
        assert!(!observed.latest.contains(first_id));
        assert!(
            !exists!(pattern!(ready.facts.view(), [
                { second_id @ metadata::tag: &schema::KIND_REPORT }
            ])),
            "foreground upkeep must not replace an earlier selected view"
        );
        assert!(
            observed.presentations.view().is_empty(),
            "observing is not presenting"
        );
        assert!(observed.snapshot.wants().unwrap().next().is_none());
    }

    #[test]
    fn health_reads_and_polls_carry_existing_private_receipts_before_delivery() {
        let mut f = Fixture::new();
        let persona = *fucid();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        f.publish(
            recorder
                .record(clock::now().unwrap(), [condition(State::Stalled, true)])
                .unwrap(),
        );
        let health = f.sources.observe(&mut f.store, &f.signer).unwrap();
        let events: Vec<_> = health.report().attention.ids().collect();
        assert!(!events.is_empty());

        // Receipt ownership is the signing zooid, independent of the selected
        // contact. An earlier source COMMIT must be carried before reporting.
        let reader_key = SigningKey::from_bytes(&[73; 32]);
        f.sources.presentations = {
            let mut local = f.store.store();
            ReceiptSource::register(&mut *local, &reader_key).unwrap()
        };
        f.store
            .commit(
                f.sources.presentations.source,
                &reader_key,
                entity! {
                    metadata::tag: &KIND_PRESENTED,
                    presentation::event*: events.iter().copied(),
                },
            )
            .unwrap();
        let before = f.store.snapshot().unwrap();
        let raw_receipts = before
            .collection(f.sources.presentations.source)
            .unwrap()
            .cover()
            .clone();
        let lagging = f.sources.at(before, clock::now().unwrap()).unwrap();
        assert!(events
            .iter()
            .all(|event| !lagging.presentations.view().contains(*event)));
        assert!(matches!(
            lagging.news(persona, &lagging.report()),
            News::Report { .. }
        ));
        let ready = f.sources.observe(&mut f.store, &reader_key).unwrap();
        assert!(events
            .iter()
            .all(|event| ready.presentations.view().contains(*event)));
        assert!(matches!(ready.news(persona, &ready.report()), News::Quiet));
        let mut parts = Vec::new();
        let mut emit = |part| {
            parts.push(part);
            Ok(())
        };
        let (fired, _) = f
            .sources
            .poll(
                &mut f.store,
                &reader_key,
                &fmt_id(persona),
                false,
                &mut Out::new(&mut emit),
            )
            .unwrap();
        assert!(
            !fired,
            "foreground receipt upkeep suppresses an already presented report"
        );
        assert!(parts.is_empty());
        let after = f.store.snapshot().unwrap();
        assert_eq!(
            after
                .collection(f.sources.presentations.source)
                .unwrap()
                .cover(),
            &raw_receipts,
            "catching up a receipt projection must not author another receipt",
        );
        assert!(after.wants().unwrap().next().is_none());
    }

    #[test]
    fn malformed_receipt_upkeep_is_reported_without_blocking_resident_health() {
        let mut f = Fixture::new();
        let persona = *fucid();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        f.publish(
            recorder
                .record(clock::now().unwrap(), [condition(State::Stalled, true)])
                .unwrap(),
        );
        let receipts = f.sources.presentations.source;
        f.malformed_member(receipts);
        let before = f.store.snapshot().unwrap();
        assert!(receipts
            .writer_is_admitted(&before, f.signer.verifying_key())
            .unwrap());
        let raw_receipts = before.collection(receipts).unwrap().cover().clone();
        let failure = {
            let mut local = f.store.store();
            pollster::block_on(local.maintain(f.sources.presentations.ids, &f.signer))
                .err()
                .expect("resident malformed admitted receipt must actually fail upkeep")
        };
        assert!(format!("{failure:#}").contains("malformed"));

        // The baseline/show observation is still useful even though its
        // optional private presentation projection could not catch up.
        let observed = f.sources.observe(&mut f.store, &f.signer).unwrap();
        assert!(!observed.report().attention.is_empty());
        assert!(observed.presentations.view().is_empty());
        let mut text = String::new();
        let mut emit = |part| {
            let crate::out::Part::Text { text: part } = part else {
                bail!("expected health text");
            };
            text.push_str(&part);
            Ok(())
        };
        let (fired, _) = f
            .sources
            .poll(
                &mut f.store,
                &f.signer,
                &fmt_id(persona),
                true,
                &mut Out::new(&mut emit),
            )
            .unwrap();
        assert!(fired);
        assert!(text.contains("note: Orient receipt membership not refreshed"));
        assert!(text.contains("malformed"));
        assert!(text.contains("News:"));
        let after = f.store.snapshot().unwrap();
        assert_eq!(after.collection(receipts).unwrap().cover(), &raw_receipts);
        assert!(after.wants().unwrap().next().is_none());
    }

    #[test]
    fn failed_receipt_attempt_remains_visible_on_unchanged_quiet_polls() {
        let mut f = Fixture::new();
        let receipts = f.sources.presentations.source;
        f.malformed_member(receipts);
        let before = f.store.snapshot().unwrap();
        let records = before
            .records()
            .unwrap()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        for _ in 0..2 {
            let mut text = String::new();
            let mut emit = |part| {
                let crate::out::Part::Text { text: part } = part else {
                    bail!("expected health text");
                };
                text.push_str(&part);
                Ok(())
            };
            let (fired, _) = f
                .sources
                .poll(
                    &mut f.store,
                    &f.signer,
                    "unused-quiet-persona",
                    true,
                    &mut Out::new(&mut emit),
                )
                .unwrap();
            assert!(!fired);
            assert!(text.contains("note: Orient receipt membership not refreshed"));
            assert!(text.contains("malformed"));
            assert_eq!(f.sources.maintenance_passes.get(), 1);
        }
        let after = f.store.snapshot().unwrap();
        assert!(after.changes_since(&before).is_empty());
        assert_eq!(
            after
                .records()
                .unwrap()
                .map(Result::unwrap)
                .collect::<Vec<_>>(),
            records
        );
        assert!(after.wants().unwrap().next().is_none());
    }

    #[test]
    fn malformed_health_input_is_not_downgraded_to_a_receipt_warning() {
        let mut f = Fixture::new();
        let source = f.sources.health.source;
        f.malformed_member(source);
        let error = f
            .sources
            .observe(&mut f.store, &f.signer)
            .err()
            .expect("malformed health data remains a real observation error");
        assert!(format!("{error:#}").contains("malformed"));
        let mut parts = Vec::new();
        let mut emit = |part| {
            parts.push(part);
            Ok(())
        };
        assert!(f
            .sources
            .poll(
                &mut f.store,
                &f.signer,
                "unused-error-persona",
                true,
                &mut Out::new(&mut emit),
            )
            .is_err());
        assert!(parts.is_empty());
        assert!(f.sources.maintained_view.is_none());
        assert!(f
            .store
            .snapshot()
            .unwrap()
            .wants()
            .unwrap()
            .next()
            .is_none());
    }

    #[test]
    fn health_poll_maintains_new_input_without_turning_peek_into_a_receipt() {
        let mut f = Fixture::new();
        let persona = *fucid();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        f.publish(
            recorder
                .record(clock::now().unwrap(), [condition(State::Stalled, true)])
                .unwrap(),
        );
        let mut parts = Vec::new();
        let mut emit = |part| {
            parts.push(part);
            Ok(())
        };
        assert!(
            f.sources
                .poll(
                    &mut f.store,
                    &f.signer,
                    &fmt_id(persona),
                    true,
                    &mut Out::new(&mut emit),
                )
                .unwrap()
                .0
        );
        assert!(!parts.is_empty());
        let peeked = f.store.snapshot().unwrap();
        assert!(peeked
            .collection(f.sources.presentations.source)
            .unwrap()
            .cover()
            .is_empty());
        assert!(peeked.wants().unwrap().next().is_none());

        parts.clear();
        let mut emit = |part| {
            parts.push(part);
            Ok(())
        };
        assert!(
            f.sources
                .poll(
                    &mut f.store,
                    &f.signer,
                    &fmt_id(persona),
                    false,
                    &mut Out::new(&mut emit),
                )
                .unwrap()
                .0
        );
        assert!(!parts.is_empty());

        // A new watcher has no process-local receipt state to lean on. Its
        // first poll carries the committed receipt through the ordinary set.
        let mut rearmed =
            HealthSources::open(&mut f.store, &f.signer, Duration::from_secs(60)).unwrap();
        parts.clear();
        let mut emit = |part| {
            parts.push(part);
            Ok(())
        };
        assert!(
            !rearmed
                .poll(
                    &mut f.store,
                    &f.signer,
                    &fmt_id(persona),
                    false,
                    &mut Out::new(&mut emit),
                )
                .unwrap()
                .0
        );
        assert!(parts.is_empty());
    }

    #[test]
    fn unchanged_health_poll_prefix_skips_upkeep_after_own_writes_settle() {
        let mut f = Fixture::new();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        f.publish(
            recorder
                .record(at(0.0), [condition(State::Current, false)])
                .unwrap(),
        );
        assert!(f
            .sources
            .maintain_if_changed(&mut f.store, &f.signer)
            .unwrap());
        assert_eq!(f.sources.maintenance_passes.get(), 1);
        assert!(f
            .sources
            .maintain_if_changed(&mut f.store, &f.signer)
            .unwrap());
        assert_eq!(f.sources.maintenance_passes.get(), 2);
        let before = f.store.snapshot().unwrap();
        for instant in [1.0, 60.0, -1.0, 2.0] {
            assert!(!f
                .sources
                .maintain_if_changed(&mut f.store, &f.signer)
                .unwrap());
            f.sources
                .refresh_poll_view(f.store.snapshot().unwrap(), at(instant))
                .unwrap();
        }
        assert_eq!(f.sources.maintenance_passes.get(), 2);
        assert_eq!(f.sources.poll_observations, 1);
        assert!(f
            .store
            .snapshot()
            .unwrap()
            .changes_since(&before)
            .is_empty());
    }

    #[test]
    fn health_upkeep_does_not_cover_a_second_writer_after_its_attempt() {
        let mut f = Fixture::new();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        f.publish(
            recorder
                .record(at(0.0), [condition(State::Current, false)])
                .unwrap(),
        );
        f.sources
            .maintain_if_changed(&mut f.store, &f.signer)
            .unwrap();
        let earlier = f.sources.at(f.store.snapshot().unwrap(), at(1.0)).unwrap();

        // Deterministic interleaving: a separately opened writer appends after
        // upkeep, but before this reader's final selected observation. No
        // concurrent-thread timing is needed to place the append at the seam.
        let second = recorder
            .record(at(2.0), [condition(State::Stalled, true)])
            .unwrap();
        let second_id = second.root().unwrap();
        let mut writer = open_store(&f._directory.path().join("health.pile")).unwrap();
        writer
            .commit(f.sources.health.source, &f.signer, second)
            .unwrap();
        let raced = f.store.snapshot().unwrap();
        f.sources.refresh_poll_view(raced, at(3.0)).unwrap();
        assert!(!exists!(
            pattern!(f.sources.poll_view.as_ref().unwrap().1.facts.view(), [
                { second_id @ metadata::tag: &schema::KIND_REPORT }
            ])
        ));

        assert!(f
            .sources
            .maintain_if_changed(&mut f.store, &f.signer)
            .unwrap());
        f.sources
            .refresh_poll_view(f.store.snapshot().unwrap(), at(3.0))
            .unwrap();
        assert!(exists!(
            pattern!(f.sources.poll_view.as_ref().unwrap().1.facts.view(), [
                { second_id @ metadata::tag: &schema::KIND_REPORT }
            ])
        ));
        assert!(!exists!(pattern!(earlier.facts.view(), [
            { second_id @ metadata::tag: &schema::KIND_REPORT }
        ])));
    }

    #[test]
    fn reader_age_deadline_changes_attention_without_new_records_and_never_repeats() {
        let mut f = Fixture::new();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        let heartbeat = recorder
            .record(at(0.0), [condition(State::Current, false)])
            .unwrap();
        let report_id = heartbeat.root().unwrap();
        f.publish(heartbeat);
        let fresh = f.observe_at(at(59.0));
        let before = fresh.report();
        assert!(before.attention.is_empty());
        assert!(before.text.contains("converged at observed pairwise roots"));
        assert_eq!(before.next_change, Some(at(60.0)));
        assert_eq!(
            until(before.next_change, at(59.0)),
            Some(Duration::from_secs(1))
        );

        // Same stored records and resident targets: time is the only difference.
        let expired = f.sources.at(f.store.snapshot().unwrap(), at(60.0)).unwrap();
        assert!(expired.snapshot.changes_since(&fresh.snapshot).is_empty());
        let after = expired.report();
        assert_eq!(after.attention.ids().collect::<Vec<_>>(), vec![report_id]);
        assert!(after.text.contains("unknown (report too old)"));
        assert!(after.text.contains("last sample only"));
        assert_eq!(after.next_change, None);
        let persona = *fucid();
        save_presentations(&mut f.store, &f.signer, [report_id]).unwrap();
        let next = f.observe_at(at(100.0));
        assert!(matches!(next.news(persona, &next.report()), News::Quiet));
        assert!(next.snapshot.wants().unwrap().next().is_none());
    }

    #[test]
    fn health_poll_reuses_views_through_expiry_and_clock_rollback() {
        let mut f = Fixture::new();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        let report = recorder
            .record(at(0.0), [condition(State::Current, false)])
            .unwrap();
        let report_id = report.root().unwrap();
        f.publish(report);
        // Complete local production before the counted polling observation.
        assert!(f.sources.maintain(&f.store, &f.signer).unwrap().is_none());
        let watermark = f.store.snapshot().unwrap();
        for (instant, stale, next) in [
            (59.0, false, Some(60.0)),
            (59.5, false, Some(60.0)),
            (60.0, true, None),
            (61.0, true, None),
            (-1.0, false, Some(0.0)),
            (0.0, false, Some(60.0)),
        ] {
            let sampled = f.store.snapshot().unwrap();
            assert!(sampled.changes_since(&watermark).is_empty());
            f.sources.refresh_poll_view(sampled, at(instant)).unwrap();
            let report = f.sources.poll_view.as_ref().unwrap().1.report();
            assert_eq!(report.attention.ids().any(|id| id == report_id), stale);
            assert_eq!(report.next_change, next.map(at));
            assert_eq!(f.sources.poll_observations, 1);
        }
    }

    #[test]
    fn health_poll_reuses_views_after_unrelated_blob_and_collection_appends() {
        let mut f = Fixture::new();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        f.publish(
            recorder
                .record(at(0.0), [condition(State::Current, false)])
                .unwrap(),
        );
        assert!(f.sources.maintain(&f.store, &f.signer).unwrap().is_none());
        let before = f.store.snapshot().unwrap();
        f.sources
            .refresh_poll_view(before.clone(), at(1.0))
            .unwrap();
        assert_eq!(f.sources.poll_observations, 1);

        f.store
            .put::<blobencodings::UTF8String, _>("unrelated hydrated payload".to_owned())
            .unwrap();
        let unrelated =
            open_configured(&mut f.store, MESSAGE_SCOPE_ID, f.signer.verifying_key()).unwrap();
        f.store
            .commit(
                unrelated,
                &f.signer,
                entity! { metadata::tag: &metadata::KIND_MULTI },
            )
            .unwrap();
        let sampled = f.store.snapshot().unwrap();
        let changes = sampled.changes_since(&before);
        assert!(changes.contains(StoreChanges::BLOBS));
        assert!(changes.contains(StoreChanges::COLLECTION_RECORDS));
        assert!(f.sources.poll_view.as_ref().unwrap().1.is_current(&sampled));

        f.sources
            .refresh_poll_view(sampled.clone(), at(2.0))
            .unwrap();
        assert_eq!(f.sources.poll_observations, 1);
        let observed = &f.sources.poll_view.as_ref().unwrap().1;
        assert_eq!(observed.evaluated_at, at(2.0));
        assert!(observed.report().attention.is_empty());
        assert!(f
            .store
            .snapshot()
            .unwrap()
            .changes_since(&sampled)
            .is_empty());
    }

    #[test]
    fn health_poll_refreshes_when_only_latest_target_advances() {
        let mut f = Fixture::new();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        f.publish(
            recorder
                .record(at(0.0), [condition(State::Stalled, true)])
                .unwrap(),
        );
        assert!(f.sources.maintain(&f.store, &f.signer).unwrap().is_none());
        f.sources
            .refresh_poll_view(f.store.snapshot().unwrap(), at(1.0))
            .unwrap();
        let original_facts = f
            .sources
            .poll_view
            .as_ref()
            .unwrap()
            .1
            .facts
            .collection
            .cover()
            .clone();
        assert!(!f
            .sources
            .poll_view
            .as_ref()
            .unwrap()
            .1
            .report()
            .attention
            .is_empty());

        f.publish(
            recorder
                .record(at(2.0), [condition(State::Current, false)])
                .unwrap(),
        );
        {
            let mut local = f.store.store();
            drop(pollster::block_on(local.maintain(f.sources.latest, &f.signer)).unwrap());
        }
        let sampled = f.store.snapshot().unwrap();
        let prior = &f.sources.poll_view.as_ref().unwrap().1;
        assert!(prior.facts.is_current(&sampled));
        assert!(!prior.latest_collection.is_current(&sampled));
        f.sources
            .refresh_poll_view(sampled.clone(), at(3.0))
            .unwrap();
        assert_eq!(f.sources.poll_observations, 2);
        let observed = &f.sources.poll_view.as_ref().unwrap().1;
        assert_eq!(observed.facts.collection.cover(), &original_facts);
        assert!(observed.report().attention.is_empty());
        assert!(observed
            .report()
            .text
            .contains("not observed / not configured"));
        assert!(f
            .store
            .snapshot()
            .unwrap()
            .changes_since(&sampled)
            .is_empty());
    }

    #[test]
    fn health_poll_refreshes_private_membership_only_when_its_target_advances() {
        let mut f = Fixture::new();
        let persona = *fucid();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        f.publish(
            recorder
                .record(at(0.0), [condition(State::Stalled, true)])
                .unwrap(),
        );
        assert!(f.sources.maintain(&f.store, &f.signer).unwrap().is_none());
        f.sources
            .refresh_poll_view(f.store.snapshot().unwrap(), at(1.0))
            .unwrap();
        let events: Vec<_> = f
            .sources
            .poll_view
            .as_ref()
            .unwrap()
            .1
            .report()
            .attention
            .ids()
            .collect();
        assert!(!events.is_empty());
        f.store
            .commit(
                f.sources.presentations.source,
                &f.signer,
                entity! {
                    metadata::tag: &KIND_PRESENTED,
                    presentation::event*: events.iter().copied(),
                },
            )
            .unwrap();
        let lagging = f.store.snapshot().unwrap();
        assert!(f.sources.poll_view.as_ref().unwrap().1.is_current(&lagging));
        f.sources
            .refresh_poll_view(lagging.clone(), at(2.0))
            .unwrap();
        assert_eq!(f.sources.poll_observations, 1);
        let observed = &f.sources.poll_view.as_ref().unwrap().1;
        assert!(matches!(
            observed.news(persona, &observed.report()),
            News::Report { .. }
        ));
        assert!(f
            .store
            .snapshot()
            .unwrap()
            .changes_since(&lagging)
            .is_empty());

        {
            let mut local = f.store.store();
            drop(
                pollster::block_on(local.maintain(f.sources.presentations.ids, &f.signer)).unwrap(),
            );
        }
        let caught_up = f.store.snapshot().unwrap();
        let prior = &f.sources.poll_view.as_ref().unwrap().1;
        assert!(prior.facts.is_current(&caught_up));
        assert!(prior.latest_collection.is_current(&caught_up));
        assert!(!prior.presentations.is_current(&caught_up));
        f.sources
            .refresh_poll_view(caught_up.clone(), at(3.0))
            .unwrap();
        assert_eq!(f.sources.poll_observations, 2);
        let observed = &f.sources.poll_view.as_ref().unwrap().1;
        assert!(events
            .iter()
            .all(|event| observed.presentations.view().contains(*event)));
        assert!(matches!(
            observed.news(persona, &observed.report()),
            News::Quiet
        ));
        assert!(f
            .store
            .snapshot()
            .unwrap()
            .changes_since(&caught_up)
            .is_empty());
    }

    #[test]
    fn latest_report_reordering_and_healthy_heartbeats_are_quiet() {
        let mut f = Fixture::new();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        let old = recorder
            .record(at(0.0), [condition(State::Unknown, false)])
            .unwrap();
        let first = recorder
            .record(at(10.0), [condition(State::Current, false)])
            .unwrap();
        let next = recorder
            .record(at(20.0), [condition(State::Current, false)])
            .unwrap();
        f.publish(next);
        f.publish(old);
        f.publish(first);
        let report = f.observe_at(at(70.0)).report();
        assert!(report.attention.is_empty());
        assert_eq!(report.next_change, Some(at(80.0)));
        assert_eq!(report.text.matches("- observer").count(), 1);
        assert!(report.text.contains("converged at observed pairwise roots"));
        assert!(!report.text.contains("report too old"));
    }

    #[test]
    fn failure_is_stable_attention_and_recovery_is_quiet() {
        let mut f = Fixture::new();
        let persona = *fucid();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        f.publish(
            recorder
                .record(at(0.0), [condition(State::Stalled, true)])
                .unwrap(),
        );
        let failure = f.observe_at(at(1.0)).report();
        assert_eq!(failure.attention.ids().len(), 1);
        save_presentations(&mut f.store, &f.signer, failure.attention.ids()).unwrap();
        f.publish(
            recorder
                .record(at(10.0), [condition(State::Stalled, true)])
                .unwrap(),
        );
        let heartbeat = f.observe_at(at(11.0));
        assert_eq!(failure.attention, heartbeat.report().attention);
        assert!(matches!(
            heartbeat.news(persona, &heartbeat.report()),
            News::Quiet
        ));

        f.publish(
            recorder
                .record(at(20.0), [condition(State::Current, false)])
                .unwrap(),
        );
        let recovered = f.observe_at(at(21.0)).report();
        assert!(recovered.attention.is_empty());
        assert!(recovered
            .text
            .contains("converged at observed pairwise roots"));
        assert!(matches!(
            f.observe_at(at(21.0)).news(persona, &recovered),
            News::Quiet
        ));
        f.publish(
            recorder
                .record(at(30.0), [condition(State::Current, false)])
                .unwrap(),
        );
        let heartbeat = f.observe_at(at(31.0));
        assert!(matches!(
            heartbeat.news(persona, &heartbeat.report()),
            News::Quiet
        ));

        let mut restarted = Recorder::new(f.signer.verifying_key());
        f.publish(
            restarted
                .record(at(40.0), [condition(State::Current, false)])
                .unwrap(),
        );
        assert!(f.observe_at(at(41.0)).report().attention.is_empty());
    }

    #[test]
    fn news_groups_collection_sync_alerts_with_the_same_observer_and_peer() {
        let mut f = Fixture::new();
        let persona = *fucid();
        let first = *fucid();
        let second = *fucid();
        let group = CollectionSyncGroup {
            observer: "010203040506".to_owned(),
            peer_scope: " via [111213141516]".to_owned(),
            issue: CollectionSyncIssue::ComparisonUnavailable,
        };
        let mut attention = AttentionView::default();
        attention.insert(AttentionEvent::Health {
            event: first,
            detail: "observer [010203040506] collection sync alpha [aaaaaaaaaaaa] via [111213141516]: pairwise-root comparison unavailable beyond progress grace".to_owned(),
            collection_group: Some(group.clone()),
        });
        attention.insert(AttentionEvent::Health {
            event: second,
            detail: "observer [010203040506] collection sync beta [bbbbbbbbbbbb] via [111213141516]: pairwise-root comparison unavailable beyond progress grace".to_owned(),
            collection_group: Some(group),
        });
        let report = HealthReport {
            text: "complete snapshot".to_owned(),
            attention,
            next_change: None,
        };
        let observation = f.observe_at(at(1.0));
        let (text, events) = match observation.news(persona, &report) {
            News::Report { text, events } => (text, events),
            News::Quiet => panic!("grouped alerts must remain actionable"),
        };
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains(
            "observer [010203040506] collection sync via [111213141516]: 2 collection comparisons unavailable beyond progress grace"
        ));
        assert!(!text.contains("complete snapshot"));
        assert!(!text.contains("alpha"));
        assert!(!text.contains("beta"));
        assert_eq!(
            events.into_iter().collect::<BTreeSet<_>>(),
            BTreeSet::from([first, second])
        );
    }

    #[test]
    fn opaque_ids_extra_facts_partial_rows_and_source_isolation_remain_readable() {
        let mut f = Fixture::new();
        let report = fucid();
        let node = fucid();
        let session = fucid();
        let issue = fucid();
        let unfamiliar = fucid();
        let facts = entity! { &report @
            metadata::tag: &schema::KIND_REPORT,
            metadata::created_at: clock::point(at(0.0)).unwrap(),
            metadata::expires_at: clock::point(at(60.0)).unwrap(),
            attrs::node: &node,
            attrs::session: &session,
            attrs::condition: &issue,
        } + entity! { &node @ attrs::endpoint: f.signer.verifying_key() }
            + entity! { &issue @
                metadata::tag*: [schema::KIND_CONDITION, schema::DHT, schema::KIND_ALERT, *unfamiliar],
                attrs::node: &node,
                attrs::session: &session,
                attrs::state: &schema::STALLED,
            }
            + entity! { metadata::tag: &schema::KIND_REPORT };
        let unrelated =
            open_configured(&mut f.store, MESSAGE_SCOPE_ID, f.signer.verifying_key()).unwrap();
        f.store.commit(unrelated, &f.signer, facts.clone()).unwrap();
        assert!(f
            .observe_at(at(1.0))
            .report()
            .text
            .contains("not observed / not configured"));
        f.publish(facts);
        let selected = f.observe_at(at(1.0)).report();
        assert_eq!(selected.attention.ids().collect::<Vec<_>>(), vec![*issue]);
        assert!(selected.text.contains("DHT publication: stalled"));
        assert!(selected.text.contains("do not prove blob availability"));
    }

    #[test]
    fn maintained_winners_and_facts_need_not_have_identical_support() {
        let mut f = Fixture::new();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        f.publish(
            recorder
                .record(at(0.0), [condition(State::Stalled, true)])
                .unwrap(),
        );
        let first = f.observe_at(at(1.0)).report();
        f.publish(
            recorder
                .record(at(10.0), [condition(State::Current, false)])
                .unwrap(),
        );
        {
            let mut local = f.store.store();
            pollster::block_on(async {
                drop(
                    local
                        .maintain(f.sources.health.succinct, &f.signer)
                        .await
                        .unwrap(),
                );
                drop(
                    local
                        .maintain(f.sources.health.rank9, &f.signer)
                        .await
                        .unwrap(),
                );
            });
        }
        let lagging = f.sources.at(f.store.snapshot().unwrap(), at(11.0)).unwrap();
        assert_ne!(
            lagging.facts.collection.support().unwrap(),
            lagging.latest_collection.support().unwrap(),
        );
        assert_eq!(lagging.report().attention, first.attention);
        assert!(f
            .observe_at(at(11.0))
            .report()
            .text
            .contains("converged at observed pairwise roots"));
    }

    #[test]
    fn reader_policy_controls_freshness_and_ignores_legacy_expiry_annotations() {
        let mut f = Fixture::new();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        let mut report = recorder
            .record(at(0.0), [condition(State::Current, false)])
            .unwrap();
        let id = report.root().unwrap();
        assert!(!exists!(
            pattern!(report.facts(), [{ id @ metadata::expires_at: _?expiry }])
        ));
        // Historical annotations are ordinary extra facts, not reader policy.
        // Neither an already-past nor a far-future expiry can alter the deadline.
        report += entity! { ExclusiveId::force_ref(&id) @ metadata::expires_at*: [
            clock::point(at(-100.0)).unwrap(),
            clock::point(at(1_000_000.0)).unwrap(),
        ] };
        f.publish(report);
        let short = f.observe_at(at(90.0));
        assert_eq!(short.report().attention.ids().collect::<Vec<_>>(), vec![id]);

        f.sources.max_age = Duration::from_secs(120);
        let long = f
            .sources
            .at(short.snapshot.clone(), short.evaluated_at)
            .unwrap();
        assert!(long.report().attention.is_empty());
        assert_eq!(long.report().next_change, Some(at(120.0)));
        assert!(long.snapshot.changes_since(&short.snapshot).is_empty());
        assert_eq!(long.report().text.matches("- observer").count(), 1);
    }

    #[test]
    fn future_observation_waits_for_its_timestamp_before_becoming_current() {
        let mut f = Fixture::new();
        let mut recorder = Recorder::new(f.signer.verifying_key());
        f.publish(
            recorder
                .record(at(10.0), [condition(State::Current, false)])
                .unwrap(),
        );
        let future = f.observe_at(at(0.0)).report();
        assert!(future.text.contains("sample is in the future"));
        assert!(future.attention.is_empty());
        assert_eq!(future.next_change, Some(at(10.0)));
        assert_eq!(f.observe_at(at(10.0)).report().next_change, Some(at(70.0)));
    }

    #[test]
    fn an_elapsed_health_deadline_interrupts_a_pending_ordinary_read() {
        runtime().unwrap().block_on(async {
            let deadline_at = clock::now().unwrap() - hifitime::Duration::from_seconds(1.0);
            let was_deadline = tokio::select! {
                result = deadline(Some(deadline_at)) => { result.unwrap(); true }
                _ = std::future::pending::<()>() => false,
            };
            assert!(was_deadline);
            assert_eq!(until(Some(at(1.0)), at(2.0)), Some(Duration::ZERO));
            assert_eq!(until(None, at(2.0)), None);
        });
    }
}
