//! Resident-only health input. No source ensure, host activation, or blob fetch.
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
    presentations: OrientSource,
    max_age: Duration,
}

impl HealthSources {
    pub(super) fn open(
        pile: &FacultyStore,
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
        let presentations = open(crate::schemas::orient::DEFAULT_SCOPE_ID, "Orient")?;
        let policy = health.source.policy(&local.snapshot()?)?;
        let latest = local.derive::<LwwRegisterBlob>(
            health.source,
            (attrs::node.id(), metadata::created_at.id()),
            policy,
        )?;
        Ok(Self {
            health,
            latest,
            relations,
            presentations,
            max_age,
        })
    }

    fn maintain(&self, pile: &FacultyStore) -> Result<()> {
        let mut local = pile.store();
        // Pile acquisition is immediately resident-only. Run these local
        // mapping futures to completion without yielding a Peer store guard
        // across network I/O or re-entering a Peer operation.
        pollster::block_on(async {
            for source in [&self.health, &self.relations, &self.presentations] {
                drop(local.maintain(source.succinct).await?);
                drop(local.maintain(source.rank9).await?);
            }
            drop(local.maintain(self.latest).await?);
            Ok(())
        })
    }

    pub(super) fn observe(&self, pile: &mut FacultyStore) -> Result<HealthObservation> {
        self.maintain(pile)?;
        self.at(pile.snapshot()?)
    }

    /// Health is delivered before any ordinary source or payload acquisition.
    /// An unresolved resident persona leaves the normal resolution path intact.
    pub(super) fn poll(
        &self,
        pile: &mut FacultyStore,
        signer: &SigningKey,
        input: &str,
        peek: bool,
        output: &mut Out<'_>,
    ) -> Result<(bool, Option<Epoch>)> {
        let observation = self.observe(pile)?;
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
        apply_prepared_news(pile, signer, persona, peek, &news, "", output)?;
        Ok((fired, report.next_change))
    }

    fn at(&self, snapshot: FacultySnapshot) -> Result<HealthObservation> {
        let facts = self.health.observe(&snapshot)?;
        let latest = snapshot.collection(self.latest)?.view::<LwwIndex>()?;
        let relations = self.relations.observe(&snapshot)?;
        let presentations = self.presentations.observe(&snapshot)?;
        Ok(HealthObservation {
            snapshot,
            facts,
            latest,
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
    facts: OrientFact,
    latest: LwwIndex,
    relations: OrientFact,
    presentations: OrientFact,
    max_age: Duration,
}

pub(super) struct HealthReport {
    pub(super) text: String,
    pub(super) attention: AttentionView,
    pub(super) next_change: Option<Epoch>,
}

impl HealthObservation {
    pub(super) fn report(&self) -> HealthReport {
        render_health(
            self.facts.view(),
            &self.latest,
            &self.snapshot,
            self.max_age,
        )
    }

    pub(super) fn persona(&self, input: &str) -> Result<Id> {
        resolve_resident_persona(self.relations.view(), &self.snapshot, input)
    }

    pub(super) fn news(&self, persona: Id, report: &HealthReport) -> News {
        let presented = presented_events(self.presentations.view(), persona);
        let pending = report.attention.pending(&presented);
        if pending.is_empty() {
            return News::Quiet;
        }
        use std::fmt::Write as _;
        let mut text = String::new();
        for event in pending.events.values() {
            writeln!(text, "News: {}", event.reason()).unwrap();
        }
        text.push_str(&report.text);
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
        schema::COLLECTION => Some("collection repair"),
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
    latest: &LwwIndex,
    snapshot: &FacultySnapshot,
    max_age: Duration,
) -> HealthReport {
    use std::fmt::Write as _;

    let now = snapshot.instant();
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
            let mut scope = String::new();
            for collection in find!(collection: Inline<inlineencodings::Handle<SimpleArchive>>,
                pattern!(facts, [{ condition @ attrs::collection: ?collection }]))
            {
                write!(scope, " {}", collection_label(snapshot, collection)).unwrap();
            }
            for peer in find!(peer: ed25519_dalek::VerifyingKey,
                pattern!(facts, [{ condition @ attrs::peer: ?peer }]))
            {
                write!(scope, " via [{}]", &hex::encode(peer.to_bytes())[..12]).unwrap();
            }
            let detail = format!("{component_name}{scope}: {}", state_name(component, state));
            conditions.insert(detail.clone());
            if fresh
                && (exists!(pattern!(facts, [{ condition @ metadata::tag: &schema::KIND_ALERT }]))
                    || exists!(
                        pattern!(facts, [{ condition @ metadata::tag: &schema::KIND_RECOVERED }])
                    ))
            {
                let recovered = exists!(
                    pattern!(facts, [{ condition @ metadata::tag: &schema::KIND_RECOVERED }])
                );
                attention.insert(AttentionEvent::Health {
                    event: condition,
                    detail: format!(
                        "observer [{observer}] {detail}{}",
                        if recovered { " (recovered)" } else { "" }
                    ),
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
    use triblespace::core::repo::WantRead;

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
            let store = open_store(&path).unwrap();
            let sources = HealthSources::open(&store, &signer, Duration::from_secs(60)).unwrap();
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
            self.sources.maintain(&self.store).unwrap();
            self.sources
                .at(self.store.snapshot_at(at).unwrap())
                .unwrap()
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
        let expired = f
            .sources
            .at(f.store.snapshot_at(at(60.0)).unwrap())
            .unwrap();
        assert!(expired.snapshot.changes_since(&fresh.snapshot).is_empty());
        let after = expired.report();
        assert_eq!(after.attention.ids().collect::<Vec<_>>(), vec![report_id]);
        assert!(after.text.contains("unknown (report too old)"));
        assert!(after.text.contains("last sample only"));
        assert_eq!(after.next_change, None);
        let persona = *fucid();
        save_presentations(&mut f.store, &f.signer, persona, [report_id]).unwrap();
        let next = f.observe_at(at(100.0));
        assert!(matches!(next.news(persona, &next.report()), News::Quiet));
        assert!(next.snapshot.wants().unwrap().next().is_none());
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
    fn failure_and_recovery_use_exact_stable_condition_episodes() {
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
        save_presentations(&mut f.store, &f.signer, persona, failure.attention.ids()).unwrap();
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
        assert_eq!(recovered.attention.ids().len(), 1);
        assert_ne!(
            failure.attention.ids().next(),
            recovered.attention.ids().next()
        );
        assert!(recovered
            .attention
            .events
            .values()
            .next()
            .unwrap()
            .reason()
            .contains("recovered"));
        save_presentations(&mut f.store, &f.signer, persona, recovered.attention.ids()).unwrap();
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
                drop(local.maintain(f.sources.health.succinct).await.unwrap());
                drop(local.maintain(f.sources.health.rank9).await.unwrap());
            });
        }
        let lagging = f
            .sources
            .at(f.store.snapshot_at(at(11.0)).unwrap())
            .unwrap();
        assert_ne!(
            lagging.facts.support(),
            lagging
                .snapshot
                .collection(f.sources.latest)
                .unwrap()
                .support()
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
        let long = f.sources.at(short.snapshot.clone()).unwrap();
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
