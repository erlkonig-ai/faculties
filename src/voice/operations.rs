//! Typed Voice persistence; routing reads close before any device or model work.

use crate::clock;
use crate::collection_names::open_configured;
use crate::schemas::voice::{CHANNEL_SAY, CHANNEL_SHOUT, COLLECTION_SCOPE_ID};
#[cfg(test)]
use crate::storage::open_pile_strict;
use crate::storage::FactArchive;
use crate::voice as voice_model;
use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::blob::encodings::succinctarchive::{
    Rank9AcceleratedSuccinctArchiveBlob, SuccinctArchiveBlob,
};
use triblespace::core::collection::{
    Collection, CollectionCommit, CollectionSnapshotExt, CollectionStoreExt,
};
use triblespace::core::metadata;
use triblespace::core::repo::pile::Pile;
#[cfg(test)]
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::SnapshotSource;
use triblespace::prelude::*;

use super::routing::{classify, DeviceClass};

#[cfg(test)]
use crate::schemas::voice::KIND_LIVE_RECORD;

type U256 = Inline<inlineencodings::U256BE>;

// Default routing policy, used when the pile holds no `route set` for a channel.
// `say` lists ONLY private devices (the classifier rejects anything else anyway);
// `shout` is the public broadcast ladder.
const DEFAULT_SAY_DEVICES: &[&str] = &["AirPods Max", "AirPods Pro", "AirPods", "Headphones"];
const DEFAULT_SHOUT_DEVICES: &[&str] = &[
    "Reachy Mini Audio",
    "Studio Display Speakers",
    "MacBook Pro Speakers",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Say,
    Shout,
}
impl Channel {
    pub fn name(self) -> &'static str {
        match self {
            Self::Say => CHANNEL_SAY,
            Self::Shout => CHANNEL_SHOUT,
        }
    }
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.to_ascii_lowercase().as_str() {
            CHANNEL_SAY => Ok(Self::Say),
            CHANNEL_SHOUT => Ok(Self::Shout),
            _ => bail!("unknown channel {raw:?}; use say or shout"),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutePolicy {
    pub channel: Channel,
    pub devices: Vec<String>,
}
#[derive(Clone, Debug)]
pub struct RouteReceipt {
    pub policy: RoutePolicy,
    pub ignored_private_patterns: Vec<String>,
}
impl RouteReceipt {
    pub fn emit(&self, out: &mut crate::out::Out<'_>) -> Result<()> {
        for pattern in &self.ignored_private_patterns {
            out.line(format!(
                "warning: {pattern:?} is not classified private and cannot route say to a speaker"
            ))?;
        }
        out.line(format!(
            "{} policy set: {}",
            self.policy.channel.name(),
            self.policy.devices.join(" → ")
        ))
    }
}
#[derive(Clone, Debug)]
pub struct Voice {
    storage: crate::storage::Storage,
}
impl Voice {
    pub fn new(pile: PathBuf, key: Option<PathBuf>) -> Self {
        Self::with_storage(crate::storage::Storage::new(pile, key))
    }
    pub fn with_storage(storage: crate::storage::Storage) -> Self {
        Self { storage }
    }
    fn storage(&self) -> VoiceStorage<'_> {
        VoiceStorage {
            storage: &self.storage,
        }
    }
    pub fn routes(&self) -> Result<Vec<RoutePolicy>> {
        self.storage().with_session(|session| {
            [Channel::Say, Channel::Shout]
                .into_iter()
                .map(|channel| {
                    Ok(RoutePolicy {
                        channel,
                        devices: load_route(&session.facts, channel.name())?,
                    })
                })
                .collect()
        })
    }
    pub fn route(&self, channel: Channel) -> Result<Vec<String>> {
        self.storage()
            .with_session(|session| load_route(&session.facts, channel.name()))
    }
    pub fn set_route(&self, channel: Channel, devices: &[String]) -> Result<RouteReceipt> {
        validate_devices(devices)?;
        self.storage()
            .with_session(|session| store_route(session, channel.name(), devices))?;
        Ok(RouteReceipt {
            policy: RoutePolicy {
                channel,
                devices: devices.to_vec(),
            },
            ignored_private_patterns: if channel == Channel::Say {
                devices
                    .iter()
                    .filter(|name| classify(name) != DeviceClass::Private)
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            },
        })
    }
    /// Record one already-completed attempt, without playing or synthesizing.
    /// Callers provide the actual disposition in the commit description.
    pub fn record(
        &self,
        channel: Channel,
        text: &str,
        audio: Option<Vec<u8>>,
        description: &'static str,
    ) -> Result<Id> {
        validate_text(text)?;
        let at = clock::point_now()?;
        let fragment = voice_model::utterance_fragment(channel.name(), text, audio, at)?;
        let id = fragment.root().context("Voice utterance has no root")?;
        self.storage().with_session(move |session| {
            session.commit(fragment, description)?;
            Ok(id)
        })
    }
}
pub fn validate_text(text: &str) -> Result<()> {
    anyhow::ensure!(!text.trim().is_empty(), "voice text must not be empty");
    Ok(())
}
pub fn validate_devices(devices: &[String]) -> Result<()> {
    anyhow::ensure!(
        !devices.is_empty(),
        "a route needs at least one device pattern"
    );
    anyhow::ensure!(
        devices.iter().all(|name| !name.trim().is_empty()),
        "device patterns must not be empty"
    );
    Ok(())
}
fn now_tai() -> Result<Inline<inlineencodings::NsTAIInterval>> {
    clock::point_now()
}

// ── native collection persistence ─────────────────────────────────────────

#[derive(Clone, Copy)]
struct VoiceStorage<'a> {
    storage: &'a crate::storage::Storage,
}

struct VoiceSession<'a> {
    pile: &'a mut Pile,
    collection: Collection<SimpleArchive>,
    signer: &'a ed25519_dalek::SigningKey,
    facts: FactArchive,
    #[cfg(test)]
    reader: PileSnapshot,
}

impl VoiceSession<'_> {
    fn commit(
        &mut self,
        mut fragment: Fragment,
        description: &'static str,
    ) -> Result<CollectionCommit> {
        voice_model::validate_staged_payloads(&mut fragment)?;
        fragment.describe_with(entity! { metadata::description: description });
        self.pile
            .commit(self.collection, self.signer, fragment)
            .context("commit Voice fragment")
    }
}

impl VoiceStorage<'_> {
    fn with_session<T>(
        &self,
        operation: impl FnOnce(&mut VoiceSession<'_>) -> Result<T>,
    ) -> Result<T> {
        self.storage.with_pile(|pile, signer| {
            let result = (|| {
                let collection =
                    open_configured(pile, COLLECTION_SCOPE_ID, signer.verifying_key())?;
                let descriptor_snapshot = pile.snapshot()?;
                let policy = collection.policy(&descriptor_snapshot)?;
                drop(descriptor_snapshot);
                let maintained_succinct =
                    pile.derive::<SuccinctArchiveBlob>(collection, (), policy.clone())?;
                let maintained_rank9 = pile.derive::<Rank9AcceleratedSuccinctArchiveBlob>(
                    maintained_succinct,
                    (),
                    policy,
                )?;
                let store_snapshot = pollster::block_on(async {
                    drop(pile.ensure(collection).await?);
                    drop(pile.maintain(maintained_succinct).await?);
                    pile.maintain(maintained_rank9).await
                })
                .context("maintain Voice fact collection")?;
                let facts = store_snapshot
                    .collection(maintained_rank9)
                    .context("observe maintained Voice fact collection")?
                    .view::<FactArchive>()
                    .context("read maintained Voice fact collection")?;
                operation(&mut VoiceSession {
                    pile,
                    collection,
                    signer,
                    facts,
                    #[cfg(test)]
                    reader: store_snapshot,
                })
            })();
            result
        })
    }
}

/// Read a channel's routing policy from the pile. Each `voice route set` writes
/// a whole GENERATION of entries sharing one `metadata::updated_at`; the policy
/// is the LATEST generation only (a set replaces, it doesn't accumulate).
/// Exact timestamp ties are unioned. Falls back to the baked-in defaults when
/// the live projection holds no policy for the channel.
fn load_route<P: TriblePattern>(space: &P, channel: &str) -> Result<Vec<String>> {
    // (set-generation key, priority, device) for this channel.
    let rows: Vec<(i128, u64, String)> = voice_model::route_rows(space, channel)
        .into_iter()
        .map(|row| (row.updated_at.0, row.priority, row.device))
        .collect();
    let Some(latest_gen) = rows.iter().map(|(k, _, _)| *k).max() else {
        let defaults = match channel {
            CHANNEL_SAY => DEFAULT_SAY_DEVICES,
            _ => DEFAULT_SHOUT_DEVICES,
        };
        return Ok(defaults.iter().map(|s| s.to_string()).collect());
    };
    let mut entries: Vec<(u64, String)> = rows
        .into_iter()
        .filter(|(k, _, _)| *k == latest_gen)
        .map(|(_, p, d)| (p, d))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    Ok(entries.into_iter().map(|(_, d)| d).collect())
}

fn route_set_fragment(
    channel: &str,
    devices: &[String],
    set_time: Inline<inlineencodings::NsTAIInterval>,
) -> Fragment {
    let mut generation = Fragment::empty();
    for (i, dev) in devices.iter().enumerate() {
        let prio: U256 = (i as u64).to_inline();
        generation += voice_model::route_record(channel, dev, prio, set_time);
    }
    generation
}

fn store_route(session: &mut VoiceSession<'_>, channel: &str, devices: &[String]) -> Result<()> {
    let generation = route_set_fragment(channel, devices, now_tai()?);
    session.commit(generation, "voice route set")?;
    Ok(())
}

// ── tests: device resolution + the privacy invariant (no audio is played) ──
#[cfg(test)]
mod tests {
    use super::*;
    use crate::voice::routing::*;
    use crate::voice::synthesis::{estimate_audio_secs, prebuffer_target_secs};

    use std::fs::File;
    use triblespace::core::repo::BlobStoreGet;

    use crate::schemas::voice::{utterance, KIND_UTTERANCE};
    use crate::storage::{discover_target, initialize_signer};

    fn dev(name: &str, default: bool) -> AudioDevice {
        AudioDevice {
            name: name.to_string(),
            is_default_output: default,
        }
    }

    fn prefs(p: &[&str]) -> Vec<String> {
        p.iter().map(|s| s.to_string()).collect()
    }

    fn ladder(routed: Routed) -> Vec<String> {
        match routed {
            Routed::Devices(l) => l,
            other => panic!("expected a device ladder, got: {}", other.describe()),
        }
    }

    #[test]
    fn native_storage_uses_fixed_descriptor_and_atomic_voice_commits() {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join("voice.pile");
        let key = directory.path().join("voice.key");
        File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        let storage = VoiceStorage {
            storage: &crate::storage::Storage::new(pile.clone(), Some(key.clone())),
        };

        let route = vec!["AirPods Max".to_owned(), "AirPods Pro".to_owned()];
        storage
            .with_session(|session| store_route(session, CHANNEL_SAY, &route))
            .unwrap();
        let wav = directory.path().join("utterance.wav");
        std::fs::write(&wav, b"synthetic wav bytes").unwrap();
        storage
            .with_session(|session| {
                session.commit(
                    voice_model::utterance_fragment(
                        CHANNEL_SAY,
                        "hello collection",
                        Some(std::fs::read(&wav)?),
                        now_tai()?,
                    )?,
                    "voice spoke",
                )
            })
            .unwrap();

        storage
            .with_session(|session| {
                assert_eq!(load_route(&session.facts, CHANNEL_SAY)?, route);
                let (text, audio) = find!(
                    (text: voice_model::TextHandle, audio: voice_model::AudioHandle),
                    pattern!(&session.facts, [{
                        metadata::tag: KIND_LIVE_RECORD,
                        metadata::tag: KIND_UTTERANCE,
                        utterance::text: ?text,
                        utterance::audio: ?audio,
                    }])
                )
                .next()
                .expect("one live utterance");
                let text: anybytes::View<str> = session.reader.get(text)?;
                let audio: anybytes::Bytes = session.reader.get(audio)?;
                assert_eq!(text.as_ref(), "hello collection");
                assert_eq!(audio.as_ref(), b"synthetic wav bytes");
                Ok(())
            })
            .unwrap();

        let mut pile_storage = open_pile_strict(&pile).unwrap();
        let signer = crate::storage::load_signer(&pile, Some(&key)).unwrap();
        let collection = open_configured(
            &mut pile_storage,
            COLLECTION_SCOPE_ID,
            signer.verifying_key(),
        )
        .unwrap();
        let discovery = discover_target(
            &mut pile_storage,
            COLLECTION_SCOPE_ID,
            signer.verifying_key(),
        )
        .unwrap();
        assert_eq!(discovery.commits().len(), 2);
        assert!(discovery
            .commits()
            .iter()
            .all(|commit| commit.collection() == collection.handle()));
        pile_storage.close().unwrap();
    }

    #[test]
    fn classify_is_fail_closed() {
        assert_eq!(classify("AirPods Max"), DeviceClass::Private);
        assert_eq!(classify("Sony WH-1000XM5"), DeviceClass::Private);
        assert_eq!(classify("Reachy Mini Audio"), DeviceClass::Reachy);
        // Speaker markers beat brand hints: a Beats Pill is a room speaker.
        assert_eq!(classify("Beats Pill"), DeviceClass::Speaker);
        // Anything unrecognised is PUBLIC — never fail-open into Private.
        assert_eq!(classify("Some Unknown Device"), DeviceClass::Speaker);
        assert_eq!(classify("MacBook Pro Speakers"), DeviceClass::Speaker);
    }

    #[test]
    fn say_ladders_all_private_matches_in_priority_order() {
        let devices = [
            dev("MacBook Pro Speakers", true),
            dev("AirPods Max", false),
            dev("AirPods Pro", false),
        ];
        // One pattern can ladder several devices (Max first: enumeration order).
        let l = ladder(route_say(&prefs(&["AirPods"]), &devices));
        assert_eq!(l, vec!["AirPods Max", "AirPods Pro"]);
    }

    #[test]
    fn say_never_ladders_a_speaker_even_when_the_policy_lists_one() {
        let devices = [dev("MacBook Pro Speakers", true), dev("AirPods Max", false)];
        // A (mis)configured policy that puts a speaker FIRST cannot make it play:
        // the ladder holds only the private device.
        let l = ladder(route_say(
            &prefs(&["MacBook Pro Speakers", "AirPods"]),
            &devices,
        ));
        assert_eq!(l, vec!["AirPods Max"]);
    }

    #[test]
    fn say_falls_to_text_when_no_private_device_connected() {
        let devices = [
            dev("MacBook Pro Speakers", true),
            dev("Studio Display Speakers", false),
            dev("Reachy Mini Audio", false),
        ];
        // Even a policy listing ONLY public devices yields TEXT, never sound.
        assert!(matches!(
            route_say(&prefs(&["MacBook", "Studio", "Reachy"]), &devices),
            Routed::Text(_)
        ));
        assert!(matches!(
            route_say(&prefs(&["AirPods"]), &devices),
            Routed::Text(_)
        ));
    }

    #[test]
    fn shout_short_circuits_to_reachy_when_daemon_up() {
        let devices = [
            dev("MacBook Pro Speakers", true),
            dev("Reachy Mini Audio", false),
        ];
        assert!(matches!(
            route_shout(&prefs(&["Reachy", "MacBook"]), &devices, true),
            Routed::Reachy
        ));
    }

    #[test]
    fn shout_skips_reachy_when_daemon_down_and_ladders_the_rest() {
        let devices = [
            dev("MacBook Pro Speakers", true),
            dev("Reachy Mini Audio", false),
            dev("Studio Display Speakers", false),
        ];
        let l = ladder(route_shout(
            &prefs(&["Reachy", "Studio", "MacBook"]),
            &devices,
            false,
        ));
        assert_eq!(l, vec!["Studio Display Speakers", "MacBook Pro Speakers"]);
    }

    #[test]
    fn shout_appends_default_output_as_last_resort() {
        let devices = [
            dev("MacBook Pro Speakers", true),
            dev("Studio Display Speakers", false),
        ];
        // Policy matches nothing: fall to the default output alone.
        let l = ladder(route_shout(&prefs(&["Reachy"]), &devices, false));
        assert_eq!(l, vec!["MacBook Pro Speakers"]);
        // Policy matches something: default output still appended as fallback.
        let l = ladder(route_shout(&prefs(&["Studio"]), &devices, false));
        assert_eq!(l, vec!["Studio Display Speakers", "MacBook Pro Speakers"]);
    }

    #[test]
    fn shout_local_device_above_reachy_wins() {
        let devices = [
            dev("MacBook Pro Speakers", true),
            dev("Reachy Mini Audio", false),
        ];
        // Reachy below a local match is not a streaming-sink candidate.
        let l = ladder(route_shout(&prefs(&["MacBook", "Reachy"]), &devices, true));
        assert_eq!(l, vec!["MacBook Pro Speakers"]);
    }

    // ── adaptive prebuffer math ──

    #[test]
    fn estimate_scales_by_reference_chars_per_second() {
        // Same char count as the reference → the reference's duration;
        // double the chars → double the estimate.
        assert!((estimate_audio_secs(240, 11.46, 240) - 11.46).abs() < 1e-4);
        assert!((estimate_audio_secs(480, 11.46, 240) - 22.92).abs() < 1e-3);
        // Degenerate reference: estimate 0 (the target floor still guards).
        assert_eq!(estimate_audio_secs(100, 11.46, 0), 0.0);
    }

    #[test]
    fn prebuffer_is_margin_only_when_synthesis_keeps_up() {
        // At or above realtime there is no deficit — just the 0.5 s margin,
        // met by the first ~0.64 s chunk: playback starts almost immediately
        // regardless of how long the utterance is.
        assert_eq!(prebuffer_target_secs(10.0, 1.0), 0.5);
        assert_eq!(prebuffer_target_secs(10.0, 1.05), 0.5);
        assert_eq!(prebuffer_target_secs(60.0, 2.0), 0.5);
    }

    #[test]
    fn prebuffer_covers_the_deficit_when_synthesis_is_slow() {
        // 1.4x-slower synthesis (rate ≈ 0.714): buffer ~29% of the utterance.
        let t = prebuffer_target_secs(10.0, 1.0 / 1.4);
        assert!((t - (10.0 * (1.0 - 1.0 / 1.4) + 0.5)).abs() < 1e-4);
        // 2.1x-slower (the live stutter case, rate ≈ 0.476): ~half + margin.
        let t = prebuffer_target_secs(10.0, 1.0 / 2.1);
        assert!(t > 5.7 && t < 5.8, "got {t}");
    }

    #[test]
    fn prebuffer_never_underruns_at_constant_rate() {
        // Simulate: start playback once `prebuffer_target_secs` is met and
        // check production stays ahead of the playhead to the end, over a
        // grid of rates and utterance lengths (buffered capped at the whole
        // utterance — a deficit larger than the text means play-after-drain,
        // which trivially can't underrun).
        for rate in [0.3f32, 1.0 / 2.1, 1.0 / 1.4, 0.9, 1.0, 1.5] {
            for total in [1.0f32, 5.0, 12.0, 60.0] {
                let b = prebuffer_target_secs(total, rate).min(total);
                let mut t = 0.0f32;
                while t <= total {
                    let produced = (b + rate * t).min(total);
                    let played = t.min(total);
                    assert!(
                        produced + 1e-3 >= played,
                        "underrun: rate {rate}, total {total}, t {t}: \
                         produced {produced} < played {played}"
                    );
                    t += 0.05;
                }
            }
        }
    }

    #[test]
    fn describe_names_the_ladder() {
        let routed = Routed::Devices(vec!["AirPods Max".into(), "AirPods Pro".into()]);
        assert_eq!(
            routed.describe(),
            "AirPods Max (native sink; fallbacks: AirPods Pro)"
        );
    }
}
