//! Portable, locally authorized onboarding seed.
//!
//! The seed is declarative program data, not a pile image. Import authors one
//! Wiki revision DAG and one Compass event set under the recipient's existing
//! durable signer. No builder signature, branch pin, repository commit, or
//! private key crosses that boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{bail, Context, Result};
use hifitime::Epoch;
use triblespace::core::collection::CollectionCommit;
use triblespace::core::id::Id;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::trible::Fragment;
use triblespace::macros::id_hex;
use triblespace::prelude::TryToInline;

use crate::storage::{load_signer, open_pile_strict};
use crate::wiki::{self, RevisionDraft};
use crate::{compass, wiki as wiki_model};

const GENERATION_DOMAIN: &[u8] = b"faculties.portable-bootstrap.v1";
const ROOT_TITLE: &str = "Portable bootstrap entry anchor";

struct WikiSeed {
    anchor: Id,
    title: &'static str,
    content: &'static str,
    tags: &'static [&'static str],
}

const WIKI_SEED: &[WikiSeed] = &[
    WikiSeed {
        anchor: id_hex!("25E8F009E33207755109F19F7A68DFF5"),
        title: "How Faculties Work",
        content: include_str!("../bootstrap/01_how_faculties_work.typ"),
        tags: &["bootstrap", "onboarding", "faculties"],
    },
    WikiSeed {
        anchor: id_hex!("82129C70B693F7E2D781D78AC5EFBB86"),
        title: "Wiki Fragment Style Guide",
        content: include_str!("../bootstrap/02_wiki_style_guide.typ"),
        tags: &["bootstrap", "onboarding", "wiki"],
    },
    WikiSeed {
        anchor: id_hex!("7CDD48C272FF344628FE74F4C07783E4"),
        title: "Compass Goals Workflow",
        content: include_str!("../bootstrap/03_compass_workflow.typ"),
        tags: &["bootstrap", "onboarding", "compass"],
    },
    WikiSeed {
        anchor: id_hex!("996E648886CCCB61D1AFD48296B0A0CB"),
        title: "Work As Its Own Ledger",
        content: include_str!("../bootstrap/05_work_as_its_own_ledger.typ"),
        tags: &["bootstrap", "onboarding", "design", "principle"],
    },
    WikiSeed {
        anchor: id_hex!("F4AFF48FFF04F313552F5B32244F9873"),
        title: "Tool Selection: Faculties First",
        content: include_str!("../bootstrap/06_tool_selection.typ"),
        tags: &["bootstrap", "onboarding", "tools", "reference"],
    },
    WikiSeed {
        anchor: id_hex!("44D63D174814371C7468A3E604ED2303"),
        title: "Getting Started: Your First Hour",
        content: include_str!("../bootstrap/07_getting_started.typ"),
        tags: &["bootstrap", "onboarding", "start-here"],
    },
    WikiSeed {
        anchor: id_hex!("B08448855DE9CCE7610D68DAC2555003"),
        title: "Files Faculty: Archiving and Citing Artefacts",
        content: include_str!("../bootstrap/08_files_faculty.typ"),
        tags: &["bootstrap", "onboarding", "files"],
    },
    WikiSeed {
        anchor: id_hex!("67477D2173928FD91EF20173EABFEAE4"),
        title: "Teams: Positive Authority and CONNECT",
        content: include_str!("../bootstrap/09_teams_faculty.typ"),
        tags: &["bootstrap", "onboarding", "teams", "auth"],
    },
    WikiSeed {
        anchor: id_hex!("65C6965CB3D11052E87804527734A697"),
        title: "Local Messages: Agent-to-Agent Direct Messaging",
        content: include_str!("../bootstrap/10_local_messages_faculty.typ"),
        tags: &["bootstrap", "onboarding", "local-messages", "coordination"],
    },
    WikiSeed {
        anchor: id_hex!("FF27B500D93E1D545B7465438A0146E1"),
        title: "Orient: The Situation-Snapshot Faculty",
        content: include_str!("../bootstrap/11_orient_faculty.typ"),
        tags: &["bootstrap", "onboarding", "orient", "coordination"],
    },
    WikiSeed {
        anchor: id_hex!("E7E3F672A66B39E0B5B3C0EAF212B1DA"),
        title: "Relations: People and Handle Mappings",
        content: include_str!("../bootstrap/12_relations_faculty.typ"),
        tags: &["bootstrap", "onboarding", "relations", "people"],
    },
    WikiSeed {
        anchor: id_hex!("ABE651F605C823085D861F296D9F9907"),
        title: "Web: Search and Fetch Through Provider APIs",
        content: include_str!("../bootstrap/13_web_faculty.typ"),
        tags: &["bootstrap", "onboarding", "web", "research"],
    },
    WikiSeed {
        anchor: id_hex!("999D2565F2E3AF57FA5CFE2ED507D450"),
        title: "Recipe: Research Workflow",
        content: include_str!("../bootstrap/14_research_workflow.typ"),
        tags: &["bootstrap", "onboarding", "recipe", "research"],
    },
    WikiSeed {
        anchor: id_hex!("45E1B9BEF3AD9836536AB7BCE367DEB0"),
        title: "Recipe: Multi-Agent Coordination",
        content: include_str!("../bootstrap/15_coordination_workflow.typ"),
        tags: &["bootstrap", "onboarding", "recipe", "coordination"],
    },
    WikiSeed {
        anchor: id_hex!("5C86DF3DCD5994DE2967483FCA7170AC"),
        title: "Harness Hooks: Mechanical Agent Sync (Watcher, Poll, Enforcement)",
        content: include_str!("../bootstrap/22_harness_hooks.typ"),
        tags: &["bootstrap", "onboarding", "hooks", "coordination"],
    },
    WikiSeed {
        anchor: id_hex!("D06247B9D9183721E47A2940806E5D7F"),
        title: "Recipe: Auth Setup for a Multi-Agent Team",
        content: include_str!("../bootstrap/16_auth_setup_workflow.typ"),
        tags: &["bootstrap", "onboarding", "recipe", "auth"],
    },
    WikiSeed {
        anchor: id_hex!("4E19893B36BF37D471BB9EA968EDAC20"),
        title: "Substrate 1/4: What Is a Trible",
        content: include_str!("../bootstrap/17_substrate_tribles.typ"),
        tags: &["bootstrap", "onboarding", "substrate", "concepts"],
    },
    WikiSeed {
        anchor: id_hex!("5232EA531FEDFCB17BF15E88C3D52A36"),
        title: "Substrate 2/4: The Pile",
        content: include_str!("../bootstrap/18_substrate_pile.typ"),
        tags: &["bootstrap", "onboarding", "substrate", "concepts"],
    },
    WikiSeed {
        anchor: id_hex!("5CC10E2B0263008B261CF8A1EF30BD8C"),
        title: "Substrate 3/4: Monotonic Merge",
        content: include_str!("../bootstrap/19_substrate_merge.typ"),
        tags: &["bootstrap", "onboarding", "substrate", "concepts"],
    },
    WikiSeed {
        anchor: id_hex!("6E5F38BDFD589CD0359BF668D1AF9841"),
        title: "Substrate 4/4: The Architecture — Zero Sync Code",
        content: include_str!("../bootstrap/20_substrate_architecture.typ"),
        tags: &[
            "bootstrap",
            "onboarding",
            "substrate",
            "concepts",
            "architecture",
        ],
    },
    WikiSeed {
        anchor: id_hex!("864C45BED65311B27B1CAFE268B6ED2D"),
        title: "Authoring a Faculty",
        content: include_str!("../bootstrap/21_authoring_a_faculty.typ"),
        tags: &["bootstrap", "onboarding", "faculties", "authoring"],
    },
];

struct CompassSeed {
    goal: Id,
    occurrence: Id,
    created_nanosecond: u32,
    title: &'static str,
    tags: &'static [&'static str],
    note: &'static str,
}

// These are the semantic goal and note-occurrence anchors already shipped in
// the final legacy seed. The builder's branch id and signatures are not data;
// the goal identities, note occurrences, and their original provenance are.
const COMPASS_SEED: &[CompassSeed] = &[
    CompassSeed {
        goal: id_hex!("912FA6E9E235D263FF5FE95D6F3E9A20"),
        occurrence: id_hex!("912FA6E955EE223F11D78FDC6EAC7C9E"),
        created_nanosecond: 81_074_000,
        title: "Read the start-here wiki fragment",
        tags: &["bootstrap", "onboarding"],
        note: "Run `wiki list --tag bootstrap` to find the 'Getting Started: Your First Hour' fragment, then `wiki show <id>` to read it. This is your orientation tour.",
    },
    CompassSeed {
        goal: id_hex!("912FA6F5CC103BC1FACF8492AC4418FC"),
        occurrence: id_hex!("912FA6F5C4BD0CA6F67525F2DE505A46"),
        created_nanosecond: 93_142_000,
        title: "Mint your first id with `trible genid`",
        tags: &["bootstrap", "faculties"],
        note: "Stable IDs in TribleSpace are minted, never guessed. Run `trible genid` and copy the 32-char hex output. Try minting 3 in a row — they should all be different.",
    },
    CompassSeed {
        goal: id_hex!("912FA700A04FE403663F6F182AFC842F"),
        occurrence: id_hex!("912FA701C22DD8E1CC7D900E3BB3D43C"),
        created_nanosecond: 104_858_000,
        title: "Create your first wiki fragment",
        tags: &["bootstrap", "wiki"],
        note: "Pick something you've learned today. Write a 5-10 line typst body to /tmp/myfrag.typ, then `wiki create \"My first fragment\" @/tmp/myfrag.typ --tag personal`. Verify with `wiki show <id>`.",
    },
    CompassSeed {
        goal: id_hex!("912FA70BF4E072597F88787CDAF2B742"),
        occurrence: id_hex!("912FA70CE6D31327ED9E734C1B4216B1"),
        created_nanosecond: 115_536_000,
        title: "Archive a file with `files add`",
        tags: &["bootstrap", "files"],
        note: "Pick any local file (not a binary in a git repo). Run `files add <path>`. The output `files:<hash>` is a content-addressed reference you can cite from wiki fragments. Confirm the hash is stable: re-run on the same file, same hash.",
    },
    CompassSeed {
        goal: id_hex!("912FA7161B02418D9CC75A980B8DC2D2"),
        occurrence: id_hex!("912FA717BC9D2D34B3AD4E7879046A30"),
        created_nanosecond: 126_687_000,
        title: "Run `wiki lint` and `wiki check`",
        tags: &["bootstrap", "wiki", "hygiene"],
        note: "lint applies markdown→typst transforms and rebuilds the links_to index. check reports orphan fragments, broken links, truncated ids. Run both. Note any warnings — they're the wiki's self-diagnostic surface.",
    },
    CompassSeed {
        goal: id_hex!("912FA7218AFC6A31E632EF7E6AF3E404"),
        occurrence: id_hex!("912FA721CFF741621418C61AEC7754FD"),
        created_nanosecond: 137_024_000,
        title: "Scaffold a trivial faculty",
        tags: &["bootstrap", "faculties", "authoring"],
        note: "Mint an id with `trible genid`, add `faculties/src/bin/echofact.rs`: a clap Cli with `#[arg(long, env = \"PILE\")] pile`, that opens the pile and prints one fact (e.g. the id you minted). `cargo install --path faculties --bins`, then run `echofact`. You've added a verb. See the 'Authoring a Faculty' fragment for the full skeleton.",
    },
    CompassSeed {
        goal: id_hex!("912FA72C738EF64C52FD81FB02913734"),
        occurrence: id_hex!("912FA72CF6A1BCA0BAB951F50B79DBB4"),
        created_nanosecond: 148_025_000,
        title: "Mark this goal done and write an outcome note",
        tags: &["bootstrap", "compass"],
        note: "When you finish working through the bootstrap goals, move this one to done with `compass move <id> done` and add a final note recording what stuck and what you'd improve. The outcome note IS the audit trail.",
    },
];

/// The complete locally authored onboarding seed before collection publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PortableSeed {
    pub wiki: Fragment,
    pub compass: Fragment,
    pub wiki_roots: Vec<Id>,
}

/// Result of authorizing one logical seed under the recipient's key.
#[derive(Clone, Debug)]
pub struct ImportReport {
    pub generation: [u8; 32],
    pub wiki_commit: CollectionCommit,
    pub compass_commit: CollectionCommit,
}

fn seed_time(nanosecond: u32) -> compass::IntervalValue {
    let epoch = Epoch::from_gregorian_tai(2026, 7, 23, 22, 54, 44, nanosecond);
    (epoch, epoch)
        .try_to_inline()
        .expect("fixed bootstrap timestamps are representable")
}

fn wiki_time(nanosecond: u32) -> wiki_model::IntervalValue {
    seed_time(200_000_000 + nanosecond)
}

fn root_record(author: Id, anchor: Id) -> Result<(Fragment, Id)> {
    wiki::revision_record(RevisionDraft {
        title: ROOT_TITLE.to_owned(),
        content: format!(
            "This revision anchors portable bootstrap entry {anchor:x}. Follow the entry to its current frontier."
        ),
        tags: BTreeSet::new(),
        predecessors: BTreeSet::new(),
        author,
        authored_at: wiki_time(0),
    })
}

fn tag_set(out: &mut Fragment, labels: &[&str]) -> Result<BTreeSet<Id>> {
    let mut tags = BTreeSet::new();
    for label in labels {
        let (record, id, _) = wiki::tag_record(label)?;
        *out += record;
        tags.insert(id);
    }
    Ok(tags)
}

fn normalize_source(content: &str, roots: &BTreeMap<Id, Id>) -> String {
    let wiki_links = regex::Regex::new(r"\[([^\]]+)\]\(wiki:([0-9A-Fa-f]{32})\)")
        .expect("static Wiki markdown-link expression");
    let web_links =
        regex::Regex::new(r"\[([^\]]+)\]\((https?://[^)]+)\)").expect("static URL expression");
    let bold = regex::Regex::new(r"\*\*([^*]+)\*\*").expect("static bold expression");

    let mut output = String::with_capacity(content.len());
    let mut fenced = false;
    for line in content.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
        }
        let line = if fenced {
            line.to_owned()
        } else {
            let line = if let Some(rest) = line.strip_prefix("### ") {
                format!("=== {rest}")
            } else if let Some(rest) = line.strip_prefix("## ") {
                format!("== {rest}")
            } else if let Some(rest) = line.strip_prefix("# ") {
                format!("= {rest}")
            } else {
                line.to_owned()
            };
            let line = bold.replace_all(&line, "*$1*").to_string();
            let line = wiki_links
                .replace_all(&line, |captures: &regex::Captures<'_>| {
                    let alias = Id::from_hex(&captures[2]).expect("expression matched a full id");
                    let root = roots
                        .get(&alias)
                        .expect("every source-level Wiki alias is declared");
                    format!("#link(\"wiki:entry:{root:x}\")[{}]", &captures[1])
                })
                .to_string();
            let line = web_links
                .replace_all(&line, "#link(\"$2\")[$1]")
                .to_string();
            if matches!(line.trim(), "---" | "***" | "___") {
                String::new()
            } else {
                line
            }
        };
        output.push_str(&line);
        output.push('\n');
    }
    if !content.ends_with('\n') {
        output.pop();
    }
    output
}

fn wiki_fragment(
    key: &ed25519_dalek::VerifyingKey,
    current: Option<(&wiki_model::WikiCatalog, &PileReader)>,
) -> Result<(Fragment, Vec<Id>)> {
    let (mut out, author) = wiki_model::author_record(key);

    let mut roots = BTreeMap::new();
    let mut root_ids = Vec::with_capacity(WIKI_SEED.len());
    for spec in WIKI_SEED {
        let (record, root) = root_record(author, spec.anchor)?;
        out += record;
        roots.insert(spec.anchor, root);
        root_ids.push(root);
    }

    for (index, spec) in WIKI_SEED.iter().enumerate() {
        let tags = tag_set(&mut out, spec.tags)?;
        let content = normalize_source(spec.content, &roots);
        // One fixed provenance coordinate marks generated successors. It is
        // deliberately independent of manifest ordering and mutable payload.
        let source_time = wiki_time(1);
        let predecessors = match current.and_then(|(catalog, reader)| {
            catalog
                .revisions
                .entry_containing(root_ids[index])
                .map(|entry| (catalog, reader, entry))
        }) {
            Some((catalog, reader, entry)) => {
                let is_source = |revision: &wiki_model::RevisionRecord| {
                    revision.author == Some(author)
                        && revision.authorships.iter().any(|authorship| {
                            authorship.author == Some(author)
                                && authorship.authored_at == Some(source_time)
                        })
                };
                let mut sources: Vec<_> = entry
                    .members
                    .iter()
                    .filter_map(|id| catalog.revisions.revision(*id))
                    .filter(|revision| is_source(revision))
                    .collect();
                sources.sort_by_key(|revision| revision.id);

                let source_ids: BTreeSet<_> = sources.iter().map(|revision| revision.id).collect();
                let referenced: BTreeSet<_> = sources
                    .iter()
                    .flat_map(|revision| revision.supersedes.iter().copied())
                    .filter(|id| source_ids.contains(id))
                    .collect();
                let source_heads: BTreeSet<_> =
                    source_ids.difference(&referenced).copied().collect();

                // Replay an exact revision only when it is already the sole
                // maximal source revision. It may sit below recipient-only
                // successors; those are an independent lane. Reverting A -> B
                // -> A or reconciling source forks instead mints a successor
                // over every current source head.
                let exact_source_head = if source_heads.len() == 1 {
                    let head = catalog
                        .revisions
                        .revision(*source_heads.first().expect("one source head"))
                        .expect("source head came from the catalog");
                    (head.tags == tags
                        && wiki_model::read_text(reader, head.title)? == spec.title
                        && wiki_model::read_text(reader, head.content)? == content)
                        .then_some(head)
                } else {
                    None
                };
                if let Some(revision) = exact_source_head {
                    revision.supersedes.clone()
                } else if source_heads.is_empty() {
                    BTreeSet::from([root_ids[index]])
                } else {
                    // Advance only the recognizable bootstrap source strand.
                    // Recipient edits remain independent visible frontier forks.
                    source_heads
                }
            }
            None => BTreeSet::from([root_ids[index]]),
        };
        let (record, _) = wiki::revision_record(RevisionDraft {
            title: spec.title.to_owned(),
            content,
            tags,
            predecessors,
            author,
            authored_at: source_time,
        })?;
        out += record;
    }
    Ok((out, root_ids))
}

fn compass_fragment() -> Result<Fragment> {
    let mut out = compass::kind_catalog_fragment();
    for spec in COMPASS_SEED {
        let at = seed_time(spec.created_nanosecond);
        out += compass::goal_fragment(
            spec.goal,
            spec.title,
            spec.tags.iter().map(|tag| (*tag).to_owned()).collect(),
            None,
            at,
        )?;
        out += compass::status_fragment(spec.goal, "todo", None, at)?;
        out += compass::note_fragment(
            spec.occurrence,
            spec.goal,
            spec.note,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
            at,
        )?;
    }
    Ok(out)
}

/// Build the exact self-contained logical seed for one recipient author.
pub fn build(key: &ed25519_dalek::VerifyingKey) -> Result<PortableSeed> {
    let (wiki, wiki_roots) = wiki_fragment(key, None)?;
    Ok(PortableSeed {
        wiki,
        compass: compass_fragment()?,
        wiki_roots,
    })
}

/// Content identity of the declarative manifest, independent of recipient key.
pub fn generation() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(GENERATION_DOMAIN);
    for spec in WIKI_SEED {
        hasher.update(spec.anchor.as_ref());
        hasher.update(spec.title.as_bytes());
        hasher.update(spec.content.as_bytes());
        for tag in spec.tags {
            hasher.update(tag.as_bytes());
            hasher.update(&[0]);
        }
    }
    for spec in COMPASS_SEED {
        hasher.update(spec.goal.as_ref());
        hasher.update(spec.occurrence.as_ref());
        hasher.update(&spec.created_nanosecond.to_be_bytes());
        hasher.update(spec.title.as_bytes());
        hasher.update(spec.note.as_bytes());
        for tag in spec.tags {
            hasher.update(tag.as_bytes());
            hasher.update(&[0]);
        }
    }
    *hasher.finalize().as_bytes()
}

/// Import one locally authored Wiki root and one locally authored Compass root.
///
/// The pile and durable key must already exist. Both fragments are constructed
/// completely before publication. Replaying with the same key is
/// content-addressed and yields the same two content COMMIT ids.
pub fn import(pile_path: &Path, key_path: Option<&Path>) -> Result<ImportReport> {
    let signer = load_signer(pile_path, key_path)?;
    let mut pile = open_pile_strict(pile_path)?;
    let result = (|| {
        let wiki_before = wiki_model::materialize_indexed_collection(&mut pile, &signer)
            .context("materialize Wiki before bootstrap import")?;
        let (compass_before, compass_reader) = compass::materialize_collection(&mut pile, &signer)
            .context("materialize Compass before bootstrap import")?;
        let (wiki, wiki_roots) = wiki_fragment(
            &signer.verifying_key(),
            Some((wiki_before.catalog(), wiki_before.reader())),
        )?;
        let seed = PortableSeed {
            wiki,
            compass: compass_fragment()?,
            wiki_roots,
        };

        // Compass seed identities are fixed anchors rather than intrinsic
        // artifacts. Reject an existing, divergent use of one of those ids
        // before publishing either half of the seed.
        compass::validate_candidate(&compass_reader, &compass_before, &seed.compass)
            .context("validate portable Compass anchor compatibility")?;

        let expected_wiki = seed.wiki.facts().clone();
        let expected_compass = seed.compass.facts().clone();
        let wiki_commit = wiki_model::commit_collection(&mut pile, &signer, seed.wiki)?;
        let compass_commit = compass::commit_collection(&mut pile, &signer, seed.compass)?;

        let wiki_after = wiki_model::materialize_indexed_collection(&mut pile, &signer)?;
        if !expected_wiki.difference(wiki_after.facts()).is_empty() {
            bail!("Wiki collection omitted portable bootstrap facts after publication");
        }
        let (compass_after, reader) = compass::materialize_collection(&mut pile, &signer)?;
        compass::validate_known_payloads(&reader, &compass_after)?;
        if !expected_compass.difference(&compass_after).is_empty() {
            bail!("Compass collection omitted portable bootstrap facts after publication");
        }

        Ok(ImportReport {
            generation: generation(),
            wiki_commit,
            compass_commit,
        })
    })();
    let close = pile.close();
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(anyhow::anyhow!("close bootstrap pile: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => {
            Err(error.context(format!("closing bootstrap pile also failed: {close_error}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use triblespace::core::blob::MemoryBlobStore;
    use triblespace::core::collection::discover_collection_records;

    use super::*;
    use crate::storage::{initialize_signer, load_signer, open_pile_strict};

    struct Imported {
        _directory: tempfile::TempDir,
        pile: std::path::PathBuf,
        key: std::path::PathBuf,
        report: ImportReport,
    }

    fn imported(name: &str) -> Imported {
        let directory = tempfile::tempdir().unwrap();
        let pile = directory.path().join(format!("{name}.pile"));
        let key = directory.path().join(format!("{name}.key"));
        File::create(&pile).unwrap();
        initialize_signer(&pile, Some(&key)).unwrap();
        let report = import(&pile, Some(&key)).unwrap();
        Imported {
            _directory: directory,
            pile,
            key,
            report,
        }
    }

    fn views(
        imported: &Imported,
    ) -> (
        triblespace::prelude::TribleSet,
        triblespace::prelude::TribleSet,
    ) {
        let signer = load_signer(&imported.pile, Some(&imported.key)).unwrap();
        let mut pile = open_pile_strict(&imported.pile).unwrap();
        let (wiki, _) = wiki_model::materialize_collection(&mut pile, &signer).unwrap();
        let (compass, _) = compass::materialize_collection(&mut pile, &signer).unwrap();
        pile.close().unwrap();
        (wiki, compass)
    }

    #[test]
    fn declared_seed_shape_is_complete_without_alias_entities() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let seed = build(&signer.verifying_key()).unwrap();
        let wiki = wiki_model::load_catalog(seed.wiki.facts()).unwrap();
        assert_eq!(wiki.revisions.all_entries().len(), 21);
        assert_eq!(wiki.revisions.revision_records().count(), 42);
        assert_eq!(seed.wiki_roots.len(), 21);
        assert_eq!(compass::goal_ids(seed.compass.facts()).len(), 7);
        assert_eq!(compass::note_ids(seed.compass.facts()).len(), 7);
        for spec in COMPASS_SEED {
            assert!(compass::goal_ids(seed.compass.facts()).contains(&spec.goal));
            assert!(compass::note_ids(seed.compass.facts()).contains(&spec.occurrence));
        }
    }

    #[test]
    fn independent_keys_author_equivalent_but_distinct_wikis() {
        let left = imported("left");
        let right = imported("right");
        assert_eq!(left.report.generation, right.report.generation);
        assert_ne!(left.report.wiki_commit.id(), right.report.wiki_commit.id());
        assert_ne!(
            left.report.compass_commit.id(),
            right.report.compass_commit.id()
        );

        let (left_wiki, left_compass) = views(&left);
        let (right_wiki, right_compass) = views(&right);
        assert_ne!(left_wiki, right_wiki, "Wiki authorship is part of identity");
        assert_eq!(left_compass, right_compass);

        let left_catalog = wiki_model::load_catalog(&left_wiki).unwrap();
        let right_catalog = wiki_model::load_catalog(&right_wiki).unwrap();
        let left_titles: BTreeSet<_> = left_catalog
            .revisions
            .list_entries()
            .into_iter()
            .flat_map(|entry| entry.frontier)
            .map(|revision| revision.title)
            .collect();
        let right_titles: BTreeSet<_> = right_catalog
            .revisions
            .list_entries()
            .into_iter()
            .flat_map(|entry| entry.frontier)
            .map(|revision| revision.title)
            .collect();
        assert_eq!(left_titles, right_titles);
    }

    #[test]
    fn compass_anchor_preflight_rejects_missing_attachments_without_publishing() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("empty.pile");
        let key = directory.path().join("empty.key");
        File::create(&pile_path).unwrap();
        let signer = initialize_signer(&pile_path, Some(&key)).unwrap();
        let length_before = std::fs::metadata(&pile_path).unwrap().len();
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let (compass_before, compass_reader) =
            compass::materialize_collection(&mut pile, &signer).unwrap();
        let seed = build(&signer.verifying_key()).unwrap();

        compass::validate_candidate(&compass_reader, &compass_before, &seed.compass).unwrap();
        let missing_compass =
            Fragment::from_facts_and_blobs(seed.compass.facts().clone(), MemoryBlobStore::new());
        assert!(
            compass::validate_candidate(&compass_reader, &compass_before, &missing_compass)
                .is_err()
        );
        pile.close().unwrap();
        assert_eq!(
            std::fs::metadata(&pile_path).unwrap().len(),
            length_before,
            "Compass preflight must not append collection records"
        );
    }

    #[test]
    fn import_is_collection_only_and_idempotent() {
        let imported = imported("native");
        let first = imported.report.clone();
        let signer = load_signer(&imported.pile, Some(&imported.key)).unwrap();
        let mut pile = open_pile_strict(&imported.pile).unwrap();
        let ticket_before = crate::collection_names::open(
            &mut pile,
            crate::schemas::wiki::DEFAULT_SCOPE_ID,
            signer,
        )
        .ticket()
        .unwrap();
        pile.close().unwrap();
        let bytes_before = std::fs::metadata(&imported.pile).unwrap().len();
        let second = import(&imported.pile, Some(&imported.key)).unwrap();
        let bytes_after = std::fs::metadata(&imported.pile).unwrap().len();
        let signer = load_signer(&imported.pile, Some(&imported.key)).unwrap();
        let mut pile = open_pile_strict(&imported.pile).unwrap();
        let ticket_after = crate::collection_names::open(
            &mut pile,
            crate::schemas::wiki::DEFAULT_SCOPE_ID,
            signer,
        )
        .ticket()
        .unwrap();
        pile.close().unwrap();
        assert_eq!(first.generation, second.generation);
        assert_eq!(first.wiki_commit.id(), second.wiki_commit.id());
        assert_eq!(first.compass_commit.id(), second.compass_commit.id());
        assert_eq!(
            bytes_before, bytes_after,
            "exact replay must not grow the pile"
        );
        assert_eq!(
            ticket_before, ticket_after,
            "maintaining the Wiki index must not advance source authority"
        );

        let mut pile = open_pile_strict(&imported.pile).unwrap();
        let records = discover_collection_records(&mut pile).unwrap();
        assert_eq!(records.commits().len(), 2);
        pile.close().unwrap();
    }

    #[test]
    fn changed_generation_advances_only_source_strand_and_preserves_local_edit() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("upgrade.pile");
        let key_path = directory.path().join("upgrade.key");
        File::create(&pile_path).unwrap();
        let signer = initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let (mut staged, author) = wiki_model::author_record(&signer.verifying_key());
        let tags = tag_set(&mut staged, WIKI_SEED[0].tags).unwrap();

        let (root_fragment, root) = root_record(author, WIKI_SEED[0].anchor).unwrap();
        staged += root_fragment;
        let (prior_source, prior_source_id) = wiki::revision_record(RevisionDraft {
            title: WIKI_SEED[0].title.to_owned(),
            content: "A simulated earlier bootstrap generation.".to_owned(),
            tags: tags.clone(),
            predecessors: BTreeSet::from([root]),
            author,
            // The fixed odd timestamp identifies this as source-lane output.
            authored_at: wiki_time(1),
        })
        .unwrap();
        staged += prior_source;
        let (local_edit, local_edit_id) = wiki::revision_record(RevisionDraft {
            title: "Recipient's local onboarding edit".to_owned(),
            content: "This recipient-authored edit must remain visible.".to_owned(),
            tags: tags.clone(),
            predecessors: BTreeSet::from([prior_source_id]),
            author,
            authored_at: wiki_time(999),
        })
        .unwrap();
        staged += local_edit;

        let mut pile = open_pile_strict(&pile_path).unwrap();
        wiki_model::commit_collection(&mut pile, &signer, staged).unwrap();
        pile.close().unwrap();

        let built = build(&signer.verifying_key()).unwrap();
        assert_eq!(built.wiki_roots[0], root);
        let roots = BTreeMap::from_iter(
            WIKI_SEED
                .iter()
                .zip(built.wiki_roots)
                .map(|(seed, root)| (seed.anchor, root)),
        );
        let desired_content = normalize_source(WIKI_SEED[0].content, &roots);
        let (_, bundled_source_id) = wiki::revision_record(RevisionDraft {
            title: WIKI_SEED[0].title.to_owned(),
            content: desired_content.clone(),
            tags,
            predecessors: BTreeSet::from([prior_source_id]),
            author,
            authored_at: wiki_time(1),
        })
        .unwrap();

        let upgraded = import(&pile_path, Some(&key_path)).unwrap();
        let bytes_after_upgrade = std::fs::metadata(&pile_path).unwrap().len();
        let replay = import(&pile_path, Some(&key_path)).unwrap();
        assert_eq!(upgraded.wiki_commit.id(), replay.wiki_commit.id());
        assert_eq!(upgraded.compass_commit.id(), replay.compass_commit.id());
        assert_eq!(
            bytes_after_upgrade,
            std::fs::metadata(&pile_path).unwrap().len()
        );

        let signer = load_signer(&pile_path, Some(&key_path)).unwrap();
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let (after, reader) = wiki_model::materialize_collection(&mut pile, &signer).unwrap();
        let catalog = wiki_model::load_catalog(&after).unwrap();
        let entry = catalog.revisions.entry_containing(root).unwrap();
        let frontier: BTreeSet<_> = entry.frontier.iter().map(|revision| revision.id).collect();
        assert_eq!(frontier, BTreeSet::from([local_edit_id, bundled_source_id]));
        let bundled = catalog.revisions.revision(bundled_source_id).unwrap();
        assert_eq!(bundled.supersedes, BTreeSet::from([prior_source_id]));
        assert_eq!(
            wiki_model::read_text(&reader, bundled.content).unwrap(),
            desired_content
        );
        pile.close().unwrap();
    }

    #[test]
    fn source_revert_mints_successor_over_current_source_head() {
        let imported = imported("source-revert");
        let signer = load_signer(&imported.pile, Some(&imported.key)).unwrap();
        let mut pile = open_pile_strict(&imported.pile).unwrap();
        let (before, _) = wiki_model::materialize_collection(&mut pile, &signer).unwrap();
        let catalog = wiki_model::load_catalog(&before).unwrap();
        let root = build(&signer.verifying_key()).unwrap().wiki_roots[0];
        let source_a = catalog.revisions.entry_containing(root).unwrap().frontier[0].clone();
        let (_, author) = wiki_model::author_record(&signer.verifying_key());

        let (source_b, source_b_id) = wiki::revision_record(RevisionDraft {
            title: WIKI_SEED[0].title.to_owned(),
            content: "A simulated intervening bootstrap generation B.".to_owned(),
            tags: source_a.tags.clone(),
            predecessors: BTreeSet::from([source_a.id]),
            author,
            authored_at: wiki_time(1),
        })
        .unwrap();
        wiki_model::commit_collection(&mut pile, &signer, source_b).unwrap();
        pile.close().unwrap();

        import(&imported.pile, Some(&imported.key)).unwrap();
        let signer = load_signer(&imported.pile, Some(&imported.key)).unwrap();
        let mut pile = open_pile_strict(&imported.pile).unwrap();
        let (after, reader) = wiki_model::materialize_collection(&mut pile, &signer).unwrap();
        let catalog = wiki_model::load_catalog(&after).unwrap();
        let entry = catalog.revisions.entry_containing(root).unwrap();
        assert_eq!(entry.frontier.len(), 1);
        let reverted_a = &entry.frontier[0];
        assert_ne!(reverted_a.id, source_a.id);
        assert_eq!(reverted_a.supersedes, BTreeSet::from([source_b_id]));
        assert_eq!(
            wiki_model::read_text(&reader, reverted_a.content).unwrap(),
            wiki_model::read_text(&reader, source_a.content).unwrap()
        );
        pile.close().unwrap();
    }

    #[test]
    fn desired_historical_payload_reconciles_all_source_forks() {
        let imported = imported("source-forks");
        let signer = load_signer(&imported.pile, Some(&imported.key)).unwrap();
        let mut pile = open_pile_strict(&imported.pile).unwrap();
        let (before, _) = wiki_model::materialize_collection(&mut pile, &signer).unwrap();
        let catalog = wiki_model::load_catalog(&before).unwrap();
        let root = build(&signer.verifying_key()).unwrap().wiki_roots[0];
        let source_a = catalog.revisions.entry_containing(root).unwrap().frontier[0].clone();
        let (_, author) = wiki_model::author_record(&signer.verifying_key());
        let mut forks = Fragment::empty();
        let mut fork_ids = BTreeSet::new();
        for label in ["B", "C"] {
            let (fork, id) = wiki::revision_record(RevisionDraft {
                title: WIKI_SEED[0].title.to_owned(),
                content: format!("Simulated forked bootstrap generation {label}."),
                tags: source_a.tags.clone(),
                predecessors: BTreeSet::from([source_a.id]),
                author,
                authored_at: wiki_time(1),
            })
            .unwrap();
            forks += fork;
            fork_ids.insert(id);
        }
        wiki_model::commit_collection(&mut pile, &signer, forks).unwrap();
        pile.close().unwrap();

        import(&imported.pile, Some(&imported.key)).unwrap();
        let signer = load_signer(&imported.pile, Some(&imported.key)).unwrap();
        let mut pile = open_pile_strict(&imported.pile).unwrap();
        let (after, reader) = wiki_model::materialize_collection(&mut pile, &signer).unwrap();
        let catalog = wiki_model::load_catalog(&after).unwrap();
        let entry = catalog.revisions.entry_containing(root).unwrap();
        assert_eq!(entry.frontier.len(), 1);
        let reconciled = &entry.frontier[0];
        assert_eq!(reconciled.supersedes, fork_ids);
        assert_eq!(
            wiki_model::read_text(&reader, reconciled.content).unwrap(),
            wiki_model::read_text(&reader, source_a.content).unwrap()
        );
        pile.close().unwrap();
    }

    #[test]
    fn stable_anchor_keeps_title_and_tag_changes_in_the_same_entry() {
        let directory = tempfile::tempdir().unwrap();
        let pile_path = directory.path().join("shape-change.pile");
        let key_path = directory.path().join("shape-change.key");
        File::create(&pile_path).unwrap();
        let signer = initialize_signer(&pile_path, Some(&key_path)).unwrap();
        let (mut staged, author) = wiki_model::author_record(&signer.verifying_key());
        let (root_fragment, root) = root_record(author, WIKI_SEED[0].anchor).unwrap();
        staged += root_fragment;
        let old_tags = tag_set(&mut staged, &["bootstrap", "obsolete-tag"]).unwrap();
        let (old_source, old_source_id) = wiki::revision_record(RevisionDraft {
            title: "An earlier bootstrap title".to_owned(),
            content: "An earlier bootstrap body.".to_owned(),
            tags: old_tags,
            predecessors: BTreeSet::from([root]),
            author,
            authored_at: wiki_time(1),
        })
        .unwrap();
        staged += old_source;
        let mut pile = open_pile_strict(&pile_path).unwrap();
        wiki_model::commit_collection(&mut pile, &signer, staged).unwrap();
        pile.close().unwrap();

        let built = build(&signer.verifying_key()).unwrap();
        assert_eq!(built.wiki_roots[0], root);
        import(&pile_path, Some(&key_path)).unwrap();

        let signer = load_signer(&pile_path, Some(&key_path)).unwrap();
        let mut pile = open_pile_strict(&pile_path).unwrap();
        let (after, reader) = wiki_model::materialize_collection(&mut pile, &signer).unwrap();
        let catalog = wiki_model::load_catalog(&after).unwrap();
        assert_eq!(catalog.revisions.all_entries().len(), WIKI_SEED.len());
        let entry = catalog.revisions.entry_containing(root).unwrap();
        assert_eq!(entry.frontier.len(), 1);
        assert_eq!(
            entry.frontier[0].supersedes,
            BTreeSet::from([old_source_id])
        );
        assert_eq!(
            wiki_model::read_text(&reader, entry.frontier[0].title).unwrap(),
            WIKI_SEED[0].title
        );
        assert_ne!(
            entry.frontier[0].tags,
            catalog.revisions.revision(old_source_id).unwrap().tags
        );
        pile.close().unwrap();
    }

    #[test]
    fn payload_equal_successor_with_other_authorship_replays_exact_identity() {
        let imported = imported("equal-successor");
        let signer = load_signer(&imported.pile, Some(&imported.key)).unwrap();
        let mut pile = open_pile_strict(&imported.pile).unwrap();
        let (before, reader) = wiki_model::materialize_collection(&mut pile, &signer).unwrap();
        let catalog = wiki_model::load_catalog(&before).unwrap();
        let root = build(&signer.verifying_key()).unwrap().wiki_roots[0];
        let head = catalog.revisions.entry_containing(root).unwrap().frontier[0].clone();
        let title = wiki_model::read_text(&reader, head.title).unwrap();
        let content = wiki_model::read_text(&reader, head.content).unwrap();
        drop(reader);

        let (_, author) = wiki_model::author_record(&signer.verifying_key());
        let (same_payload, successor) = wiki::revision_record(RevisionDraft {
            title,
            content,
            tags: head.tags,
            predecessors: BTreeSet::from([head.id]),
            author,
            // Authorship time is occurrence provenance, not revision identity.
            authored_at: wiki_time(999),
        })
        .unwrap();
        wiki_model::commit_collection(&mut pile, &signer, same_payload).unwrap();
        pile.close().unwrap();

        let first = import(&imported.pile, Some(&imported.key)).unwrap();
        let bytes = std::fs::metadata(&imported.pile).unwrap().len();
        let second = import(&imported.pile, Some(&imported.key)).unwrap();
        assert_eq!(first.wiki_commit.id(), second.wiki_commit.id());
        assert_eq!(bytes, std::fs::metadata(&imported.pile).unwrap().len());

        let signer = load_signer(&imported.pile, Some(&imported.key)).unwrap();
        let mut pile = open_pile_strict(&imported.pile).unwrap();
        let (after, _) = wiki_model::materialize_collection(&mut pile, &signer).unwrap();
        let catalog = wiki_model::load_catalog(&after).unwrap();
        let entry = catalog.revisions.entry_containing(root).unwrap();
        assert_eq!(
            entry
                .frontier
                .iter()
                .map(|revision| revision.id)
                .collect::<Vec<_>>(),
            vec![successor]
        );
        pile.close().unwrap();
    }
}
