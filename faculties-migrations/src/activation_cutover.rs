//! Pure aggregate planning for one stopped-world native-collection activation.
//!
//! This module deliberately stops before there is a candidate filesystem. It
//! erases every validated faculty-specific migration plan into one small
//! in-memory value and proves that every legacy pin in the frozen source is
//! either an input to at least one collection or has exactly one explicit
//! source disposition. There is no activation manifest, transform registry,
//! checkpoint, resume protocol, target head, signer, or target write here.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use triblespace::core::authority::resolve_authority;
use triblespace::core::blob::{BlobEncoding, TryFromBlob};
use triblespace::core::collection::reach;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::InlineEncoding;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::CommitHandle;
use triblespace::core::repo::{BlobStore, BlobStoreGet, BlobStoreMeta};
use triblespace::prelude::{CollectionName, Fragment, Id, Inline, TribleSet};

use crate::collection_cutover::{FrozenSource, LegacyPinCoordinate};
use crate::{
    archive_cutover, atlas_cutover, body_cutover, cognition_cutover, comb_cutover, compass_cutover,
    decide_cutover, discord_cutover, files_cutover, habit_cutover, headspace_cutover, mail_cutover,
    memory_cutover, message_cutover, orient_cutover, planner_cutover, posture_cutover,
    relations_cutover, secrets_cutover, secrets_v2_cutover, status_cutover, teams_cutover,
    voice_cutover, web_cutover, wiki_cutover,
};
use faculties::schemas;
use faculties::secrets::v2;
use faculties::{
    atlas, blockdag, body, cognition, comb, compass, decide, discord, files, habits, headspace,
    mail, memory, message, planner, relations, status, teams, voice, wiki,
};

#[derive(Clone, Copy)]
struct PlannedActivationReader<'a, Overlay> {
    overlay: &'a Overlay,
    source: &'a PileReader,
}

#[derive(Debug)]
struct PlannedActivationReadError(String);

impl fmt::Display for PlannedActivationReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PlannedActivationReadError {}

impl<Overlay> BlobStoreGet for PlannedActivationReader<'_, Overlay>
where
    Overlay: BlobStoreGet + BlobStoreMeta,
{
    type GetError<E: std::error::Error + Send + Sync + 'static> = PlannedActivationReadError;

    fn get<T, S>(
        &self,
        handle: Inline<Handle<S>>,
    ) -> std::result::Result<T, Self::GetError<<T as TryFromBlob<S>>::Error>>
    where
        S: BlobEncoding + 'static,
        T: TryFromBlob<S>,
        Handle<S>: InlineEncoding,
    {
        let staged = self
            .overlay
            .metadata(handle)
            .map_err(|error| {
                PlannedActivationReadError(format!("inspect planned blob: {error:?}"))
            })?
            .is_some();
        if staged {
            self.overlay.get(handle).map_err(|error| {
                PlannedActivationReadError(format!("read planned blob: {error:?}"))
            })
        } else {
            self.source.get(handle).map_err(|error| {
                PlannedActivationReadError(format!("read frozen source blob: {error:?}"))
            })
        }
    }
}

/// Semantic role of one target collection inside the complete candidate.
///
/// The collection handle, not this key, is the publication identity. This key
/// exists only to route the exact materialized facts to their validator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum CandidateViewKey {
    Faculty(Id),
    Vault(Id),
}

/// Authority policy implied by one semantic target kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetPolicy {
    Faculty,
    Vault {
        readers: BTreeSet<v2::RecipientPublicKey>,
    },
}

/// One validated native collection projection with its concrete source inputs.
///
/// `fragments` retains authored empty commits: an empty [`Fragment`] is still
/// an element of this vector. An empty vector is also valid when a verified
/// legacy branch has no authored commits. `expected_facts` is the typed
/// planner's materialized value and is checked against the fragment union when
/// the typed plan is erased.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedCollection {
    name: CollectionName,
    reach: Fragment,
    view: CandidateViewKey,
    policy: TargetPolicy,
    fragments: Vec<Fragment>,
    expected_facts: TribleSet,
}

impl PlannedCollection {
    pub fn name(&self) -> &CollectionName {
        &self.name
    }

    pub const fn view(&self) -> CandidateViewKey {
        self.view
    }

    pub fn reach(&self) -> &Fragment {
        &self.reach
    }

    pub fn fragments(&self) -> &[Fragment] {
        &self.fragments
    }

    pub fn expected_facts(&self) -> &TribleSet {
        &self.expected_facts
    }

    pub fn policy(&self) -> &TargetPolicy {
        &self.policy
    }

    fn new(
        name: &'static str,
        scope: Id,
        source_pins: impl IntoIterator<Item = LegacyPinCoordinate>,
        fragments: impl IntoIterator<Item = Fragment>,
        expected_facts: TribleSet,
    ) -> Result<PlannedOutput> {
        let source_pins = source_pins.into_iter().collect::<Vec<_>>();
        let fragments = fragments.into_iter().collect::<Vec<_>>();
        let staged_facts = materialized_facts(&fragments);
        if staged_facts != expected_facts {
            bail!(
                "erased {name} plan stages {} facts but its typed plan expects {}",
                staged_facts.len(),
                expected_facts.len()
            );
        }
        Ok(PlannedOutput {
            collection: Self {
                name: faculties::collection_names::require_name(scope),
                reach: faculties::collection_names::require_reach(scope),
                view: CandidateViewKey::Faculty(scope),
                policy: TargetPolicy::Faculty,
                fragments,
                expected_facts,
            },
            consumption: SourceConsumption {
                name: name.to_owned(),
                source_pins,
                retired_source_facts: 0,
            },
        })
    }

    fn vault(
        vault: Id,
        fragments: impl IntoIterator<Item = Fragment>,
        expected_facts: TribleSet,
        readers: BTreeSet<v2::RecipientPublicKey>,
    ) -> Result<Self> {
        let name = v2::vault_name(vault);
        let fragments = fragments.into_iter().collect::<Vec<_>>();
        let staged_facts = materialized_facts(&fragments);
        if staged_facts != expected_facts {
            bail!(
                "erased vault {vault:X} plan stages {} facts but expects {}",
                staged_facts.len(),
                expected_facts.len()
            );
        }
        Ok(Self {
            name,
            reach: reach::private(),
            view: CandidateViewKey::Vault(vault),
            policy: TargetPolicy::Vault { readers },
            fragments,
            expected_facts,
        })
    }
}

struct PlannedOutput {
    collection: PlannedCollection,
    consumption: SourceConsumption,
}

impl PlannedOutput {
    fn with_retired_source_facts(mut self, retired_source_facts: usize) -> Self {
        self.consumption.retired_source_facts = retired_source_facts;
        self
    }
}

#[derive(Default)]
struct ActivationBuilder {
    collections: Vec<PlannedCollection>,
    consumptions: Vec<SourceConsumption>,
}

impl ActivationBuilder {
    fn push(&mut self, output: PlannedOutput) {
        self.collections.push(output.collection);
        self.consumptions.push(output.consumption);
    }

    fn push_target(&mut self, collection: PlannedCollection) {
        self.collections.push(collection);
    }

    fn into_parts(self) -> (Vec<PlannedCollection>, Vec<SourceConsumption>) {
        (self.collections, self.consumptions)
    }
}

/// An exact legacy branch that intentionally contributes no native authority.
///
/// Values are constructed only by [`plan`], after resolving the exact branch
/// name through [`FrozenSource::legacy_branch`]. That resolution validates the
/// branch pin, head signature, complete commit DAG, and authored signatures.
/// This is in-memory coverage evidence, not a signed omission record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceDisposition {
    branch_name: &'static str,
    source_pin: LegacyPinCoordinate,
    reason: &'static str,
}

/// One typed source transform, independent of how many target collections it
/// emits. This is the coverage unit: a consumed-empty source and a source that
/// fans out to many vaults are both represented exactly once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceConsumption {
    name: String,
    source_pins: Vec<LegacyPinCoordinate>,
    retired_source_facts: usize,
}

impl SourceConsumption {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn source_pins(&self) -> &[LegacyPinCoordinate] {
        &self.source_pins
    }

    pub const fn retired_source_facts(&self) -> usize {
        self.retired_source_facts
    }
}

impl SourceDisposition {
    pub const fn branch_name(&self) -> &'static str {
        self.branch_name
    }

    pub const fn source_pin(&self) -> LegacyPinCoordinate {
        self.source_pin
    }

    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

/// Complete pure plan for one atomic activation candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationPlan {
    team: [u8; 32],
    collections: Vec<PlannedCollection>,
    consumptions: Vec<SourceConsumption>,
    dispositions: Vec<SourceDisposition>,
}

/// Complete semantic views from one closed candidate snapshot.
///
/// `vaults` is the global structural census of every vault targeted by this
/// activation. `local_vaults` is the strict subset for which the durable local
/// signer has accepted exact-resource `READ` authority. Runtime references are
/// validated only against that local subset.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CandidateViews {
    faculties: BTreeMap<Id, TribleSet>,
    vaults: BTreeMap<Id, TribleSet>,
    local_vaults: BTreeMap<Id, TribleSet>,
}

impl CandidateViews {
    pub fn new(
        faculties: BTreeMap<Id, TribleSet>,
        vaults: BTreeMap<Id, TribleSet>,
        local_vaults: BTreeMap<Id, TribleSet>,
    ) -> Result<Self> {
        for (vault, local) in &local_vaults {
            let Some(global) = vaults.get(vault) else {
                bail!("local READ vault {vault:X} is absent from the global vault snapshot");
            };
            if local != global {
                bail!("local READ vault {vault:X} differs from its global vault facts");
            }
        }
        Ok(Self {
            faculties,
            vaults,
            local_vaults,
        })
    }

    pub fn faculties(&self) -> &BTreeMap<Id, TribleSet> {
        &self.faculties
    }

    pub fn vaults(&self) -> &BTreeMap<Id, TribleSet> {
        &self.vaults
    }

    pub fn local_vaults(&self) -> &BTreeMap<Id, TribleSet> {
        &self.local_vaults
    }
}

impl ActivationPlan {
    pub const fn team(&self) -> [u8; 32] {
        self.team
    }

    pub fn collections(&self) -> &[PlannedCollection] {
        &self.collections
    }

    pub fn dispositions(&self) -> &[SourceDisposition] {
        &self.dispositions
    }

    pub fn consumptions(&self) -> &[SourceConsumption] {
        &self.consumptions
    }

    pub fn retired_source_facts(&self) -> usize {
        self.consumptions
            .iter()
            .map(SourceConsumption::retired_source_facts)
            .sum()
    }

    /// Recheck exact source coverage against the same immutable snapshot.
    pub fn verify_source_coverage(&self, source: &FrozenSource) -> Result<()> {
        validate_source_coverage(
            source.legacy_pins(),
            &self.collections,
            &self.consumptions,
            &self.dispositions,
        )
    }
}

/// Validate the complete post-publication view of every planned faculty.
///
/// This is deliberately one static dispatch table rather than another
/// transform trait. Each value is the final authorized collection union from
/// a coherent native snapshot. Local predicates run first; faculty
/// cross-collection invariants run over the same immutable pile reader and
/// the catalogs parsed from those exact candidate views afterwards.
pub fn validate_candidate_views(reader: &PileReader, views: &CandidateViews) -> Result<()> {
    let faculty_views = views.faculties();
    let known_scopes = BTreeSet::from([
        schemas::blockdag::DEFAULT_SCOPE_ID,
        schemas::atlas::DEFAULT_SCOPE_ID,
        schemas::body::DEFAULT_SCOPE_ID,
        schemas::cognition::DEFAULT_SCOPE_ID,
        schemas::memory::DEFAULT_COMB_SCOPE_ID,
        schemas::compass::DEFAULT_SCOPE_ID,
        schemas::decide::DEFAULT_SCOPE_ID,
        schemas::discord::DEFAULT_SCOPE_ID,
        schemas::files::DEFAULT_SCOPE_ID,
        schemas::habit::DEFAULT_SCOPE_ID,
        schemas::headspace::DEFAULT_SCOPE_ID,
        schemas::mail::DEFAULT_SCOPE_ID,
        schemas::memory::DEFAULT_SCOPE_ID,
        schemas::message::DEFAULT_SCOPE_ID,
        schemas::planner::DEFAULT_SCOPE_ID,
        schemas::posture::DEFAULT_POLICY_SCOPE_ID,
        schemas::relations::DEFAULT_SCOPE_ID,
        schemas::status::DEFAULT_SCOPE_ID,
        schemas::teams::DEFAULT_SCOPE_ID,
        schemas::voice::COLLECTION_SCOPE_ID,
        schemas::web::DEFAULT_SCOPE_ID,
        schemas::wiki::DEFAULT_SCOPE_ID,
    ]);
    for scope in faculty_views.keys() {
        if !known_scopes.contains(scope) {
            bail!("candidate contains an unrecognized planned collection scope {scope:X}");
        }
    }

    let archive = required_view(
        faculty_views,
        "Archive",
        schemas::blockdag::DEFAULT_SCOPE_ID,
    )?;
    match blockdag::validate_catalog(reader, archive).context("validate Archive candidate")? {
        blockdag::CatalogValidation::Accepted => {}
        blockdag::CatalogValidation::Pending { missing } => {
            bail!(
                "Archive candidate is missing {} referenced attachment(s)",
                missing.len()
            );
        }
        blockdag::CatalogValidation::Rejected(reason) => {
            bail!("Archive candidate was rejected: {reason}");
        }
    }

    atlas::validate_catalog(
        reader,
        required_view(faculty_views, "Atlas", schemas::atlas::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Atlas candidate")?;
    body::validate_catalog(
        reader,
        required_view(faculty_views, "Body", schemas::body::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Body candidate")?;
    cognition::validate_catalog(
        reader,
        required_view(
            faculty_views,
            "Cognition",
            schemas::cognition::DEFAULT_SCOPE_ID,
        )?,
    )
    .context("validate Cognition candidate")?;
    if let Some(facts) = faculty_views.get(&schemas::memory::DEFAULT_COMB_SCOPE_ID) {
        comb::load_catalog(facts).context("validate optional Comb candidate")?;
    }
    compass::validate_known_payloads(
        reader,
        required_view(faculty_views, "Compass", schemas::compass::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Compass candidate")?;
    decide::validate_catalog(
        reader,
        required_view(faculty_views, "Decide", schemas::decide::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Decide candidate")?;
    if let Some(facts) = faculty_views.get(&schemas::discord::DEFAULT_SCOPE_ID) {
        discord::validate_catalog(reader, facts).context("validate optional Discord candidate")?;
    }
    let files = required_view(faculty_views, "Files", schemas::files::DEFAULT_SCOPE_ID)?;
    files::validate_catalog(reader, files).context("validate Files candidate")?;
    if let Some(facts) = faculty_views.get(&schemas::habit::DEFAULT_SCOPE_ID) {
        habits::validate_catalog(reader, facts).context("validate optional Habit candidate")?;
    }
    let headspace_catalog = headspace::project_result(
        reader,
        required_view(
            faculty_views,
            "Headspace",
            schemas::headspace::DEFAULT_SCOPE_ID,
        )?,
    )
    .context("validate Headspace candidate")?;
    let mail_facts = required_view(faculty_views, "Mail", schemas::mail::DEFAULT_SCOPE_ID)?;
    mail::validate_local_catalog(reader, mail_facts).context("validate local Mail candidate")?;
    memory::validate_catalog(
        reader,
        required_view(faculty_views, "Memory", schemas::memory::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Memory candidate")?;
    planner::validate_catalog(
        reader,
        required_view(faculty_views, "Planner", schemas::planner::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Planner candidate")?;
    faculties::posture_policy::validate_policy_catalog(
        reader,
        required_view(
            faculty_views,
            "Posture",
            schemas::posture::DEFAULT_POLICY_SCOPE_ID,
        )?,
    )
    .context("validate Posture candidate")?;
    let relation_facts = required_view(
        faculty_views,
        "Relations",
        schemas::relations::DEFAULT_SCOPE_ID,
    )?;
    relations::validate_catalog(reader, relation_facts).context("validate Relations candidate")?;
    let _all_secrets = v2::SecretsSnapshot::new(reader.clone(), views.vaults.clone())
        .context("validate global Secrets v2 vault candidate")?;
    let local_secrets = v2::SecretsSnapshot::new(reader.clone(), views.local_vaults.clone())
        .context("validate local READ-authorized Secrets v2 vault candidate")?;
    headspace::validate_secret_references_v2(&headspace_catalog, &local_secrets)
        .context("validate Headspace candidate exact local Secrets references")?;
    status::validate_catalog(
        reader,
        required_view(faculty_views, "Status", schemas::status::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Status candidate")?;
    let teams_facts = required_view(faculty_views, "Teams", schemas::teams::DEFAULT_SCOPE_ID)?;
    teams::validate_catalog(reader, teams_facts).context("validate Teams candidate")?;
    teams::validate_auth_secret_references(teams_facts, &local_secrets)
        .context("validate Teams candidate exact local Secrets references")?;
    voice::validate_catalog(
        reader,
        required_view(faculty_views, "Voice", schemas::voice::COLLECTION_SCOPE_ID)?,
    )
    .context("validate Voice candidate")?;
    if let Some(facts) = faculty_views.get(&schemas::web::DEFAULT_SCOPE_ID) {
        web_cutover::validate_known_payloads(reader, facts)
            .context("validate optional Web candidate")?;
    }
    wiki::validate_catalog(
        reader,
        required_view(faculty_views, "Wiki", schemas::wiki::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Wiki candidate")?;

    let message_facts =
        required_view(faculty_views, "Message", schemas::message::DEFAULT_SCOPE_ID)?;
    message::validate_catalog(reader, message_facts, relation_facts)
        .context("validate Message -> Relations candidate references")?;
    mail::validate_catalog(
        reader,
        mail_facts,
        files,
        required_view(faculty_views, "Decide", schemas::decide::DEFAULT_SCOPE_ID)?,
        relation_facts,
        &local_secrets,
    )
    .context("validate Mail candidate cross-collection references")?;

    Ok(())
}

fn required_view<'a>(
    views: &'a BTreeMap<Id, TribleSet>,
    name: &str,
    scope: Id,
) -> Result<&'a TribleSet> {
    views
        .get(&scope)
        .ok_or_else(|| anyhow!("candidate has no planned {name} collection ({scope:X})"))
}

/// Run every current typed V4 planner against one immutable source snapshot.
///
/// Comb, Discord, Habit, and Web are optional typed sources: an absent historical
/// branch produces no collection. Every other typed source and every explicit
/// disposition must be present and valid. The resulting coverage proof is
/// completed before this function returns.
pub fn plan(
    source: &FrozenSource,
    signer: &SigningKey,
    password: Option<&[u8]>,
) -> Result<ActivationPlan> {
    let mut frozen_collections = source.collection_store();
    crate::collection_cutover::reject_dormant_local_commits(
        &mut frozen_collections,
        signer,
        crate::collection_cutover::fixed_write_targets(signer),
    )
    .context("preflight dormant COMMITs on fixed activation WRITE targets")?;
    let mut collections = ActivationBuilder::default();

    let archive = archive_cutover::plan(source).context("plan Archive activation")?;
    collections.push(PlannedCollection::new(
        "archive",
        schemas::blockdag::DEFAULT_SCOPE_ID,
        [archive.source_pin()],
        archive
            .commits()
            .iter()
            .map(|commit| commit.fragment().clone()),
        archive.materialized_facts(),
    )?);

    if let Some(comb) =
        comb_cutover::plan_if_present(source).context("plan optional Comb activation")?
    {
        collections.push(PlannedCollection::new(
            "comb",
            schemas::memory::DEFAULT_COMB_SCOPE_ID,
            [comb.source_pin()],
            comb.commits()
                .iter()
                .map(|commit| commit.fragment().clone()),
            comb.facts().clone(),
        )?);
    }

    let atlas = atlas_cutover::plan(source).context("plan Atlas activation")?;
    collections.push(PlannedCollection::new(
        "atlas",
        schemas::atlas::DEFAULT_SCOPE_ID,
        [atlas.source_pin()],
        atlas.commits().iter().map(|commit| commit.fragment.clone()),
        atlas.materialized_facts(),
    )?);

    let body = body_cutover::plan(source).context("plan Body activation")?;
    collections.push(PlannedCollection::new(
        "body",
        schemas::body::DEFAULT_SCOPE_ID,
        body.source_pins().iter().copied(),
        body.commits().iter().map(|commit| commit.fragment.clone()),
        body.materialized_facts(),
    )?);

    let cognition = cognition_cutover::plan(source).context("plan Cognition activation")?;
    collections.push(PlannedCollection::new(
        "cognition",
        schemas::cognition::DEFAULT_SCOPE_ID,
        cognition.source_pins().iter().copied(),
        cognition
            .commits()
            .iter()
            .map(|commit| commit.fragment.clone()),
        cognition.materialized_facts(),
    )?);

    let compass = compass_cutover::plan(source).context("plan Compass activation")?;
    collections.push(PlannedCollection::new(
        "compass",
        schemas::compass::DEFAULT_SCOPE_ID,
        [compass.source_pin()],
        compass
            .commits()
            .iter()
            .map(|commit| commit.fragment.clone()),
        compass.materialized_facts(),
    )?);

    let decide = decide_cutover::plan(source).context("plan Decide activation")?;
    collections.push(PlannedCollection::new(
        "decide",
        schemas::decide::DEFAULT_SCOPE_ID,
        [decide.source_pin()],
        decide
            .commits()
            .iter()
            .map(|commit| commit.fragment.clone()),
        decide.materialized_facts(),
    )?);

    if let Some(discord) = plan_if_branch_present(
        source,
        schemas::discord::LEGACY_BRANCH_NAME,
        discord_cutover::plan,
    )
    .context("plan optional Discord activation")?
    {
        collections.push(PlannedCollection::new(
            "discord",
            schemas::discord::DEFAULT_SCOPE_ID,
            [discord.source_pin()],
            discord
                .commits()
                .iter()
                .map(|commit| commit.fragment.clone()),
            discord.materialized_facts(),
        )?);
    }

    let files = files_cutover::plan(source).context("plan Files activation")?;
    collections.push(PlannedCollection::new(
        "files",
        schemas::files::DEFAULT_SCOPE_ID,
        [files.source_pin()],
        files.commits().iter().map(|commit| commit.fragment.clone()),
        files.materialized_facts(),
    )?);

    if let Some(habit) = plan_if_branch_present(
        source,
        habit_cutover::LEGACY_BRANCH_NAME,
        habit_cutover::plan,
    )
    .context("plan optional Habit activation")?
    {
        collections.push(PlannedCollection::new(
            "habit",
            schemas::habit::DEFAULT_SCOPE_ID,
            [habit.source_pin()],
            habit.publication_fragments(),
            habit.materialized_facts(),
        )?);
    }

    // Headspace's historical Repository branch is named `config`; the typed
    // planner performs that exact lookup and validation.
    let headspace =
        headspace_cutover::plan(source).context("plan Headspace (config) activation")?;
    collections.push(PlannedCollection::new(
        "headspace",
        schemas::headspace::DEFAULT_SCOPE_ID,
        [headspace.source_pin()],
        headspace
            .commits()
            .iter()
            .map(|commit| commit.fragment.clone()),
        headspace.materialized_facts(),
    )?);

    let mail = mail_cutover::plan(source).context("plan Mail activation")?;
    collections.push(PlannedCollection::new(
        "mail",
        schemas::mail::DEFAULT_SCOPE_ID,
        [mail.source_pin()],
        mail.commits().iter().map(|commit| commit.fragment.clone()),
        mail.materialized_facts(),
    )?);

    let memory = memory_cutover::plan(source).context("plan Memory activation")?;
    collections.push(PlannedCollection::new(
        "memory",
        schemas::memory::DEFAULT_SCOPE_ID,
        [memory.source_pin()],
        memory
            .commits()
            .iter()
            .map(|commit| commit.fragment.clone()),
        memory.materialized_facts(),
    )?);

    // Relations is planned once: Message consumes that verified projection as
    // recipient evidence, and the same plan is published below as Relations.
    let relations = relations_cutover::plan(source).context("plan Relations activation")?;
    let message = message_cutover::plan_with_relations(source, &relations)
        .context("plan Message activation")?;
    collections.push(PlannedCollection::new(
        "message",
        schemas::message::DEFAULT_SCOPE_ID,
        [message.message_source_pin(), message.relations_source_pin()],
        message
            .commits()
            .iter()
            .map(|commit| commit.fragment.clone()),
        message.materialized_facts(),
    )?);

    let planner = planner_cutover::plan(source).context("plan Planner activation")?;
    collections.push(PlannedCollection::new(
        "planner",
        schemas::planner::DEFAULT_SCOPE_ID,
        [planner.source_pin()],
        planner
            .commits()
            .iter()
            .map(|commit| commit.fragment().clone()),
        planner.materialized_facts(),
    )?);

    let posture = posture_cutover::plan(source).context("plan Posture activation")?;
    collections.push(PlannedCollection::new(
        "posture",
        schemas::posture::DEFAULT_POLICY_SCOPE_ID,
        [posture.source_pin()],
        posture
            .commits()
            .iter()
            .map(|commit| commit.fragment.clone()),
        posture.materialized_facts(),
    )?);

    // Relations remains its own collection even though the Message transform
    // also consumes the exact Relations source as recipient evidence.
    collections.push(PlannedCollection::new(
        "relations",
        schemas::relations::DEFAULT_SCOPE_ID,
        [relations.source_pin()],
        relations
            .commits()
            .iter()
            .map(|commit| commit.fragment.clone()),
        relations.materialized_facts(),
    )?);

    let secret_plan = secrets_cutover::plan(source)
        .context("project pre-collection Secrets activation source")?;
    let direct = secrets_v2_cutover::plan_from_legacy_in_store(
        &mut frozen_collections,
        signer,
        source.reader(),
        secret_plan.retained_facts().clone(),
        password,
    )
    .context("plan direct Secrets vault activation")?;
    if direct.team() != signer.verifying_key().to_bytes() {
        bail!("direct Secrets plan belongs to a different durable team root");
    }
    for vault in direct.vaults() {
        for recipient in &vault.recipients {
            VerifyingKey::from_bytes(recipient)
                .context("validate planned direct Secrets READ recipient")?;
        }
        let fragments = vault
            .report
            .data_pending
            .then(|| vault.required.clone())
            .into_iter()
            .collect::<Vec<_>>();
        let expected_facts = materialized_facts(&fragments);
        collections.push_target(PlannedCollection::vault(
            vault.vault,
            fragments,
            expected_facts,
            vault.recipients.clone(),
        )?);
    }

    let status = status_cutover::plan(source).context("plan Status activation")?;
    collections.push(PlannedCollection::new(
        "status",
        schemas::status::DEFAULT_SCOPE_ID,
        [status.source_pin()],
        status
            .commits()
            .iter()
            .map(|commit| commit.fragment.clone()),
        status.materialized_facts(),
    )?);

    let teams = teams_cutover::plan(source).context("plan Teams activation")?;
    collections.push(
        PlannedCollection::new(
            "teams",
            schemas::teams::DEFAULT_SCOPE_ID,
            [teams.source_pin()],
            teams.commits().iter().map(|commit| commit.fragment.clone()),
            teams.materialized_facts(),
        )?
        .with_retired_source_facts(teams.report().retired_facts),
    );

    let voice = voice_cutover::plan(source).context("plan Voice activation")?;
    collections.push(PlannedCollection::new(
        "voice",
        schemas::voice::COLLECTION_SCOPE_ID,
        voice.source_pins().iter().copied(),
        voice.commits().iter().map(|commit| commit.fragment.clone()),
        voice.materialized_facts(),
    )?);

    if let Some(web) =
        plan_if_branch_present(source, schemas::web::LEGACY_BRANCH_NAME, web_cutover::plan)
            .context("plan optional Web activation")?
    {
        collections.push(PlannedCollection::new(
            "web",
            schemas::web::DEFAULT_SCOPE_ID,
            [web.source_pin()],
            web.commits().iter().map(|commit| commit.fragment.clone()),
            web.materialized_facts(),
        )?);
    }

    let wiki = wiki_cutover::plan(source).context("plan Wiki activation")?;
    collections.push(PlannedCollection::new(
        "wiki",
        schemas::wiki::DEFAULT_SCOPE_ID,
        [wiki.source_pin()],
        wiki.commits().iter().map(|commit| commit.fragment.clone()),
        wiki.materialized_facts(),
    )?);

    // Prove the full cross-faculty world before a disposable COMMIT exists.
    // Global vault validation sees every frozen authorized vault plus every
    // staged direct projection; runtime references see only the hypothetical
    // final subset for which the durable signer has exact READ.
    let global = v2::storage::discover_all_vaults_strict(&mut frozen_collections, signer)
        .context("discover frozen global Secrets vault baseline")?;
    let mut vault_facts = global
        .snapshot()
        .vaults()
        .iter()
        .map(|(vault, snapshot)| (*vault, snapshot.facts().clone()))
        .collect::<BTreeMap<_, _>>();
    let locations = global.locations().clone();
    drop(global);

    let planned_readers = direct
        .vaults()
        .iter()
        .map(|vault| (vault.vault, vault.recipients.clone()))
        .collect::<BTreeMap<_, _>>();
    let local_team_authority =
        resolve_authority(&mut frozen_collections, signer.verifying_key())
            .map_err(|error| anyhow!("resolve frozen local-team Secrets authority: {error}"))?;
    let mut staged_vaults = Fragment::empty();
    for vault in direct.vaults() {
        let handle = v2::vault_handle(vault.vault, signer.verifying_key());
        let current = v2::read_authority_recipient_keys(&local_team_authority, handle);
        if !current.is_subset(&vault.recipients) {
            bail!(
                "frozen vault {:X} already has a READ recipient outside the projected legacy effective-recipient set",
                vault.vault
            );
        }
        if let Some(location) = locations.get(&vault.vault) {
            if location.team() != signer.verifying_key() {
                bail!(
                    "planned vault {:X} is already anchored by another team",
                    vault.vault
                );
            }
        }
        let facts = vault_facts.entry(vault.vault).or_default();
        *facts += vault.required.facts().clone();
        staged_vaults += vault.required.clone();
    }

    let mut local_vault_facts = BTreeMap::new();
    let mut final_readers = BTreeMap::new();
    for (vault, facts) in &vault_facts {
        let readers = if let Some(readers) = planned_readers.get(vault) {
            readers.clone()
        } else if let Some(location) = locations.get(vault) {
            let authority = resolve_authority(&mut frozen_collections, location.team())
                .map_err(|error| anyhow!("resolve frozen vault {vault:X} authority: {error}"))?;
            v2::read_authority_recipient_keys(&authority, location.collection())
        } else {
            BTreeSet::new()
        };
        final_readers.insert(*vault, readers.clone());
        if readers.contains(&signer.verifying_key().to_bytes()) {
            local_vault_facts.insert(*vault, facts.clone());
        }
    }

    let staged_reader = staged_vaults
        .blobs_mut()
        .reader()
        .context("snapshot staged direct Secrets attachments")?;
    let global_secrets = v2::SecretsSnapshot::new(
        PlannedActivationReader {
            overlay: &staged_reader,
            source: source.reader(),
        },
        vault_facts,
    )
    .context("validate planned global Secrets vault snapshot")?;
    for (vault, snapshot) in global_secrets.vaults() {
        let readers = &final_readers[vault];
        for secret in snapshot.catalog().secrets.keys().copied() {
            if !readers.is_subset(&snapshot.catalog().wrap_holders(secret)) {
                bail!(
                    "planned vault {vault:X} leaves an accepted READ recipient without a wrap for secret {secret:X}"
                );
            }
        }
    }
    let local_secrets = v2::SecretsSnapshot::new(
        PlannedActivationReader {
            overlay: &staged_reader,
            source: source.reader(),
        },
        local_vault_facts,
    )
    .context("validate planned local READ-authorized Secrets vault snapshot")?;
    drop(global_secrets);

    let headspace_catalog =
        headspace::project_result(source.reader(), &headspace.materialized_facts())
            .context("validate planned Headspace catalog")?;
    headspace::validate_secret_references_v2(&headspace_catalog, &local_secrets)
        .context("validate planned Headspace local Secrets references")?;
    let teams_facts = teams.materialized_facts();
    teams::validate_catalog(source.reader(), &teams_facts)
        .context("validate planned Teams catalog")?;
    teams::validate_auth_secret_references(&teams_facts, &local_secrets)
        .context("validate planned Teams local Secrets references")?;

    let staged_mail = mail
        .commits()
        .iter()
        .fold(Fragment::empty(), |mut all, commit| {
            all += commit.fragment.clone();
            all
        });
    let mut blob_overlay = staged_mail.clone();
    for fragment in files
        .commits()
        .iter()
        .map(|commit| &commit.fragment)
        .chain(decide.commits().iter().map(|commit| &commit.fragment))
    {
        blob_overlay.blobs_mut().union(fragment.blobs().clone());
    }
    let validated_mail = mail::validate_catalog_union_with_blobs(
        source.reader(),
        &TribleSet::new(),
        &staged_mail,
        &blob_overlay,
        &files.materialized_facts(),
        &decide.materialized_facts(),
        &relations.materialized_facts(),
        &local_secrets,
    )
    .context("validate planned Mail cross-collection and local Secrets references")?;
    if validated_mail != mail.materialized_facts() {
        bail!("planned Mail cross-collection preflight reconstructed different facts");
    }

    let dispositions = plan_source_dispositions(source)?;
    let (collections, mut consumptions) = collections.into_parts();
    consumptions.push(SourceConsumption {
        name: "secrets-vaults".to_owned(),
        source_pins: vec![secret_plan.source_pin()],
        retired_source_facts: secret_plan.report().retired_facts,
    });
    let activation = ActivationPlan {
        team: signer.verifying_key().to_bytes(),
        collections,
        consumptions,
        dispositions,
    };
    activation.verify_source_coverage(source)?;
    Ok(activation)
}

fn materialized_facts(fragments: &[Fragment]) -> TribleSet {
    fragments
        .iter()
        .fold(TribleSet::new(), |mut union, fragment| {
            // Each fragment already owns all six indexed PATCH projections of its
            // facts. Preserve that work and compose the sets directly instead of
            // flattening them back into rows and rebuilding six tries per trible.
            union += fragment.facts().clone();
            union
        })
}

/// Absence means there is no source coordinate to consume. A present branch
/// with no head is deliberately different: its typed planner still runs and
/// returns a consumed-empty plan.
fn plan_if_branch_present<T>(
    source: &FrozenSource,
    branch_name: &str,
    planner: impl FnOnce(&FrozenSource) -> Result<T>,
) -> Result<Option<T>> {
    if source.legacy_branch(branch_name)?.is_some() {
        planner(source).map(Some)
    } else {
        Ok(None)
    }
}

fn plan_source_dispositions(source: &FrozenSource) -> Result<Vec<SourceDisposition>> {
    // These three are reviewed exact closures. A later append, same-name
    // replacement, or different source snapshot invalidates the disposition.
    let interoception = exact_closure_disposition(
        source,
        "interoception",
        Id::from_hex("1955E06E3BBC627BA6615591B793F036").expect("reviewed branch id"),
        commit_handle("3CDDF18FE9C26DD85EADBA5A1A1F1D7D80AF91FE95D98B3F13C6A84DBBF61FE4"),
        "the reviewed abandoned interoception experiment is intentionally not translated into native collection authority",
    )?;
    let logs = exact_closure_disposition(
        source,
        "logs",
        Id::from_hex("0F5E424D339342729958D43CF97B871B").expect("reviewed branch id"),
        commit_handle("90C2020D055CADFFCA8318F956DC12D669A03CBEE9ECBA3C49A1F2DE1A8A186F"),
        "the reviewed operational-log closure is rebuildable exhaust and is intentionally not translated",
    )?;
    let workspace = exact_closure_disposition(
        source,
        "workspace",
        Id::from_hex("04E57624196D059D8920D6EB862755D3").expect("reviewed branch id"),
        commit_handle("644E9D1228A3EEB40151B6242C88FAEB3EDC87251455D0357B8F28CA82D96963"),
        "the reviewed retired workspace snapshot is rebuildable and is intentionally not translated",
    )?;

    // Orient heads may legitimately advance until the writer cohort is
    // stopped, so their reviewed disposition is bound to exact branch ids and
    // a closed semantic/attachment validator rather than fixed heads.
    let retired = orient_cutover::validate_retired(source)
        .context("validate retired legacy Orient checkpoint ledgers")?;
    let orient = SourceDisposition {
        branch_name: "orient",
        source_pin: retired.orient,
        reason: "legacy Orient operational snapshots are intentionally not translated; the native baseline is recreated after swap",
    };
    let orient_state = SourceDisposition {
        branch_name: "orient-state",
        source_pin: retired.orient_state,
        reason: "legacy physical cursor checkpoints are intentionally not translated and the native baseline is recreated after swap",
    };

    Ok(vec![interoception, logs, workspace, orient, orient_state])
}

fn exact_closure_disposition(
    source: &FrozenSource,
    branch_name: &'static str,
    expected_branch: Id,
    expected_head: CommitHandle,
    reason: &'static str,
) -> Result<SourceDisposition> {
    let branch = exact_named_branch(source, branch_name, expected_branch)?;
    if branch.head != Some(expected_head) {
        let actual = branch
            .head
            .map(|head| hex::encode_upper(head.raw))
            .unwrap_or_else(|| "EMPTY".to_owned());
        bail!(
            "disposed legacy {branch_name} closure changed: expected {}, found {actual}",
            hex::encode_upper(expected_head.raw)
        );
    }
    Ok(SourceDisposition {
        branch_name,
        source_pin: branch.pin_coordinate(),
        reason,
    })
}

fn exact_named_branch(
    source: &FrozenSource,
    branch_name: &'static str,
    expected_branch: Id,
) -> Result<crate::collection_cutover::FrozenLegacyBranch> {
    let branch = source
        .legacy_branch(branch_name)
        .with_context(|| format!("validate disposed legacy {branch_name} branch"))?
        .ok_or_else(|| {
            anyhow!(
                "frozen source has no exact legacy {branch_name} branch required by the activation disposition census"
            )
        })?;
    if branch.branch != expected_branch {
        bail!(
            "disposed legacy {branch_name} expected branch {expected_branch:X}, found {:X}",
            branch.branch
        );
    }
    Ok(branch)
}

fn commit_handle(value: &str) -> CommitHandle {
    let mut raw = [0_u8; 32];
    hex::decode_to_slice(value, &mut raw).expect("reviewed legacy head is valid hexadecimal");
    Inline::new(raw)
}

fn validate_source_coverage(
    source_pins: &[LegacyPinCoordinate],
    collections: &[PlannedCollection],
    consumptions: &[SourceConsumption],
    dispositions: &[SourceDisposition],
) -> Result<()> {
    let mut source = BTreeSet::new();
    for pin in source_pins {
        if !source.insert(*pin) {
            bail!("frozen source repeats legacy pin coordinate {:X}", pin.id);
        }
    }

    let mut collection_views = BTreeSet::new();
    for collection in collections {
        if !collection_views.insert(collection.view) {
            bail!(
                "activation plan repeats semantic collection view {:?}",
                collection.view
            );
        }
    }

    let mut consumption_names = BTreeSet::new();
    let mut consumed = BTreeMap::<LegacyPinCoordinate, BTreeSet<&str>>::new();
    for consumption in consumptions {
        if !consumption_names.insert(consumption.name.as_str()) {
            bail!(
                "activation plan repeats source transform {}",
                consumption.name
            );
        }
        if consumption.source_pins.is_empty() {
            bail!(
                "source transform {} has no legacy source pin",
                consumption.name
            );
        }
        let mut own_pins = BTreeSet::new();
        for pin in &consumption.source_pins {
            if !own_pins.insert(*pin) {
                bail!(
                    "source transform {} repeats legacy pin {:X}",
                    consumption.name,
                    pin.id
                );
            }
            if !source.contains(pin) {
                bail!(
                    "source transform {} consumes unknown legacy pin {:X}",
                    consumption.name,
                    pin.id
                );
            }
            consumed
                .entry(*pin)
                .or_default()
                .insert(consumption.name.as_str());
        }
    }

    let mut disposed = BTreeMap::<LegacyPinCoordinate, &str>::new();
    for disposition in dispositions {
        let pin = disposition.source_pin;
        if !source.contains(&pin) {
            bail!(
                "source disposition {} names unknown legacy pin {:X}",
                disposition.branch_name,
                pin.id
            );
        }
        if let Some(previous) = disposed.insert(pin, disposition.branch_name) {
            bail!(
                "legacy pin {:X} has duplicate source dispositions {previous} and {}",
                pin.id,
                disposition.branch_name
            );
        }
        if let Some(collections) = consumed.get(&pin) {
            bail!(
                "legacy pin {:X} is both consumed by {} and disposed as {}",
                pin.id,
                collections.iter().copied().collect::<Vec<_>>().join(", "),
                disposition.branch_name
            );
        }
    }

    for pin in source {
        if !consumed.contains_key(&pin) && !disposed.contains_key(&pin) {
            bail!("legacy pin {:X} is neither consumed nor disposed", pin.id);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    use ed25519_dalek::SigningKey;
    use hifitime::Epoch;
    use triblespace::core::authority::{
        publish_grant, AuthorityGrant, AuthorityMode, ACTION_WRITE,
    };
    use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace::core::inline::encodings::hash::Handle;
    use triblespace::core::inline::Inline;
    use triblespace::core::repo::pile::Pile;
    use triblespace::core::repo::BlobStore;
    use triblespace::prelude::TryToInline;

    use crate::collection_cutover::test_support::{TestBranchSpec, TestDeltaSpec, TestSourceSpec};

    fn pin(byte: u8) -> LegacyPinCoordinate {
        LegacyPinCoordinate {
            id: Id::new([byte; 16]).unwrap(),
            value: Inline::<Handle<SimpleArchive>>::new([byte; 32]),
        }
    }

    fn empty_mandatory_candidate_views() -> CandidateViews {
        let faculties = [
            schemas::blockdag::DEFAULT_SCOPE_ID,
            schemas::atlas::DEFAULT_SCOPE_ID,
            schemas::body::DEFAULT_SCOPE_ID,
            schemas::cognition::DEFAULT_SCOPE_ID,
            schemas::compass::DEFAULT_SCOPE_ID,
            schemas::decide::DEFAULT_SCOPE_ID,
            schemas::files::DEFAULT_SCOPE_ID,
            schemas::headspace::DEFAULT_SCOPE_ID,
            schemas::mail::DEFAULT_SCOPE_ID,
            schemas::memory::DEFAULT_SCOPE_ID,
            schemas::message::DEFAULT_SCOPE_ID,
            schemas::planner::DEFAULT_SCOPE_ID,
            schemas::posture::DEFAULT_POLICY_SCOPE_ID,
            schemas::relations::DEFAULT_SCOPE_ID,
            schemas::status::DEFAULT_SCOPE_ID,
            schemas::teams::DEFAULT_SCOPE_ID,
            schemas::voice::COLLECTION_SCOPE_ID,
            schemas::wiki::DEFAULT_SCOPE_ID,
        ]
        .into_iter()
        .map(|scope| (scope, TribleSet::new()))
        .collect();
        CandidateViews::new(faculties, BTreeMap::new(), BTreeMap::new()).unwrap()
    }

    #[test]
    fn candidate_validation_rejects_unknown_collection_scope_first() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate.pile");
        File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let reader = pile.reader().unwrap();
        pile.close().unwrap();

        let unknown = Id::new([0xE7; 16]).unwrap();
        let views = CandidateViews::new(
            BTreeMap::from([(unknown, TribleSet::new())]),
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap();
        let error = validate_candidate_views(&reader, &views).unwrap_err();
        assert!(format!("{error:#}").contains("unrecognized planned collection scope"));
    }

    #[test]
    fn candidate_validation_requires_the_complete_mandatory_view_set() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate.pile");
        File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let reader = pile.reader().unwrap();
        pile.close().unwrap();

        let error = validate_candidate_views(&reader, &CandidateViews::default()).unwrap_err();
        assert!(format!("{error:#}").contains("no planned Archive collection"));
    }

    #[test]
    fn aggregate_plan_rejects_fixed_root_dormant_commit_before_source_planning() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.pile");
        let key = directory.path().join("source.key");
        File::create(&path).unwrap();
        let signer = faculties::storage::initialize_signer(&path, Some(&key)).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        publish_grant(
            &mut pile,
            signer.verifying_key(),
            &signer,
            AuthorityGrant::root(
                signer.verifying_key(),
                Inline::<Handle<SimpleArchive>>::new([0xE6; 32]),
                ACTION_WRITE,
                AuthorityMode::Invoke,
            ),
        )
        .unwrap();
        triblespace::core::collection::simplearchive_union::publish_fragment_commit(
            &mut pile,
            &faculties::collection_names::root_descriptor(
                schemas::wiki::DEFAULT_SCOPE_ID,
                signer.verifying_key(),
            ),
            Fragment::empty(),
            &signer,
        )
        .unwrap();
        pile.close().unwrap();

        let source = crate::collection_cutover::freeze_source(&path).unwrap();
        let error = plan(&source, &signer, None).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("preflight dormant COMMITs on fixed activation WRITE targets"));
        assert!(message.contains("would awaken dormant local COMMIT"));
        assert!(!message.contains("plan Archive activation"));
    }

    #[test]
    fn candidate_validation_rejects_globally_present_but_nonlocal_secret_references() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate.pile");
        File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let signer = SigningKey::from_bytes(&[0xE8; 32]);
        faculties::storage::ensure_team_of_one_write_authority(&mut pile, &signer).unwrap();

        let team = signer.verifying_key();
        let vault = Id::new([0xE9; 16]).unwrap();
        let outsider = SigningKey::from_bytes(&[0xEA; 32]);
        let epoch = Epoch::from_unix_seconds(1.0);
        let created_at = (epoch, epoch).try_to_inline().unwrap();
        let sealed = v2::seal_version(
            "globally-visible",
            b"not locally readable",
            &BTreeSet::from([outsider.verifying_key().to_bytes()]),
            created_at,
        )
        .unwrap();
        let secret = sealed.secret;
        let mut vault_fragment =
            v2::vault_header_fragment(vault, "global-only", created_at).unwrap();
        vault_fragment += sealed.fragment;
        let vault_facts = vault_fragment.facts().clone();
        let vault_handle = v2::vault_handle(vault, team);
        publish_grant(
            &mut pile,
            team,
            &signer,
            AuthorityGrant::root(team, vault_handle, ACTION_WRITE, AuthorityMode::Invoke),
        )
        .unwrap();
        v2::vault_collection(&mut pile, vault, team, signer.clone())
            .commit(vault_fragment)
            .unwrap();
        publish_grant(
            &mut pile,
            team,
            &signer,
            AuthorityGrant::root(
                outsider.verifying_key(),
                vault_handle,
                v2::ACTION_READ,
                AuthorityMode::Invoke,
            ),
        )
        .unwrap();
        let authority = resolve_authority(&mut pile, team).unwrap();
        let local_readers = v2::read_authority_recipient_keys(&authority, vault_handle);
        assert!(!local_readers.contains(&team.to_bytes()));

        let headspace_anchor = Id::new([0xEB; 16]).unwrap();
        let mut profile = headspace::default_profile(headspace_anchor, "global-only-secret");
        profile.model_secret_version = Some(secret);
        let (headspace_fragment, _, _) = headspace::add_profile_fragment(
            &profile,
            &headspace::default_config(headspace_anchor),
            &[],
        )
        .unwrap();
        let headspace_facts = headspace_fragment.facts().clone();
        faculties::collection_names::open(
            &mut pile,
            schemas::headspace::DEFAULT_SCOPE_ID,
            signer.clone(),
        )
        .commit(headspace_fragment)
        .unwrap();

        let mut teams_fragment = teams::source_fragment("tenant.example");
        let teams_source = teams_fragment.root().unwrap();
        let (auth_profile, _) = teams::auth_profile_fragment(
            teams_source,
            "client",
            "user",
            "offline_access",
            None,
            Some(secret),
            [],
        )
        .unwrap();
        teams_fragment += auth_profile;
        let teams_facts = teams_fragment.facts().clone();
        faculties::collection_names::open(
            &mut pile,
            schemas::teams::DEFAULT_SCOPE_ID,
            signer.clone(),
        )
        .commit(teams_fragment)
        .unwrap();

        let (mail_fragment, _) = mail::account_config_fragment(
            Id::new([0xEC; 16]).unwrap(),
            mail::AccountConfigInput {
                address: "operator@example.test".to_owned(),
                display_name: "Operator".to_owned(),
                pop_endpoint: "pop.example.test:995".to_owned(),
                smtp_endpoint: "smtp.example.test:465".to_owned(),
                username: "operator@example.test".to_owned(),
                credential: secret,
                enabled: true,
                predecessors: Vec::new(),
            },
        )
        .unwrap();
        let mail_facts = mail_fragment.facts().clone();
        faculties::collection_names::open(
            &mut pile,
            schemas::mail::DEFAULT_SCOPE_ID,
            signer.clone(),
        )
        .commit(mail_fragment)
        .unwrap();

        let reader = pile.reader().unwrap();
        pile.close().unwrap();

        let global_vaults = BTreeMap::from([(vault, vault_facts)]);
        for (scope, facts, context, detail) in [
            (
                schemas::headspace::DEFAULT_SCOPE_ID,
                headspace_facts,
                "validate Headspace candidate exact local Secrets references",
                "missing exact model Secrets version",
            ),
            (
                schemas::teams::DEFAULT_SCOPE_ID,
                teams_facts,
                "validate Teams candidate exact local Secrets references",
                "unknown delegated token bundle Secrets version",
            ),
            (
                schemas::mail::DEFAULT_SCOPE_ID,
                mail_facts,
                "validate Mail candidate cross-collection references",
                "names unknown Secrets version",
            ),
        ] {
            let mut faculties = empty_mandatory_candidate_views().faculties;
            faculties.insert(scope, facts);
            let views =
                CandidateViews::new(faculties, global_vaults.clone(), BTreeMap::new()).unwrap();
            let error = validate_candidate_views(&reader, &views).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains(context), "{message}");
            assert!(message.contains(detail), "{message}");
        }
    }

    fn collection(name: &str, scope_byte: u8) -> PlannedCollection {
        PlannedCollection {
            name: CollectionName::new(name).unwrap(),
            reach: reach::private(),
            view: CandidateViewKey::Faculty(Id::new([scope_byte; 16]).unwrap()),
            policy: TargetPolicy::Faculty,
            fragments: Vec::new(),
            expected_facts: TribleSet::new(),
        }
    }

    fn consumption(
        name: &str,
        source_pins: impl IntoIterator<Item = LegacyPinCoordinate>,
    ) -> SourceConsumption {
        SourceConsumption {
            name: name.to_owned(),
            source_pins: source_pins.into_iter().collect(),
            retired_source_facts: 0,
        }
    }

    fn disposition(
        branch_name: &'static str,
        source_pin: LegacyPinCoordinate,
    ) -> SourceDisposition {
        SourceDisposition {
            branch_name,
            source_pin,
            reason: "test disposition",
        }
    }

    #[test]
    fn one_source_transform_may_emit_many_collections() {
        let shared = pin(1);
        let targets = [collection("left", 11), collection("right", 12)];
        let sources = [consumption("fan-out", [shared])];
        validate_source_coverage(&[shared], &targets, &sources, &[]).unwrap();
    }

    #[test]
    fn consumed_empty_source_needs_no_target_collection() {
        let source = pin(1);
        let sources = [consumption("zero-output", [source])];
        validate_source_coverage(&[source], &[], &sources, &[]).unwrap();
    }

    #[test]
    fn authored_empty_legacy_secrets_is_consumed_without_a_vault_target() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.pile");
        File::create(&path).unwrap();
        let signer = SigningKey::from_bytes(&[0xA4; 32]);
        let mut pile = Pile::open(&path).unwrap();
        faculties::storage::ensure_team_of_one_write_authority(&mut pile, &signer).unwrap();
        pile.close().unwrap();

        let source = TestSourceSpec::new(vec![TestBranchSpec::new(
            faculties::secrets::schema::LEGACY_BRANCH_NAME,
            Id::new([0xA4; 16]).unwrap(),
            SigningKey::from_bytes(&[0xA5; 32]),
            vec![TestDeltaSpec::authored(
                Fragment::empty(),
                "legacy authored empty Secrets",
            )],
        )])
        .freeze(&path)
        .unwrap()
        .source;
        let legacy = secrets_cutover::plan(&source).unwrap();
        assert!(legacy.retained_facts().is_empty());
        assert_eq!(legacy.report().source_facts, 0);

        let mut frozen_collections = source.collection_store();
        let direct = secrets_v2_cutover::plan_from_legacy_in_store(
            &mut frozen_collections,
            &signer,
            source.reader(),
            legacy.retained_facts().clone(),
            None,
        )
        .unwrap();
        assert!(direct.vaults().is_empty());

        let activation = ActivationPlan {
            team: signer.verifying_key().to_bytes(),
            collections: Vec::new(),
            consumptions: vec![SourceConsumption {
                name: "secrets-vaults".to_owned(),
                source_pins: vec![legacy.source_pin()],
                retired_source_facts: legacy.report().retired_facts,
            }],
            dispositions: Vec::new(),
        };
        activation.verify_source_coverage(&source).unwrap();
    }

    #[test]
    fn one_source_transform_may_not_repeat_a_pin() {
        let source = pin(1);
        let sources = [consumption("duplicate", [source, source])];
        let error = validate_source_coverage(&[source], &[], &sources, &[]).unwrap_err();
        assert!(format!("{error:#}").contains("repeats legacy pin"));
    }

    #[test]
    fn duplicate_semantic_target_view_is_rejected() {
        let source = pin(1);
        let targets = [collection("left", 11), collection("right", 11)];
        let sources = [consumption("source", [source])];
        let error = validate_source_coverage(&[source], &targets, &sources, &[]).unwrap_err();
        assert!(format!("{error:#}").contains("repeats semantic collection view"));
    }

    #[test]
    fn duplicate_disposition_is_rejected() {
        let source = pin(1);
        let dispositions = [disposition("first", source), disposition("second", source)];
        let error = validate_source_coverage(&[source], &[], &[], &dispositions).unwrap_err();
        assert!(format!("{error:#}").contains("duplicate source dispositions"));
    }

    #[test]
    fn consumed_and_disposed_overlap_is_rejected() {
        let source = pin(1);
        let sources = [consumption("collection", [source])];
        let dispositions = [disposition("disposed", source)];
        let error = validate_source_coverage(&[source], &[], &sources, &dispositions).unwrap_err();
        assert!(format!("{error:#}").contains("both consumed"));
    }

    #[test]
    fn uncovered_source_pin_is_rejected() {
        let source = pin(1);
        let error = validate_source_coverage(&[source], &[], &[], &[]).unwrap_err();
        assert!(format!("{error:#}").contains("neither consumed nor disposed"));
    }

    #[test]
    fn unknown_disposition_pin_is_rejected() {
        let source = pin(1);
        let dispositions = [disposition("unknown", pin(2))];
        let error = validate_source_coverage(&[source], &[], &[], &dispositions).unwrap_err();
        assert!(format!("{error:#}").contains("names unknown legacy pin"));
    }

    #[test]
    fn optional_branch_distinguishes_absence_from_consumed_empty() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.pile");
        File::create(&path).unwrap();
        let source = TestSourceSpec::new(vec![TestBranchSpec::empty(
            "empty",
            Id::new([0xA5; 16]).unwrap(),
            SigningKey::from_bytes(&[0xA5; 32]),
        )])
        .freeze(&path)
        .unwrap()
        .source;
        let absent = plan_if_branch_present(&source, "absent", |_| -> Result<()> {
            panic!("an absent branch must not run its typed planner")
        })
        .unwrap();
        assert_eq!(absent, None);

        let empty = plan_if_branch_present(&source, "empty", |source| {
            let branch = source.legacy_branch("empty")?.unwrap();
            assert_eq!(branch.head, None);
            Ok(branch.pin_coordinate())
        })
        .unwrap();
        assert_eq!(
            empty,
            source
                .legacy_branch("empty")
                .unwrap()
                .map(|branch| branch.pin_coordinate())
        );
    }
}
