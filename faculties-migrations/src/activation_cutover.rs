//! Pure aggregate planning for one stopped-world native-collection activation.
//!
//! This module deliberately stops before there is a candidate filesystem. It
//! erases every validated faculty-specific migration plan into one small
//! in-memory value and proves that every legacy pin in the frozen source is
//! either an input to at least one collection or has exactly one explicit
//! source disposition. There is no activation manifest, transform registry,
//! checkpoint, resume protocol, target head, signer, or target write here.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::CommitHandle;
use triblespace::prelude::Inline;
use triblespace::prelude::{Fragment, Id, TribleSet};

use crate::collection_cutover::{FrozenSource, LegacyPinCoordinate};
use crate::{
    archive_cutover, atlas_cutover, body_cutover, cognition_cutover, comb_cutover, compass_cutover,
    decide_cutover, discord_cutover, files_cutover, habit_cutover, headspace_cutover, mail_cutover,
    memory_cutover, message_cutover, orient_cutover, planner_cutover, posture_cutover,
    relations_cutover, secrets_cutover, status_cutover, teams_cutover, voice_cutover, web_cutover,
    wiki_cutover,
};
use faculties::schemas;
use faculties::secrets;
use faculties::{
    atlas, blockdag, body, cognition, comb, compass, decide, discord, files, habits, headspace,
    mail, memory, message, planner, relations, status, teams, voice, wiki,
};

/// One validated native collection projection with its concrete source inputs.
///
/// `fragments` retains authored empty commits: an empty [`Fragment`] is still
/// an element of this vector. An empty vector is also valid when a verified
/// legacy branch has no authored commits. `expected_facts` is the typed
/// planner's materialized value and is checked against the fragment union when
/// the typed plan is erased.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedCollection {
    name: &'static str,
    scope: Id,
    source_pins: Vec<LegacyPinCoordinate>,
    fragments: Vec<Fragment>,
    expected_facts: TribleSet,
    /// Exact source facts deliberately excluded by the typed migration.
    /// This is diagnostic evidence only; the typed plan owns the conservation
    /// proof before erasure into this aggregate plan.
    retired_source_facts: usize,
}

impl PlannedCollection {
    pub const fn name(&self) -> &'static str {
        self.name
    }

    pub const fn scope(&self) -> Id {
        self.scope
    }

    pub fn source_pins(&self) -> &[LegacyPinCoordinate] {
        &self.source_pins
    }

    pub fn fragments(&self) -> &[Fragment] {
        &self.fragments
    }

    pub fn expected_facts(&self) -> &TribleSet {
        &self.expected_facts
    }

    pub const fn retired_source_facts(&self) -> usize {
        self.retired_source_facts
    }

    fn new(
        name: &'static str,
        scope: Id,
        source_pins: impl IntoIterator<Item = LegacyPinCoordinate>,
        fragments: impl IntoIterator<Item = Fragment>,
        expected_facts: TribleSet,
    ) -> Result<Self> {
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
        Ok(Self {
            name,
            scope,
            source_pins,
            fragments,
            expected_facts,
            retired_source_facts: 0,
        })
    }

    fn with_retired_source_facts(mut self, retired_source_facts: usize) -> Self {
        self.retired_source_facts = retired_source_facts;
        self
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
    collections: Vec<PlannedCollection>,
    dispositions: Vec<SourceDisposition>,
}

impl ActivationPlan {
    pub fn collections(&self) -> &[PlannedCollection] {
        &self.collections
    }

    pub fn dispositions(&self) -> &[SourceDisposition] {
        &self.dispositions
    }

    /// Recheck exact source coverage against the same immutable snapshot.
    pub fn verify_source_coverage(&self, source: &FrozenSource) -> Result<()> {
        validate_source_coverage(source.legacy_pins(), &self.collections, &self.dispositions)
    }
}

/// Validate the complete post-publication view of every planned faculty.
///
/// This is deliberately one static dispatch table rather than another
/// transform trait. Each value is the final authorized collection union from
/// a coherent native snapshot. Local predicates run first; faculty
/// cross-collection invariants run over the same immutable pile reader and
/// the catalogs parsed from those exact candidate views afterwards.
pub fn validate_candidate_views(
    reader: &PileReader,
    views: &BTreeMap<Id, TribleSet>,
) -> Result<()> {
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
        secrets::schema::DEFAULT_SCOPE_ID,
        schemas::status::DEFAULT_SCOPE_ID,
        schemas::teams::DEFAULT_SCOPE_ID,
        schemas::voice::COLLECTION_SCOPE_ID,
        schemas::web::DEFAULT_SCOPE_ID,
        schemas::wiki::DEFAULT_SCOPE_ID,
    ]);
    for scope in views.keys() {
        if !known_scopes.contains(scope) {
            bail!("candidate contains an unrecognized planned collection scope {scope:X}");
        }
    }

    let archive = required_view(views, "Archive", schemas::blockdag::DEFAULT_SCOPE_ID)?;
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
        required_view(views, "Atlas", schemas::atlas::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Atlas candidate")?;
    body::validate_catalog(
        reader,
        required_view(views, "Body", schemas::body::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Body candidate")?;
    cognition::validate_catalog(
        reader,
        required_view(views, "Cognition", schemas::cognition::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Cognition candidate")?;
    if let Some(facts) = views.get(&schemas::memory::DEFAULT_COMB_SCOPE_ID) {
        comb::load_catalog(facts).context("validate optional Comb candidate")?;
    }
    compass::validate_known_payloads(
        reader,
        required_view(views, "Compass", schemas::compass::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Compass candidate")?;
    decide::validate_catalog(
        reader,
        required_view(views, "Decide", schemas::decide::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Decide candidate")?;
    if let Some(facts) = views.get(&schemas::discord::DEFAULT_SCOPE_ID) {
        discord::validate_catalog(reader, facts).context("validate optional Discord candidate")?;
    }
    let files = required_view(views, "Files", schemas::files::DEFAULT_SCOPE_ID)?;
    files::validate_catalog(reader, files).context("validate Files candidate")?;
    if let Some(facts) = views.get(&schemas::habit::DEFAULT_SCOPE_ID) {
        habits::validate_catalog(reader, facts).context("validate optional Habit candidate")?;
    }
    let headspace_catalog = headspace::project_result(
        reader,
        required_view(views, "Headspace", schemas::headspace::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Headspace candidate")?;
    let mail_facts = required_view(views, "Mail", schemas::mail::DEFAULT_SCOPE_ID)?;
    mail::validate_local_catalog(reader, mail_facts).context("validate local Mail candidate")?;
    memory::validate_catalog(
        reader,
        required_view(views, "Memory", schemas::memory::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Memory candidate")?;
    planner::validate_catalog(
        reader,
        required_view(views, "Planner", schemas::planner::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Planner candidate")?;
    faculties::posture_policy::validate_policy_catalog(
        reader,
        required_view(views, "Posture", schemas::posture::DEFAULT_POLICY_SCOPE_ID)?,
    )
    .context("validate Posture candidate")?;
    let relation_facts = required_view(views, "Relations", schemas::relations::DEFAULT_SCOPE_ID)?;
    relations::validate_catalog(reader, relation_facts).context("validate Relations candidate")?;
    let secrets_catalog = secrets::validate_catalog(
        reader,
        required_view(views, "Secrets", secrets::schema::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Secrets candidate")?;
    headspace::validate_secret_references(&headspace_catalog, &secrets_catalog)
        .context("validate Headspace candidate exact Secrets references")?;
    status::validate_catalog(
        reader,
        required_view(views, "Status", schemas::status::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Status candidate")?;
    let teams_facts = required_view(views, "Teams", schemas::teams::DEFAULT_SCOPE_ID)?;
    teams::validate_catalog(reader, teams_facts).context("validate Teams candidate")?;
    validate_frozen_v1_teams_secret_references(teams_facts, &secrets_catalog)
        .context("validate Teams candidate exact Secrets references")?;
    voice::validate_catalog(
        reader,
        required_view(views, "Voice", schemas::voice::COLLECTION_SCOPE_ID)?,
    )
    .context("validate Voice candidate")?;
    if let Some(facts) = views.get(&schemas::web::DEFAULT_SCOPE_ID) {
        web_cutover::validate_known_payloads(reader, facts)
            .context("validate optional Web candidate")?;
    }
    wiki::validate_catalog(
        reader,
        required_view(views, "Wiki", schemas::wiki::DEFAULT_SCOPE_ID)?,
    )
    .context("validate Wiki candidate")?;

    let message_facts = required_view(views, "Message", schemas::message::DEFAULT_SCOPE_ID)?;
    message::validate_catalog(reader, message_facts, relation_facts)
        .context("validate Message -> Relations candidate references")?;
    mail::validate_catalog_legacy_secrets_v1(
        reader,
        mail_facts,
        files,
        required_view(views, "Decide", schemas::decide::DEFAULT_SCOPE_ID)?,
        relation_facts,
        &secrets_catalog,
    )
    .context("validate Mail candidate cross-collection references")?;

    Ok(())
}

/// Preserve the stopped-world activation invariant against its exact frozen
/// v1 Secrets candidate. Live Teams deliberately accepts only a discovered v2
/// vault snapshot; the retired fixed collection remains local to migration.
fn validate_frozen_v1_teams_secret_references(
    teams_facts: &TribleSet,
    secrets_catalog: &secrets::SecretsCatalog,
) -> Result<()> {
    for source in teams::auth_profile_sources(teams_facts) {
        for profile in teams::auth_profile_ids(teams_facts, source) {
            let record = teams::auth_profile(teams_facts, profile)?;
            for (label, secret) in [
                ("client secret", record.client_secret_version),
                ("delegated token bundle", record.delegated_token_version),
            ] {
                if let Some(secret) = secret {
                    if !secrets_catalog.secrets.contains_key(&secret) {
                        bail!(
                            "Teams auth profile {profile:x} names unknown {label} Secrets version {secret:x}"
                        );
                    }
                }
            }
        }
    }
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
pub fn plan(source: &FrozenSource) -> Result<ActivationPlan> {
    let mut collections = Vec::new();

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

    let secret_plan = secrets_cutover::plan(source).context("plan Secrets activation")?;
    collections.push(
        PlannedCollection::new(
            "secrets",
            secrets::schema::DEFAULT_SCOPE_ID,
            [secret_plan.source_pin()],
            secret_plan
                .commits()
                .iter()
                .map(|commit| commit.fragment.clone()),
            secret_plan.materialized_facts(),
        )?
        .with_retired_source_facts(secret_plan.report().retired_facts),
    );

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

    // The individual Mail planner can prove only its local algebra. Before
    // any candidate bytes exist, prove its references against the planned
    // Files, Decide, Relations, and Secrets projections that will accompany
    // it. Mail/Files/Decide may own newly staged payloads, so expose their
    // combined in-memory blob closure to the same validator used at publish.
    // Existing WRITE-authorized native facts are intentionally outside this
    // pure legacy-source plan; disposable activation repeats the predicate
    // over the authoritative baseline union planned facts before replacement.
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
    let files_facts = files.materialized_facts();
    let decide_facts = decide.materialized_facts();
    let relations_facts = relations.materialized_facts();
    let secrets_facts = secret_plan.materialized_facts();
    let secrets_catalog = secrets::validate_catalog(source.reader(), &secrets_facts)
        .context("validate planned Secrets catalog for Mail preflight")?;
    let validated_mail = mail::validate_catalog_union_with_blobs_legacy_secrets_v1(
        source.reader(),
        &TribleSet::new(),
        &staged_mail,
        &blob_overlay,
        &files_facts,
        &decide_facts,
        &relations_facts,
        &secrets_catalog,
    )
    .context("validate planned Mail cross-collection references")?;
    let planned_mail = mail.materialized_facts();
    if validated_mail != planned_mail {
        bail!(
            "Mail cross-collection preflight reconstructed {} facts but its typed plan carries {}",
            validated_mail.len(),
            planned_mail.len()
        );
    }

    let dispositions = plan_source_dispositions(source)?;
    let activation = ActivationPlan {
        collections,
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
    dispositions: &[SourceDisposition],
) -> Result<()> {
    let mut source = BTreeSet::new();
    for pin in source_pins {
        if !source.insert(*pin) {
            bail!("frozen source repeats legacy pin coordinate {:X}", pin.id);
        }
    }

    let mut collection_names = BTreeSet::new();
    let mut collection_scopes = BTreeSet::new();
    let mut consumed = BTreeMap::<LegacyPinCoordinate, BTreeSet<&str>>::new();
    for collection in collections {
        if !collection_names.insert(collection.name) {
            bail!(
                "activation plan repeats collection name {}",
                collection.name
            );
        }
        if !collection_scopes.insert(collection.scope) {
            bail!(
                "activation plan repeats target collection scope {:X}",
                collection.scope
            );
        }
        if collection.source_pins.is_empty() {
            bail!(
                "planned collection {} has no legacy source pin",
                collection.name
            );
        }
        let mut own_pins = BTreeSet::new();
        for pin in &collection.source_pins {
            if !own_pins.insert(*pin) {
                bail!(
                    "planned collection {} repeats legacy pin {:X}",
                    collection.name,
                    pin.id
                );
            }
            if !source.contains(pin) {
                bail!(
                    "planned collection {} consumes unknown legacy pin {:X}",
                    collection.name,
                    pin.id
                );
            }
            consumed.entry(*pin).or_default().insert(collection.name);
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
    use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
    use triblespace::core::inline::encodings::hash::Handle;
    use triblespace::core::inline::Inline;
    use triblespace::core::repo::pile::Pile;
    use triblespace::core::repo::BlobStore;

    use crate::collection_cutover::test_support::{TestBranchSpec, TestSourceSpec};

    fn pin(byte: u8) -> LegacyPinCoordinate {
        LegacyPinCoordinate {
            id: Id::new([byte; 16]).unwrap(),
            value: Inline::<Handle<SimpleArchive>>::new([byte; 32]),
        }
    }

    fn empty_mandatory_candidate_views() -> BTreeMap<Id, TribleSet> {
        [
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
            secrets::schema::DEFAULT_SCOPE_ID,
            schemas::status::DEFAULT_SCOPE_ID,
            schemas::teams::DEFAULT_SCOPE_ID,
            schemas::voice::COLLECTION_SCOPE_ID,
            schemas::wiki::DEFAULT_SCOPE_ID,
        ]
        .into_iter()
        .map(|scope| (scope, TribleSet::new()))
        .collect()
    }

    #[test]
    fn frozen_activation_keeps_its_exact_v1_teams_reference_invariant_local() {
        let source_identity = teams::source_fragment("tenant.example");
        let source = source_identity.root().unwrap();
        let missing = Id::new([0xE6; 16]).unwrap();
        let (profile, _) = teams::auth_profile_fragment(
            source,
            "client",
            "user",
            "offline_access",
            None,
            Some(missing),
            [],
        )
        .unwrap();
        let mut teams_facts = source_identity;
        teams_facts += profile;

        let error = validate_frozen_v1_teams_secret_references(
            teams_facts.facts(),
            &secrets::SecretsCatalog::default(),
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("unknown delegated token bundle"),
            "{rendered}"
        );
        assert!(rendered.contains(&format!("{missing:x}")), "{rendered}");
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
        let views = BTreeMap::from([(unknown, TribleSet::new())]);
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

        let error = validate_candidate_views(&reader, &BTreeMap::new()).unwrap_err();
        assert!(format!("{error:#}").contains("no planned Archive collection"));
    }

    #[test]
    fn candidate_validation_rejects_missing_exact_headspace_secret_version() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("candidate.pile");
        File::create(&path).unwrap();
        let mut pile = Pile::open(&path).unwrap();
        let signer = SigningKey::from_bytes(&[0xE8; 32]);
        faculties::storage::ensure_team_of_one_write_authority(&mut pile, &signer).unwrap();

        let anchor = Id::new([0xE9; 16]).unwrap();
        let missing_secret = Id::new([0xEA; 16]).unwrap();
        let mut profile = headspace::default_profile(anchor, "missing-secret");
        profile.model_secret_version = Some(missing_secret);
        let (fragment, _, _) =
            headspace::add_profile_fragment(&profile, &headspace::default_config(anchor), &[])
                .unwrap();
        let headspace_facts = fragment.facts().clone();
        faculties::collection_names::open(&mut pile, schemas::headspace::DEFAULT_SCOPE_ID, signer)
            .commit(fragment)
            .unwrap();
        let reader = pile.reader().unwrap();
        pile.close().unwrap();

        let mut views = empty_mandatory_candidate_views();
        views.insert(schemas::headspace::DEFAULT_SCOPE_ID, headspace_facts);
        let error = validate_candidate_views(&reader, &views).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("validate Headspace candidate exact Secrets references"));
        assert!(message.contains("missing exact model Secrets version"));
    }

    fn collection(
        name: &'static str,
        scope_byte: u8,
        source_pins: impl IntoIterator<Item = LegacyPinCoordinate>,
        fragments: Vec<Fragment>,
    ) -> PlannedCollection {
        let expected = materialized_facts(&fragments);
        PlannedCollection::new(
            name,
            Id::new([scope_byte; 16]).unwrap(),
            source_pins,
            fragments,
            expected,
        )
        .unwrap()
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
    fn one_pin_may_feed_two_planned_collections() {
        let shared = pin(1);
        let plans = [
            collection("message", 11, [shared], vec![]),
            collection("relations", 12, [shared], vec![]),
        ];
        validate_source_coverage(&[shared], &plans, &[]).unwrap();
    }

    #[test]
    fn one_planned_collection_may_consume_many_pins() {
        let left = pin(1);
        let right = pin(2);
        let plans = [collection("message", 11, [left, right], vec![])];
        validate_source_coverage(&[left, right], &plans, &[]).unwrap();
    }

    #[test]
    fn one_collection_may_not_repeat_a_source_pin() {
        let source = pin(1);
        let plans = [collection("duplicate", 11, [source, source], vec![])];
        let error = validate_source_coverage(&[source], &plans, &[]).unwrap_err();
        assert!(format!("{error:#}").contains("repeats legacy pin"));
    }

    #[test]
    fn collection_names_and_scopes_are_unique() {
        let left = pin(1);
        let right = pin(2);
        let duplicate_name = [
            collection("same", 11, [left], vec![]),
            collection("same", 12, [right], vec![]),
        ];
        let error = validate_source_coverage(&[left, right], &duplicate_name, &[]).unwrap_err();
        assert!(format!("{error:#}").contains("repeats collection name"));

        let duplicate_scope = [
            collection("left", 11, [left], vec![]),
            collection("right", 11, [right], vec![]),
        ];
        let error = validate_source_coverage(&[left, right], &duplicate_scope, &[]).unwrap_err();
        assert!(format!("{error:#}").contains("repeats target collection scope"));
    }

    #[test]
    fn an_empty_plan_still_consumes_its_source_pin() {
        let source = pin(1);
        let plans = [collection("empty", 11, [source], vec![])];
        assert!(plans[0].fragments().is_empty());
        assert!(plans[0].expected_facts().is_empty());
        validate_source_coverage(&[source], &plans, &[]).unwrap();
    }

    #[test]
    fn unknown_planned_pin_is_rejected() {
        let source = pin(1);
        let unknown = pin(2);
        let plans = [collection("unknown", 11, [unknown], vec![])];
        let error = validate_source_coverage(&[source], &plans, &[]).unwrap_err();
        assert!(format!("{error:#}").contains("consumes unknown legacy pin"));
    }

    #[test]
    fn duplicate_disposition_is_rejected() {
        let source = pin(1);
        let dispositions = [disposition("first", source), disposition("second", source)];
        let error = validate_source_coverage(&[source], &[], &dispositions).unwrap_err();
        assert!(format!("{error:#}").contains("duplicate source dispositions"));
    }

    #[test]
    fn consumed_and_disposed_overlap_is_rejected() {
        let source = pin(1);
        let plans = [collection("collection", 11, [source], vec![])];
        let dispositions = [disposition("disposed", source)];
        let error = validate_source_coverage(&[source], &plans, &dispositions).unwrap_err();
        assert!(format!("{error:#}").contains("both consumed"));
    }

    #[test]
    fn uncovered_source_pin_is_rejected() {
        let source = pin(1);
        let error = validate_source_coverage(&[source], &[], &[]).unwrap_err();
        assert!(format!("{error:#}").contains("neither consumed nor disposed"));
    }

    #[test]
    fn unknown_disposition_pin_is_rejected() {
        let source = pin(1);
        let dispositions = [disposition("unknown", pin(2))];
        let error = validate_source_coverage(&[source], &[], &dispositions).unwrap_err();
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
