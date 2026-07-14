//! Compass (kanban) schema: goals, statuses, notes, priority relations,
//! and revision-bound review settlement.
//!
//! Used by `compass.rs` (the faculty CLI) and by any viewer that wants to
//! read compass boards from a pile (the playground dashboard, the pile
//! inspector notebook, etc.).

use crate::schemas::relations::head_members;
use std::collections::{BTreeSet, HashSet};
use triblespace::core::metadata;
use triblespace::macros::{find, id_hex, pattern};
use triblespace::prelude::*;

pub const KIND_GOAL_LABEL: &str = "goal";
pub const KIND_STATUS_LABEL: &str = "status";
pub const KIND_NOTE_LABEL: &str = "note";
pub const KIND_PRIORITIZE_LABEL: &str = "prioritize";
pub const KIND_DEPRIORITIZE_LABEL: &str = "deprioritize";
pub const KIND_REVIEW_REQUEST_LABEL: &str = "review-request";
pub const KIND_REVIEW_ATTESTATION_LABEL: &str = "review-attestation";
pub const KIND_REVIEW_SETTLEMENT_LABEL: &str = "review-settlement";
pub const KIND_REVIEW_OVERRIDE_LABEL: &str = "review-override";

pub const KIND_GOAL_ID: Id = id_hex!("83476541420F46402A6A9911F46FBA3B");
pub const KIND_STATUS_ID: Id = id_hex!("89602B3277495F4E214D4A417C8CF260");
pub const KIND_NOTE_ID: Id = id_hex!("D4E49A6F02A14E66B62076AE4C01715F");
pub const KIND_PRIORITIZE_ID: Id = id_hex!("6907A81922DA6DF79966616EA60DEC70");
pub const KIND_DEPRIORITIZE_ID: Id = id_hex!("86C4621538FB0E30CD63BB7A3B847E8B");
pub const KIND_REVIEW_REQUEST_ID: Id = id_hex!("1B8F3B1197BDFAE5CBB98F1981CD0B4C");
pub const KIND_REVIEW_ATTESTATION_ID: Id = id_hex!("5934FE62F8532B334B338B2D0FA4383E");
pub const KIND_REVIEW_SETTLEMENT_ID: Id = id_hex!("CF764FEF4CD0FAC1DBC67E1C786EB2F1");
pub const KIND_REVIEW_OVERRIDE_ID: Id = id_hex!("D378DC073A6B683F869C3F4391CAA5F1");

pub const KIND_SPECS: [(Id, &str); 9] = [
    (KIND_GOAL_ID, KIND_GOAL_LABEL),
    (KIND_STATUS_ID, KIND_STATUS_LABEL),
    (KIND_NOTE_ID, KIND_NOTE_LABEL),
    (KIND_PRIORITIZE_ID, KIND_PRIORITIZE_LABEL),
    (KIND_DEPRIORITIZE_ID, KIND_DEPRIORITIZE_LABEL),
    (KIND_REVIEW_REQUEST_ID, KIND_REVIEW_REQUEST_LABEL),
    (KIND_REVIEW_ATTESTATION_ID, KIND_REVIEW_ATTESTATION_LABEL),
    (KIND_REVIEW_SETTLEMENT_ID, KIND_REVIEW_SETTLEMENT_LABEL),
    (KIND_REVIEW_OVERRIDE_ID, KIND_REVIEW_OVERRIDE_LABEL),
];

pub const DEFAULT_STATUSES: [&str; 5] = ["todo", "doing", "blocked", "review", "done"];

pub const REVIEW_STATUS: &str = "review";
pub const DONE_STATUS: &str = "done";
pub const VERDICT_APPROVE: &str = "approve";
pub const VERDICT_REQUEST_CHANGES: &str = "request-changes";
pub const VERDICT_ABSTAIN: &str = "abstain";

pub mod board {
    use super::*;

    attributes! {
        "EE18CEC15C18438A2FAB670E2E46E00C" as title: inlineencodings::Handle<blobencodings::LongString>;
        // TODO: migrate to metadata::tag (GenId) — tags should be entities with
        // their own ID + metadata::name, not inline strings. See wiki.rs TagIndex
        // for the correct pattern. This ShortString tag is a legacy design mistake.
        "5FF4941DCC3F6C35E9B3FD57216F69ED" as tag: inlineencodings::ShortString;
        "9D2B6EBDA67E9BB6BE6215959D182041" as parent: inlineencodings::GenId;

        "C1EAAA039DA7F486E4A54CC87D42E72C" as task: inlineencodings::GenId;
        "61C44E0F8A73443ED592A713151E99A4" as status: inlineencodings::ShortString;
        // Acting persona (relations person id) on a status event.
        // Optional — written when $PERSONA / --persona is set, so the
        // audit trail records WHO moved a goal and watchers can absorb
        // their own edits.
        "34718CDC13D0E3D8750DB58105390AB3" as by: inlineencodings::GenId;
        "47351DF00B3DDA96CB305157CD53D781" as note: inlineencodings::Handle<blobencodings::LongString>;
        "B88842D9D00361A0F2728C478C79D75C" as higher: inlineencodings::GenId;
        "18F3446C9E9281A248D370A56395A3F0" as lower: inlineencodings::GenId;
    }
}

pub mod review {
    use super::*;

    attributes! {
        /// Attestation/override/settlement -> immutable review request.
        "7DDEFBFDB2BC2EED08E31A4EE01699DD" as request: inlineencodings::GenId;
        /// Frozen required reviewer roster on a request (repeated). Legacy
        /// requests (and, as a snapshot, all requests) carry this; the gate
        /// prefers the live `group` roster below when present.
        "8070093BBD38BD6A06D5078D01BF2C18" as required: inlineencodings::GenId;
        /// Live roster source: the relations group anchor whose CURRENT head
        /// snapshot resolves this request's reviewers at gate time. When
        /// present, the gate ignores the frozen `required` snapshot and
        /// resolves the group's current members live, so removing a member
        /// unblocks the request with no supersede-for-reroster. Written as an
        /// extra fact outside the sealed fragment, so adding it never
        /// invalidates an existing request.
        "159A8189CD8DAA0098A250B3DE5BBBBB" as group: inlineencodings::GenId;
        /// Frozen break-glass authority roster on a request (repeated).
        "8079D8E6C5F8DC92EF3DFF7111CF7612" as override_authority: inlineencodings::GenId;
        /// approve | request-changes | abstain.
        "5C18CCC8D073A201659DCEA0564CE0DF" as verdict: inlineencodings::ShortString;
        /// A newer request or attestation explicitly replaces these heads.
        "8EAF3178069E8E9215C419FD1D125F4B" as supersedes: inlineencodings::GenId;
        /// Identity-sealed predecessor of an exact same-target roster successor.
        /// The canonical roster-successor fragment also names this as its sole
        /// `supersedes` edge, distinguishing the guarded transition from an
        /// ordinary changed-target successor without trusting mutable history.
        "FC923070BDBAEB9E1F5AC5D4ADE3156C" as roster_predecessor: inlineencodings::GenId;
        /// Settlement -> exact attestation evidence used (repeated).
        "7BF4989BFA09875884BF89E165B2C913" as attestation: inlineencodings::GenId;
        /// Settlement -> exact break-glass override event used.
        "A624198E9D3180377FBADD000B571A1B" as override_event: inlineencodings::GenId;
    }
}

pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::LongString>>;
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

/// Construct the identity-defining core of a review request.
///
/// Review records deliberately use intrinsic ids: every field that can affect
/// the gate is part of this fragment's root. Append-only facts may still add
/// descriptive annotations, but back-patching any proof field changes the
/// reconstructed root and therefore makes the stored record non-canonical.
pub fn review_request_fragment(
    goal: Id,
    author: Id,
    target: TextHandle,
    required: &[Id],
    override_authorities: &[Id],
    supersedes: &[Id],
    created_at: IntervalValue,
) -> Fragment {
    entity! { _ @
        metadata::tag: &KIND_REVIEW_REQUEST_ID,
        metadata::tag: &KIND_STATUS_ID,
        board::task: &goal,
        board::status: REVIEW_STATUS,
        board::by: &author,
        metadata::iri: target,
        review::required*: required.iter(),
        review::override_authority*: override_authorities.iter(),
        review::supersedes*: supersedes.iter(),
        metadata::created_at: created_at,
    }
}

/// Construct a request that changes only the frozen roster of one exact,
/// unsettled predecessor. The dedicated predecessor marker is part of the
/// successor's intrinsic identity and is repeated as its sole supersession
/// edge; evaluation can therefore enforce this narrower transition even if
/// facts about the predecessor arrive or are backpatched after replicas merge.
pub fn review_roster_successor_fragment(
    goal: Id,
    author: Id,
    target: TextHandle,
    required: &[Id],
    override_authorities: &[Id],
    predecessor: Id,
    created_at: IntervalValue,
) -> Fragment {
    entity! { _ @
        metadata::tag: &KIND_REVIEW_REQUEST_ID,
        metadata::tag: &KIND_STATUS_ID,
        board::task: &goal,
        board::status: REVIEW_STATUS,
        board::by: &author,
        metadata::iri: target,
        review::required*: required.iter(),
        review::override_authority*: override_authorities.iter(),
        review::supersedes: &predecessor,
        review::roster_predecessor: &predecessor,
        metadata::created_at: created_at,
    }
}

/// Construct the identity-defining core of one review attestation.
pub fn review_attestation_fragment(
    request: Id,
    reviewer: Id,
    verdict: &str,
    report: TextHandle,
    supersedes: &[Id],
    created_at: IntervalValue,
) -> Fragment {
    entity! { _ @
        metadata::tag: &KIND_REVIEW_ATTESTATION_ID,
        review::request: &request,
        board::by: &reviewer,
        review::verdict: verdict,
        metadata::description: report,
        review::supersedes*: supersedes.iter(),
        metadata::created_at: created_at,
    }
}

/// Construct the identity-defining core of a break-glass event.
pub fn review_override_fragment(
    request: Id,
    actor: Id,
    reason: TextHandle,
    created_at: IntervalValue,
) -> Fragment {
    entity! { _ @
        metadata::tag: &KIND_REVIEW_OVERRIDE_ID,
        review::request: &request,
        board::by: &actor,
        metadata::description: reason,
        metadata::created_at: created_at,
    }
}

/// Construct a settlement whose proof is the exact attestation head set.
pub fn review_attestation_settlement_fragment(
    request: Id,
    goal: Id,
    actor: Id,
    evidence: &[Id],
    created_at: IntervalValue,
) -> Fragment {
    entity! { _ @
        metadata::tag: &KIND_REVIEW_SETTLEMENT_ID,
        metadata::tag: &KIND_STATUS_ID,
        review::request: &request,
        review::attestation*: evidence.iter(),
        board::task: &goal,
        board::status: DONE_STATUS,
        board::by: &actor,
        metadata::created_at: created_at,
    }
}

/// Construct a settlement whose proof is one exact break-glass event.
pub fn review_override_settlement_fragment(
    request: Id,
    goal: Id,
    actor: Id,
    override_event: Id,
    created_at: IntervalValue,
) -> Fragment {
    entity! { _ @
        metadata::tag: &KIND_REVIEW_SETTLEMENT_ID,
        metadata::tag: &KIND_STATUS_ID,
        review::request: &request,
        review::override_event: &override_event,
        board::task: &goal,
        board::status: DONE_STATUS,
        board::by: &actor,
        metadata::created_at: created_at,
    }
}

#[derive(Debug, Clone)]
pub struct ReviewRequest {
    pub id: Id,
    pub tags: Vec<Id>,
    pub goals: Vec<Id>,
    pub statuses: Vec<String>,
    pub authors: Vec<Id>,
    pub targets: Vec<TextHandle>,
    pub required: Vec<Id>,
    pub override_authorities: Vec<Id>,
    pub supersedes: Vec<Id>,
    pub roster_predecessors: Vec<Id>,
    pub created_at: Vec<IntervalValue>,
    /// Live roster source (relations group anchor), if this request records
    /// one. Deliberately NOT part of `canonical_id` — it is an extra fact, so
    /// it never invalidates a request and the gate can prefer it at eval time.
    pub groups: Vec<Id>,
}

impl ReviewRequest {
    pub fn goal(&self) -> Option<Id> {
        exactly_one(&self.goals)
    }

    pub fn author(&self) -> Option<Id> {
        exactly_one(&self.authors)
    }

    pub fn target(&self) -> Option<TextHandle> {
        exactly_one(&self.targets)
    }

    /// The live-roster group anchor this request records, if any.
    pub fn group(&self) -> Option<Id> {
        self.groups.first().copied()
    }

    fn canonical_id(&self) -> Option<Id> {
        if self.tags != sorted_unique(vec![KIND_REVIEW_REQUEST_ID, KIND_STATUS_ID])
            || self.statuses.as_slice() != [REVIEW_STATUS]
        {
            return None;
        }
        let goal = self.goal()?;
        let author = self.author()?;
        let target = self.target()?;
        let created_at = exactly_one(&self.created_at)?;
        match self.roster_predecessors.as_slice() {
            [] => review_request_fragment(
                goal,
                author,
                target,
                &self.required,
                &self.override_authorities,
                &self.supersedes,
                created_at,
            )
            .root(),
            [predecessor] if self.supersedes.as_slice() == [*predecessor] => {
                review_roster_successor_fragment(
                    goal,
                    author,
                    target,
                    &self.required,
                    &self.override_authorities,
                    *predecessor,
                    created_at,
                )
                .root()
            }
            _ => None,
        }
    }

    pub fn is_canonical(&self) -> bool {
        self.canonical_id() == Some(self.id)
    }
}

#[derive(Debug, Clone)]
pub struct ReviewAttestation {
    pub id: Id,
    pub tags: Vec<Id>,
    pub requests: Vec<Id>,
    pub reviewers: Vec<Id>,
    pub verdicts: Vec<String>,
    pub reports: Vec<TextHandle>,
    pub supersedes: Vec<Id>,
    pub created_at: Vec<IntervalValue>,
}

impl ReviewAttestation {
    pub fn request(&self) -> Option<Id> {
        exactly_one(&self.requests)
    }

    pub fn reviewer(&self) -> Option<Id> {
        exactly_one(&self.reviewers)
    }

    pub fn verdict(&self) -> Option<&str> {
        (self.verdicts.len() == 1).then(|| self.verdicts[0].as_str())
    }

    pub fn report(&self) -> Option<TextHandle> {
        exactly_one(&self.reports)
    }

    fn canonical_id(&self) -> Option<Id> {
        if self.tags.as_slice() != [KIND_REVIEW_ATTESTATION_ID] {
            return None;
        }
        review_attestation_fragment(
            self.request()?,
            self.reviewer()?,
            self.verdict()?,
            self.report()?,
            &self.supersedes,
            exactly_one(&self.created_at)?,
        )
        .root()
    }

    pub fn is_canonical(&self) -> bool {
        self.canonical_id() == Some(self.id)
    }
}

#[derive(Debug, Clone)]
pub struct ReviewOverride {
    pub id: Id,
    pub tags: Vec<Id>,
    pub requests: Vec<Id>,
    pub actors: Vec<Id>,
    pub reasons: Vec<TextHandle>,
    pub created_at: Vec<IntervalValue>,
}

impl ReviewOverride {
    fn canonical_id(&self) -> Option<Id> {
        if self.tags.as_slice() != [KIND_REVIEW_OVERRIDE_ID] {
            return None;
        }
        review_override_fragment(
            exactly_one(&self.requests)?,
            exactly_one(&self.actors)?,
            exactly_one(&self.reasons)?,
            exactly_one(&self.created_at)?,
        )
        .root()
    }

    pub fn is_canonical(&self) -> bool {
        self.canonical_id() == Some(self.id)
    }
}

#[derive(Debug, Clone)]
struct ReviewSettlement {
    id: Id,
    tags: Vec<Id>,
    requests: Vec<Id>,
    tasks: Vec<Id>,
    statuses: Vec<String>,
    actors: Vec<Id>,
    attestations: Vec<Id>,
    override_events: Vec<Id>,
    created_at: Vec<IntervalValue>,
}

impl ReviewSettlement {
    fn canonical_mode(&self) -> Option<SettlementMode> {
        if self.tags != sorted_unique(vec![KIND_REVIEW_SETTLEMENT_ID, KIND_STATUS_ID])
            || self.statuses.as_slice() != [DONE_STATUS]
        {
            return None;
        }
        let request = exactly_one(&self.requests)?;
        let goal = exactly_one(&self.tasks)?;
        let actor = exactly_one(&self.actors)?;
        let created_at = exactly_one(&self.created_at)?;
        let (expected, mode) = match (self.attestations.is_empty(), self.override_events.as_slice())
        {
            (false, []) => (
                review_attestation_settlement_fragment(
                    request,
                    goal,
                    actor,
                    &self.attestations,
                    created_at,
                ),
                SettlementMode::Attestations,
            ),
            (true, [override_event]) => (
                review_override_settlement_fragment(
                    request,
                    goal,
                    actor,
                    *override_event,
                    created_at,
                ),
                SettlementMode::Override,
            ),
            _ => return None,
        };
        (expected.root() == Some(self.id)).then_some(mode)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementMode {
    Attestations,
    Override,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidSettlement {
    pub id: Id,
    pub mode: SettlementMode,
    /// Exact reviewer evidence sealed by an ordinary settlement.
    pub attestations: Vec<Id>,
    /// Exact reasoned break-glass event sealed by an override settlement.
    pub override_event: Option<Id>,
}

#[derive(Debug, Clone)]
pub struct ReviewerSlot {
    pub reviewer: Id,
    /// Zero heads means pending; more than one is a merge-visible fork.
    pub heads: Vec<ReviewAttestation>,
}

impl ReviewerSlot {
    /// Whether the reviewer has supplied one structurally valid response.
    /// A request-changes verdict fulfills the reviewer's obligation even
    /// though it deliberately keeps the settlement gate closed.
    pub fn is_fulfilled(&self, request_id: Id) -> bool {
        matches!(self.heads.as_slice(), [head]
            if head.is_canonical()
                && head.request() == Some(request_id)
                && head.reviewer() == Some(self.reviewer)
                && matches!(head.verdict(), Some(VERDICT_APPROVE | VERDICT_REQUEST_CHANGES | VERDICT_ABSTAIN))
                && head.created_at.len() == 1
                && head.reports.len() == 1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewGateState {
    Invalid {
        reasons: Vec<String>,
    },
    Pending {
        submitted: usize,
        required: usize,
    },
    Blocked {
        submitted: usize,
        reasons: Vec<String>,
    },
    Ready,
    Settled {
        settlements: Vec<ValidSettlement>,
    },
}

#[derive(Debug, Clone)]
pub struct ReviewEvaluation {
    pub request: ReviewRequest,
    pub slots: Vec<ReviewerSlot>,
    pub state: ReviewGateState,
}

#[derive(Debug, Clone)]
pub enum ReviewProjection {
    /// A legacy goal in the review lane, or a goal never submitted.
    Unbound,
    /// Concurrent successor requests are preserved and close the gate.
    Forked {
        request_ids: Vec<Id>,
    },
    Bound(ReviewEvaluation),
}

fn exactly_one<T: Copy>(values: &[T]) -> Option<T> {
    (values.len() == 1).then(|| values[0])
}

fn sorted_unique<T: Ord>(mut values: Vec<T>) -> Vec<T> {
    values.sort();
    values.dedup();
    values
}

fn interval_key(interval: IntervalValue) -> i128 {
    let (lower, _): (i128, i128) = interval
        .try_from_inline()
        .expect("NsTAIInterval inline values have a lower bound");
    lower
}

/// Natural DAG heads, plus every node in a component that cannot be reached
/// from those heads. The caller must supply only authenticated/canonical
/// supersession edges: a malformed source cannot use its own edges to hide an
/// otherwise-current predecessor. Unless a canonical successor explicitly
/// supersedes that malformed id, it remains visible as repair work. The
/// unreachable nodes are synthetic repair heads: a trusted cycle or other
/// rootless component stays visible so one fresh intrinsic successor can
/// explicitly supersede it instead of letting it disappear.
fn repair_frontier(all: Vec<Id>, edges: Vec<(Id, Id)>) -> Vec<Id> {
    let all_set: HashSet<Id> = all.iter().copied().collect();
    let mut predecessors: std::collections::HashMap<Id, Vec<Id>> =
        std::collections::HashMap::new();
    let mut superseded = HashSet::new();
    for (new, old) in edges {
        if all_set.contains(&new) && all_set.contains(&old) {
            predecessors.entry(new).or_default().push(old);
            superseded.insert(old);
        }
    }
    let mut frontier: Vec<Id> = all
        .iter()
        .copied()
        .filter(|id| !superseded.contains(id))
        .collect();
    let mut reachable = HashSet::new();
    let mut stack = frontier.clone();
    while let Some(id) = stack.pop() {
        if !reachable.insert(id) {
            continue;
        }
        if let Some(older) = predecessors.get(&id) {
            stack.extend(older.iter().copied());
        }
    }
    frontier.extend(all.into_iter().filter(|id| !reachable.contains(id)));
    sorted_unique(frontier)
}

/// Deterministic latest status event for one goal. Ties on timestamp are
/// broken by intrinsic/extrinsic event id so merged replicas agree.
pub fn latest_status_event(
    space: &TribleSet,
    goal_id: Id,
) -> Option<(Id, String, IntervalValue)> {
    find!(
        (event: Id, status: String, at: IntervalValue),
        pattern!(space, [{ ?event @
            metadata::tag: &KIND_STATUS_ID,
            board::task: &goal_id,
            board::status: ?status,
            metadata::created_at: ?at,
        }])
    )
    .max_by(|left, right| {
        (interval_key(left.2), left.0).cmp(&(interval_key(right.2), right.0))
    })
}

pub fn review_request(space: &TribleSet, request_id: Id) -> Option<ReviewRequest> {
    if !exists!(pattern!(space, [{ request_id @ metadata::tag: &KIND_REVIEW_REQUEST_ID }])) {
        return None;
    }
    let tags = sorted_unique(
        find!(v: Id, pattern!(space, [{ request_id @ metadata::tag: ?v }])).collect(),
    );
    let goals =
        sorted_unique(find!(v: Id, pattern!(space, [{ request_id @ board::task: ?v }])).collect());
    let statuses = sorted_unique(
        find!(v: String, pattern!(space, [{ request_id @ board::status: ?v }])).collect(),
    );
    let authors =
        sorted_unique(find!(v: Id, pattern!(space, [{ request_id @ board::by: ?v }])).collect());
    let targets = sorted_unique(
        find!(v: TextHandle, pattern!(space, [{ request_id @ metadata::iri: ?v }])).collect(),
    );
    let required = sorted_unique(
        find!(v: Id, pattern!(space, [{ request_id @ review::required: ?v }])).collect(),
    );
    let override_authorities = sorted_unique(
        find!(v: Id, pattern!(space, [{ request_id @ review::override_authority: ?v }])).collect(),
    );
    let supersedes = sorted_unique(
        find!(v: Id, pattern!(space, [{ request_id @ review::supersedes: ?v }])).collect(),
    );
    let roster_predecessors = sorted_unique(
        find!(v: Id, pattern!(space, [{ request_id @ review::roster_predecessor: ?v }])).collect(),
    );
    let groups = sorted_unique(
        find!(v: Id, pattern!(space, [{ request_id @ review::group: ?v }])).collect(),
    );
    let created_at = sorted_unique(
        find!(v: IntervalValue, pattern!(space, [{ request_id @ metadata::created_at: ?v }]))
            .collect(),
    );
    Some(ReviewRequest {
        id: request_id,
        tags,
        goals,
        statuses,
        authors,
        targets,
        required,
        override_authorities,
        supersedes,
        roster_predecessors,
        created_at,
        groups,
    })
}

pub fn review_attestation(space: &TribleSet, attestation_id: Id) -> Option<ReviewAttestation> {
    if !exists!(pattern!(space, [{ attestation_id @ metadata::tag: &KIND_REVIEW_ATTESTATION_ID }]))
    {
        return None;
    }
    Some(ReviewAttestation {
        id: attestation_id,
        tags: sorted_unique(find!(v: Id, pattern!(space, [{ attestation_id @ metadata::tag: ?v }])).collect()),
        requests: sorted_unique(find!(v: Id, pattern!(space, [{ attestation_id @ review::request: ?v }])).collect()),
        reviewers: sorted_unique(find!(v: Id, pattern!(space, [{ attestation_id @ board::by: ?v }])).collect()),
        verdicts: sorted_unique(find!(v: String, pattern!(space, [{ attestation_id @ review::verdict: ?v }])).collect()),
        reports: sorted_unique(find!(v: TextHandle, pattern!(space, [{ attestation_id @ metadata::description: ?v }])).collect()),
        supersedes: sorted_unique(find!(v: Id, pattern!(space, [{ attestation_id @ review::supersedes: ?v }])).collect()),
        created_at: sorted_unique(find!(v: IntervalValue, pattern!(space, [{ attestation_id @ metadata::created_at: ?v }])).collect()),
    })
}

pub fn review_override(space: &TribleSet, override_id: Id) -> Option<ReviewOverride> {
    if !exists!(pattern!(space, [{ override_id @ metadata::tag: &KIND_REVIEW_OVERRIDE_ID }])) {
        return None;
    }
    Some(ReviewOverride {
        id: override_id,
        tags: sorted_unique(
            find!(v: Id, pattern!(space, [{ override_id @ metadata::tag: ?v }])).collect(),
        ),
        requests: sorted_unique(
            find!(v: Id, pattern!(space, [{ override_id @ review::request: ?v }])).collect(),
        ),
        actors: sorted_unique(
            find!(v: Id, pattern!(space, [{ override_id @ board::by: ?v }])).collect(),
        ),
        reasons: sorted_unique(
            find!(v: TextHandle, pattern!(space, [{ override_id @ metadata::description: ?v }]))
                .collect(),
        ),
        created_at: sorted_unique(
            find!(v: IntervalValue, pattern!(space, [{ override_id @ metadata::created_at: ?v }]))
                .collect(),
        ),
    })
}

fn review_settlement(space: &TribleSet, settlement_id: Id) -> Option<ReviewSettlement> {
    if !exists!(pattern!(space, [{ settlement_id @ metadata::tag: &KIND_REVIEW_SETTLEMENT_ID }]))
    {
        return None;
    }
    Some(ReviewSettlement {
        id: settlement_id,
        tags: sorted_unique(
            find!(v: Id, pattern!(space, [{ settlement_id @ metadata::tag: ?v }])).collect(),
        ),
        requests: sorted_unique(
            find!(v: Id, pattern!(space, [{ settlement_id @ review::request: ?v }])).collect(),
        ),
        tasks: sorted_unique(
            find!(v: Id, pattern!(space, [{ settlement_id @ board::task: ?v }])).collect(),
        ),
        statuses: sorted_unique(
            find!(v: String, pattern!(space, [{ settlement_id @ board::status: ?v }])).collect(),
        ),
        actors: sorted_unique(
            find!(v: Id, pattern!(space, [{ settlement_id @ board::by: ?v }])).collect(),
        ),
        attestations: sorted_unique(
            find!(v: Id, pattern!(space, [{ settlement_id @ review::attestation: ?v }])).collect(),
        ),
        override_events: sorted_unique(
            find!(v: Id, pattern!(space, [{ settlement_id @ review::override_event: ?v }])).collect(),
        ),
        created_at: sorted_unique(
            find!(v: IntervalValue, pattern!(space, [{ settlement_id @ metadata::created_at: ?v }]))
                .collect(),
        ),
    })
}

pub fn all_request_ids_for_goal(space: &TribleSet, goal_id: Id) -> Vec<Id> {
    sorted_unique(
        find!(id: Id, pattern!(space, [{ ?id @
            metadata::tag: &KIND_REVIEW_REQUEST_ID,
            board::task: &goal_id,
        }]))
        .collect(),
    )
}

pub fn active_request_ids_for_goal(space: &TribleSet, goal_id: Id) -> Vec<Id> {
    let all = all_request_ids_for_goal(space, goal_id);
    let edges = all
        .iter()
        .filter_map(|id| review_request(space, *id))
        .filter(|request| request.is_canonical() && request.goal() == Some(goal_id))
        .flat_map(|request| {
            request
                .supersedes
                .into_iter()
                .map(move |old| (request.id, old))
        })
        .collect();
    repair_frontier(all, edges)
}

pub fn all_attestation_ids_for_request(space: &TribleSet, request_id: Id) -> Vec<Id> {
    sorted_unique(
        find!(id: Id, pattern!(space, [{ ?id @
            metadata::tag: &KIND_REVIEW_ATTESTATION_ID,
            review::request: &request_id,
        }]))
        .collect(),
    )
}

/// Every attestation entity ever attributed to one reviewer on one request.
///
/// Unlike `active_attestation_ids_for_reviewer`, this intentionally includes
/// superseded, forked, and non-canonical records. Same-target roster changes
/// use the complete immutable history so an old vote cannot be made invisible
/// merely by moving the attestation frontier.
pub fn all_attestation_ids_for_reviewer(
    space: &TribleSet,
    request_id: Id,
    reviewer_id: Id,
) -> Vec<Id> {
    sorted_unique(
        find!(id: Id, pattern!(space, [{ ?id @
            metadata::tag: &KIND_REVIEW_ATTESTATION_ID,
            review::request: &request_id,
            board::by: &reviewer_id,
        }]))
        .collect(),
    )
}

pub fn active_attestation_ids_for_reviewer(
    space: &TribleSet,
    request_id: Id,
    reviewer_id: Id,
) -> Vec<Id> {
    let all = sorted_unique(
        find!(id: Id, pattern!(space, [{ ?id @
            metadata::tag: &KIND_REVIEW_ATTESTATION_ID,
            review::request: &request_id,
            board::by: &reviewer_id,
        }]))
        .collect(),
    );
    let edges = all
        .iter()
        .filter_map(|id| review_attestation(space, *id))
        .filter(|attestation| {
            attestation.is_canonical()
                && attestation.request() == Some(request_id)
                && attestation.reviewer() == Some(reviewer_id)
        })
        .flat_map(|attestation| {
            attestation
                .supersedes
                .into_iter()
                .map(move |old| (attestation.id, old))
        })
        .collect();
    repair_frontier(all, edges)
}

fn attestation_satisfies(
    attestation: &ReviewAttestation,
    request_id: Id,
    reviewer: Id,
    author: Id,
) -> bool {
    if !attestation.is_canonical()
        || attestation.request() != Some(request_id)
        || attestation.reviewer() != Some(reviewer)
        || attestation.reports.len() != 1
        || attestation.created_at.len() != 1
    {
        return false;
    }
    match attestation.verdict() {
        Some(VERDICT_APPROVE) => true,
        Some(VERDICT_ABSTAIN) => reviewer == author,
        _ => false,
    }
}

/// Validate immutable settlement certificates.
///
/// An ordinary certificate is sound only while its named attestations are
/// still the unique active heads for their reviewers. The CLI's CAS loop
/// establishes that condition locally, and this projection repeats it after
/// replicas merge so an offline-concurrent blocker cannot be mistaken for a
/// causally-later comment. Any extra head fails closed and requires an
/// explicit successor request. Authenticity remains cooperative until actors
/// gain signed capabilities.
fn valid_settlements(space: &TribleSet, request: &ReviewRequest) -> Vec<ValidSettlement> {
    let Some(goal) = request.goal() else {
        return Vec::new();
    };
    let Some(author) = request.author() else {
        return Vec::new();
    };
    let mut valid = Vec::new();
    let ids = sorted_unique(
        find!(id: Id, pattern!(space, [{ ?id @ metadata::tag: &KIND_REVIEW_SETTLEMENT_ID }]))
            .collect(),
    );
    for id in ids {
        let Some(settlement) = review_settlement(space, id) else {
            continue;
        };
        let Some(mode) = settlement.canonical_mode() else {
            continue;
        };
        if settlement.requests.as_slice() != [request.id]
            || settlement.tasks.as_slice() != [goal]
        {
            continue;
        }
        if mode == SettlementMode::Attestations
            && settlement.attestations.len() == request.required.len()
            && settlement.actors.as_slice() == [author]
        {
            let mut reviewers = BTreeSet::new();
            let mut all_valid = true;
            for attestation_id in &settlement.attestations {
                let Some(attestation) = review_attestation(space, *attestation_id) else {
                    all_valid = false;
                    break;
                };
                let Some(reviewer) = attestation.reviewer() else {
                    all_valid = false;
                    break;
                };
                if !request.required.contains(&reviewer)
                    || !attestation_satisfies(&attestation, request.id, reviewer, author)
                    || active_attestation_ids_for_reviewer(space, request.id, reviewer)
                        .as_slice()
                        != [*attestation_id]
                    || !reviewers.insert(reviewer)
                {
                    all_valid = false;
                    break;
                }
            }
            if all_valid && reviewers.len() == request.required.len() {
                valid.push(ValidSettlement {
                    id,
                    mode: SettlementMode::Attestations,
                    attestations: settlement.attestations.clone(),
                    override_event: None,
                });
            }
        } else if mode == SettlementMode::Override {
            if let Some(event) = review_override(space, settlement.override_events[0]) {
                if exactly_one(&event.requests) == Some(request.id)
                    && event.actors.len() == 1
                    && settlement.actors == event.actors
                    && request.override_authorities.contains(&event.actors[0])
                    && event.reasons.len() == 1
                    && event.created_at.len() == 1
                    && event.is_canonical()
                {
                    valid.push(ValidSettlement {
                        id,
                        mode: SettlementMode::Override,
                        attestations: Vec::new(),
                        override_event: Some(event.id),
                    });
                }
            }
        }
    }
    valid.sort_by_key(|settlement| settlement.id);
    valid
}

fn settlement_ids_for_request(space: &TribleSet, request_id: Id) -> Vec<Id> {
    sorted_unique(
        find!(id: Id, pattern!(space, [{ ?id @
            metadata::tag: &KIND_REVIEW_SETTLEMENT_ID,
            review::request: &request_id,
        }]))
        .collect(),
    )
}

/// Reject an ordinary successor that reuses any direct predecessor target.
///
/// The successor's target is identity-sealed, while target facts on an older
/// request are append-only. Membership is therefore monotone: once this rule
/// recognizes a same-target transition, no later backpatch can make it look
/// like an ordinary changed-target revision. We deliberately reject even an
/// otherwise identical same-target ordinary successor. Same-target evolution
/// has one explicit protocol, the identity-marked roster transition below.
fn ordinary_same_target_invalid_reasons(
    space: &TribleSet,
    request: &ReviewRequest,
) -> Vec<String> {
    if !request.roster_predecessors.is_empty() {
        return Vec::new();
    }
    let Some(target) = request.target() else {
        return Vec::new();
    };
    let mut reasons = Vec::new();
    for predecessor_id in &request.supersedes {
        if find!(observed: TextHandle, pattern!(space, [{ *predecessor_id @ metadata::iri: ?observed }]))
            .any(|observed| observed == target)
        {
            reasons.push(format!(
                "ordinary successor reuses superseded request {predecessor_id:x}'s exact target and must use the sealed roster_predecessor protocol; same-target ordinary revision and fork repair are deliberately forbidden"
            ));
        }
    }
    reasons
}

/// Validate an identity-marked same-target roster-successor lineage.
///
/// Every marker edge must form one canonical, acyclic, same-target chain. The
/// whole chain remains proof-relevant: a settlement on any ancestor closes
/// later roster migration, and evidence submitted by a reviewer on any
/// ancestor can never be discarded by removing that reviewer farther down the
/// chain. This transitive check prevents add-then-remove laundering and is
/// repeated after replica merges so late ancestor evidence fails closed.
fn roster_successor_invalid_reasons(
    space: &TribleSet,
    request: &ReviewRequest,
    known_people: &HashSet<Id>,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if request.roster_predecessors.is_empty() {
        return ordinary_same_target_invalid_reasons(space, request);
    }

    let mut newest_to_oldest = vec![request.clone()];
    let mut visited = HashSet::from([request.id]);
    let mut cursor = request.clone();
    loop {
        let predecessor_id = match cursor.roster_predecessors.as_slice() {
            [] => break,
            [predecessor] => *predecessor,
            _ => {
                reasons.push(format!(
                    "roster lineage node {:x} must name exactly one sealed roster_predecessor",
                    cursor.id
                ));
                return reasons;
            }
        };
        if cursor.supersedes.as_slice() != [predecessor_id] {
            reasons.push(format!(
                "roster lineage node {:x}'s roster_predecessor must also be its sole supersedes edge",
                cursor.id
            ));
        }
        if !visited.insert(predecessor_id) {
            reasons.push(format!(
                "roster predecessor lineage contains a cycle at {predecessor_id:x}"
            ));
            return reasons;
        }
        if !cursor.is_canonical() {
            reasons.push(format!(
                "roster lineage node {:x} is non-canonical",
                cursor.id
            ));
            return reasons;
        }
        let Some(predecessor) = review_request(space, predecessor_id) else {
            reasons.push(format!(
                "roster predecessor {predecessor_id:x} is missing or not a review request"
            ));
            return reasons;
        };
        if predecessor
            .roster_predecessors
            .iter()
            .any(|older| visited.contains(older))
        {
            reasons.push(format!(
                "roster predecessor lineage contains a cycle through {predecessor_id:x}"
            ));
            return reasons;
        }
        if !predecessor.is_canonical() {
            reasons.push(format!(
                "roster predecessor {predecessor_id:x} is non-canonical"
            ));
            return reasons;
        }
        newest_to_oldest.push(predecessor.clone());
        cursor = predecessor;
    }

    if let Some(root) = newest_to_oldest.last() {
        reasons.extend(
            ordinary_same_target_invalid_reasons(space, root)
                .into_iter()
                .map(|reason| format!("invalid roster-lineage root {:x}: {reason}", root.id)),
        );
    }

    newest_to_oldest.reverse();
    let lineage = newest_to_oldest;
    for node in &lineage {
        let Some(author) = node.author() else {
            reasons.push(format!(
                "roster lineage node {:x} does not seal exactly one author",
                node.id
            ));
            continue;
        };
        if !node.required.contains(&author)
            || !node.required.iter().any(|reviewer| *reviewer != author)
        {
            reasons.push(format!(
                "roster lineage node {:x} has an invalid frozen roster",
                node.id
            ));
        }
        if node.override_authorities.len() > 1 || node.override_authorities.contains(&author) {
            reasons.push(format!(
                "roster lineage node {:x} has an invalid frozen override authority",
                node.id
            ));
        }
        if node
            .required
            .iter()
            .chain(node.override_authorities.iter())
            .any(|person| !known_people.contains(person))
        {
            reasons.push(format!(
                "roster lineage node {:x} contains unknown frozen people",
                node.id
            ));
        }
    }

    for edge in lineage.windows(2) {
        let predecessor = &edge[0];
        let successor = &edge[1];
        if successor.roster_predecessors.as_slice() != [predecessor.id]
            || successor.supersedes.as_slice() != [predecessor.id]
        {
            reasons.push(format!(
                "roster lineage edge {:x} -> {:x} is not identity-sealed",
                predecessor.id, successor.id
            ));
        }
        if predecessor.goal() != successor.goal() {
            reasons.push(format!(
                "roster successor {:x} must preserve predecessor {:x}'s exact goal",
                successor.id, predecessor.id
            ));
        }
        if predecessor.target() != successor.target() {
            reasons.push(format!(
                "roster successor {:x} must preserve predecessor {:x}'s exact target",
                successor.id, predecessor.id
            ));
        }
        if predecessor.author() != successor.author() {
            reasons.push(format!(
                "roster successor must preserve author across predecessor {:x} -> successor {:x}",
                predecessor.id, successor.id
            ));
        }
        if predecessor.override_authorities != successor.override_authorities {
            reasons.push(format!(
                "roster successor {:x} must preserve predecessor {:x}'s override authority",
                successor.id, predecessor.id
            ));
        }
        if predecessor.required == successor.required {
            reasons.push(format!(
                "roster successor {:x} must actually change predecessor {:x}'s frozen roster",
                successor.id, predecessor.id
            ));
        }
    }

    for ancestor in lineage.iter().take(lineage.len().saturating_sub(1)) {
        let settlements = settlement_ids_for_request(space, ancestor.id);
        if !settlements.is_empty() {
            reasons.push(format!(
                "roster successor requires unsettled predecessor history, but ancestor {:x} has {} settlement record(s)",
                ancestor.id,
                settlements.len()
            ));
        }
    }

    for successor_index in 1..lineage.len() {
        let successor = &lineage[successor_index];
        for ancestor in &lineage[..successor_index] {
            for removed in ancestor
                .required
                .iter()
                .filter(|reviewer| !successor.required.contains(reviewer))
            {
                let evidence = all_attestation_ids_for_reviewer(space, ancestor.id, *removed);
                if !evidence.is_empty() {
                    reasons.push(format!(
                        "roster successor removes reviewer {removed:x} at {:x}, but ancestor {:x} has {} submitted attestation record(s) by the reviewer",
                        successor.id,
                        ancestor.id,
                        evidence.len()
                    ));
                }
            }
        }
    }
    reasons
}

fn status_event_is_predecessor_of_request(
    space: &TribleSet,
    event: Id,
    request: &ReviewRequest,
) -> bool {
    let target = review_settlement(space, event)
        .and_then(|settlement| exactly_one(&settlement.requests))
        .unwrap_or(event);
    let goal = request.goal();
    let mut stack = request.supersedes.clone();
    let mut visited = HashSet::new();
    while let Some(predecessor) = stack.pop() {
        if predecessor == target {
            return true;
        }
        if !visited.insert(predecessor) {
            continue;
        }
        // Only a canonical predecessor may carry the walk farther back. The
        // current request's canonical edge still explicitly dominates the
        // predecessor id itself, even if that older entity was later
        // backpatched and can no longer authorize edges of its own.
        if let Some(older) = review_request(space, predecessor)
            .filter(|older| older.is_canonical() && older.goal() == goal)
        {
            stack.extend(older.supersedes);
        }
    }
    false
}

/// Evaluate one exact request against the frozen reviewer roster.
///
/// `known_people` contains every person in the relations snapshot, including
/// soft-retired identities. Retirement prevents future assignments but must
/// not retroactively invalidate a frozen roster or its historical evidence.
/// Keeping it explicit makes the projection deterministic for one pair of
/// Compass/Relations snapshots and avoids consulting mutable group membership.
/// Frozen-roster evaluation: uses the request's sealed `required`. Used by
/// tests and any caller without a relations snapshot at hand.
pub fn evaluate_request(
    space: &TribleSet,
    request_id: Id,
    known_people: &HashSet<Id>,
) -> Option<ReviewEvaluation> {
    evaluate_request_inner(space, request_id, known_people, None)
}

/// Live-roster evaluation: when the request records a `review::group` anchor,
/// resolves that group's CURRENT head members from `relations_space` as the
/// effective roster, so removing a member unblocks the request with no
/// supersede-for-reroster. Falls back to the frozen roster otherwise.
pub fn evaluate_request_live(
    space: &TribleSet,
    request_id: Id,
    known_people: &HashSet<Id>,
    relations_space: &TribleSet,
) -> Option<ReviewEvaluation> {
    evaluate_request_inner(space, request_id, known_people, Some(relations_space))
}

fn evaluate_request_inner(
    space: &TribleSet,
    request_id: Id,
    known_people: &HashSet<Id>,
    relations_space: Option<&TribleSet>,
) -> Option<ReviewEvaluation> {
    let request = review_request(space, request_id)?;
    // Identity + supersede-protocol checks use the FROZEN sealed roster.
    let canonical_ok = request.is_canonical();
    let roster_reasons = roster_successor_invalid_reasons(space, &request, known_people);
    // Level B live roster: if the request records a group anchor AND a relations
    // snapshot is supplied, resolve that group's CURRENT head members as the
    // effective roster; otherwise keep the frozen `required`.
    let mut request = request;
    if let (Some(relations_space), Some(group)) = (relations_space, request.group()) {
        request.required =
            sorted_unique(head_members(relations_space, group).into_iter().collect());
    }
    let settlements = valid_settlements(space, &request);
    let mut invalid = Vec::new();
    if !request.tags.contains(&KIND_STATUS_ID)
        || request.statuses.as_slice() != [REVIEW_STATUS]
    {
        invalid.push("request must also be the goal's review status event".to_string());
    }
    if request.goals.len() != 1 {
        invalid.push("request must name exactly one goal".to_string());
    }
    if request.authors.len() != 1 {
        invalid.push("request must name exactly one author".to_string());
    }
    if request.targets.len() != 1 {
        invalid.push("request must bind exactly one immutable target".to_string());
    }
    if request.created_at.len() != 1 {
        invalid.push("request must have exactly one creation time".to_string());
    }
    if !canonical_ok {
        invalid.push("request id does not seal its proof-defining fields".to_string());
    }
    invalid.extend(roster_reasons);
    if let Some(goal) = request.goal() {
        if !exists!(pattern!(space, [{ goal @ metadata::tag: &KIND_GOAL_ID }])) {
            invalid.push("request must name an entity tagged as a goal".to_string());
        }
    }
    if let Some(author) = request.author() {
        if !request.required.contains(&author) {
            invalid.push("review roster must include the author".to_string());
        }
        if !request.required.iter().any(|reviewer| *reviewer != author) {
            invalid.push(
                "review roster must include at least one distinct non-author reviewer".to_string(),
            );
        }
        if request.override_authorities.contains(&author) {
            invalid.push("review author cannot be their own break-glass authority".to_string());
        }
    }
    if request.override_authorities.len() > 1 {
        invalid.push("review may freeze at most one break-glass authority".to_string());
    }
    let unknown: Vec<Id> = request
        .required
        .iter()
        .copied()
        .filter(|id| !known_people.contains(id))
        .collect();
    if !unknown.is_empty() {
        invalid.push(format!(
            "review roster contains {} unknown people",
            unknown.len()
        ));
    }
    let invalid_authorities = request
        .override_authorities
        .iter()
        .filter(|id| !known_people.contains(*id))
        .count();
    if invalid_authorities != 0 {
        invalid.push(format!(
            "override roster contains {invalid_authorities} unknown people"
        ));
    }
    if settlements.is_empty() {
        if !settlement_ids_for_request(space, request.id).is_empty() {
            invalid.push(
                "request has an invalid or conflicted settlement proof; sealed evidence may no longer be the unique active frontier"
                    .to_string(),
            );
        }
        if let Some(goal) = request.goal() {
            let bound = latest_status_event(space, goal).is_some_and(|(event, status, _)| {
                (event == request.id && status == REVIEW_STATUS)
                    || status_event_is_predecessor_of_request(space, event, &request)
            });
            if !bound {
                invalid.push(
                    "request is not the goal's current exact review status event".to_string(),
                );
            }
        }
    }

    let mut slots = Vec::new();
    for reviewer in &request.required {
        let heads = active_attestation_ids_for_reviewer(space, request.id, *reviewer)
            .into_iter()
            .filter_map(|id| review_attestation(space, id))
            .collect();
        slots.push(ReviewerSlot {
            reviewer: *reviewer,
            heads,
        });
    }

    let state = if !invalid.is_empty() {
        ReviewGateState::Invalid { reasons: invalid }
    } else if !settlements.is_empty() {
        ReviewGateState::Settled { settlements }
    } else {
        let author = request.author().expect("validated above");
        let mut submitted = 0;
        let mut blocked = Vec::new();
        for slot in &slots {
            match slot.heads.as_slice() {
                [] => {}
                [head] => {
                    submitted += 1;
                    if !head.is_canonical()
                        || head.request() != Some(request.id)
                        || head.reviewer() != Some(slot.reviewer)
                        || head.created_at.len() != 1
                        || head.reports.len() != 1
                    {
                        blocked.push(format!("malformed attestation by {:x}", slot.reviewer));
                        continue;
                    }
                    match head.verdict() {
                        Some(VERDICT_APPROVE) => {}
                        Some(VERDICT_ABSTAIN) if slot.reviewer == author => {}
                        Some(VERDICT_ABSTAIN) => {
                            blocked.push(format!("non-author {:x} abstained", slot.reviewer))
                        }
                        Some(VERDICT_REQUEST_CHANGES) => {
                            blocked.push(format!("{:x} requested changes", slot.reviewer))
                        }
                        Some(other) => blocked.push(format!(
                            "{:x} supplied unknown verdict '{other}'",
                            slot.reviewer
                        )),
                        None => blocked
                            .push(format!("{:x} supplied a malformed verdict", slot.reviewer)),
                    }
                }
                heads => blocked.push(format!(
                    "{:x} has {} concurrent attestation heads",
                    slot.reviewer,
                    heads.len()
                )),
            }
        }
        if !blocked.is_empty() {
            ReviewGateState::Blocked {
                submitted,
                reasons: blocked,
            }
        } else if submitted < request.required.len() {
            ReviewGateState::Pending {
                submitted,
                required: request.required.len(),
            }
        } else {
            ReviewGateState::Ready
        }
    };

    Some(ReviewEvaluation {
        request,
        slots,
        state,
    })
}

pub fn evaluate_goal(
    space: &TribleSet,
    goal_id: Id,
    known_people: &HashSet<Id>,
) -> ReviewProjection {
    match active_request_ids_for_goal(space, goal_id).as_slice() {
        [] => ReviewProjection::Unbound,
        [request_id] => evaluate_request_inner(space, *request_id, known_people, None)
            .map(ReviewProjection::Bound)
            .unwrap_or(ReviewProjection::Unbound),
        request_ids => ReviewProjection::Forked {
            request_ids: request_ids.to_vec(),
        },
    }
}

/// Outstanding exact review request heads for one persona. This is the
/// derived assignment surface consumed by Orient: no notification event is
/// written separately. A request remains outstanding when the reviewer has
/// no attestation head, has a fork to heal, or supplied malformed evidence.
pub fn outstanding_review_requests(
    space: &TribleSet,
    known_people: &HashSet<Id>,
    reviewer_id: Id,
) -> Vec<(Id, Id)> {
    let mut obligations = Vec::new();
    let goals = sorted_unique(
        find!(goal: Id, pattern!(space, [{ ?goal @ metadata::tag: &KIND_GOAL_ID }])).collect(),
    );
    for goal in goals {
        let ReviewProjection::Bound(evaluation) = evaluate_goal(space, goal, known_people) else {
            continue;
        };
        if matches!(
            evaluation.state,
            ReviewGateState::Invalid { .. } | ReviewGateState::Settled { .. }
        ) || !evaluation.request.required.contains(&reviewer_id)
        {
            continue;
        }
        let request_id = evaluation.request.id;
        let slot = evaluation
            .slots
            .iter()
            .find(|slot| slot.reviewer == reviewer_id);
        let fulfilled = slot.is_some_and(|slot| slot.is_fulfilled(request_id));
        if !fulfilled {
            obligations.push((goal, request_id));
        }
    }
    obligations.sort();
    obligations
}

#[cfg(test)]
mod tests {
    use super::*;
    use hifitime::Epoch;

    fn now() -> IntervalValue {
        let epoch = Epoch::from_gregorian_utc(2026, 7, 13, 12, 0, 0, 0);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn later() -> IntervalValue {
        let epoch = Epoch::from_gregorian_utc(2026, 7, 13, 12, 1, 0, 0);
        (epoch, epoch).try_to_inline().unwrap()
    }

    fn add_request(
        space: &mut TribleSet,
        goal: Id,
        author: Id,
        required: &[Id],
        authorities: &[Id],
        supersedes: &[Id],
        target: &str,
    ) -> Id {
        let target_handle = target.to_string().to_blob().get_handle();
        let fragment = review_request_fragment(
            goal,
            author,
            target_handle,
            required,
            authorities,
            supersedes,
            now(),
        );
        let id = fragment.root().expect("intrinsic review request");
        *space += fragment;
        id
    }

    fn add_roster_successor(
        space: &mut TribleSet,
        goal: Id,
        author: Id,
        required: &[Id],
        authorities: &[Id],
        predecessor: Id,
        target: &str,
    ) -> Id {
        let target_handle = target.to_string().to_blob().get_handle();
        let fragment = review_roster_successor_fragment(
            goal,
            author,
            target_handle,
            required,
            authorities,
            predecessor,
            now(),
        );
        let id = fragment.root().expect("intrinsic roster successor");
        *space += fragment;
        id
    }

    fn add_attestation(
        space: &mut TribleSet,
        request: Id,
        reviewer: Id,
        verdict: &str,
        supersedes: &[Id],
    ) -> Id {
        let report = format!("review report from {reviewer:x}")
            .to_blob()
            .get_handle();
        let fragment = review_attestation_fragment(
            request,
            reviewer,
            verdict,
            report,
            supersedes,
            now(),
        );
        let id = fragment.root().expect("intrinsic review attestation");
        *space += fragment;
        id
    }

    fn settle_request(
        space: &mut TribleSet,
        goal: Id,
        request: Id,
        author: Id,
        required: &[Id],
    ) -> Id {
        let evidence = required
            .iter()
            .map(|reviewer| {
                let verdict = if *reviewer == author {
                    VERDICT_ABSTAIN
                } else {
                    VERDICT_APPROVE
                };
                add_attestation(space, request, *reviewer, verdict, &[])
            })
            .collect::<Vec<_>>();
        let fragment =
            review_attestation_settlement_fragment(request, goal, author, &evidence, now());
        let id = fragment.root().expect("intrinsic review settlement");
        *space += fragment;
        id
    }

    fn fixture_with_reviewers<const N: usize>() -> (TribleSet, Id, [Id; N], Id, HashSet<Id>) {
        let mut space = TribleSet::new();
        let goal = ufoid().id;
        let reviewers = std::array::from_fn(|_| ufoid().id);
        let authority = ufoid().id;
        let active = reviewers
            .iter()
            .copied()
            .chain(std::iter::once(authority))
            .collect();
        space += entity! { ExclusiveId::force_ref(&goal) @
            metadata::tag: &KIND_GOAL_ID,
        };
        (space, goal, reviewers, authority, active)
    }

    fn fixture() -> (TribleSet, Id, [Id; 3], Id, HashSet<Id>) {
        fixture_with_reviewers()
    }

    fn pair_fixture() -> (TribleSet, Id, [Id; 2], Id, HashSet<Id>) {
        fixture_with_reviewers()
    }

    #[test]
    fn live_group_roster_resolves_current_members_not_the_frozen_snapshot() {
        use crate::schemas::relations::{group as rel_group, KIND_GROUP as REL_KIND_GROUP};
        let (mut space, goal, reviewers, authority, known) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:live-roster",
        );
        // Record a live-roster group anchor on the request (extra fact, so it
        // does not disturb the sealed identity).
        let group = ufoid().id;
        space += entity! { ExclusiveId::force_ref(&request) @ review::group: &group };

        // Frozen path: the sealed roster is all three reviewers.
        let frozen = evaluate_request(&space, request, &known).unwrap();
        assert_eq!(frozen.request.required, sorted_unique(reviewers.to_vec()));

        // Relations snapshot: the group's head lists only the first two
        // reviewers (the third was removed from the group).
        let snapshot = ufoid().id;
        let mut relations_space = TribleSet::new();
        relations_space +=
            entity! { ExclusiveId::force_ref(&group) @ metadata::tag: &REL_KIND_GROUP };
        relations_space += entity! { ExclusiveId::force_ref(&snapshot) @
            rel_group::snapshot_of: &group,
            rel_group::member: reviewers[0],
            rel_group::member: reviewers[1],
        };

        // Live path: the effective roster is the group's CURRENT head = {r0, r1}.
        let live = evaluate_request_live(&space, request, &known, &relations_space).unwrap();
        assert_eq!(
            live.request.required,
            sorted_unique(vec![reviewers[0], reviewers[1]])
        );
        assert!(!live.request.required.contains(&reviewers[2]));
    }

    #[test]
    fn pair_author_abstain_and_independent_approval_is_exact_and_settleable() {
        let (mut space, goal, reviewers, authority, known) = pair_fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:pair",
        );

        for reviewer in reviewers {
            assert_eq!(
                outstanding_review_requests(&space, &known, reviewer),
                vec![(goal, request)]
            );
        }

        let author_evidence = add_attestation(
            &mut space,
            request,
            reviewers[0],
            VERDICT_ABSTAIN,
            &[],
        );
        assert!(matches!(
            evaluate_request(&space, request, &known).unwrap().state,
            ReviewGateState::Pending {
                submitted: 1,
                required: 2
            }
        ));
        assert!(outstanding_review_requests(&space, &known, reviewers[0]).is_empty());
        assert_eq!(
            outstanding_review_requests(&space, &known, reviewers[1]),
            vec![(goal, request)]
        );

        let peer_evidence = add_attestation(
            &mut space,
            request,
            reviewers[1],
            VERDICT_APPROVE,
            &[],
        );
        assert!(matches!(
            evaluate_request(&space, request, &known).unwrap().state,
            ReviewGateState::Ready
        ));
        assert!(outstanding_review_requests(&space, &known, reviewers[1]).is_empty());

        let settlement = review_attestation_settlement_fragment(
            request,
            goal,
            reviewers[0],
            &[author_evidence, peer_evidence],
            now(),
        );
        let settlement_id = settlement.root().expect("intrinsic pair settlement");
        space += settlement;
        match evaluate_request(&space, request, &known).unwrap().state {
            ReviewGateState::Settled { settlements } => {
                assert_eq!(settlements.len(), 1);
                assert_eq!(settlements[0].id, settlement_id);
                assert_eq!(settlements[0].attestations.len(), 2);
            }
            other => panic!("expected pair settlement, got {other:?}"),
        }
    }

    #[test]
    fn pair_change_request_and_unknown_reject_both_block() {
        let (mut space, goal, reviewers, authority, known) = pair_fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:pair-blocked",
        );
        add_attestation(
            &mut space,
            request,
            reviewers[0],
            VERDICT_ABSTAIN,
            &[],
        );
        let blocker = add_attestation(
            &mut space,
            request,
            reviewers[1],
            VERDICT_REQUEST_CHANGES,
            &[],
        );
        assert!(matches!(
            evaluate_request(&space, request, &known).unwrap().state,
            ReviewGateState::Blocked { submitted: 2, .. }
        ));

        add_attestation(
            &mut space,
            request,
            reviewers[1],
            "reject",
            &[blocker],
        );
        match evaluate_request(&space, request, &known).unwrap().state {
            ReviewGateState::Blocked { submitted, reasons } => {
                assert_eq!(submitted, 2);
                assert!(reasons.iter().any(|reason| reason.contains("unknown verdict 'reject'")));
            }
            other => panic!("expected unknown rejection to fail closed, got {other:?}"),
        }
    }

    #[test]
    fn author_only_empty_and_missing_author_rosters_are_invalid() {
        let (mut one_space, one_goal, one_reviewer, one_authority, one_known) =
            fixture_with_reviewers::<1>();
        let one_request = add_request(
            &mut one_space,
            one_goal,
            one_reviewer[0],
            &one_reviewer,
            &[one_authority],
            &[],
            "urn:revision:one-reviewer",
        );
        match evaluate_request(&one_space, one_request, &one_known)
            .unwrap()
            .state
        {
            ReviewGateState::Invalid { reasons } => assert!(reasons
                .iter()
                .any(|reason| reason.contains("at least one distinct non-author"))),
            other => panic!("expected author-only roster to be invalid, got {other:?}"),
        }

        let (mut empty_space, empty_goal, empty_people, empty_authority, mut empty_known) =
            fixture_with_reviewers::<0>();
        let empty_author = ufoid().id;
        empty_known.insert(empty_author);
        let empty_request = add_request(
            &mut empty_space,
            empty_goal,
            empty_author,
            &empty_people,
            &[empty_authority],
            &[],
            "urn:revision:empty-roster",
        );
        assert!(matches!(
            evaluate_request(&empty_space, empty_request, &empty_known)
                .unwrap()
                .state,
            ReviewGateState::Invalid { .. }
        ));

        let (mut missing_space, missing_goal, required, missing_authority, mut missing_known) =
            fixture_with_reviewers::<2>();
        let missing_author = ufoid().id;
        missing_known.insert(missing_author);
        let missing_request = add_request(
            &mut missing_space,
            missing_goal,
            missing_author,
            &required,
            &[missing_authority],
            &[],
            "urn:revision:missing-author",
        );
        match evaluate_request(&missing_space, missing_request, &missing_known)
            .unwrap()
            .state
        {
            ReviewGateState::Invalid { reasons } => assert!(reasons
                .iter()
                .any(|reason| reason.contains("must include the author"))),
            other => panic!("expected missing-author roster to be invalid, got {other:?}"),
        }
    }

    #[test]
    fn five_person_council_remains_all_required() {
        let (mut space, goal, reviewers, authority, known) = fixture_with_reviewers::<5>();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:five-reviewers",
        );
        add_attestation(
            &mut space,
            request,
            reviewers[0],
            VERDICT_ABSTAIN,
            &[],
        );
        for reviewer in &reviewers[1..4] {
            add_attestation(&mut space, request, *reviewer, VERDICT_APPROVE, &[]);
        }
        assert!(matches!(
            evaluate_request(&space, request, &known).unwrap().state,
            ReviewGateState::Pending {
                submitted: 4,
                required: 5
            }
        ));

        add_attestation(
            &mut space,
            request,
            reviewers[4],
            VERDICT_APPROVE,
            &[],
        );
        assert!(matches!(
            evaluate_request(&space, request, &known).unwrap().state,
            ReviewGateState::Ready
        ));
    }

    #[test]
    fn author_may_abstain_when_both_peers_approve() {
        let (mut space, goal, reviewers, authority, active) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "git+https://example.test/repo@1111111111111111111111111111111111111111",
        );
        add_attestation(
            &mut space,
            request,
            reviewers[0],
            VERDICT_ABSTAIN,
            &[],
        );
        add_attestation(
            &mut space,
            request,
            reviewers[1],
            VERDICT_APPROVE,
            &[],
        );
        assert!(matches!(
            evaluate_request(&space, request, &active).unwrap().state,
            ReviewGateState::Pending {
                submitted: 2,
                required: 3
            }
        ));
        add_attestation(
            &mut space,
            request,
            reviewers[2],
            VERDICT_APPROVE,
            &[],
        );

        assert!(matches!(
            evaluate_request(&space, request, &active).unwrap().state,
            ReviewGateState::Ready
        ));
    }

    #[test]
    fn superseding_a_blocker_repairs_the_gate_monotonically() {
        let (mut space, goal, reviewers, authority, active) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:blake3:first",
        );
        let blocker = add_attestation(
            &mut space,
            request,
            reviewers[0],
            VERDICT_REQUEST_CHANGES,
            &[],
        );
        for reviewer in &reviewers[1..] {
            add_attestation(
                &mut space,
                request,
                *reviewer,
                VERDICT_APPROVE,
                &[],
            );
        }
        assert!(matches!(
            evaluate_request(&space, request, &active).unwrap().state,
            ReviewGateState::Blocked { .. }
        ));

        add_attestation(
            &mut space,
            request,
            reviewers[0],
            VERDICT_APPROVE,
            &[blocker],
        );
        assert!(matches!(
            evaluate_request(&space, request, &active).unwrap().state,
            ReviewGateState::Ready
        ));
    }

    #[test]
    fn concurrent_request_successors_are_a_visible_closed_fork() {
        let (mut space, goal, reviewers, authority, active) = fixture();
        let base = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:base",
        );
        let left = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[base],
            "urn:revision:left",
        );
        let right = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[base],
            "urn:revision:right",
        );

        match evaluate_goal(&space, goal, &active) {
            ReviewProjection::Forked { request_ids } => {
                assert_eq!(request_ids.len(), 2);
                assert!(request_ids.contains(&left));
                assert!(request_ids.contains(&right));
            }
            other => panic!("expected request fork, got {other:?}"),
        }
    }

    #[test]
    fn successor_revision_does_not_inherit_old_attestations_and_reassigns() {
        let (mut space, goal, reviewers, authority, active) = fixture();
        let first = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:first",
        );
        for reviewer in reviewers {
            add_attestation(
                &mut space,
                first,
                reviewer,
                VERDICT_APPROVE,
                &[],
            );
        }
        let second = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[first],
            "urn:revision:second",
        );

        assert_eq!(active_request_ids_for_goal(&space, goal), vec![second]);
        assert!(matches!(
            evaluate_request(&space, second, &active).unwrap().state,
            ReviewGateState::Pending {
                submitted: 0,
                required: 3
            }
        ));
        for reviewer in reviewers {
            assert_eq!(
                outstanding_review_requests(&space, &active, reviewer),
                vec![(goal, second)]
            );
        }
    }

    #[test]
    fn late_old_attestation_invalidates_same_target_roster_successor() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let target = "urn:revision:same-target-roster";
        let predecessor = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            target,
        );
        let successor = add_roster_successor(
            &mut space,
            goal,
            reviewers[0],
            &reviewers[..2],
            &[authority],
            predecessor,
            target,
        );
        let evidence = [
            add_attestation(
                &mut space,
                successor,
                reviewers[0],
                VERDICT_ABSTAIN,
                &[],
            ),
            add_attestation(
                &mut space,
                successor,
                reviewers[1],
                VERDICT_APPROVE,
                &[],
            ),
        ];
        space += review_attestation_settlement_fragment(
            successor,
            goal,
            reviewers[0],
            &evidence,
            now(),
        );
        assert!(matches!(
            evaluate_request(&space, successor, &known).unwrap().state,
            ReviewGateState::Settled { .. }
        ));

        let late = add_attestation(
            &mut space,
            predecessor,
            reviewers[2],
            VERDICT_APPROVE,
            &[],
        );
        assert_eq!(
            all_attestation_ids_for_reviewer(&space, predecessor, reviewers[2]),
            vec![late]
        );
        match evaluate_request(&space, successor, &known).unwrap().state {
            ReviewGateState::Invalid { reasons } => assert!(reasons
                .iter()
                .any(|reason| reason.contains("roster successor removes reviewer"))),
            other => panic!("late predecessor evidence must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn late_old_override_settlement_invalidates_same_target_roster_successor() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let target = "urn:revision:same-target-late-override";
        let predecessor = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            target,
        );
        let successor = add_roster_successor(
            &mut space,
            goal,
            reviewers[0],
            &reviewers[..2],
            &[authority],
            predecessor,
            target,
        );
        assert!(matches!(
            evaluate_request(&space, successor, &known).unwrap().state,
            ReviewGateState::Pending {
                submitted: 0,
                required: 2
            }
        ));

        let reason = "offline override".to_string().to_blob().get_handle();
        let override_event = review_override_fragment(predecessor, authority, reason, now());
        let override_id = override_event.root().expect("intrinsic override fixture");
        space += override_event;
        space += review_override_settlement_fragment(
            predecessor,
            goal,
            authority,
            override_id,
            now(),
        );
        match evaluate_request(&space, successor, &known).unwrap().state {
            ReviewGateState::Invalid { reasons } => assert!(reasons
                .iter()
                .any(|reason| reason.contains("requires unsettled predecessor"))),
            other => panic!("late predecessor settlement must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn transitive_add_then_remove_cannot_launder_ancestor_dissent() {
        let (mut space, goal, reviewers, authority, known) = fixture_with_reviewers::<4>();
        let target = "urn:revision:transitive-roster-dissent";
        let grandparent = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers[..3],
            &[authority],
            &[],
            target,
        );
        add_attestation(
            &mut space,
            grandparent,
            reviewers[2],
            VERDICT_REQUEST_CHANGES,
            &[],
        );
        let parent = add_roster_successor(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            grandparent,
            target,
        );
        let successor_roster = [reviewers[0], reviewers[1], reviewers[3]];
        let successor = add_roster_successor(
            &mut space,
            goal,
            reviewers[0],
            &successor_roster,
            &[authority],
            parent,
            target,
        );

        match evaluate_request(&space, successor, &known).unwrap().state {
            ReviewGateState::Invalid { reasons } => assert!(
                reasons.iter().any(|reason| {
                    reason.contains("removes reviewer")
                        && reason.contains(&format!("{:x}", grandparent))
                }),
                "grandparent dissent was not retained: {reasons:?}"
            ),
            other => panic!("transitive reviewer removal must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn late_grandparent_evidence_invalidates_a_settled_roster_descendant() {
        let (mut space, goal, reviewers, authority, known) = fixture_with_reviewers::<4>();
        let target = "urn:revision:late-grandparent-evidence";
        let grandparent = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers[..3],
            &[authority],
            &[],
            target,
        );
        let parent = add_roster_successor(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            grandparent,
            target,
        );
        let successor_roster = [reviewers[0], reviewers[1], reviewers[3]];
        let successor = add_roster_successor(
            &mut space,
            goal,
            reviewers[0],
            &successor_roster,
            &[authority],
            parent,
            target,
        );
        settle_request(
            &mut space,
            goal,
            successor,
            reviewers[0],
            &successor_roster,
        );
        assert!(matches!(
            evaluate_request(&space, successor, &known).unwrap().state,
            ReviewGateState::Settled { .. }
        ));

        add_attestation(
            &mut space,
            grandparent,
            reviewers[2],
            VERDICT_REQUEST_CHANGES,
            &[],
        );
        match evaluate_request(&space, successor, &known).unwrap().state {
            ReviewGateState::Invalid { reasons } => assert!(
                reasons.iter().any(|reason| {
                    reason.contains("removes reviewer")
                        && reason.contains(&format!("{:x}", grandparent))
                }),
                "late grandparent evidence did not invalidate settlement: {reasons:?}"
            ),
            other => panic!("late grandparent evidence must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn late_grandparent_settlement_invalidates_a_settled_roster_descendant() {
        let (mut space, goal, reviewers, authority, known) = fixture_with_reviewers::<4>();
        let target = "urn:revision:late-grandparent-settlement";
        let grandparent = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers[..3],
            &[authority],
            &[],
            target,
        );
        let parent = add_roster_successor(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            grandparent,
            target,
        );
        let successor_roster = [reviewers[0], reviewers[1], reviewers[3]];
        let successor = add_roster_successor(
            &mut space,
            goal,
            reviewers[0],
            &successor_roster,
            &[authority],
            parent,
            target,
        );
        settle_request(
            &mut space,
            goal,
            successor,
            reviewers[0],
            &successor_roster,
        );
        assert!(matches!(
            evaluate_request(&space, successor, &known).unwrap().state,
            ReviewGateState::Settled { .. }
        ));

        let reason = "late grandparent override".to_string().to_blob().get_handle();
        let override_event = review_override_fragment(grandparent, authority, reason, now());
        let override_id = override_event.root().expect("intrinsic override fixture");
        space += override_event;
        space += review_override_settlement_fragment(
            grandparent,
            goal,
            authority,
            override_id,
            now(),
        );
        match evaluate_request(&space, successor, &known).unwrap().state {
            ReviewGateState::Invalid { reasons } => assert!(
                reasons.iter().any(|reason| {
                    reason.contains("unsettled predecessor history")
                        && reason.contains(&format!("{:x}", grandparent))
                }),
                "late grandparent settlement did not invalidate descendant: {reasons:?}"
            ),
            other => panic!("late grandparent settlement must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn same_target_successor_cannot_rewrite_the_frozen_author() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let target = "urn:revision:same-target-author";
        let predecessor = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            target,
        );
        let successor = add_roster_successor(
            &mut space,
            goal,
            reviewers[1],
            &reviewers[1..],
            &[authority],
            predecessor,
            target,
        );

        match evaluate_request(&space, successor, &known).unwrap().state {
            ReviewGateState::Invalid { reasons } => assert!(reasons
                .iter()
                .any(|reason| reason.contains("roster successor must preserve")
                    && reason.contains("author"))),
            other => panic!("same-target author rewrite must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn unmarked_same_target_frozen_field_rewrites_are_monotonically_invalid() {
        for rewrite in ["author", "roster", "override"] {
            let (mut space, goal, reviewers, authority, mut known) = fixture();
            let replacement_authority = ufoid().id;
            known.insert(replacement_authority);
            let target = format!("urn:revision:unmarked-{rewrite}-change");
            let predecessor = add_request(
                &mut space,
                goal,
                reviewers[0],
                &reviewers,
                &[authority],
                &[],
                &target,
            );
            let (author, required, authorities) = match rewrite {
                "author" => (reviewers[1], reviewers[1..].to_vec(), vec![authority]),
                "roster" => (reviewers[0], reviewers[..2].to_vec(), vec![authority]),
                "override" => (reviewers[0], reviewers.to_vec(), vec![replacement_authority]),
                _ => unreachable!(),
            };
            let successor = add_request(
                &mut space,
                goal,
                author,
                &required,
                &authorities,
                &[predecessor],
                &target,
            );

            match evaluate_request(&space, successor, &known).unwrap().state {
                ReviewGateState::Invalid { reasons } => assert!(
                    reasons
                        .iter()
                        .any(|reason| reason.contains("must use the sealed roster_predecessor")),
                    "missing monotone same-target rejection for {rewrite}: {reasons:?}"
                ),
                other => panic!("unmarked {rewrite} rewrite must fail closed, got {other:?}"),
            }

            let injected = format!("urn:revision:unmarked-{rewrite}-backpatch")
                .to_blob()
                .get_handle();
            space += entity! { ExclusiveId::force_ref(&predecessor) @
                metadata::iri: injected,
            };
            match evaluate_request(&space, successor, &known).unwrap().state {
                ReviewGateState::Invalid { reasons } => assert!(
                    reasons
                        .iter()
                        .any(|reason| reason.contains("must use the sealed roster_predecessor")),
                    "predecessor backpatch reopened {rewrite} rewrite: {reasons:?}"
                ),
                other => panic!(
                    "predecessor backpatch must not reopen {rewrite} rewrite, got {other:?}"
                ),
            }
        }
    }

    #[test]
    fn unmarked_same_target_identical_policy_reset_is_invalid() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let target = "urn:revision:unmarked-identical-reset";
        let predecessor = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            target,
        );
        let reset = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[predecessor],
            target,
        );

        match evaluate_request(&space, reset, &known).unwrap().state {
            ReviewGateState::Invalid { reasons } => assert!(reasons
                .iter()
                .any(|reason| reason.contains("same-target ordinary revision"))),
            other => panic!("identical-policy same-target reset must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn roster_marker_fails_closed_for_missing_backpatched_or_different_target_predecessor() {
        {
            let (mut space, goal, reviewers, authority, known) = fixture();
            let missing = ufoid().id;
            let successor = add_roster_successor(
                &mut space,
                goal,
                reviewers[0],
                &reviewers[..2],
                &[authority],
                missing,
                "urn:revision:missing-roster-predecessor",
            );
            match evaluate_request(&space, successor, &known).unwrap().state {
                ReviewGateState::Invalid { reasons } => assert!(reasons
                    .iter()
                    .any(|reason| reason.contains("missing or not a review request"))),
                other => panic!("missing roster predecessor must fail closed, got {other:?}"),
            }
        }

        {
            let (mut space, goal, reviewers, authority, known) = fixture();
            let target = "urn:revision:backpatched-roster-predecessor";
            let predecessor = add_request(
                &mut space,
                goal,
                reviewers[0],
                &reviewers,
                &[authority],
                &[],
                target,
            );
            let successor = add_roster_successor(
                &mut space,
                goal,
                reviewers[0],
                &reviewers[..2],
                &[authority],
                predecessor,
                target,
            );
            let other_target = "urn:revision:injected-target"
                .to_string()
                .to_blob()
                .get_handle();
            space += entity! { ExclusiveId::force_ref(&predecessor) @
                metadata::iri: other_target,
            };
            match evaluate_request(&space, successor, &known).unwrap().state {
                ReviewGateState::Invalid { reasons } => assert!(reasons
                    .iter()
                    .any(|reason| reason.contains("roster predecessor")
                        && reason.contains("non-canonical"))),
                other => panic!("backpatched roster predecessor must fail closed, got {other:?}"),
            }
        }

        {
            let (mut space, goal, reviewers, authority, known) = fixture();
            let predecessor = add_request(
                &mut space,
                goal,
                reviewers[0],
                &reviewers,
                &[authority],
                &[],
                "urn:revision:roster-target-a",
            );
            let successor = add_roster_successor(
                &mut space,
                goal,
                reviewers[0],
                &reviewers[..2],
                &[authority],
                predecessor,
                "urn:revision:roster-target-b",
            );
            match evaluate_request(&space, successor, &known).unwrap().state {
                ReviewGateState::Invalid { reasons } => assert!(reasons
                    .iter()
                    .any(|reason| reason.contains("exact target"))),
                other => panic!("changed-target roster marker must fail closed, got {other:?}"),
            }
        }
    }

    #[test]
    fn roster_predecessor_cycle_fails_closed_before_trusting_backpatched_edges() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let target = "urn:revision:roster-lineage-cycle";
        let predecessor = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            target,
        );
        let successor = add_roster_successor(
            &mut space,
            goal,
            reviewers[0],
            &reviewers[..2],
            &[authority],
            predecessor,
            target,
        );
        space += entity! { ExclusiveId::force_ref(&predecessor) @
            review::supersedes: &successor,
            review::roster_predecessor: &successor,
        };

        match evaluate_request(&space, successor, &known).unwrap().state {
            ReviewGateState::Invalid { reasons } => assert!(
                reasons.iter().any(|reason| reason.contains("cycle")),
                "backpatched roster cycle was not surfaced: {reasons:?}"
            ),
            other => panic!("roster predecessor cycle must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn ordinary_changed_target_successor_tolerates_old_history_backpatch() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let predecessor = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:ordinary-target-a",
        );
        let successor = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[predecessor],
            "urn:revision:ordinary-target-b",
        );
        let injected = "urn:revision:ordinary-old-backpatch"
            .to_string()
            .to_blob()
            .get_handle();
        space += entity! { ExclusiveId::force_ref(&predecessor) @ metadata::iri: injected };

        assert!(matches!(
            evaluate_request(&space, successor, &known).unwrap().state,
            ReviewGateState::Pending {
                submitted: 0,
                required: 3
            }
        ));
    }

    #[test]
    fn concurrent_attestations_fail_closed_until_one_supersedes_both() {
        let (mut space, goal, reviewers, authority, active) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:forked-attestation",
        );
        let left = add_attestation(
            &mut space,
            request,
            reviewers[0],
            VERDICT_APPROVE,
            &[],
        );
        let right = add_attestation(
            &mut space,
            request,
            reviewers[0],
            VERDICT_ABSTAIN,
            &[],
        );
        for reviewer in &reviewers[1..] {
            add_attestation(
                &mut space,
                request,
                *reviewer,
                VERDICT_APPROVE,
                &[],
            );
        }
        assert!(matches!(
            evaluate_request(&space, request, &active).unwrap().state,
            ReviewGateState::Blocked { .. }
        ));

        add_attestation(
            &mut space,
            request,
            reviewers[0],
            VERDICT_ABSTAIN,
            &[left, right],
        );
        assert!(matches!(
            evaluate_request(&space, request, &active).unwrap().state,
            ReviewGateState::Ready
        ));
    }

    #[test]
    fn settlement_records_exact_attestation_evidence() {
        let (mut space, goal, reviewers, authority, active) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:settle",
        );
        let mut evidence = Vec::new();
        for reviewer in reviewers {
            let id = add_attestation(&mut space, request, reviewer, VERDICT_APPROVE, &[]);
            evidence.push(id);
        }
        let fragment = review_attestation_settlement_fragment(
            request,
            goal,
            reviewers[0],
            &evidence,
            now(),
        );
        let settlement = fragment.root().expect("intrinsic review settlement");
        space += fragment;

        match evaluate_request(&space, request, &active).unwrap().state {
            ReviewGateState::Settled { settlements } => {
                assert_eq!(
                    settlements,
                    vec![ValidSettlement {
                        id: settlement,
                        mode: SettlementMode::Attestations,
                        attestations: {
                            let mut ids = evidence.clone();
                            ids.sort();
                            ids
                        },
                        override_event: None,
                    }]
                );
            }
            other => panic!("expected settled state, got {other:?}"),
        }
    }

    #[test]
    fn concurrent_attestation_fork_invalidates_stale_settlement_proof() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:final",
        );
        let evidence: Vec<Id> = reviewers
            .iter()
            .map(|reviewer| {
                add_attestation(&mut space, request, *reviewer, VERDICT_APPROVE, &[])
            })
            .collect();
        let fragment = review_attestation_settlement_fragment(
            request,
            goal,
            reviewers[0],
            &evidence,
            now(),
        );
        let settlement = fragment.root().expect("intrinsic review settlement");
        space += fragment;

        // A flattened fact projection cannot distinguish an offline-
        // concurrent vote from a causally later one. Fail closed instead of
        // letting the certificate hide the new head; a successor request is
        // the explicit repair operation.
        add_attestation(
            &mut space,
            request,
            reviewers[0],
            VERDICT_REQUEST_CHANGES,
            &[],
        );

        assert!(matches!(
            evaluate_request(&space, request, &known).unwrap().state,
            ReviewGateState::Invalid { .. }
        ));
        assert!(settlement_ids_for_request(&space, request).contains(&settlement));
    }

    #[test]
    fn request_backpatch_changes_canonical_root_and_fails_closed() {
        let (mut space, goal, reviewers, authority, mut known) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:sealed-request",
        );
        let injected_authority = ufoid().id;
        known.insert(injected_authority);
        space += entity! { ExclusiveId::force_ref(&request) @
            review::override_authority: &injected_authority,
        };

        match evaluate_request(&space, request, &known).unwrap().state {
            ReviewGateState::Invalid { reasons } => assert!(reasons
                .iter()
                .any(|reason| reason.contains("does not seal"))),
            other => panic!("expected non-canonical request, got {other:?}"),
        }
    }

    #[test]
    fn attestation_backpatch_changes_canonical_root_and_blocks_gate() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:sealed-attestation",
        );
        let patched = add_attestation(
            &mut space,
            request,
            reviewers[0],
            VERDICT_APPROVE,
            &[],
        );
        for reviewer in &reviewers[1..] {
            add_attestation(&mut space, request, *reviewer, VERDICT_APPROVE, &[]);
        }
        let invented_predecessor = ufoid().id;
        space += entity! { ExclusiveId::force_ref(&patched) @
            review::supersedes: &invented_predecessor,
        };

        assert!(matches!(
            evaluate_request(&space, request, &known).unwrap().state,
            ReviewGateState::Blocked { .. }
        ));
    }

    #[test]
    fn noncanonical_attestation_edge_cannot_hide_a_blocker_or_be_laundered() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:edge-laundering",
        );
        let blocker = add_attestation(
            &mut space,
            request,
            reviewers[0],
            VERDICT_REQUEST_CHANGES,
            &[],
        );
        let patched = add_attestation(
            &mut space,
            request,
            reviewers[0],
            VERDICT_APPROVE,
            &[],
        );
        for reviewer in &reviewers[1..] {
            add_attestation(&mut space, request, *reviewer, VERDICT_APPROVE, &[]);
        }

        // The injected edge changes `patched`'s canonical root. It must not
        // gain authority to hide the blocker.
        space += entity! { ExclusiveId::force_ref(&patched) @
            review::supersedes: &blocker,
        };
        let mut expected = vec![blocker, patched];
        expected.sort();
        assert_eq!(
            active_attestation_ids_for_reviewer(&space, request, reviewers[0]),
            expected
        );

        // A repair based on the formerly-visible malformed head alone cannot
        // launder its untrusted edge into a clean approval chain.
        let repair = add_attestation(
            &mut space,
            request,
            reviewers[0],
            VERDICT_APPROVE,
            &[patched],
        );
        let mut expected = vec![blocker, repair];
        expected.sort();
        assert_eq!(
            active_attestation_ids_for_reviewer(&space, request, reviewers[0]),
            expected
        );
        assert!(matches!(
            evaluate_request(&space, request, &known).unwrap().state,
            ReviewGateState::Blocked { .. }
        ));
    }

    #[test]
    fn noncanonical_request_edge_cannot_hide_a_fork_or_be_laundered() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let first = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:edge-first",
        );
        let patched = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:edge-patched",
        );
        space += entity! { ExclusiveId::force_ref(&patched) @
            review::supersedes: &first,
        };

        let mut expected = vec![first, patched];
        expected.sort();
        assert_eq!(active_request_ids_for_goal(&space, goal), expected);

        let repair = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[patched],
            "urn:revision:edge-repair",
        );
        let mut expected = vec![first, repair];
        expected.sort();
        assert_eq!(active_request_ids_for_goal(&space, goal), expected);
        assert!(matches!(
            evaluate_goal(&space, goal, &known),
            ReviewProjection::Forked { .. }
        ));
    }

    #[test]
    fn stale_approval_cannot_be_named_by_a_settlement_after_a_blocker() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:stale-settlement",
        );
        let approvals: Vec<Id> = reviewers
            .iter()
            .map(|reviewer| {
                add_attestation(&mut space, request, *reviewer, VERDICT_APPROVE, &[])
            })
            .collect();
        add_attestation(
            &mut space,
            request,
            reviewers[0],
            VERDICT_REQUEST_CHANGES,
            &[approvals[0]],
        );
        space += review_attestation_settlement_fragment(
            request,
            goal,
            reviewers[0],
            &approvals,
            now(),
        );

        assert!(matches!(
            evaluate_request(&space, request, &known).unwrap().state,
            ReviewGateState::Invalid { .. }
        ));
    }

    #[test]
    fn settlement_backpatch_is_not_accepted_as_exact_proof() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:sealed-settlement",
        );
        let evidence: Vec<Id> = reviewers
            .iter()
            .map(|reviewer| {
                add_attestation(&mut space, request, *reviewer, VERDICT_APPROVE, &[])
            })
            .collect();
        let fragment = review_attestation_settlement_fragment(
            request,
            goal,
            reviewers[0],
            &evidence,
            now(),
        );
        let settlement = fragment.root().expect("intrinsic review settlement");
        space += fragment;
        let unrelated_request = ufoid().id;
        space += entity! { ExclusiveId::force_ref(&settlement) @
            review::request: &unrelated_request,
        };

        assert!(matches!(
            evaluate_request(&space, request, &known).unwrap().state,
            ReviewGateState::Invalid { .. }
        ));
    }

    #[test]
    fn reasoned_authorized_override_is_distinct_from_approval() {
        let (mut space, goal, reviewers, authority, active) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:override",
        );
        let reason = "JP break-glass reason".to_blob().get_handle();
        let override_fragment = review_override_fragment(request, authority, reason, now());
        let override_id = override_fragment.root().expect("intrinsic review override");
        space += override_fragment;
        let settlement_fragment = review_override_settlement_fragment(
            request,
            goal,
            authority,
            override_id,
            now(),
        );
        let settlement = settlement_fragment
            .root()
            .expect("intrinsic override settlement");
        space += settlement_fragment;

        match evaluate_request(&space, request, &active).unwrap().state {
            ReviewGateState::Settled { settlements } => {
                assert_eq!(settlements[0].mode, SettlementMode::Override);
                assert_eq!(settlements[0].id, settlement);
                assert!(settlements[0].attestations.is_empty());
                assert_eq!(settlements[0].override_event, Some(override_id));
            }
            other => panic!("expected overridden settlement, got {other:?}"),
        }
    }

    #[test]
    fn override_backpatch_invalidates_its_settlement_proof() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:sealed-override",
        );
        let reason = "break-glass reason".to_blob().get_handle();
        let override_fragment = review_override_fragment(request, authority, reason, now());
        let override_id = override_fragment.root().expect("intrinsic review override");
        space += override_fragment;
        space += review_override_settlement_fragment(
            request,
            goal,
            authority,
            override_id,
            now(),
        );
        space += entity! { ExclusiveId::force_ref(&override_id) @
            metadata::tag: &KIND_NOTE_ID,
        };

        assert!(matches!(
            evaluate_request(&space, request, &known).unwrap().state,
            ReviewGateState::Invalid { .. }
        ));
    }

    #[test]
    fn leaving_the_review_status_closes_an_unsettled_gate() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:detached",
        );
        for reviewer in reviewers {
            add_attestation(&mut space, request, reviewer, VERDICT_APPROVE, &[]);
        }
        let moved = ufoid();
        space += entity! { &moved @
            metadata::tag: &KIND_STATUS_ID,
            board::task: &goal,
            board::status: "doing",
            metadata::created_at: later(),
        };

        match evaluate_request(&space, request, &known).unwrap().state {
            ReviewGateState::Invalid { reasons } => assert!(reasons
                .iter()
                .any(|reason| reason.contains("current exact review status"))),
            other => panic!("expected detached request to fail closed, got {other:?}"),
        }
    }

    #[test]
    fn noncanonical_back_edge_does_not_create_a_trusted_cycle() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let first = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:cycle-a",
        );
        let second = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[first],
            "urn:revision:cycle-b",
        );
        space += entity! { ExclusiveId::force_ref(&first) @
            review::supersedes: &second,
        };

        // `second` is a canonical successor of `first`; the injected reverse
        // edge makes `first` noncanonical and therefore cannot manufacture a
        // trusted cycle or hide `second`.
        assert_eq!(active_request_ids_for_goal(&space, goal), vec![second]);

        let repaired = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[second],
            "urn:revision:cycle-repaired",
        );
        assert_eq!(active_request_ids_for_goal(&space, goal), vec![repaired]);
        assert!(matches!(
            evaluate_request(&space, repaired, &known).unwrap().state,
            ReviewGateState::Pending { .. }
        ));
    }

    #[test]
    fn malformed_verdict_remains_a_reviewer_obligation() {
        let (mut space, goal, reviewers, authority, known) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:unknown-verdict",
        );
        add_attestation(&mut space, request, reviewers[1], "shrug", &[]);

        assert!(matches!(
            evaluate_request(&space, request, &known).unwrap().state,
            ReviewGateState::Blocked { .. }
        ));
        assert_eq!(
            outstanding_review_requests(&space, &known, reviewers[1]),
            vec![(goal, request)]
        );
    }

    #[test]
    fn author_cannot_be_their_own_break_glass_authority() {
        let (mut space, goal, reviewers, _authority, known) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[reviewers[0]],
            &[],
            "urn:revision:self-override",
        );
        assert!(matches!(
            evaluate_request(&space, request, &known).unwrap().state,
            ReviewGateState::Invalid { .. }
        ));
    }

    /// A settlement cannot substitute an out-of-roster reviewer's approval for a
    /// missing roster member: `valid_settlements` rejects evidence whose reviewer
    /// is not in the frozen roster (the `required.contains` guard), even though
    /// that outsider's attestation is individually the unique active head for
    /// themselves. Evidence membership is not roster membership; a present-but-
    /// invalid settlement fails closed.
    #[test]
    fn settlement_evidence_from_a_non_roster_reviewer_fails_closed() {
        let (mut space, goal, reviewers, authority, active) = fixture();
        let outsider = ufoid().id;
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:outsider-evidence",
        );
        // Two genuine roster approvals; reviewers[2] never attests. The forged
        // settlement tries to stand an outsider's approval in for the third slot.
        let evidence = vec![
            add_attestation(&mut space, request, reviewers[0], VERDICT_APPROVE, &[]),
            add_attestation(&mut space, request, reviewers[1], VERDICT_APPROVE, &[]),
            add_attestation(&mut space, request, outsider, VERDICT_APPROVE, &[]),
        ];
        let fragment =
            review_attestation_settlement_fragment(request, goal, reviewers[0], &evidence, now());
        space += fragment;
        assert!(matches!(
            evaluate_request(&space, request, &active).unwrap().state,
            ReviewGateState::Invalid { .. }
        ));
    }

    /// The roster is frozen at request creation, so `evaluate_request` must be
    /// given a `known_people` snapshot that still includes soft-retired members.
    /// If a roster member is absent from that snapshot the gate fails closed —
    /// an incomplete snapshot cannot silently drop a required reviewer — while a
    /// complete snapshot over the same space settles.
    #[test]
    fn roster_member_missing_from_known_people_fails_closed() {
        let (mut space, goal, reviewers, authority, _active) = fixture();
        let request = add_request(
            &mut space,
            goal,
            reviewers[0],
            &reviewers,
            &[authority],
            &[],
            "urn:revision:retired-reviewer",
        );
        for reviewer in reviewers {
            add_attestation(&mut space, request, reviewer, VERDICT_APPROVE, &[]);
        }
        // A snapshot that dropped reviewers[2] (e.g. a caller that forgot to
        // include soft-retired members): the frozen roster now has an "unknown"
        // member and the gate refuses rather than settling.
        let incomplete: HashSet<Id> =
            [reviewers[0], reviewers[1], authority].into_iter().collect();
        assert!(matches!(
            evaluate_request(&space, request, &incomplete).unwrap().state,
            ReviewGateState::Invalid { .. }
        ));
        // Sanity: a complete snapshot over the identical space is Ready.
        let complete: HashSet<Id> = reviewers
            .into_iter()
            .chain(std::iter::once(authority))
            .collect();
        assert!(matches!(
            evaluate_request(&space, request, &complete).unwrap().state,
            ReviewGateState::Ready
        ));
    }
}
