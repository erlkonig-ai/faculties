//! The brokered egress boundary: asking for a crossing, granting it, refusing it.
//!
//! # What this is for
//!
//! A resident mind runs its shell commands inside a sandbox with no route to
//! the internet. Faculties that reach outside — `web` today, `mail`,
//! `linkedin` and `discord` on the same shape — cannot run there at all,
//! because they build an HTTP client in-process and resolve provider
//! credentials from the Secrets vault in that same process.
//!
//! This module splits that in two. The sandboxed side writes a *request* fact
//! and later reads a *response* fact. A broker on the outside — supervised by
//! whatever does the sandboxing — polls for unanswered requests, performs
//! them, and writes back. The pile is the entire interface between them.
//!
//! # The four properties this exists to give
//!
//! **The keys never enter the sandbox.** This is the larger half of the win,
//! and it is easy to miss behind the network part. Before the split, a model
//! driving a shell was driving a process that held decrypted Tavily and Exa
//! credentials; prompt injection reaching that shell reached the credentials.
//! After it, the requesting side needs neither a network route nor a secret —
//! [`request_fragment`] touches no vault and opens no socket — and only the
//! broker, which the mind cannot invoke, resolves keys.
//!
//! **Egress is auditable because every crossing is a durable fact.** The
//! ledger answers "everything this mind ever asked the outside world for" as a
//! query over [`schema::KIND_REQUEST`], and "what actually crossed" over
//! [`schema::KIND_RESPONSE`]. Both are collection facts in an append-only
//! pile, not a log that rotates. [`requests`] and [`responses_for`] are that
//! query, and they find entities by matching their *fields* — never by
//! rebuilding an entity to recompute an id, which after construction is
//! opaque.
//!
//! **Provenance travels with content.** A fulfilment names the observation it
//! produced ([`response::observation`]) in the faculty's own collection, and
//! that observation carries the provider and the time. So a claim sourced from
//! a fetched page traces back: content → observation → response → request →
//! the exact target string the mind asked for, and who asked.
//!
//! **Denials are recorded, not dropped.** A silently discarded request is
//! indistinguishable from a slow one, and an unrecorded refusal destroys the
//! auditability the whole design exists for. Every path out of
//! [`Broker::sweep`] writes a fact: a fulfilment, or a [`Refusal`] carrying
//! one of the four [`Denial`] categories and a human-readable reason. A denial
//! is terminal — the broker will not re-serve a request that already has any
//! response — so a mind that wants a second attempt files a second request,
//! and both attempts stay on the record.
//!
//! # Faculty-generic on purpose
//!
//! Nothing here knows what a URL is. A request names its target faculty by
//! that faculty's own collection scope, names an operation from that faculty's
//! vocabulary, and carries one target string plus a bag of string parameters.
//! The broker dispatches to a [`Handler`] registered for that scope. Adding
//! `mail` means: mint operation ids in `schemas::mail`, write a `Handler` that
//! performs them, add `request`/`result` verbs to the `mail` binary, and
//! register the handler in the broker. It means no change to this module and
//! no change to [`crate::schemas::egress`].
//!
//! # The one non-atomic seam, stated plainly
//!
//! A fulfilment is two commits into two collections: the faculty-native
//! observation first, then the response that names it. A crash between them
//! leaves an observation with no response, and the broker will re-serve the
//! request — so the ledger shows two crossings, which is true. The reverse
//! never happens: a response never claims an observation that was not
//! committed first.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileSnapshot;
use triblespace::core::repo::{BlobStoreGet, SnapshotSource};
use triblespace::macros::{entity, find, pattern};
use triblespace::prelude::*;

use crate::legacy_hint::open_scope;
use crate::schemas::egress::{self as schema, parameter, request, response};
use crate::storage::{load_signer, open_pile_strict, publish_fragment, read_fact_collection};

pub type TextHandle = Inline<inlineencodings::Handle<blobencodings::UTF8String>>;
pub type IntervalValue = Inline<inlineencodings::NsTAIInterval>;

/// Why a broker refused to perform a crossing.
///
/// These four are the whole vocabulary on purpose: an operator reading the
/// ledger wants to sort refusals into "we said no", "you asked wrong", "they
/// said no" and "we are out of budget" without reading prose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    /// This broker declines: host or scheme not permitted, no credential for
    /// the requested provider, no handler for the faculty.
    Policy,
    /// The request does not parse: unknown operation, empty target, a
    /// parameter value that is not what its name promises.
    Malformed,
    /// The crossing was attempted and the far side failed it.
    ProviderError,
    /// The far side refused for rate or budget reasons.
    Quota,
}

impl Denial {
    pub fn id(self) -> Id {
        match self {
            Self::Policy => schema::DENIAL_POLICY,
            Self::Malformed => schema::DENIAL_MALFORMED,
            Self::ProviderError => schema::DENIAL_PROVIDER_ERROR,
            Self::Quota => schema::DENIAL_QUOTA,
        }
    }

    pub fn from_id(id: Id) -> Option<Self> {
        match id {
            _ if id == schema::DENIAL_POLICY => Some(Self::Policy),
            _ if id == schema::DENIAL_MALFORMED => Some(Self::Malformed),
            _ if id == schema::DENIAL_PROVIDER_ERROR => Some(Self::ProviderError),
            _ if id == schema::DENIAL_QUOTA => Some(Self::Quota),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Malformed => "malformed",
            Self::ProviderError => "provider-error",
            Self::Quota => "quota",
        }
    }
}

/// One recorded refusal: a category and the reason in words.
#[derive(Clone, Debug)]
pub struct Refusal {
    pub denial: Denial,
    pub reason: String,
}

impl Refusal {
    pub fn policy(reason: impl Into<String>) -> Self {
        Self {
            denial: Denial::Policy,
            reason: reason.into(),
        }
    }

    pub fn malformed(reason: impl Into<String>) -> Self {
        Self {
            denial: Denial::Malformed,
            reason: reason.into(),
        }
    }

    pub fn provider_error(reason: impl Into<String>) -> Self {
        Self {
            denial: Denial::ProviderError,
            reason: reason.into(),
        }
    }

    pub fn quota(reason: impl Into<String>) -> Self {
        Self {
            denial: Denial::Quota,
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.denial.label(), self.reason)
    }
}

/// Whether a response granted the crossing or refused it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Fulfilled,
    Denied,
}

impl Status {
    pub fn id(self) -> Id {
        match self {
            Self::Fulfilled => schema::STATUS_FULFILLED,
            Self::Denied => schema::STATUS_DENIED,
        }
    }

    pub fn from_id(id: Id) -> Option<Self> {
        match id {
            _ if id == schema::STATUS_FULFILLED => Some(Self::Fulfilled),
            _ if id == schema::STATUS_DENIED => Some(Self::Denied),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Fulfilled => "fulfilled",
            Self::Denied => "denied",
        }
    }
}

/// What a caller wants written as a request.
#[derive(Clone, Debug)]
pub struct RequestSpec {
    /// The target faculty's collection scope, e.g.
    /// `schemas::web::DEFAULT_SCOPE_ID`.
    pub faculty: Id,
    /// An operation from that faculty's vocabulary.
    pub operation: Id,
    /// The single subject: a query, a URL, an address.
    pub target: String,
    /// Named options, string-valued. Order is normalised so two callers
    /// asking for the same thing produce the same request.
    pub parameters: Vec<(String, String)>,
    /// Optional anchor of whoever this is asked for.
    pub requester: Option<Id>,
}

/// One request as it was read back out of the ledger.
#[derive(Clone, Debug)]
pub struct RequestRecord {
    pub id: Id,
    pub faculty: Id,
    pub operation: Id,
    pub target: String,
    pub parameters: BTreeMap<String, String>,
    pub requester: Option<Id>,
    pub created_at: IntervalValue,
}

impl RequestRecord {
    /// One parameter value, or `None` if the request did not carry it.
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameters.get(name).map(String::as_str)
    }

    /// One parameter parsed, refusing as [`Denial::Malformed`] rather than
    /// silently substituting a default the mind did not ask for.
    pub fn parsed<T>(&self, name: &str, fallback: T) -> std::result::Result<T, Refusal>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        match self.parameters.get(name) {
            None => Ok(fallback),
            Some(raw) => raw.trim().parse::<T>().map_err(|error| {
                Refusal::malformed(format!("parameter '{name}' value '{raw}': {error}"))
            }),
        }
    }
}

/// One response as it was read back out of the ledger.
#[derive(Clone, Debug)]
pub struct ResponseRecord {
    pub id: Id,
    pub request: Id,
    pub status: Status,
    pub observation: Option<Id>,
    pub denial: Option<Denial>,
    pub reason: Option<String>,
    pub created_at: IntervalValue,
}

/// The faculty-native facts one crossing produced.
///
/// The fragment is committed into the handler's own collection, so a brokered
/// fetch and a direct one leave the *same* observation and every existing
/// query over that faculty keeps working unchanged.
pub struct Crossing {
    pub fragment: Fragment,
    pub observation: Id,
    pub description: &'static str,
}

/// One faculty's side of the boundary.
///
/// This is also the seam tests stub: a handler that returns canned crossings
/// or canned refusals exercises the whole broker loop with no socket open.
pub trait Handler {
    /// Collection scope of the faculty this serves.
    fn faculty(&self) -> Id;

    /// Perform exactly one crossing, or refuse it with a reason.
    fn perform(&self, request: &RequestRecord) -> std::result::Result<Crossing, Refusal>;
}

fn text(snapshot: &PileSnapshot, handle: TextHandle, label: &str) -> Result<String> {
    let view: anybytes::View<str> = snapshot
        .get(handle)
        .with_context(|| format!("read Egress {label}"))?;
    Ok(view.to_string())
}

/// Build one request entity and return it with its intrinsic id.
///
/// Identity covers the faculty, operation, target, parameters, requester and
/// time, so two callers asking for exactly the same thing at exactly the same
/// instant produce one request rather than two — which is the right
/// idempotency — while any later re-ask is a new request with its own record.
///
/// This function opens no socket and reads no vault. That is the property the
/// sandboxed side depends on.
pub fn request_fragment(spec: &RequestSpec, created_at: IntervalValue) -> Result<(Fragment, Id)> {
    let mut fragment = Fragment::empty();
    let target = fragment.put::<blobencodings::UTF8String, _>(spec.target.clone());

    let mut normalised: BTreeMap<&str, &str> = BTreeMap::new();
    for (name, value) in &spec.parameters {
        normalised.insert(name.as_str(), value.as_str());
    }

    let mut parameter_ids = Vec::with_capacity(normalised.len());
    for (name, value) in normalised {
        let value_handle = fragment.put::<blobencodings::UTF8String, _>(value.to_owned());
        let entry = entity! { _ @
            metadata::tag: &schema::KIND_PARAMETER,
            parameter::name: name,
            parameter::value: value_handle,
        };
        parameter_ids.push(
            entry
                .root()
                .ok_or_else(|| anyhow!("Egress parameter fragment has no intrinsic root"))?,
        );
        fragment += entry;
    }

    let core = entity! { _ @
        metadata::tag: &schema::KIND_REQUEST,
        request::faculty: &spec.faculty,
        request::operation: &spec.operation,
        request::target: target,
        request::requester?: spec.requester.as_ref(),
        metadata::created_at: created_at,
        request::parameter*: parameter_ids,
    };
    let id = core
        .root()
        .ok_or_else(|| anyhow!("Egress request fragment has no intrinsic root"))?;
    fragment += core;
    Ok((fragment, id))
}

/// Build the response that grants a crossing and names what it produced.
pub fn fulfilment_fragment(request: Id, observation: Id, at: IntervalValue) -> Fragment {
    entity! { _ @
        metadata::tag: &schema::KIND_RESPONSE,
        response::request: &request,
        response::status: &schema::STATUS_FULFILLED,
        response::observation: &observation,
        metadata::created_at: at,
    }
}

/// Build the response that refuses a crossing and says why.
pub fn denial_fragment(request: Id, refusal: &Refusal, at: IntervalValue) -> Fragment {
    let mut fragment = Fragment::empty();
    let reason = fragment.put::<blobencodings::UTF8String, _>(refusal.reason.clone());
    fragment += entity! { _ @
        metadata::tag: &schema::KIND_RESPONSE,
        response::request: &request,
        response::status: &schema::STATUS_DENIED,
        response::denial: &refusal.denial.id(),
        response::reason: reason,
        metadata::created_at: at,
    };
    fragment
}

/// Every request in the ledger, optionally narrowed to one faculty.
///
/// This is the audit query. Requests are found by matching their facts, never
/// by rebuilding an entity to recompute an id.
pub fn requests(
    facts: &TribleSet,
    snapshot: &PileSnapshot,
    faculty: Option<Id>,
) -> Result<Vec<RequestRecord>> {
    let rows: Vec<(Id, Id, Id, TextHandle, IntervalValue)> = find!(
        (id: Id, faculty: Id, operation: Id, target: TextHandle, created_at: IntervalValue),
        pattern!(facts, [{
            ?id @
            metadata::tag: &schema::KIND_REQUEST,
            request::faculty: ?faculty,
            request::operation: ?operation,
            request::target: ?target,
            metadata::created_at: ?created_at,
        }])
    )
    .collect();

    let mut records = Vec::new();
    for (id, request_faculty, operation, target, created_at) in rows {
        if faculty.is_some_and(|wanted| wanted != request_faculty) {
            continue;
        }
        let target = text(snapshot, target, "request target")?;
        let requester = find!(
            value: Id,
            pattern!(facts, [{ id @ request::requester: ?value }])
        )
        .next();

        let mut parameters = BTreeMap::new();
        let entries: Vec<(Id, String)> = find!(
            (entry: Id, name: String),
            pattern!(facts, [{
                id @ request::parameter: ?entry
            }, {
                ?entry @
                metadata::tag: &schema::KIND_PARAMETER,
                parameter::name: ?name,
            }])
        )
        .collect();
        for (entry, name) in entries {
            let Some(handle) = find!(
                value: TextHandle,
                pattern!(facts, [{ entry @ parameter::value: ?value }])
            )
            .next() else {
                continue;
            };
            parameters.insert(name, text(snapshot, handle, "request parameter")?);
        }

        records.push(RequestRecord {
            id,
            faculty: request_faculty,
            operation,
            target,
            parameters,
            requester,
            created_at,
        });
    }
    records.sort_by_key(|record| (interval_key(record.created_at), record.id));
    Ok(records)
}

/// Every request id that already has a response of any kind.
///
/// A denial counts. Refusals are terminal by design; a retry is a new request
/// so that both attempts stay on the record.
pub fn answered(facts: &TribleSet) -> BTreeSet<Id> {
    find!(
        request: Id,
        pattern!(facts, [{
            _?response @
            metadata::tag: &schema::KIND_RESPONSE,
            response::request: ?request,
        }])
    )
    .collect()
}

/// Every response for one request, oldest first.
///
/// More than one is possible — two brokers on one collection both serve, and
/// the append-only ledger records both rather than hiding either. Running one
/// broker per collection is the operational rule; seeing two here is the
/// evidence that it was broken.
pub fn responses_for(
    facts: &TribleSet,
    snapshot: &PileSnapshot,
    request: Id,
) -> Result<Vec<ResponseRecord>> {
    let rows: Vec<(Id, Id, IntervalValue)> = find!(
        (id: Id, status: Id, created_at: IntervalValue),
        pattern!(facts, [{
            ?id @
            metadata::tag: &schema::KIND_RESPONSE,
            response::request: &request,
            response::status: ?status,
            metadata::created_at: ?created_at,
        }])
    )
    .collect();

    let mut records = Vec::new();
    for (id, status, created_at) in rows {
        let status = Status::from_id(status)
            .ok_or_else(|| anyhow!("Egress response {id:X} carries an unknown status"))?;
        let observation = find!(
            value: Id,
            pattern!(facts, [{ id @ response::observation: ?value }])
        )
        .next();
        let denial = find!(value: Id, pattern!(facts, [{ id @ response::denial: ?value }]))
            .next()
            .and_then(Denial::from_id);
        let reason = match find!(
            value: TextHandle,
            pattern!(facts, [{ id @ response::reason: ?value }])
        )
        .next()
        {
            Some(handle) => Some(text(snapshot, handle, "response reason")?),
            None => None,
        };
        records.push(ResponseRecord {
            id,
            request,
            status,
            observation,
            denial,
            reason,
            created_at,
        });
    }
    records.sort_by_key(|record| (interval_key(record.created_at), record.id));
    Ok(records)
}

/// Lower bound of an interval in TAI nanoseconds, for ordering only.
pub fn interval_key(interval: IntervalValue) -> i128 {
    match interval.try_from_inline() {
        Ok((lower, _)) => {
            let lower: hifitime::Epoch = lower;
            lower.to_tai_duration().total_nanoseconds()
        }
        Err(_) => i128::MIN,
    }
}

/// Read one collection's facts and blobs without holding the pile open past
/// the closure.
///
/// The broker must not hold the pile while it is out on the network, so every
/// read is scoped and every write is its own short commit.
pub fn with_view<T>(
    pile_path: &Path,
    key_path: Option<&Path>,
    scope: Id,
    read: impl FnOnce(&TribleSet, &PileSnapshot) -> Result<T>,
) -> Result<T> {
    let signer = load_signer(pile_path, key_path)?;
    let mut pile = open_pile_strict(pile_path)?;
    let result = (|| {
        let collection = open_scope(&mut pile, scope, &signer)?;
        let snapshot = pile.snapshot().context("freeze Egress store snapshot")?;
        let (facts, _) =
            read_fact_collection(collection, &snapshot).context("materialize Egress collection")?;
        read(&facts, &snapshot)
    })();
    let close = pile.close().map_err(anyhow::Error::from);
    match (result, close) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error.context("close pile after collection read")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "closing pile after collection read also failed: {close_error}"
        ))),
    }
}

/// Commit one fragment into one collection with a description metafact.
pub fn publish(
    pile_path: &Path,
    key_path: Option<&Path>,
    scope: Id,
    mut fragment: Fragment,
    description: &'static str,
) -> Result<()> {
    fragment.describe_with(entity! { metadata::description: description });
    publish_fragment(pile_path, key_path, scope, fragment)
        .with_context(|| format!("commit {description}"))?;
    Ok(())
}

/// What one broker pass did.
#[derive(Debug, Default)]
pub struct Sweep {
    pub fulfilled: Vec<Id>,
    pub denied: Vec<(Id, Denial, String)>,
}

impl Sweep {
    pub fn handled(&self) -> usize {
        self.fulfilled.len() + self.denied.len()
    }
}

/// The broker: the only side of the boundary that holds credentials and a
/// network route.
///
/// It is deliberately a separate process from whatever enforces the sandbox.
/// The jailer decides *whether* a tenant may reach outside and supervises this
/// process with that tenant's pile, credentials and policy; the fetching
/// itself happens here, so the component whose only job is containment never
/// grows a pile snapshot, an HTTP client, or an API key.
pub struct Broker<'a> {
    pile: &'a Path,
    key: Option<&'a Path>,
    handlers: Vec<Box<dyn Handler + 'a>>,
}

impl<'a> Broker<'a> {
    pub fn new(pile: &'a Path, key: Option<&'a Path>) -> Self {
        Self {
            pile,
            key,
            handlers: Vec::new(),
        }
    }

    pub fn register(&mut self, handler: Box<dyn Handler + 'a>) {
        self.handlers.push(handler);
    }

    /// Faculties this broker will serve. A request for anything else is
    /// denied [`Denial::Policy`] rather than left pending, because a request
    /// nobody will ever answer must not look like one that is merely slow.
    pub fn served(&self) -> BTreeSet<Id> {
        self.handlers
            .iter()
            .map(|handler| handler.faculty())
            .collect()
    }

    /// Requests with no response yet, oldest first.
    pub fn pending(&self) -> Result<Vec<RequestRecord>> {
        with_view(
            self.pile,
            self.key,
            schema::DEFAULT_SCOPE_ID,
            |facts, snapshot| {
                let answered = answered(facts);
                Ok(requests(facts, snapshot, None)?
                    .into_iter()
                    .filter(|record| !answered.contains(&record.id))
                    .collect())
            },
        )
    }

    /// One pass: read the pending set, perform each crossing, write each
    /// outcome. Every request handled leaves a fact behind — there is no path
    /// through this function that consumes a request without recording one.
    pub fn sweep(&self, now: impl Fn() -> Result<IntervalValue>) -> Result<Sweep> {
        let pending = self.pending()?;
        let mut sweep = Sweep::default();
        for record in pending {
            let outcome = match self
                .handlers
                .iter()
                .find(|handler| handler.faculty() == record.faculty)
            {
                Some(handler) => handler.perform(&record),
                None => Err(Refusal::policy(format!(
                    "this broker serves no handler for faculty {:X}",
                    record.faculty
                ))),
            };

            match outcome {
                Ok(crossing) => {
                    // Observation first, then the response that names it. A
                    // response never claims an observation that is not
                    // already durable.
                    publish(
                        self.pile,
                        self.key,
                        record.faculty,
                        crossing.fragment,
                        crossing.description,
                    )?;
                    publish(
                        self.pile,
                        self.key,
                        schema::DEFAULT_SCOPE_ID,
                        fulfilment_fragment(record.id, crossing.observation, now()?),
                        "egress fulfilment",
                    )?;
                    sweep.fulfilled.push(record.id);
                }
                Err(refusal) => {
                    publish(
                        self.pile,
                        self.key,
                        schema::DEFAULT_SCOPE_ID,
                        denial_fragment(record.id, &refusal, now()?),
                        "egress denial",
                    )?;
                    sweep
                        .denied
                        .push((record.id, refusal.denial, refusal.reason));
                }
            }
        }
        Ok(sweep)
    }

    /// Sweep on an interval until interrupted, reporting each outcome.
    pub fn run(
        &self,
        poll: Duration,
        once: bool,
        now: impl Fn() -> Result<IntervalValue> + Copy,
        mut report: impl FnMut(&Sweep),
    ) -> Result<()> {
        loop {
            let sweep = self.sweep(now)?;
            report(&sweep);
            if once {
                return Ok(());
            }
            std::thread::sleep(poll);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hifitime::Epoch;

    use crate::clock;
    use crate::schemas::web as web_schema;

    fn at(seconds: f64) -> IntervalValue {
        clock::point(Epoch::from_unix_seconds(seconds)).unwrap()
    }

    fn spec() -> RequestSpec {
        RequestSpec {
            faculty: web_schema::DEFAULT_SCOPE_ID,
            operation: web_schema::OPERATION_FETCH,
            target: "https://example.test/page".to_owned(),
            parameters: vec![
                ("max-characters".to_owned(), "512".to_owned()),
                ("provider".to_owned(), "exa".to_owned()),
            ],
            requester: None,
        }
    }

    #[test]
    fn a_request_is_built_without_a_socket_or_a_vault() {
        let (fragment, id) = request_fragment(&spec(), at(1.0)).unwrap();
        let facts = fragment.facts();

        // The request entity is found by matching its fields, not by
        // recomputing an id.
        let found: Vec<Id> = find!(
            id: Id,
            pattern!(&facts, [{
                ?id @
                metadata::tag: &schema::KIND_REQUEST,
                request::faculty: &web_schema::DEFAULT_SCOPE_ID,
                request::operation: &web_schema::OPERATION_FETCH,
            }])
        )
        .collect();
        assert_eq!(found, vec![id]);

        let parameters: Vec<String> = find!(
            name: String,
            pattern!(&facts, [{
                _?entry @
                metadata::tag: &schema::KIND_PARAMETER,
                parameter::name: ?name,
            }])
        )
        .collect();
        assert_eq!(parameters.len(), 2);
    }

    #[test]
    fn parameter_order_does_not_change_request_identity() {
        let mut reversed = spec();
        reversed.parameters.reverse();
        let (_, forward) = request_fragment(&spec(), at(1.0)).unwrap();
        let (_, backward) = request_fragment(&reversed, at(1.0)).unwrap();
        assert_eq!(forward, backward);
    }

    #[test]
    fn a_denial_carries_its_category_and_reason() {
        let request = request_fragment(&spec(), at(1.0)).unwrap().1;
        let refusal = Refusal::quota("provider replied 429");
        let denial = denial_fragment(request, &refusal, at(2.0));
        let facts = denial.facts();
        let rows: Vec<(Id, Id)> = find!(
            (status: Id, denial: Id),
            pattern!(&facts, [{
                _?response @
                metadata::tag: &schema::KIND_RESPONSE,
                response::request: &request,
                response::status: ?status,
                response::denial: ?denial,
            }])
        )
        .collect();
        assert_eq!(rows, vec![(schema::STATUS_DENIED, schema::DENIAL_QUOTA)]);
    }

    #[test]
    fn parsed_refuses_a_bad_value_instead_of_defaulting() {
        let record = RequestRecord {
            id: request_fragment(&spec(), at(1.0)).unwrap().1,
            faculty: web_schema::DEFAULT_SCOPE_ID,
            operation: web_schema::OPERATION_FETCH,
            target: "https://example.test/page".to_owned(),
            parameters: BTreeMap::from([("max-characters".to_owned(), "lots".to_owned())]),
            requester: None,
            created_at: at(1.0),
        };
        let refusal = record.parsed::<usize>("max-characters", 12).unwrap_err();
        assert_eq!(refusal.denial, Denial::Malformed);
        assert_eq!(record.parsed::<usize>("absent", 12).unwrap(), 12);
    }
}
