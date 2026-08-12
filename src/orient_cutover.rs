//! Stopped-world disposition of the two legacy Orient checkpoint ledgers.
//!
//! The old `orient` and `orient-state` branches were operational snapshots:
//! they remembered mutable branch heads and large, repeated "already seen"
//! sets.  The collection-native faculty instead stores monotone intrinsic
//! `Baseline(persona)` and `Seen(persona, kind, item)` observations.  Replaying
//! the old snapshots would both retain obsolete Repository coordinates and
//! manufacture a dubious correspondence between two different observation
//! models.
//!
//! The truthful cutover therefore omits both old ledgers after validating
//! their complete schema and attachment closure.  The first consuming Orient
//! call over the empty target establishes a quiet complete baseline under the
//! new model. This validator returns the two exact frozen pin coordinates to
//! the aggregate activation coverage proof; it persists no omission record.

use std::collections::{BTreeMap, BTreeSet};

use anybytes::View;
use anyhow::{anyhow, bail, Context, Result};
use triblespace::core::attribute::Attribute;
use triblespace::core::blob::encodings::longstring::LongString;
use triblespace::core::blob::encodings::simplearchive::SimpleArchive;
use triblespace::core::id::Id;
use triblespace::core::inline::encodings::hash::Handle;
use triblespace::core::inline::{Inline, InlineEncoding};
use triblespace::core::metadata;
use triblespace::core::repo::pile::PileReader;
use triblespace::core::repo::BlobStoreGet;
use triblespace::core::trible::{Trible, TribleSet};
use triblespace::macros::{attributes, id_hex};
use triblespace::prelude::inlineencodings;

use crate::collection_cutover::{FrozenLegacyBranch, FrozenSource, LegacyPinCoordinate};

const ORIENT_BRANCH_ID: Id = id_hex!("B621BC48623BD714A9F88FB3072F0249");
const ORIENT_STATE_BRANCH_ID: Id = id_hex!("12AE1510A69B74A1F634231E670C52F2");

const KIND_ORIENT_CHECKPOINT: Id = id_hex!("163114E5F2272D15F21E1994EF418A31");
const KIND_REVIEW_WATERMARK: Id = id_hex!("A085287A166006EC395ED7682B24EF3E");

mod legacy {
    use super::*;

    attributes! {
        // Earliest global Orient checkpoint timestamp.
        "077630536F9D01DBE64320D7044D55A5" unsafe as global_at: inlineencodings::NsTAIInterval;
        // Later checkpoint/watermark timestamp.
        "EB687567424358B8780A561EA900513C" unsafe as state_at: inlineencodings::NsTAIInterval;

        "6F2D6C7C796B41C2DC7885E7E4D3D750" unsafe as local_head: inlineencodings::Handle<SimpleArchive>;
        "6E6A761126C5101CC69BE185A4B4EC4C" unsafe as compass_head: inlineencodings::Handle<SimpleArchive>;
        "3A58593A230497DEC735E92381C4C522" unsafe as relations_head: inlineencodings::Handle<SimpleArchive>;
        "789078EA4AA95F7B7AD047FF23E04C60" unsafe as config_head: inlineencodings::Handle<SimpleArchive>;
        "86A4217C3D1C8FD7854208396FF4D4A7" unsafe as mail_head: inlineencodings::Handle<SimpleArchive>;

        "AE16414EE1D15DBAC9DF44F77A742E0A" unsafe as persona: inlineencodings::GenId;
        "174944957EC01DF2C10D470DBCE4263F" unsafe as unread_msg: inlineencodings::GenId;
        "850E03FC2C26ABF7FAC129903B60F069" unsafe as unread_mail: inlineencodings::GenId;
        "5D3327421EB2F0D92FD50CF32D5A513C" unsafe as roster_member: inlineencodings::GenId;
        "7D7D457CA0184919497E2585CF779125" unsafe as goals_view: inlineencodings::Handle<LongString>;
        "673BA8486630927882901829C286FA15" unsafe as notes_view: inlineencodings::Handle<LongString>;

        "C5BEDFE3A37A1432FEE9B7BA6231E456" unsafe as wm_request: inlineencodings::GenId;
        "2234DDA93FEB2F265C25F7EBB24D4297" unsafe as wm_head: inlineencodings::GenId;
        "8F6BAB7F7F8EB992964532B82FE884D2" unsafe as wm_deadline: inlineencodings::NsTAIInterval;
    }
}

/// Exact source coordinates of the two strictly validated retired ledgers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetiredOrientPins {
    pub orient: LegacyPinCoordinate,
    pub orient_state: LegacyPinCoordinate,
}

/// Validate the complete closed content schemas and their attachment closure
/// on the two reviewed legacy Orient branches. Branch ids are explicit so a
/// same-name replacement cannot inherit the disposition. Heads remain runtime
/// values because orient-state may legitimately advance until writers stop.
pub fn validate_retired(source: &FrozenSource) -> Result<RetiredOrientPins> {
    let orient = source
        .legacy_branch("orient")?
        .ok_or_else(|| anyhow!("frozen source has no legacy orient branch"))?;
    let state = source
        .legacy_branch("orient-state")?
        .ok_or_else(|| anyhow!("frozen source has no legacy orient-state branch"))?;

    if orient.branch != ORIENT_BRANCH_ID {
        bail!(
            "retired Orient disposition expected branch {ORIENT_BRANCH_ID:X}, found {:X}",
            orient.branch
        );
    }
    if state.branch != ORIENT_STATE_BRANCH_ID {
        bail!(
            "retired Orient-state disposition expected branch {ORIENT_STATE_BRANCH_ID:X}, found {:X}",
            state.branch
        );
    }

    let mut attachments = validate_global_branch(&orient)?;
    attachments.extend(validate_state_branch(&state)?);
    attachments.validate(source.reader())?;

    Ok(RetiredOrientPins {
        orient: orient.pin_coordinate(),
        orient_state: state.pin_coordinate(),
    })
}

#[derive(Default)]
struct Attachments {
    archives: BTreeSet<Inline<Handle<SimpleArchive>>>,
    texts: BTreeSet<Inline<Handle<LongString>>>,
}

impl Attachments {
    fn extend(&mut self, other: Self) {
        self.archives.extend(other.archives);
        self.texts.extend(other.texts);
    }

    fn validate(&self, reader: &PileReader) -> Result<()> {
        for handle in &self.archives {
            let _: TribleSet = reader.get(*handle).with_context(|| {
                format!(
                    "read legacy Orient SimpleArchive {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
        for handle in &self.texts {
            let _: View<str> = reader.get(*handle).with_context(|| {
                format!(
                    "read legacy Orient LongString {}",
                    hex::encode_upper(handle.raw)
                )
            })?;
        }
        Ok(())
    }
}

fn validate_global_branch(branch: &FrozenLegacyBranch) -> Result<Attachments> {
    let mut attachments = Attachments::default();
    let mut authored = 0_usize;
    for delta in &branch.deltas {
        if !delta.is_authored() {
            continue;
        }
        authored += 1;
        let grouped = group_by_entity(&delta.facts);
        if grouped.len() != 1 {
            bail!(
                "legacy orient commit {} contains {} records; expected one global checkpoint",
                hex::encode_upper(delta.commit.raw),
                grouped.len()
            );
        }
        let (&entity, facts) = grouped.first_key_value().expect("one grouped entity");
        validate_allowed(
            facts,
            &global_attributes(),
            entity,
            "legacy global Orient checkpoint",
        )?;
        require_tag(facts, entity, KIND_ORIENT_CHECKPOINT)?;
        require_one_interval(facts, entity, &legacy::global_at, "global_at")?;
        require_one_interval(facts, entity, &legacy::state_at, "state_at")?;
        require_one_archive(
            facts,
            entity,
            &legacy::local_head,
            "local_head",
            &mut attachments,
        )?;
        require_one_archive(
            facts,
            entity,
            &legacy::compass_head,
            "compass_head",
            &mut attachments,
        )?;
        require_one_archive(
            facts,
            entity,
            &legacy::relations_head,
            "relations_head",
            &mut attachments,
        )?;
        require_one_archive(
            facts,
            entity,
            &legacy::config_head,
            "config_head",
            &mut attachments,
        )?;
        if facts.len() != 7 {
            bail!(
                "legacy global Orient checkpoint {entity:X} has {} facts; expected exactly seven",
                facts.len()
            );
        }
    }
    if authored != 1 {
        bail!("legacy orient branch has {authored} authored commits; expected exactly one");
    }
    Ok(attachments)
}

fn validate_state_branch(branch: &FrozenLegacyBranch) -> Result<Attachments> {
    let mut attachments = Attachments::default();
    let mut records = 0_usize;
    for delta in &branch.deltas {
        if !delta.is_authored() {
            continue;
        }
        let grouped = group_by_entity(&delta.facts);
        if grouped.is_empty() {
            bail!(
                "legacy orient-state authored commit {} is empty",
                hex::encode_upper(delta.commit.raw)
            );
        }
        for (&entity, facts) in &grouped {
            records += 1;
            validate_state_record(facts, entity, &mut attachments).with_context(|| {
                format!(
                    "validate legacy Orient-state record {entity:X} in commit {}",
                    hex::encode_upper(delta.commit.raw)
                )
            })?;
        }
    }
    if records == 0 {
        bail!("legacy orient-state branch contains no checkpoint records");
    }
    Ok(attachments)
}

fn validate_state_record(
    facts: &[&Trible],
    entity: Id,
    attachments: &mut Attachments,
) -> Result<()> {
    validate_allowed(
        facts,
        &state_attributes(),
        entity,
        "legacy Orient-state record",
    )?;
    let tag = exactly_one_genid(facts, entity, &metadata::tag, "metadata::tag")?;
    require_one_interval(facts, entity, &legacy::state_at, "state_at")?;

    match tag {
        KIND_ORIENT_CHECKPOINT => {
            reject_any(facts, entity, &legacy::wm_request, "wm_request")?;
            reject_any(facts, entity, &legacy::wm_head, "wm_head")?;
            reject_any(facts, entity, &legacy::wm_deadline, "wm_deadline")?;

            require_one_archive(
                facts,
                entity,
                &legacy::local_head,
                "local_head",
                attachments,
            )?;
            require_one_archive(
                facts,
                entity,
                &legacy::compass_head,
                "compass_head",
                attachments,
            )?;
            require_one_archive(
                facts,
                entity,
                &legacy::relations_head,
                "relations_head",
                attachments,
            )?;
            optional_archive(
                facts,
                entity,
                &legacy::config_head,
                "config_head",
                attachments,
            )?;
            optional_archive(facts, entity, &legacy::mail_head, "mail_head", attachments)?;
            optional_genid(facts, entity, &legacy::persona, "persona")?;
            optional_text(
                facts,
                entity,
                &legacy::goals_view,
                "goals_view",
                attachments,
            )?;
            optional_text(
                facts,
                entity,
                &legacy::notes_view,
                "notes_view",
                attachments,
            )?;
            // unread_msg, unread_mail and roster_member are intentional sets.
            decode_genid_set(facts, entity, &legacy::unread_msg, "unread_msg")?;
            decode_genid_set(facts, entity, &legacy::unread_mail, "unread_mail")?;
            decode_genid_set(facts, entity, &legacy::roster_member, "roster_member")?;
        }
        KIND_REVIEW_WATERMARK => {
            let allowed = review_watermark_attributes();
            validate_allowed(facts, &allowed, entity, "legacy Orient review watermark")?;
            exactly_one_genid(facts, entity, &legacy::persona, "persona")?;
            exactly_one_genid(facts, entity, &legacy::wm_request, "wm_request")?;
            decode_genid_set(facts, entity, &legacy::wm_head, "wm_head")?;
            optional_interval(facts, entity, &legacy::wm_deadline, "wm_deadline")?;
        }
        other => bail!("legacy Orient-state record {entity:X} has unknown kind {other:X}"),
    }
    Ok(())
}

fn group_by_entity(facts: &TribleSet) -> BTreeMap<Id, Vec<&Trible>> {
    let mut grouped = BTreeMap::<Id, Vec<&Trible>>::new();
    for fact in facts.iter() {
        grouped.entry(*fact.e()).or_default().push(fact);
    }
    grouped
}

fn global_attributes() -> BTreeSet<Id> {
    BTreeSet::from([
        metadata::tag.id(),
        legacy::global_at.id(),
        legacy::state_at.id(),
        legacy::local_head.id(),
        legacy::compass_head.id(),
        legacy::relations_head.id(),
        legacy::config_head.id(),
    ])
}

fn state_attributes() -> BTreeSet<Id> {
    BTreeSet::from([
        metadata::tag.id(),
        legacy::state_at.id(),
        legacy::local_head.id(),
        legacy::compass_head.id(),
        legacy::relations_head.id(),
        legacy::config_head.id(),
        legacy::mail_head.id(),
        legacy::persona.id(),
        legacy::unread_msg.id(),
        legacy::unread_mail.id(),
        legacy::roster_member.id(),
        legacy::goals_view.id(),
        legacy::notes_view.id(),
        legacy::wm_request.id(),
        legacy::wm_head.id(),
        legacy::wm_deadline.id(),
    ])
}

fn review_watermark_attributes() -> BTreeSet<Id> {
    BTreeSet::from([
        metadata::tag.id(),
        legacy::state_at.id(),
        legacy::persona.id(),
        legacy::wm_request.id(),
        legacy::wm_head.id(),
        legacy::wm_deadline.id(),
    ])
}

fn validate_allowed(
    facts: &[&Trible],
    allowed: &BTreeSet<Id>,
    entity: Id,
    label: &str,
) -> Result<()> {
    for fact in facts {
        if !allowed.contains(fact.a()) {
            bail!(
                "{label} {entity:X} contains unknown attribute {:X}",
                fact.a()
            );
        }
    }
    Ok(())
}

fn inline_values<V: InlineEncoding>(
    facts: &[&Trible],
    entity: Id,
    attribute: &Attribute<V>,
) -> Vec<Inline<V>> {
    facts
        .iter()
        .filter(|fact| fact.e() == &entity && fact.a() == &attribute.id())
        .map(|fact| *fact.v::<V>())
        .collect()
}

fn exactly_one_genid(
    facts: &[&Trible],
    entity: Id,
    attribute: &Attribute<inlineencodings::GenId>,
    field: &str,
) -> Result<Id> {
    let values = inline_values(facts, entity, attribute);
    if values.len() != 1 {
        bail!(
            "legacy Orient record {entity:X} has {} {field} values; expected exactly one",
            values.len()
        );
    }
    values[0]
        .try_from_inline()
        .map_err(|error| anyhow!("decode legacy Orient {field}: {error:?}"))
}

fn require_tag(facts: &[&Trible], entity: Id, expected: Id) -> Result<()> {
    let tag = exactly_one_genid(facts, entity, &metadata::tag, "metadata::tag")?;
    if tag != expected {
        bail!("legacy Orient record {entity:X} has kind {tag:X}; expected {expected:X}");
    }
    Ok(())
}

fn optional_genid(
    facts: &[&Trible],
    entity: Id,
    attribute: &Attribute<inlineencodings::GenId>,
    field: &str,
) -> Result<Option<Id>> {
    let values = inline_values(facts, entity, attribute);
    if values.len() > 1 {
        bail!(
            "legacy Orient record {entity:X} has {} {field} values; expected at most one",
            values.len()
        );
    }
    values
        .first()
        .map(|value| {
            value
                .try_from_inline()
                .map_err(|error| anyhow!("decode legacy Orient {field}: {error:?}"))
        })
        .transpose()
}

fn decode_genid_set(
    facts: &[&Trible],
    entity: Id,
    attribute: &Attribute<inlineencodings::GenId>,
    field: &str,
) -> Result<BTreeSet<Id>> {
    inline_values(facts, entity, attribute)
        .into_iter()
        .map(|value| {
            value
                .try_from_inline()
                .map_err(|error| anyhow!("decode legacy Orient {field} on {entity:X}: {error:?}"))
        })
        .collect()
}

fn reject_any<V: InlineEncoding>(
    facts: &[&Trible],
    entity: Id,
    attribute: &Attribute<V>,
    field: &str,
) -> Result<()> {
    let count = inline_values(facts, entity, attribute).len();
    if count != 0 {
        bail!("legacy Orient checkpoint {entity:X} unexpectedly carries {field}");
    }
    Ok(())
}

fn decode_intervals(
    values: Vec<Inline<inlineencodings::NsTAIInterval>>,
    entity: Id,
    field: &str,
) -> Result<()> {
    for value in values {
        let _: (i128, i128) = value
            .try_from_inline()
            .map_err(|error| anyhow!("decode legacy Orient {field} on {entity:X}: {error:?}"))?;
    }
    Ok(())
}

fn require_one_interval(
    facts: &[&Trible],
    entity: Id,
    attribute: &Attribute<inlineencodings::NsTAIInterval>,
    field: &str,
) -> Result<()> {
    let values = inline_values(facts, entity, attribute);
    if values.len() != 1 {
        bail!(
            "legacy Orient record {entity:X} has {} {field} values; expected exactly one",
            values.len()
        );
    }
    decode_intervals(values, entity, field)
}

fn optional_interval(
    facts: &[&Trible],
    entity: Id,
    attribute: &Attribute<inlineencodings::NsTAIInterval>,
    field: &str,
) -> Result<()> {
    let values = inline_values(facts, entity, attribute);
    if values.len() > 1 {
        bail!(
            "legacy Orient record {entity:X} has {} {field} values; expected at most one",
            values.len()
        );
    }
    decode_intervals(values, entity, field)
}

fn require_one_archive(
    facts: &[&Trible],
    entity: Id,
    attribute: &Attribute<Handle<SimpleArchive>>,
    field: &str,
    attachments: &mut Attachments,
) -> Result<()> {
    let values = inline_values(facts, entity, attribute);
    if values.len() != 1 {
        bail!(
            "legacy Orient record {entity:X} has {} {field} values; expected exactly one",
            values.len()
        );
    }
    attachments.archives.insert(values[0]);
    Ok(())
}

fn optional_archive(
    facts: &[&Trible],
    entity: Id,
    attribute: &Attribute<Handle<SimpleArchive>>,
    field: &str,
    attachments: &mut Attachments,
) -> Result<()> {
    let values = inline_values(facts, entity, attribute);
    if values.len() > 1 {
        bail!(
            "legacy Orient record {entity:X} has {} {field} values; expected at most one",
            values.len()
        );
    }
    attachments.archives.extend(values);
    Ok(())
}

fn optional_text(
    facts: &[&Trible],
    entity: Id,
    attribute: &Attribute<Handle<LongString>>,
    field: &str,
    attachments: &mut Attachments,
) -> Result<()> {
    let values = inline_values(facts, entity, attribute);
    if values.len() > 1 {
        bail!(
            "legacy Orient record {entity:X} has {} {field} values; expected at most one",
            values.len()
        );
    }
    attachments.texts.extend(values);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use triblespace::core::id::ExclusiveId;
    use triblespace::macros::entity;

    const RECORD: Id = id_hex!("B2000000000000000000000000000001");
    const PERSONA: Id = id_hex!("B2000000000000000000000000000002");
    const REQUEST: Id = id_hex!("B2000000000000000000000000000003");

    fn at() -> Inline<inlineencodings::NsTAIInterval> {
        Inline::new([0; 32])
    }

    #[test]
    fn checkpoint_sets_are_admitted_but_watermark_fields_are_not() {
        let fragment = entity! { ExclusiveId::force_ref(&RECORD) @
            metadata::tag: &KIND_ORIENT_CHECKPOINT,
            legacy::state_at: at(),
            legacy::local_head: Inline::new([1; 32]),
            legacy::compass_head: Inline::new([2; 32]),
            legacy::relations_head: Inline::new([3; 32]),
            legacy::persona: PERSONA,
            legacy::unread_msg: &REQUEST,
            legacy::unread_msg: &PERSONA,
        };
        let facts = fragment.into_facts();
        let grouped = group_by_entity(&facts);
        let row = grouped.get(&RECORD).unwrap();
        validate_state_record(row, RECORD, &mut Attachments::default()).unwrap();

        let malformed = facts
            + entity! { ExclusiveId::force_ref(&RECORD) @ legacy::wm_request: REQUEST }
                .into_facts();
        let grouped = group_by_entity(&malformed);
        let error = validate_state_record(
            grouped.get(&RECORD).unwrap(),
            RECORD,
            &mut Attachments::default(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("unexpectedly carries wm_request"));
    }

    #[test]
    fn checkpoint_sets_reject_invalid_genids() {
        let facts = entity! { ExclusiveId::force_ref(&RECORD) @
            metadata::tag: &KIND_ORIENT_CHECKPOINT,
            legacy::state_at: at(),
            legacy::local_head: Inline::new([1; 32]),
            legacy::compass_head: Inline::new([2; 32]),
            legacy::relations_head: Inline::new([3; 32]),
            legacy::unread_msg: Inline::<inlineencodings::GenId>::new([0; 32]),
        }
        .into_facts();
        let grouped = group_by_entity(&facts);
        let error = validate_state_record(
            grouped.get(&RECORD).unwrap(),
            RECORD,
            &mut Attachments::default(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("decode legacy Orient unread_msg"));
    }

    #[test]
    fn review_watermark_has_a_closed_distinct_shape() {
        let facts = entity! { ExclusiveId::force_ref(&RECORD) @
            metadata::tag: &KIND_REVIEW_WATERMARK,
            legacy::state_at: at(),
            legacy::persona: PERSONA,
            legacy::wm_request: REQUEST,
            legacy::wm_head: &REQUEST,
        }
        .into_facts();
        let grouped = group_by_entity(&facts);
        validate_state_record(
            grouped.get(&RECORD).unwrap(),
            RECORD,
            &mut Attachments::default(),
        )
        .unwrap();

        let malformed = facts
            + entity! { ExclusiveId::force_ref(&RECORD) @ legacy::unread_msg: REQUEST }
                .into_facts();
        let grouped = group_by_entity(&malformed);
        let error = validate_state_record(
            grouped.get(&RECORD).unwrap(),
            RECORD,
            &mut Attachments::default(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("unknown attribute"));
    }

    #[test]
    fn reviewed_branch_ids_are_stable() {
        assert_eq!(
            format!("{ORIENT_BRANCH_ID:X}"),
            "B621BC48623BD714A9F88FB3072F0249"
        );
        assert_eq!(
            format!("{ORIENT_STATE_BRANCH_ID:X}"),
            "12AE1510A69B74A1F634231E670C52F2"
        );
    }
}
