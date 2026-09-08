//! Presentation of typed Relations write receipts.
use super::{
    AddedGroup, AddedPerson, GroupAddition, GroupReconciliation, GroupRemoval, GroupRename,
    IdentityChange, LifecycleChange, ProfileReconciliation, ProfileUpdate,
};
use crate::out::Out;
use anyhow::Result;

pub fn added(receipt: &AddedPerson, output: &mut Out<'_>) -> Result<()> {
    output.line(format!("person: {:x}", receipt.person))?;
    output.line(format!("profile: {:x}", receipt.profile))?;
    output.line(format!("lifecycle: {:x}", receipt.lifecycle))
}
pub fn profile_updated(receipt: &ProfileUpdate, output: &mut Out<'_>) -> Result<()> {
    if let Some(current) = receipt.current {
        output.line(format!("profile: {:x} -> {current:x}", receipt.previous))?;
    }
    if receipt.provenance_added {
        output.line(format!("Added provenance for {:x}.", receipt.person))?;
    } else if receipt.current.is_none() {
        output.line(format!("No profile change for {:x}.", receipt.person))?;
    }
    Ok(())
}
pub fn profile_reconciled(receipt: &ProfileReconciliation, output: &mut Out<'_>) -> Result<()> {
    match receipt {
        ProfileReconciliation::Settled(id) => {
            output.line(format!("Profile {id:x} is already settled."))
        }
        ProfileReconciliation::Reconciled { heads, successor } => {
            output.line(format!("profile: {heads} heads -> {successor:x}"))
        }
    }
}
pub fn lifecycle(receipt: &LifecycleChange, retired: bool, output: &mut Out<'_>) -> Result<()> {
    let state = if retired { "retired" } else { "active" };
    match receipt {
        LifecycleChange::Unchanged(person) => {
            output.line(format!("{person:x} is already {state}."))
        }
        LifecycleChange::Changed { person, successor } => {
            output.line(format!("{state}: {person:x} ({successor:x})"))
        }
    }
}
pub fn group_created(receipt: &AddedGroup, output: &mut Out<'_>) -> Result<()> {
    output.line(format!(
        "group: {:x}\nsnapshot: {:x}",
        receipt.group, receipt.snapshot
    ))
}
pub fn group_added(receipt: &GroupAddition, output: &mut Out<'_>) -> Result<()> {
    match receipt {
        GroupAddition::Already(person) => {
            output.line(format!("{person:x} is already represented in the group."))
        }
        GroupAddition::Changed { old, new } => output.line(format!("snapshot: {old:x} -> {new:x}")),
    }
}
pub fn group_removed(receipt: &GroupRemoval, output: &mut Out<'_>) -> Result<()> {
    match receipt {
        GroupRemoval::Absent(person) => {
            output.line(format!("{person:x} is not represented in the group."))
        }
        GroupRemoval::Changed { old, new } => output.line(format!("snapshot: {old:x} -> {new:x}")),
    }
}
pub fn group_renamed(receipt: &GroupRename, output: &mut Out<'_>) -> Result<()> {
    match receipt {
        GroupRename::Unchanged(name) => output.line(format!("Group is already named {name}.")),
        GroupRename::Changed { old, new } => output.line(format!("snapshot: {old:x} -> {new:x}")),
    }
}
pub fn group_reconciled(receipt: &GroupReconciliation, output: &mut Out<'_>) -> Result<()> {
    match receipt {
        GroupReconciliation::Settled(id) => {
            output.line(format!("Group is already settled at {id:x}."))
        }
        GroupReconciliation::Reconciled { heads, successor } => {
            output.line(format!("group: {heads} heads -> {successor:x}"))
        }
    }
}
pub fn identity(receipt: &IdentityChange, same: bool, output: &mut Out<'_>) -> Result<()> {
    match receipt {
        IdentityChange::Settled(id) => {
            output.line(format!("Identity verdict is already settled at {id:x}."))
        }
        IdentityChange::Changed {
            first,
            second,
            successor,
        } => {
            let relation = if same { "same-as" } else { "distinct-from" };
            output.line(format!(
                "identity: {first:x} {relation} {second:x} ({successor:x})"
            ))
        }
    }
}
