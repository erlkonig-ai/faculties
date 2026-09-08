use super::*;

fn snapshot(id: Id, outcome: decide::TextHandle, forced: bool) -> ResolutionSnapshot {
    ResolutionSnapshot {
        id,
        decision: genid().id,
        outcome,
        result: None,
        forced,
        evidence: Vec::new(),
        predecessors: Vec::new(),
        finished_at: epoch_interval(Epoch::from_unix_seconds(1.0)),
    }
}

#[test]
fn ordinary_actions_accept_only_missing_resolution() {
    let decision = genid().id;
    assert!(ensure_missing(&Resolution::Missing, "act", decision).is_ok());
    assert!(ensure_missing(&Resolution::Invalid("bad".into()), "act", decision).is_err());
}

#[test]
fn reconciliation_accepts_only_genuine_forks_and_keeps_every_head() {
    let decision = genid().id;
    let first = genid().id;
    let second = genid().id;
    let handle = Inline::new([0x11; 32]);
    let heads = reconciliation_heads(
        Resolution::Forked(vec![
            snapshot(first, handle, false),
            snapshot(second, handle, true),
        ]),
        decision,
    )
    .unwrap();
    assert_eq!(heads, vec![first, second]);
    assert!(reconciliation_heads(
        Resolution::Agreed(vec![
            snapshot(first, handle, false),
            snapshot(second, handle, false),
        ]),
        decision,
    )
    .is_err());
}
