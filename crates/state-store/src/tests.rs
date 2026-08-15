//! Tests for the durable store.
//!
//! Every one uses a temporary directory: a test that wrote to the developer's
//! real XDG state directory would be a test that changed the machine it ran on.

use super::*;

fn store() -> StateStore {
    StateStore::in_memory().expect("in-memory store")
}

fn probe(ok: bool, latency: Option<u32>) -> ProbeResult {
    ProbeResult {
        at_unix_ms: 0,
        latency_ms: latency,
        outcome: if ok {
            ProbeOutcome::Ok
        } else {
            ProbeOutcome::ConnectFailed {
                detail: "refused".into(),
            }
        },
        kind: ProbeKind::TcpConnect,
    }
}

#[test]
fn a_fresh_store_recovers_nothing_rather_than_guessing() {
    let recovered = store().recover().expect("recover");
    assert_eq!(recovered, Recovered::default());
}

#[test]
fn mode_and_tunnel_state_survive() {
    let store = store();
    store.record_mode(SystemMode::Rule, true).expect("record");
    let recovered = store.recover().expect("recover");
    assert_eq!(recovered.mode, Some(SystemMode::Rule));
    assert!(recovered.tun_enabled);

    store.record_mode(SystemMode::Off, false).expect("record");
    let recovered = store.recover().expect("recover");
    assert_eq!(recovered.mode, Some(SystemMode::Off));
    assert!(!recovered.tun_enabled);
}

#[test]
fn profile_targets_come_back_in_a_stable_order() {
    let store = store();
    store
        .record_profile_target("work", "node:hk-01", 10)
        .expect("record");
    store
        .record_profile_target("media", "group:fast", 11)
        .expect("record");
    // A second write for the same profile replaces rather than duplicates: a
    // profile has one target, and a stale row would be replayed after a restart.
    store
        .record_profile_target("work", "chain:relay", 12)
        .expect("record");

    let recovered = store.recover().expect("recover");
    assert_eq!(
        recovered.profile_targets,
        vec![
            ("media".to_owned(), "group:fast".to_owned()),
            ("work".to_owned(), "chain:relay".to_owned()),
        ]
    );

    store.forget_profile("media").expect("forget");
    let recovered = store.recover().expect("recover");
    assert_eq!(recovered.profile_targets.len(), 1);
}

#[test]
fn the_last_known_good_generation_survives() {
    let store = store();
    store
        .record_last_known_good(GenerationId(7), 1_700_000_000)
        .expect("record");
    let recovered = store.recover().expect("recover");
    assert_eq!(recovered.last_known_good, Some(GenerationId(7)));
    assert_eq!(recovered.last_known_good_at, Some(1_700_000_000));
}

#[test]
fn an_unfinished_transaction_is_reported_as_interrupted() {
    let store = store();
    let token = store
        .begin_transaction("migrate", "nodes.toml 1 -> 2", 100)
        .expect("begin");
    assert!(
        store.recover().expect("recover").interrupted.is_some(),
        "a started transaction must be visible while it is running"
    );

    store.finish_transaction(token, 101).expect("finish");
    assert!(
        store.recover().expect("recover").interrupted.is_none(),
        "a finished transaction is not an interruption"
    );

    // The case that matters: begun, never finished, then the process died.
    store
        .begin_transaction("subscription-update", "upstream", 200)
        .expect("begin");
    let interrupted = store
        .recover()
        .expect("recover")
        .interrupted
        .expect("interrupted");
    assert_eq!(interrupted.operation, "subscription-update");
    assert_eq!(interrupted.detail, "upstream");
    assert_eq!(interrupted.started_at, 200);

    store.clear_interrupted().expect("clear");
    assert!(store.recover().expect("recover").interrupted.is_none());
}

#[test]
fn subscription_metadata_tracks_success_and_failure() {
    let store = store();
    let id = SubscriptionId::new("upstream").expect("id");
    assert_eq!(
        store.subscription(&id).expect("read"),
        SubscriptionState::default()
    );

    store
        .record_subscription_success(&id, 100, Some("\"abc\""))
        .expect("success");
    let state = store.subscription(&id).expect("read");
    assert_eq!(state.last_success, Some(100));
    assert_eq!(state.etag.as_deref(), Some("\"abc\""));
    assert_eq!(state.failures, 0);

    store
        .record_subscription_failure(&id, 200, "connection refused")
        .expect("failure");
    store
        .record_subscription_failure(&id, 300, "connection refused")
        .expect("failure");
    let state = store.subscription(&id).expect("read");
    assert_eq!(state.failures, 2, "failures accumulate");
    assert_eq!(
        state.last_success,
        Some(100),
        "a failure must not erase the last success, or the next update would refetch everything"
    );
    assert_eq!(state.last_attempt, Some(300));

    // A success clears the failure streak, and the ETag is replaced.
    store
        .record_subscription_success(&id, 400, None)
        .expect("success");
    let state = store.subscription(&id).expect("read");
    assert_eq!(state.failures, 0);
    assert!(state.last_error.is_none());
    assert!(state.etag.is_none());
}

#[test]
fn health_is_folded_from_the_stored_history() {
    let store = store();
    let subject = node_subject(&NodeId::new("hk-01").expect("id"));
    store
        .record_probe(&subject, 1, &probe(true, Some(40)))
        .expect("probe");
    store
        .record_probe(&subject, 2, &probe(true, Some(60)))
        .expect("probe");
    store
        .record_probe(&subject, 3, &probe(false, None))
        .expect("probe");

    let health = store.health(&subject).expect("health");
    assert_eq!(health.attempts, 3);
    assert_eq!(health.successes, 2);
    assert_eq!(health.consecutive_failures, 1, "the newest probe failed");
    assert!(health.ema_latency_ms.is_some());
    assert!(matches!(
        health.last.as_ref().map(|last| &last.outcome),
        Some(ProbeOutcome::ConnectFailed { .. })
    ));

    // A success resets the streak but not the window.
    store
        .record_probe(&subject, 4, &probe(true, Some(50)))
        .expect("probe");
    let health = store.health(&subject).expect("health");
    assert_eq!(health.consecutive_failures, 0);
    assert_eq!(health.attempts, 4);
}

#[test]
fn history_is_bounded_per_subject() {
    let store = store();
    let subject = node_subject(&NodeId::new("hk-01").expect("id"));
    for index in 0..(HISTORY_LIMIT as u64 + 50) {
        store
            .record_probe(&subject, index, &probe(true, Some(10)))
            .expect("probe");
    }
    let health = store.health(&subject).expect("health");
    assert_eq!(
        health.attempts as usize, HISTORY_LIMIT,
        "trimming happens in the same transaction as the insert, so the bound is exact"
    );
}

#[test]
fn one_subject_does_not_trim_another() {
    let store = store();
    let a = node_subject(&NodeId::new("hk-01").expect("id"));
    let b = node_subject(&NodeId::new("us-01").expect("id"));
    store
        .record_probe(&b, 1, &probe(true, Some(10)))
        .expect("probe");
    for index in 0..(HISTORY_LIMIT as u64 + 10) {
        store
            .record_probe(&a, index, &probe(true, Some(10)))
            .expect("probe");
    }
    assert_eq!(store.health(&b).expect("health").attempts, 1);
}

#[test]
fn node_health_lists_only_nodes() {
    let store = store();
    store
        .record_probe(
            &node_subject(&NodeId::new("hk-01").expect("id")),
            1,
            &probe(true, Some(9)),
        )
        .expect("probe");
    store
        .record_probe(&profile_subject("work"), 1, &probe(true, Some(9)))
        .expect("probe");

    let health = store.node_health().expect("node health");
    assert_eq!(health.len(), 1, "a profile is not a node");
    assert_eq!(health[0].0.as_str(), "hk-01");
}

#[test]
fn pruning_drops_old_probes_and_keeps_recent_ones() {
    let store = store();
    let subject = node_subject(&NodeId::new("hk-01").expect("id"));
    store
        .record_probe(&subject, 10, &probe(true, Some(10)))
        .expect("probe");
    store
        .record_probe(&subject, 5_000, &probe(true, Some(10)))
        .expect("probe");
    let removed = store.prune(1_000).expect("prune");
    assert_eq!(removed, 1);
    assert_eq!(store.health(&subject).expect("health").attempts, 1);
}

#[test]
fn a_failure_reason_is_bounded_and_stored_without_the_credential() {
    let store = store();
    let subject = node_subject(&NodeId::new("hk-01").expect("id"));
    let long = "x".repeat(5_000);
    store
        .record_probe(
            &subject,
            1,
            &ProbeResult {
                at_unix_ms: 0,
                latency_ms: None,
                outcome: ProbeOutcome::NotRun { reason: long },
                kind: ProbeKind::TcpConnect,
            },
        )
        .expect("probe");
    let health = store.health(&subject).expect("health");
    let detail = match health.last.expect("last").outcome {
        ProbeOutcome::ConnectFailed { detail } => detail,
        other => panic!("unexpected outcome {other:?}"),
    };
    assert!(detail.len() < 400, "a reason must not grow without bound");
}

#[test]
fn the_database_and_its_directory_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("state/state.sqlite3");
    let store = StateStore::open(&path).expect("open");
    store.record_mode(SystemMode::Direct, false).expect("write");

    let mode = |path: &Path| {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(
        mode(&path),
        0o600,
        "the database must not be world-readable"
    );
    assert_eq!(mode(path.parent().expect("parent")), 0o700);
    drop(store);
}

#[test]
fn a_store_written_by_a_newer_build_is_refused() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("state.sqlite3");
    {
        let connection = Connection::open(&path).expect("open");
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .expect("bump");
    }
    let error = StateStore::open(&path).expect_err("must refuse");
    assert!(
        matches!(error, StoreError::TooNew { .. }),
        "a downgrade must not silently mangle state: {error}"
    );
}

#[test]
fn reopening_keeps_everything() {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("state.sqlite3");
    {
        let store = StateStore::open(&path).expect("open");
        store.record_mode(SystemMode::Global, true).expect("mode");
        store
            .record_profile_target("work", "node:hk-01", 1)
            .expect("target");
        store
            .record_probe(
                &node_subject(&NodeId::new("hk-01").expect("id")),
                1,
                &probe(true, Some(12)),
            )
            .expect("probe");
    }
    let store = StateStore::open(&path).expect("reopen");
    let recovered = store.recover().expect("recover");
    assert_eq!(recovered.mode, Some(SystemMode::Global));
    assert!(recovered.tun_enabled);
    assert_eq!(recovered.profile_targets.len(), 1);
    assert_eq!(store.node_health().expect("health").len(), 1);
}
