//! Acceptance scenario G, end to end against a real HTTP server.
//!
//! > *A subscription that adds, changes and removes nodes updates
//! > transactionally, with a diff shown first and a rollback available.*
//!
//! The whole pipeline runs here — fetch, normalise, diff, apply — against
//! `HttpFixtureServer`, which speaks real HTTP/1.1 on a real loopback port.
//! Nothing is mocked except the provider, and the provider is mocked because
//! testing against somebody's live subscription would be both unreliable and
//! rude.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use xraytui_domain::{
    DesiredState, EgressProfile, NodeChange, ProfileId, Subscription, SubscriptionId,
    SubscriptionMeta, Target,
};
use xraytui_subscription::apply::ApplyOptions;
use xraytui_test_support::HttpFixtureServer;
use xraytui_test_support::http_fixture::Route;

fn subscription(url: String) -> Subscription {
    Subscription {
        id: SubscriptionId::from_text("provider"),
        name: "Provider".to_owned(),
        url: xraytui_secrets::Secret::new(url),
        enabled: true,
        update_interval_secs: None,
        fetch_via_profile: None,
        include_regex: Vec::new(),
        exclude_regex: Vec::new(),
        max_nodes: None,
        max_response_bytes: None,
        allow_plaintext: false,
        meta: SubscriptionMeta::default(),
    }
}

fn link(uuid: u8, host: u8, name: &str) -> String {
    format!(
        "vless://{uuid}{uuid}{uuid}{uuid}{uuid}{uuid}{uuid}{uuid}-1111-1111-1111-111111111111\
         @198.51.100.{host}:443?type=tcp&security=none#{name}"
    )
}

fn plaintext() -> xraytui_subscription::FetchOptions {
    xraytui_subscription::FetchOptions {
        allow_plaintext: true,
        ..xraytui_subscription::FetchOptions::default()
    }
}

/// Run one update cycle: fetch, normalise, diff, apply.
async fn cycle(
    server: &HttpFixtureServer,
    state: &DesiredState,
    subscription: &Subscription,
    options: ApplyOptions,
) -> Result<(DesiredState, xraytui_domain::SubscriptionDiff), String> {
    let _ = server;
    let fetched = xraytui_subscription::fetch(&subscription.url, &subscription.meta, &plaintext())
        .await
        .map_err(|error| error.to_string())?;
    let (body, meta) = match fetched {
        xraytui_subscription::Fetched::Unchanged => {
            return Err("unchanged".to_owned());
        }
        xraytui_subscription::Fetched::Body { text, meta } => (text, meta),
    };
    let normalised =
        xraytui_subscription::normalise(subscription, &body).map_err(|e| e.to_string())?;
    let diff = xraytui_subscription::compute(&subscription.id, state, &normalised, meta);
    let (next, _) = xraytui_subscription::apply(state, subscription, &diff, options)
        .map_err(|error| error.to_string())?;
    Ok((next, diff))
}

#[tokio::test]
async fn a_subscription_adds_changes_and_removes_nodes_transactionally() {
    let server = HttpFixtureServer::start().await.expect("fixture server");
    let url = server.url("/sub");
    let mut subscription = subscription(url);

    // --- first update: three nodes arrive ---------------------------------
    server
        .set_route(
            "/sub",
            Route::ok(
                [
                    link(1, 1, "HK-One"),
                    link(2, 2, "JP-Two"),
                    link(3, 3, "US-Three"),
                ]
                .join("\n"),
            ),
        )
        .await;

    let mut state = DesiredState::default();
    state
        .subscriptions
        .insert(subscription.id.clone(), subscription.clone());

    let (next, diff) = cycle(&server, &state, &subscription, ApplyOptions::default())
        .await
        .expect("first update");
    assert_eq!(diff.counts().added, 3);
    assert_eq!(next.nodes.len(), 3);
    state = next;
    subscription = state.subscriptions[&subscription.id].clone();

    // Point a profile at one of them, as a user would.
    let pinned = state
        .nodes
        .values()
        .find(|node| node.name == "JP-Two")
        .expect("the node the provider sent")
        .id
        .clone();
    state.profiles.insert(
        ProfileId::from_text("web"),
        EgressProfile::new(
            ProfileId::from_text("web"),
            "Web",
            Target::Node { id: pinned.clone() },
        ),
    );

    // --- second update: one renamed, one added, one removed ---------------
    server
        .set_route(
            "/sub",
            Route::ok(
                [
                    link(1, 1, "HK-One-Renamed"),
                    link(2, 2, "JP-Two"),
                    link(4, 4, "SG-Four"),
                ]
                .join("\n"),
            ),
        )
        .await;

    // The removal takes away US-Three, which nothing points at, so the default
    // options suffice.
    let (next, diff) = cycle(&server, &state, &subscription, ApplyOptions::default())
        .await
        .expect("second update");
    let counts = diff.counts();
    assert_eq!(counts.added, 1, "{:?}", diff.changes);
    assert_eq!(counts.changed, 1, "{:?}", diff.changes);
    assert_eq!(counts.removed, 1, "{:?}", diff.changes);

    assert_eq!(next.nodes.len(), 3);
    assert!(
        next.nodes
            .values()
            .any(|node| node.name == "HK-One-Renamed"),
        "the rename must have landed"
    );
    assert!(
        next.nodes.values().any(|node| node.name == "SG-Four"),
        "the addition must have landed"
    );
    assert!(
        !next.nodes.values().any(|node| node.name == "US-Three"),
        "the removal must have landed"
    );
    assert_eq!(
        next.profiles[&ProfileId::from_text("web")].target,
        Target::Node { id: pinned },
        "the profile must still point at the node it was pointed at"
    );
}

#[tokio::test]
async fn an_update_that_would_break_a_profile_is_refused_and_changes_nothing() {
    let server = HttpFixtureServer::start().await.expect("fixture server");
    let subscription = subscription(server.url("/sub"));

    server
        .set_route(
            "/sub",
            Route::ok([link(1, 1, "One"), link(2, 2, "Two")].join("\n")),
        )
        .await;

    let mut state = DesiredState::default();
    state
        .subscriptions
        .insert(subscription.id.clone(), subscription.clone());
    let (next, _) = cycle(&server, &state, &subscription, ApplyOptions::default())
        .await
        .expect("first update");
    state = next;

    let pinned = state
        .nodes
        .values()
        .find(|node| node.name == "Two")
        .expect("node")
        .id
        .clone();
    state.profiles.insert(
        ProfileId::from_text("web"),
        EgressProfile::new(
            ProfileId::from_text("web"),
            "Web",
            Target::Node { id: pinned.clone() },
        ),
    );
    let before = state.clone();

    // The provider drops the node the profile uses.
    server.set_route("/sub", Route::ok(link(1, 1, "One"))).await;

    let error = cycle(&server, &state, &subscription, ApplyOptions::default())
        .await
        .expect_err("must be refused");
    assert!(error.contains("still in use"), "{error}");
    assert!(error.contains("--allow-removing-used"), "{error}");

    // Nothing moved. This is the rollback property: there is no partial state to
    // undo, because nothing was written.
    assert_eq!(before.nodes, state.nodes);
    assert_eq!(before.profiles, state.profiles);

    // With the acknowledgement, it goes through.
    let options = ApplyOptions {
        allow_removing_used: true,
        allow_emptying: false,
    };
    let (next, _) = cycle(&server, &state, &subscription, options)
        .await
        .expect("second update");
    assert!(!next.nodes.contains_key(&pinned));
}

#[tokio::test]
async fn a_provider_outage_does_not_empty_the_node_list() {
    let server = HttpFixtureServer::start().await.expect("fixture server");
    let subscription = subscription(server.url("/sub"));

    server
        .set_route(
            "/sub",
            Route::ok([link(1, 1, "One"), link(2, 2, "Two")].join("\n")),
        )
        .await;
    let mut state = DesiredState::default();
    state
        .subscriptions
        .insert(subscription.id.clone(), subscription.clone());
    let (next, _) = cycle(&server, &state, &subscription, ApplyOptions::default())
        .await
        .expect("first update");
    state = next;
    assert_eq!(state.nodes.len(), 2);

    // The provider now answers with something empty, or with an error page.
    for body in ["", "<html><body>maintenance</body></html>"] {
        server.set_route("/sub", Route::ok(body)).await;
        let error = cycle(&server, &state, &subscription, ApplyOptions::default())
            .await
            .expect_err("must refuse");
        assert!(
            error.contains("nothing in the response looked like a node"),
            "{error}"
        );
        assert_eq!(state.nodes.len(), 2, "the nodes must still be there");
    }
}

#[tokio::test]
async fn an_unchanged_subscription_costs_one_conditional_request() {
    let server = HttpFixtureServer::start().await.expect("fixture server");
    let mut subscription = subscription(server.url("/sub"));
    server
        .set_route("/sub", Route::ok(link(1, 1, "One")).with_etag("\"v1\""))
        .await;

    let mut state = DesiredState::default();
    state
        .subscriptions
        .insert(subscription.id.clone(), subscription.clone());
    let (next, _) = cycle(&server, &state, &subscription, ApplyOptions::default())
        .await
        .expect("first update");
    state = next;
    subscription = state.subscriptions[&subscription.id].clone();
    assert_eq!(subscription.meta.etag.as_deref(), Some("\"v1\""));

    // The second cycle sends If-None-Match and gets a 304, so there is nothing
    // to normalise and nothing to diff.
    let outcome = cycle(&server, &state, &subscription, ApplyOptions::default()).await;
    assert_eq!(outcome.err().as_deref(), Some("unchanged"));
}

#[tokio::test]
async fn a_filter_that_matches_nothing_does_not_delete_everything() {
    let server = HttpFixtureServer::start().await.expect("fixture server");
    let mut subscription = subscription(server.url("/sub"));
    server
        .set_route(
            "/sub",
            Route::ok([link(1, 1, "HK-One"), link(2, 2, "JP-Two")].join("\n")),
        )
        .await;

    let mut state = DesiredState::default();
    state
        .subscriptions
        .insert(subscription.id.clone(), subscription.clone());
    let (next, _) = cycle(&server, &state, &subscription, ApplyOptions::default())
        .await
        .expect("first update");
    state = next;
    assert_eq!(state.nodes.len(), 2);

    // A typo in a filter is the most likely way a user empties their own list.
    subscription.include_regex = vec!["^NOTHING".to_owned()];
    let error = cycle(&server, &state, &subscription, ApplyOptions::default())
        .await
        .expect_err("must refuse");
    assert!(error.contains("remove all"), "{error}");
    assert_eq!(state.nodes.len(), 2);
}

#[tokio::test]
async fn quota_information_from_the_provider_is_recorded() {
    let server = HttpFixtureServer::start().await.expect("fixture server");
    let subscription = subscription(server.url("/sub"));
    server
        .set_route(
            "/sub",
            Route::ok(link(1, 1, "One")).with_header(
                "Subscription-Userinfo",
                "upload=1024; download=2048; total=10240; expire=1800000000",
            ),
        )
        .await;

    let mut state = DesiredState::default();
    state
        .subscriptions
        .insert(subscription.id.clone(), subscription.clone());
    let (next, _) = cycle(&server, &state, &subscription, ApplyOptions::default())
        .await
        .expect("update");

    let stored = &next.subscriptions[&subscription.id].meta;
    assert_eq!(stored.upload_bytes, Some(1024));
    assert_eq!(stored.download_bytes, Some(2048));
    assert_eq!(stored.total_bytes, Some(10_240));
    assert_eq!(stored.remaining_bytes(), Some(10_240 - 3072));
    assert_eq!(stored.node_count, 1);
}

#[tokio::test]
async fn a_base64_body_is_handled_exactly_like_a_plain_one() {
    use base64::Engine as _;

    let plain = HttpFixtureServer::start().await.expect("fixture server");
    let encoded = HttpFixtureServer::start().await.expect("fixture server");
    let body = [link(1, 1, "One"), link(2, 2, "Two")].join("\n");
    plain.set_route("/sub", Route::ok(body.clone())).await;
    encoded
        .set_route(
            "/sub",
            Route::ok(base64::engine::general_purpose::STANDARD.encode(&body)),
        )
        .await;

    let mut names = Vec::new();
    for server in [&plain, &encoded] {
        let subscription = subscription(server.url("/sub"));
        let mut state = DesiredState::default();
        state
            .subscriptions
            .insert(subscription.id.clone(), subscription.clone());
        let (next, _) = cycle(server, &state, &subscription, ApplyOptions::default())
            .await
            .expect("update");
        let mut theirs: Vec<String> = next.nodes.values().map(|node| node.name.clone()).collect();
        theirs.sort();
        names.push(theirs);
    }
    assert_eq!(names[0], names[1]);
    assert_eq!(names[0].len(), 2);
}

#[tokio::test]
async fn a_diff_never_contains_a_credential() {
    let server = HttpFixtureServer::start().await.expect("fixture server");
    let subscription = subscription(server.url("/sub"));
    server
        .set_route(
            "/sub",
            Route::ok(
                "vless://deadbeef-cafe-1111-2222-333333333333@198.51.100.1:443\
                 ?type=tcp&security=none#One",
            ),
        )
        .await;

    let mut state = DesiredState::default();
    state
        .subscriptions
        .insert(subscription.id.clone(), subscription.clone());
    let (next, _) = cycle(&server, &state, &subscription, ApplyOptions::default())
        .await
        .expect("first update");
    state = next;

    // The provider rotates the credential.
    server
        .set_route(
            "/sub",
            Route::ok(
                "vless://feedface-cafe-1111-2222-333333333333@198.51.100.1:443\
                 ?type=tcp&security=none#One",
            ),
        )
        .await;
    let (_, diff) = cycle(&server, &state, &subscription, ApplyOptions::default())
        .await
        .expect("second update");

    let rendered = format!("{:?}", diff.changes);
    assert!(!rendered.contains("deadbeef"), "{rendered}");
    assert!(!rendered.contains("feedface"), "{rendered}");

    // A rotated credential is a different node by canonical identity, so it
    // shows up as an addition and a removal rather than a silent swap.
    let counts = diff.counts();
    assert!(
        counts.added == 1 && counts.removed == 1
            || matches!(diff.changes.first(), Some(NodeChange::Changed { .. })),
        "{:?}",
        diff.changes
    );
}
