//! The thing that happens without anybody asking.
//!
//! Health probes and subscription updates both want to run periodically. Both
//! use [`xraytui_controller::Schedule`], which is pure: it decides *what* and
//! *when*, and this module does it.
//!
//! # Three properties that matter on a laptop
//!
//! * **Nothing runs at start-up.** A daemon that has just come up should serve
//!   the user first. Every entry is first due one interval later.
//! * **Nothing stampedes.** After a suspend, everything is overdue at once; the
//!   sweeper takes a bounded number per tick, most important first, and comes
//!   back for the rest.
//! * **A failure backs off.** A provider that is down, or a node that is
//!   unreachable, is retried at a doubling interval up to a cap — often enough
//!   to notice when it comes back, rarely enough not to be a nuisance.
//!
//! # Why probes are prioritised
//!
//! On a hundred-node subscription, probing everything equally means the node
//! the user is *currently using* is checked as rarely as one they have never
//! selected. [`xraytui_controller::node_priorities`] puts active targets first,
//! then group candidates, then chain hops.

use std::time::Duration;

use tokio::sync::Mutex;
use xraytui_config::ConfigFile;
use xraytui_controller::{Entry, Schedule, node_priorities};
use xraytui_domain::NodeId;

/// How often the sweeper looks at its schedule.
///
/// Not the same as how often anything runs: this is the resolution at which
/// deadlines are noticed, and five seconds is fine for intervals measured in
/// minutes.
pub const TICK: Duration = Duration::from_secs(5);

/// Most entries started per tick.
///
/// The number that turns "everything is overdue after a suspend" into a queue
/// rather than a stampede.
pub const MAX_PER_TICK: usize = 4;

/// Prefix distinguishing the two kinds of entry in one schedule.
const NODE: &str = "node:";
/// As above, for subscriptions.
const SUBSCRIPTION: &str = "sub:";

/// The periodic worker.
#[derive(Debug)]
pub struct Sweeper {
    schedule: Mutex<Schedule>,
}

impl Default for Sweeper {
    fn default() -> Self {
        Self::new()
    }
}

impl Sweeper {
    /// An empty sweeper.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schedule: Mutex::new(Schedule::new()),
        }
    }

    /// How many entries are scheduled. For diagnostics and tests.
    pub async fn len(&self) -> usize {
        self.schedule.lock().await.len()
    }

    /// Bring the schedule in line with the configuration and the desired state.
    ///
    /// Called after every state change, so a node that was just added starts
    /// being probed and one that was removed stops, without anybody having to
    /// remember to say so. Entries whose interval has not changed keep their
    /// deadlines, so this is cheap to call often.
    pub async fn reconcile(
        &self,
        config: &ConfigFile,
        state: &xraytui_domain::DesiredState,
        now: u64,
    ) {
        let mut schedule = self.schedule.lock().await;
        let mut wanted = std::collections::BTreeSet::new();

        if config.health.enabled
            && let Some(interval) = config.health.interval_secs
        {
            let priorities = node_priorities(state);
            for (id, priority) in priorities {
                if !config.health.probe_idle_nodes
                    && priority >= xraytui_controller::priority::CONFIGURED
                {
                    // The user asked for probes of what matters, not of
                    // everything a provider ever sent them.
                    continue;
                }
                let Some(node) = state.nodes.get(&id) else {
                    continue;
                };
                if !node.enabled {
                    continue;
                }
                let key = format!("{NODE}{id}");
                wanted.insert(key.clone());
                schedule.insert(Entry::new(key, interval, now).with_priority(priority));
            }
        }

        for subscription in state.subscriptions.values() {
            let Some(interval) = subscription.update_interval_secs else {
                continue;
            };
            if !subscription.enabled {
                continue;
            }
            let key = format!("{SUBSCRIPTION}{}", subscription.id);
            wanted.insert(key.clone());
            schedule.insert(
                Entry::new(key, interval, now)
                    .with_priority(xraytui_controller::priority::BACKGROUND),
            );
        }

        schedule.retain_keys(&wanted);
    }

    /// Run whatever is due, and record how it went.
    ///
    /// Returns what was attempted, for the log line and for the tests.
    /// `run` performs one job and says whether it worked. Keeping the doing
    /// outside means the scheduling logic can be tested without a core, a
    /// network or a daemon.
    pub async fn tick<Run, Fut>(&self, now: u64, mut run: Run) -> Vec<Job>
    where
        Run: FnMut(Job) -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let due = self.schedule.lock().await.due(now, MAX_PER_TICK);
        let mut attempted = Vec::new();

        for key in due {
            let Some(job) = Job::parse(&key) else {
                continue;
            };
            let succeeded = run(job.clone()).await;
            let mut schedule = self.schedule.lock().await;
            if succeeded {
                schedule.succeeded(&key, now);
            } else {
                schedule.failed(&key, now);
            }
            drop(schedule);
            attempted.push(job);
        }
        attempted
    }

    /// When the next entry is due, for diagnostics.
    pub async fn next_due(&self) -> Option<u64> {
        self.schedule.lock().await.next_due()
    }
}

/// One unit of periodic work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Job {
    /// Probe a node.
    ProbeNode(NodeId),
    /// Update a subscription.
    UpdateSubscription(xraytui_domain::SubscriptionId),
}

impl Job {
    /// Recover a job from its schedule key.
    #[must_use]
    pub fn parse(key: &str) -> Option<Self> {
        if let Some(id) = key.strip_prefix(NODE) {
            return Some(Self::ProbeNode(NodeId::from_text(id)));
        }
        key.strip_prefix(SUBSCRIPTION)
            .map(|id| Self::UpdateSubscription(xraytui_domain::SubscriptionId::from_text(id)))
    }

    /// The schedule key for a job.
    #[must_use]
    pub fn key(&self) -> String {
        match self {
            Self::ProbeNode(id) => format!("{NODE}{id}"),
            Self::UpdateSubscription(id) => format!("{SUBSCRIPTION}{id}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xraytui_domain::{DesiredState, EgressProfile, ProfileId, Target};

    const NOW: u64 = 1_000_000;

    fn node(id: &str) -> xraytui_domain::Node {
        xraytui_domain::Node::new(
            NodeId::from_text(id),
            id,
            xraytui_domain::NodeSource::Manual,
            xraytui_domain::Endpoint::new("198.51.100.1", 443),
            xraytui_domain::ProtocolSettings::Vless(xraytui_domain::VlessSettings {
                id: xraytui_secrets::Secret::new("11111111-2222-3333-4444-555555555555"),
                flow: String::new(),
                encryption: "none".to_owned(),
                level: None,
            }),
        )
    }

    fn state() -> DesiredState {
        let mut state = DesiredState::default();
        for id in ["active", "idle"] {
            let node = node(id);
            state.nodes.insert(node.id.clone(), node);
        }
        state.profiles.insert(
            ProfileId::from_text("web"),
            EgressProfile::new(
                ProfileId::from_text("web"),
                "Web",
                Target::Node {
                    id: NodeId::from_text("active"),
                },
            ),
        );
        state
    }

    fn config() -> ConfigFile {
        let mut config = ConfigFile::default();
        config.health.enabled = true;
        config.health.interval_secs = Some(300);
        config.health.probe_idle_nodes = true;
        config
    }

    #[tokio::test]
    async fn reconciling_schedules_a_probe_for_every_enabled_node() {
        let sweeper = Sweeper::new();
        sweeper.reconcile(&config(), &state(), NOW).await;
        assert_eq!(sweeper.len().await, 2);
    }

    #[tokio::test]
    async fn a_node_that_goes_away_stops_being_scheduled() {
        let sweeper = Sweeper::new();
        let mut state = state();
        sweeper.reconcile(&config(), &state, NOW).await;
        assert_eq!(sweeper.len().await, 2);

        state.nodes.remove(&NodeId::from_text("idle"));
        sweeper.reconcile(&config(), &state, NOW).await;
        assert_eq!(sweeper.len().await, 1);
    }

    #[tokio::test]
    async fn a_disabled_node_is_not_probed() {
        let sweeper = Sweeper::new();
        let mut state = state();
        if let Some(node) = state.nodes.get_mut(&NodeId::from_text("idle")) {
            node.enabled = false;
        }
        sweeper.reconcile(&config(), &state, NOW).await;
        assert_eq!(sweeper.len().await, 1);
    }

    #[tokio::test]
    async fn probes_are_off_entirely_when_health_checking_is_off() {
        let sweeper = Sweeper::new();
        let mut config = config();
        config.health.enabled = false;
        sweeper.reconcile(&config, &state(), NOW).await;
        assert_eq!(sweeper.len().await, 0);
    }

    #[tokio::test]
    async fn without_probe_all_nodes_only_what_matters_is_scheduled() {
        let sweeper = Sweeper::new();
        let mut config = config();
        config.health.probe_idle_nodes = false;
        sweeper.reconcile(&config, &state(), NOW).await;
        // `active` is a profile target; `idle` is not.
        assert_eq!(sweeper.len().await, 1);
    }

    #[tokio::test]
    async fn a_subscription_with_an_interval_is_scheduled_and_one_without_is_not() {
        let sweeper = Sweeper::new();
        let mut state = state();
        let mut subscription = xraytui_domain::Subscription {
            id: xraytui_domain::SubscriptionId::from_text("provider"),
            name: "Provider".to_owned(),
            url: xraytui_secrets::Secret::new("https://example.test/sub"),
            enabled: true,
            update_interval_secs: None,
            fetch_via_profile: None,
            include_regex: Vec::new(),
            exclude_regex: Vec::new(),
            max_nodes: None,
            max_response_bytes: None,
            meta: xraytui_domain::SubscriptionMeta::default(),
        };
        state
            .subscriptions
            .insert(subscription.id.clone(), subscription.clone());

        let mut config = config();
        config.health.enabled = false;
        sweeper.reconcile(&config, &state, NOW).await;
        assert_eq!(sweeper.len().await, 0, "no interval means no schedule");

        subscription.update_interval_secs = Some(3600);
        state
            .subscriptions
            .insert(subscription.id.clone(), subscription);
        sweeper.reconcile(&config, &state, NOW).await;
        assert_eq!(sweeper.len().await, 1);
    }

    #[tokio::test]
    async fn nothing_runs_at_start_up() {
        let sweeper = Sweeper::new();
        sweeper.reconcile(&config(), &state(), NOW).await;
        let attempted = sweeper.tick(NOW, async |_| true).await;
        assert!(attempted.is_empty(), "{attempted:?}");
    }

    #[tokio::test]
    async fn work_becomes_due_and_a_success_pushes_it_out_again() {
        let sweeper = Sweeper::new();
        sweeper.reconcile(&config(), &state(), NOW).await;

        let later = NOW + 1000;
        let attempted = sweeper.tick(later, async |_| true).await;
        assert_eq!(attempted.len(), 2, "{attempted:?}");

        // Immediately afterwards there is nothing left to do.
        let again = sweeper.tick(later, async |_| true).await;
        assert!(again.is_empty(), "{again:?}");
    }

    #[tokio::test]
    async fn a_failure_is_retried_later_rather_than_immediately() {
        let sweeper = Sweeper::new();
        sweeper.reconcile(&config(), &state(), NOW).await;

        let later = NOW + 1000;
        let attempted = sweeper.tick(later, async |_| false).await;
        assert_eq!(attempted.len(), 2);

        // Backed off past one interval.
        let soon = sweeper.tick(later + 300, async |_| false).await;
        assert!(soon.is_empty(), "a failure must not be retried immediately");
        let eventually = sweeper.tick(later + 1200, async |_| true).await;
        assert_eq!(eventually.len(), 2);
    }

    #[tokio::test]
    async fn a_tick_never_starts_more_than_the_cap() {
        let sweeper = Sweeper::new();
        let mut state = DesiredState::default();
        for index in 0..50 {
            let node = node(&format!("node-{index:02}"));
            state.nodes.insert(node.id.clone(), node);
        }
        sweeper.reconcile(&config(), &state, NOW).await;

        // A week later everything is overdue.
        let attempted = sweeper.tick(NOW + 604_800, async |_| true).await;
        assert_eq!(attempted.len(), MAX_PER_TICK);
    }

    #[tokio::test]
    async fn the_active_node_is_probed_before_the_idle_one() {
        let sweeper = Sweeper::new();
        let mut state = DesiredState::default();
        // Enough nodes that the cap forces a choice.
        for index in 0..10 {
            let node = node(&format!("idle-{index:02}"));
            state.nodes.insert(node.id.clone(), node);
        }
        let active = node("zzz-active");
        state.nodes.insert(active.id.clone(), active);
        state.profiles.insert(
            ProfileId::from_text("web"),
            EgressProfile::new(
                ProfileId::from_text("web"),
                "Web",
                Target::Node {
                    id: NodeId::from_text("zzz-active"),
                },
            ),
        );

        sweeper.reconcile(&config(), &state, NOW).await;
        let attempted = sweeper.tick(NOW + 604_800, async |_| true).await;
        assert_eq!(
            attempted.first(),
            Some(&Job::ProbeNode(NodeId::from_text("zzz-active"))),
            "the node in use must be probed first, whatever its name sorts as: {attempted:?}"
        );
    }

    #[test]
    fn a_job_survives_a_round_trip_through_its_key() {
        for job in [
            Job::ProbeNode(NodeId::from_text("hk-01")),
            Job::UpdateSubscription(xraytui_domain::SubscriptionId::from_text("provider")),
        ] {
            assert_eq!(Job::parse(&job.key()), Some(job));
        }
        assert_eq!(Job::parse("nonsense"), None);
    }
}
