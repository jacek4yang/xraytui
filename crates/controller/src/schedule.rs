//! Deciding what to do next, and when.
//!
//! Two things in this project want to happen periodically without anybody
//! asking: probing nodes, and updating subscriptions. They want the same
//! machinery — an interval, a deadline, backoff when something fails, and
//! enough spread that a laptop waking from suspend does not fire everything at
//! once — so it is built once, here, and it is pure.
//!
//! # Pure, which means the interesting parts are testable
//!
//! Nothing here reads a clock. `now` is a parameter, so "a failure backs off,
//! and the fourth failure backs off four times as far, and it never backs off
//! past the cap" is a test rather than a claim. Nothing here spawns anything
//! either: [`Schedule::due`] returns what should run and the caller runs it.
//!
//! # Jitter without randomness
//!
//! Spread comes from a hash of the entry's key, not from a random number
//! generator. Two consequences, both wanted: the schedule is reproducible, so a
//! test can assert exact deadlines; and an entry's offset is stable across
//! restarts, so a daemon that restarts every few minutes does not re-roll its
//! way into a thundering herd.

use std::collections::BTreeMap;

/// Largest multiplier backoff will reach.
///
/// Six doublings: a five-minute interval becomes five hours and stops there. A
/// provider that has been down all day should still be tried occasionally,
/// because the thing that fixes it is usually the network coming back.
pub const MAX_BACKOFF_STEPS: u32 = 6;

/// Never schedule anything closer together than this, whatever the
/// configuration says.
///
/// A one-second probe interval on a hundred nodes is a way to look like an
/// attacker to your own proxy provider.
pub const MINIMUM_INTERVAL_SECS: u64 = 5;

/// Fraction of an interval used as the jitter window, as a divisor.
///
/// An eighth: enough to break up a herd, small enough that a five-minute
/// interval stays recognisably five minutes.
const JITTER_DIVISOR: u64 = 8;

/// One thing that wants doing periodically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Stable key. Also the jitter seed, so it must not change between runs.
    pub key: String,
    /// How often, in seconds, when everything is working.
    pub interval_secs: u64,
    /// Unix seconds when this is next allowed to run.
    pub due_at: u64,
    /// Consecutive failures, which drive backoff.
    pub failures: u32,
    /// Lower runs first when several are due at once.
    pub priority: u8,
}

impl Entry {
    /// A new entry, first due one interval from `now`.
    ///
    /// Not due *immediately*: a daemon that starts up should serve the user
    /// first and do its housekeeping after.
    #[must_use]
    pub fn new(key: impl Into<String>, interval_secs: u64, now: u64) -> Self {
        let key = key.into();
        let interval = interval_secs.max(MINIMUM_INTERVAL_SECS);
        let due_at = now
            .saturating_add(interval)
            .saturating_add(jitter(&key, interval));
        Self {
            key,
            interval_secs: interval,
            due_at,
            failures: 0,
            priority: 128,
        }
    }

    /// The same entry, due now.
    #[must_use]
    pub fn due_immediately(mut self) -> Self {
        self.due_at = 0;
        self
    }

    /// The same entry at a different priority.
    #[must_use]
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// The interval currently in force, including backoff.
    #[must_use]
    pub fn effective_interval(&self) -> u64 {
        let steps = self.failures.min(MAX_BACKOFF_STEPS);
        self.interval_secs.saturating_mul(1u64 << steps)
    }
}

/// A set of periodic entries.
#[derive(Debug, Clone, Default)]
pub struct Schedule {
    entries: BTreeMap<String, Entry>,
}

impl Schedule {
    /// An empty schedule.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many entries there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there is nothing to do.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add or replace an entry.
    ///
    /// Replacing preserves the existing deadline and failure count when the
    /// interval has not changed, so re-reading a configuration file does not
    /// reset every timer and cause a burst.
    pub fn insert(&mut self, entry: Entry) {
        match self.entries.get(&entry.key) {
            Some(existing) if existing.interval_secs == entry.interval_secs => {
                let mut kept = entry;
                kept.due_at = existing.due_at;
                kept.failures = existing.failures;
                self.entries.insert(kept.key.clone(), kept);
            }
            _ => {
                self.entries.insert(entry.key.clone(), entry);
            }
        }
    }

    /// Remove an entry that no longer applies.
    pub fn remove(&mut self, key: &str) {
        self.entries.remove(key);
    }

    /// Drop every entry whose key is not in `keys`.
    ///
    /// This is how a deleted node or subscription stops being probed without
    /// anybody having to remember to say so.
    pub fn retain_keys(&mut self, keys: &std::collections::BTreeSet<String>) {
        self.entries.retain(|key, _| keys.contains(key));
    }

    /// Look one up.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Entry> {
        self.entries.get(key)
    }

    /// Every entry, in key order.
    #[must_use]
    pub fn entries(&self) -> Vec<&Entry> {
        self.entries.values().collect()
    }

    /// What is due at `now`, most important first, at most `limit` of them.
    ///
    /// The limit is what keeps a hundred stale entries from becoming a hundred
    /// simultaneous network operations after a laptop wakes from suspend.
    #[must_use]
    pub fn due(&self, now: u64, limit: usize) -> Vec<String> {
        let mut ready: Vec<&Entry> = self
            .entries
            .values()
            .filter(|entry| now >= entry.due_at)
            .collect();
        // Priority first, then the one that has been waiting longest, then the
        // key — so the order is total and a test can assert it.
        ready.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then(a.due_at.cmp(&b.due_at))
                .then(a.key.cmp(&b.key))
        });
        ready
            .into_iter()
            .take(limit)
            .map(|entry| entry.key.clone())
            .collect()
    }

    /// When the next entry becomes due, if there is one.
    #[must_use]
    pub fn next_due(&self) -> Option<u64> {
        self.entries.values().map(|entry| entry.due_at).min()
    }

    /// Record that an entry ran successfully.
    pub fn succeeded(&mut self, key: &str, now: u64) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.failures = 0;
            entry.due_at = now
                .saturating_add(entry.interval_secs)
                .saturating_add(jitter(&entry.key, entry.interval_secs));
        }
    }

    /// Record that an entry failed, and back it off.
    pub fn failed(&mut self, key: &str, now: u64) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.failures = entry.failures.saturating_add(1);
            let interval = entry.effective_interval();
            entry.due_at = now
                .saturating_add(interval)
                .saturating_add(jitter(&entry.key, interval));
        }
    }
}

/// A stable offset in `0..interval/8`, derived from the key.
///
/// FNV-1a: small, fast, and — the property that matters here — the same on every
/// run and every machine, so deadlines are reproducible.
#[must_use]
pub fn jitter(key: &str, interval_secs: u64) -> u64 {
    let window = interval_secs / JITTER_DIVISOR;
    if window == 0 {
        return 0;
    }
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in key.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash % window
}

/// Priority bands, lowest number first.
pub mod priority {
    /// A profile's current target: if this is down, something is broken now.
    pub const ACTIVE: u8 = 0;
    /// A candidate a balancer could switch to.
    pub const CANDIDATE: u8 = 32;
    /// A hop in a chain that something points at.
    pub const CHAIN_HOP: u8 = 48;
    /// Everything else the user has configured.
    pub const CONFIGURED: u8 = 128;
    /// Housekeeping that can always wait.
    pub const BACKGROUND: u8 = 192;
}

/// Work out how important each node is to probe.
///
/// The ordering is the whole point: on a hundred-node subscription, probing
/// everything equally means the node the user is *currently using* is checked
/// as rarely as one they have never selected. What matters is:
///
/// 1. what a profile points at right now, directly or through a group or chain;
/// 2. what a group could switch to;
/// 3. hops in a chain something points at;
/// 4. everything else.
#[must_use]
pub fn node_priorities(
    state: &xraytui_domain::DesiredState,
) -> BTreeMap<xraytui_domain::NodeId, u8> {
    use xraytui_domain::Target;

    let mut out: BTreeMap<xraytui_domain::NodeId, u8> = state
        .nodes
        .keys()
        .map(|id| (id.clone(), priority::CONFIGURED))
        .collect();

    let mut raise = |id: &xraytui_domain::NodeId, level: u8| {
        if let Some(current) = out.get_mut(id) {
            *current = (*current).min(level);
        }
    };

    for profile in state.profiles.values() {
        if !profile.enabled {
            continue;
        }
        match &profile.target {
            Target::Node { id } => raise(id, priority::ACTIVE),
            Target::Group { id } => {
                for member in state.group_members(id) {
                    if let Target::Node { id } = member {
                        raise(&id, priority::CANDIDATE);
                    }
                }
            }
            Target::Chain { id } => {
                if let Some(chain) = state.chains.get(id) {
                    for hop in &chain.hops {
                        raise(hop, priority::CHAIN_HOP);
                    }
                }
            }
            Target::Direct | Target::Block => {}
        }
        if let Some(Target::Node { id }) = &profile.fallback {
            raise(id, priority::CANDIDATE);
        }
    }

    out
}

#[cfg(test)]
mod tests;
