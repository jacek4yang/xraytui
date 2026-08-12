//! The terminal application as a state machine.
//!
//! # Why this is separate from drawing and from the terminal
//!
//! Everything here is pure: keys go in, an [`Action`] and a new state come out.
//! Nothing touches a terminal, a socket or a clock. That is what makes a
//! keyboard-driven interface testable — every key binding in the help screen is
//! asserted by a test that presses the key and checks what came back, rather
//! than by somebody trying it once.
//!
//! [`crate::render`] turns this state into cells; [`crate::terminal`] owns the
//! terminal itself and putting it back.

use xraytui_domain::{DesiredState, RuntimeState, SystemMode, Target};

/// The panes, in the order the number keys select them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum View {
    /// Egress profiles and what they point at. The screen people live on.
    #[default]
    Profiles,
    /// Nodes with their health.
    Nodes,
    /// Groups and chains.
    Groups,
    /// Application and routing rules.
    Rules,
    /// Subscriptions.
    Subscriptions,
    /// Core log lines as they arrive.
    Logs,
}

impl View {
    /// Every view, in tab order.
    pub const ALL: [Self; 6] = [
        Self::Profiles,
        Self::Nodes,
        Self::Groups,
        Self::Rules,
        Self::Subscriptions,
        Self::Logs,
    ];

    /// Title shown in the tab bar.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::Profiles => "Profiles",
            Self::Nodes => "Nodes",
            Self::Groups => "Groups",
            Self::Rules => "Rules",
            Self::Subscriptions => "Subs",
            Self::Logs => "Logs",
        }
    }

    /// The digit that selects this view.
    #[must_use]
    pub fn digit(self) -> char {
        match self {
            Self::Profiles => '1',
            Self::Nodes => '2',
            Self::Groups => '3',
            Self::Rules => '4',
            Self::Subscriptions => '5',
            Self::Logs => '6',
        }
    }

    /// The next view, wrapping.
    #[must_use]
    pub fn next(self) -> Self {
        let index = Self::ALL.iter().position(|view| *view == self).unwrap_or(0);
        Self::ALL[(index + 1) % Self::ALL.len()]
    }

    /// The previous view, wrapping.
    #[must_use]
    pub fn previous(self) -> Self {
        let index = Self::ALL.iter().position(|view| *view == self).unwrap_or(0);
        Self::ALL[(index + Self::ALL.len() - 1) % Self::ALL.len()]
    }
}

/// What the outer loop should do, having handled a key.
///
/// The state machine never performs I/O itself; it says what it wants and the
/// runner does it. That keeps every binding assertable without a daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Redraw and wait for the next event.
    None,
    /// Leave, restoring the terminal.
    Quit,
    /// Ask the daemon for fresh state.
    Refresh,
    /// Point a profile at a target.
    SetTarget {
        /// Profile to change.
        profile: String,
        /// Where to point it.
        target: Target,
    },
    /// Advance the system mode.
    CycleMode,
    /// Start the core.
    Up,
    /// Stop the core.
    Down,
    /// Probe one node.
    TestNode {
        /// Node to probe.
        node: String,
    },
    /// Something the user should read, shown in the status line.
    Notice(String),
}

/// Which overlay, if any, is on top.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Overlay {
    /// No overlay; keys go to the current view.
    #[default]
    None,
    /// The key reference.
    Help,
    /// Incremental filter over the current view's list.
    Filter {
        /// What has been typed.
        query: String,
    },
    /// Choosing a target for the selected profile.
    TargetPicker {
        /// Profile being changed.
        profile: String,
        /// Candidate targets, in display order.
        candidates: Vec<Target>,
        /// Highlighted candidate.
        selected: usize,
    },
    /// A question that needs y or n.
    Confirm {
        /// What is being asked.
        prompt: String,
        /// What to do if the answer is yes.
        action: Box<Action>,
    },
}

/// The whole interface.
#[derive(Debug, Default)]
pub struct App {
    /// What the user has configured.
    pub desired: DesiredState,
    /// What is actually running.
    pub runtime: RuntimeState,
    /// Current pane.
    pub view: View,
    /// Overlay on top of it.
    pub overlay: Overlay,
    /// Highlighted row in the current pane.
    pub cursor: usize,
    /// Active filter, applied to the current pane's list.
    pub filter: String,
    /// Most recent log lines, oldest first.
    pub logs: Vec<String>,
    /// The status line's current message.
    pub status: String,
    /// Set when the runner should stop.
    pub should_quit: bool,
    /// Whether the daemon is reachable.
    pub connected: bool,
}

/// How many log lines are kept.
///
/// The log pane is a tail, not an archive: `xraytui logs` exists for the rest,
/// and an unbounded buffer in a long-running terminal application is a slow
/// memory leak.
pub const LOG_CAPACITY: usize = 500;

impl App {
    /// A fresh application showing the profiles pane.
    #[must_use]
    pub fn new(desired: DesiredState, runtime: RuntimeState) -> Self {
        Self {
            desired,
            runtime,
            status: "? for keys, q to quit".to_owned(),
            connected: true,
            ..Self::default()
        }
    }

    /// Replace the state after a refresh, keeping the cursor in range.
    pub fn update(&mut self, desired: DesiredState, runtime: RuntimeState) {
        self.desired = desired;
        self.runtime = runtime;
        self.connected = true;
        self.clamp_cursor();
    }

    /// Append a log line, discarding the oldest when full.
    pub fn push_log(&mut self, line: impl Into<String>) {
        self.logs.push(line.into());
        if self.logs.len() > LOG_CAPACITY {
            let excess = self.logs.len() - LOG_CAPACITY;
            self.logs.drain(..excess);
        }
    }

    /// The rows of the current view, after filtering.
    #[must_use]
    pub fn rows(&self) -> Vec<Row> {
        let all: Vec<Row> = match self.view {
            View::Profiles => self
                .desired
                .profiles
                .values()
                .map(|profile| {
                    let live = self
                        .runtime
                        .profiles
                        .iter()
                        .find(|entry| entry.id == profile.id);
                    Row {
                        id: profile.id.as_str().to_owned(),
                        primary: profile.name.clone(),
                        secondary: profile.target.to_token(),
                        detail: live
                            .and_then(|entry| entry.effective_outbound.clone())
                            .unwrap_or_else(|| "--".to_owned()),
                        state: live
                            .map_or("--", |entry| entry.health.state().label())
                            .to_owned(),
                    }
                })
                .collect(),
            View::Nodes => self
                .desired
                .nodes
                .values()
                .map(|node| Row {
                    id: node.id.as_str().to_owned(),
                    primary: node.name.clone(),
                    secondary: format!("{}:{}", node.endpoint.address, node.endpoint.port),
                    detail: node.protocol.xray_protocol().to_owned(),
                    state: self
                        .runtime
                        .node_health
                        .get(&node.id)
                        .map_or("--", |health| health.state().label())
                        .to_owned(),
                })
                .collect(),
            View::Groups => self
                .desired
                .groups
                .values()
                .map(|group| Row {
                    id: group.id.as_str().to_owned(),
                    primary: group.name.clone(),
                    secondary: format!("{} members", self.desired.group_members(&group.id).len()),
                    detail: group.strategy.xray_strategy().to_owned(),
                    state: self
                        .runtime
                        .group_health
                        .get(&group.id)
                        .map_or("--", |health| health.state().label())
                        .to_owned(),
                })
                .chain(self.desired.chains.values().map(|chain| {
                    Row {
                        id: chain.id.as_str().to_owned(),
                        primary: chain.name.clone(),
                        secondary: format!("{} hops", chain.hops.len()),
                        detail: "chain".to_owned(),
                        state: self
                            .runtime
                            .chain_health
                            .get(&chain.id)
                            .map_or("--", |health| health.state().label())
                            .to_owned(),
                    }
                }))
                .collect(),
            View::Rules => self
                .desired
                .app_rules
                .values()
                .map(|rule| Row {
                    id: rule.id.as_str().to_owned(),
                    primary: rule
                        .process
                        .iter()
                        .map(|matcher| matcher.0.clone())
                        .collect::<Vec<_>>()
                        .join(", "),
                    secondary: rule.action.to_token(),
                    detail: format!("priority {}", rule.priority),
                    state: if rule.enabled { "on" } else { "off" }.to_owned(),
                })
                .chain(self.desired.routing_rules.values().map(|rule| Row {
                    id: rule.id.as_str().to_owned(),
                    primary: rule.id.as_str().to_owned(),
                    secondary: rule.action.to_token(),
                    detail: format!("priority {}", rule.priority),
                    state: if rule.enabled { "on" } else { "off" }.to_owned(),
                }))
                .collect(),
            View::Subscriptions => self
                .desired
                .subscriptions
                .values()
                .map(|subscription| Row {
                    id: subscription.id.as_str().to_owned(),
                    primary: subscription.name.clone(),
                    // `Secret`'s Display redacts. A subscription URL usually
                    // carries a reusable token, and the specification is
                    // explicit that it must never be shown.
                    secondary: subscription.url.to_string(),
                    detail: format!("{} nodes", subscription.meta.node_count),
                    state: if subscription.enabled { "on" } else { "off" }.to_owned(),
                })
                .collect(),
            View::Logs => self
                .logs
                .iter()
                .rev()
                .map(|line| Row {
                    id: String::new(),
                    primary: line.clone(),
                    secondary: String::new(),
                    detail: String::new(),
                    state: String::new(),
                })
                .collect(),
        };

        let needle = self.active_filter();
        if needle.is_empty() {
            return all;
        }
        let needle = needle.to_lowercase();
        all.into_iter()
            .filter(|row| {
                row.id.to_lowercase().contains(&needle)
                    || row.primary.to_lowercase().contains(&needle)
                    || row.secondary.to_lowercase().contains(&needle)
            })
            .collect()
    }

    /// The filter in force: the one being typed, or the one committed.
    #[must_use]
    pub fn active_filter(&self) -> &str {
        match &self.overlay {
            Overlay::Filter { query } => query,
            _ => &self.filter,
        }
    }

    /// The highlighted row, if the current view has one.
    #[must_use]
    pub fn selected(&self) -> Option<Row> {
        self.rows().into_iter().nth(self.cursor)
    }

    fn clamp_cursor(&mut self) {
        let len = self.rows().len();
        self.cursor = if len == 0 {
            0
        } else {
            self.cursor.min(len - 1)
        };
    }

    /// Handle one key.
    ///
    /// The overlay, when there is one, gets the key first: an interface where
    /// `q` sometimes quits and sometimes types a `q` into a filter is one people
    /// stop trusting.
    pub fn on_key(&mut self, key: Key) -> Action {
        match std::mem::take(&mut self.overlay) {
            Overlay::None => self.on_key_in_view(key),
            Overlay::Help => {
                // Any key dismisses; that is what people expect of a help
                // overlay, and it cannot swallow a keystroke that mattered
                // because nothing else is reachable while it is up.
                self.status = String::new();
                Action::None
            }
            Overlay::Filter { query } => self.on_key_in_filter(key, query),
            Overlay::TargetPicker {
                profile,
                candidates,
                selected,
            } => self.on_key_in_picker(key, profile, candidates, selected),
            Overlay::Confirm { prompt, action } => match key {
                Key::Char('y') | Key::Char('Y') => *action,
                Key::Char('n') | Key::Char('N') | Key::Escape => {
                    self.status = "cancelled".to_owned();
                    Action::None
                }
                _ => {
                    self.overlay = Overlay::Confirm { prompt, action };
                    Action::None
                }
            },
        }
    }

    fn on_key_in_view(&mut self, key: Key) -> Action {
        match key {
            Key::Char('q') => {
                self.should_quit = true;
                Action::Quit
            }
            Key::Char('?') => {
                self.overlay = Overlay::Help;
                Action::None
            }
            Key::Char('/') => {
                self.overlay = Overlay::Filter {
                    query: self.filter.clone(),
                };
                Action::None
            }
            Key::Escape => {
                if self.filter.is_empty() {
                    Action::None
                } else {
                    self.filter.clear();
                    self.clamp_cursor();
                    self.status = "filter cleared".to_owned();
                    Action::None
                }
            }
            Key::Tab => {
                self.view = self.view.next();
                self.cursor = 0;
                Action::None
            }
            Key::BackTab => {
                self.view = self.view.previous();
                self.cursor = 0;
                Action::None
            }
            Key::Char(digit @ '1'..='6') => {
                if let Some(view) = View::ALL.iter().find(|view| view.digit() == digit) {
                    self.view = *view;
                    self.cursor = 0;
                }
                Action::None
            }
            Key::Char('j') | Key::Down => {
                let len = self.rows().len();
                if len > 0 {
                    self.cursor = (self.cursor + 1).min(len - 1);
                }
                Action::None
            }
            Key::Char('k') | Key::Up => {
                self.cursor = self.cursor.saturating_sub(1);
                Action::None
            }
            Key::Char('g') | Key::Home => {
                self.cursor = 0;
                Action::None
            }
            Key::Char('G') | Key::End => {
                self.cursor = self.rows().len().saturating_sub(1);
                Action::None
            }
            Key::PageDown => {
                let len = self.rows().len();
                if len > 0 {
                    self.cursor = (self.cursor + 10).min(len - 1);
                }
                Action::None
            }
            Key::PageUp => {
                self.cursor = self.cursor.saturating_sub(10);
                Action::None
            }
            Key::Char('r') => Action::Refresh,
            Key::Char('m') => Action::CycleMode,
            Key::Char('u') => Action::Up,
            Key::Char('d') => Action::Down,
            Key::Char('t') => match (self.view, self.selected()) {
                (View::Nodes, Some(row)) => Action::TestNode { node: row.id },
                (View::Nodes, None) => Action::Notice("no node selected".to_owned()),
                _ => Action::Notice("t probes a node; switch to the Nodes pane".to_owned()),
            },
            Key::Enter => self.open_picker(),
            _ => Action::None,
        }
    }

    fn on_key_in_filter(&mut self, key: Key, mut query: String) -> Action {
        match key {
            Key::Escape => {
                self.status = "filter cancelled".to_owned();
                Action::None
            }
            Key::Enter => {
                self.filter = query;
                self.cursor = 0;
                self.status = if self.filter.is_empty() {
                    String::new()
                } else {
                    format!("filter: {}", self.filter)
                };
                Action::None
            }
            Key::Backspace => {
                query.pop();
                self.overlay = Overlay::Filter { query };
                self.cursor = 0;
                Action::None
            }
            Key::Char(c) => {
                query.push(c);
                self.overlay = Overlay::Filter { query };
                self.cursor = 0;
                Action::None
            }
            _ => {
                self.overlay = Overlay::Filter { query };
                Action::None
            }
        }
    }

    fn on_key_in_picker(
        &mut self,
        key: Key,
        profile: String,
        candidates: Vec<Target>,
        selected: usize,
    ) -> Action {
        match key {
            Key::Escape | Key::Char('q') => {
                self.status = "unchanged".to_owned();
                Action::None
            }
            Key::Char('j') | Key::Down => {
                let selected = (selected + 1).min(candidates.len().saturating_sub(1));
                self.overlay = Overlay::TargetPicker {
                    profile,
                    candidates,
                    selected,
                };
                Action::None
            }
            Key::Char('k') | Key::Up => {
                let selected = selected.saturating_sub(1);
                self.overlay = Overlay::TargetPicker {
                    profile,
                    candidates,
                    selected,
                };
                Action::None
            }
            Key::Enter => match candidates.get(selected) {
                Some(target) => Action::SetTarget {
                    profile,
                    target: target.clone(),
                },
                None => Action::Notice("nothing to point at".to_owned()),
            },
            _ => {
                self.overlay = Overlay::TargetPicker {
                    profile,
                    candidates,
                    selected,
                };
                Action::None
            }
        }
    }

    /// Offer everything a profile could be pointed at.
    fn open_picker(&mut self) -> Action {
        if self.view != View::Profiles {
            return Action::Notice("Enter picks a target; switch to the Profiles pane".to_owned());
        }
        let Some(row) = self.selected() else {
            return Action::Notice("no profile selected".to_owned());
        };
        let candidates = self.targets();
        let selected = candidates
            .iter()
            .position(|target| target.to_token() == row.secondary)
            .unwrap_or(0);
        self.overlay = Overlay::TargetPicker {
            profile: row.id,
            candidates,
            selected,
        };
        Action::None
    }

    /// Every target a profile could be pointed at, in a stable order.
    #[must_use]
    pub fn targets(&self) -> Vec<Target> {
        let mut out = vec![Target::Direct, Target::Block];
        out.extend(
            self.desired
                .nodes
                .keys()
                .cloned()
                .map(|id| Target::Node { id }),
        );
        out.extend(
            self.desired
                .groups
                .keys()
                .cloned()
                .map(|id| Target::Group { id }),
        );
        out.extend(
            self.desired
                .chains
                .keys()
                .cloned()
                .map(|id| Target::Chain { id }),
        );
        out
    }

    /// One-line summary for the header.
    #[must_use]
    pub fn headline(&self) -> String {
        let mode = self.runtime.mode;
        let core = match &self.runtime.core {
            xraytui_domain::CoreStatus::Running { pid, version, .. } => {
                format!("running pid {pid} ({version})")
            }
            xraytui_domain::CoreStatus::Starting { generation } => {
                format!("starting {generation}")
            }
            xraytui_domain::CoreStatus::Stopped => "stopped".to_owned(),
            other => format!("{other:?}")
                .split_whitespace()
                .next()
                .unwrap_or("unknown")
                .to_lowercase(),
        };
        let connection = if self.connected {
            String::new()
        } else {
            "  [daemon unreachable]".to_owned()
        };
        format!(
            "mode {}  core {core}  gen {}{connection}",
            mode_label(mode),
            self.runtime.generation
        )
    }
}

fn mode_label(mode: SystemMode) -> &'static str {
    mode.as_str()
}

/// One line in a list pane.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Row {
    /// Stable identifier, used when an action names the row.
    pub id: String,
    /// Leftmost column.
    pub primary: String,
    /// Second column.
    pub secondary: String,
    /// Third column.
    pub detail: String,
    /// Rightmost column, usually health.
    pub state: String,
}

/// A key, independent of the terminal library.
///
/// Keeping this separate from `crossterm::event::KeyCode` is what lets the
/// state machine be tested without a terminal, and what would let a different
/// backend be substituted without touching any of the logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// A printable character.
    Char(char),
    /// Return.
    Enter,
    /// Escape.
    Escape,
    /// Tab.
    Tab,
    /// Shift-Tab.
    BackTab,
    /// Backspace.
    Backspace,
    /// Arrow up.
    Up,
    /// Arrow down.
    Down,
    /// Page up.
    PageUp,
    /// Page down.
    PageDown,
    /// Home.
    Home,
    /// End.
    End,
    /// Anything else.
    Other,
}

/// The key reference, shown by `?` and used to generate the help overlay.
///
/// One table, so the overlay and the documentation cannot disagree.
pub const KEYS: &[(&str, &str)] = &[
    ("q", "quit"),
    ("?", "this help"),
    ("Tab / Shift-Tab", "next / previous pane"),
    ("1..6", "jump to a pane"),
    ("j / k, arrows", "move the cursor"),
    ("g / G", "first / last row"),
    ("PgUp / PgDn", "move ten rows"),
    ("/", "filter; Enter applies, Esc cancels"),
    ("Esc", "clear an applied filter"),
    ("Enter", "point the selected profile at a target"),
    ("m", "cycle the system mode"),
    ("u / d", "start / stop the core"),
    ("t", "probe the selected node"),
    ("r", "refresh from the daemon"),
];

#[cfg(test)]
mod tests;
