//! Blocking rules in the engine (v0.2, design spec §5.6).
//!
//! Rules are saved in the encrypted store and applied as Windows Filtering
//! Platform filters (`win-firewall`). This module keeps the two in step:
//!
//! - **At start-up** it makes the firewall match the saved rules: it adds
//!   what is missing and removes what no rule asks for, so rules survive
//!   restarts and upgrades (uninstalling removes all filters).
//! - **Domain rules** are blocked by address: when the Windows DNS service
//!   confirms that a blocked domain (or a subdomain) resolved to an address,
//!   that address is blocked for the rule's program, or for every program.
//!   Only *confirmed* answers count, so an app cannot fake a lookup to get
//!   an innocent address blocked for everyone. Learned addresses expire a
//!   day after they were learned unless the domain resolves to them again,
//!   because shared cloud addresses get reused by other sites.
//! - **Pause** removes every filter but keeps the rules; resuming re-applies
//!   them. The paused state is saved.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use whereabouts_core::text::display_safe;
use whereabouts_ipc::{MAX_RULE_PATH, MAX_RULES, Response, RuleSpec, RuleView};
use whereabouts_store::{RuleTarget, Store, StoredRule};
use whereabouts_win_firewall::{Block, BlockError, Firewall, check_guard, normalize_path};

/// The saved setting for "blocking is paused".
const PAUSED_SETTING: &str = "blocking_paused";

/// How long a learned address stays blocked without being seen again.
const LEARNED_FOR: Duration = Duration::from_secs(24 * 60 * 60);

/// After this long, a learned address seen again is re-added with a fresh
/// time (so it does not expire while the domain still uses it).
const REFRESH_AFTER: Duration = Duration::from_secs(12 * 60 * 60);

/// Most learned addresses kept per domain rule; the oldest go first.
const MAX_LEARNED_PER_RULE: usize = 256;

/// Longest domain name accepted (DNS limit).
const MAX_DOMAIN: usize = 253;

/// Most addresses remembered as used by unblocked domains.
const MAX_SHARED: usize = 4096;

/// Checks a rule from a client and puts it in its one saved spelling:
/// program paths must exist and are normalised, domains are cleaned, and
/// what Whereabouts never blocks (core Windows programs, DNS servers, the
/// local network...) is refused before anything is saved.
pub fn checked_target(spec: RuleSpec) -> Result<RuleTarget, String> {
    let program = |path: &str| -> Result<String, String> {
        if path.chars().count() > MAX_RULE_PATH {
            return Err(format!(
                "the program path is longer than {MAX_RULE_PATH} characters"
            ));
        }
        let normal =
            normalize_path(Path::new(path)).map_err(|e| format!("{}: {e}", display_safe(path)))?;
        check_guard(&Block::App {
            path: normal.clone(),
        })
        .map_err(|refusal| format!("not blocked: {refusal}"))?;
        normal
            .into_os_string()
            .into_string()
            .map_err(|_| String::from("the program path is not valid text"))
    };
    match spec {
        RuleSpec::App { path } => Ok(RuleTarget::App {
            path: program(&path)?,
        }),
        RuleSpec::Domain { name, app } => Ok(RuleTarget::Domain {
            name: clean_domain(&name)?,
            app: app.as_deref().map(program).transpose()?,
        }),
        RuleSpec::Address { ip, app } => {
            let ip = ip.to_canonical();
            let app = app.as_deref().map(program).transpose()?;
            check_guard(&Block::Address {
                ip,
                app: None,
                via: None,
                learned: 0,
            })
            .map_err(|refusal| format!("not blocked: {refusal}"))?;
            Ok(RuleTarget::Address { ip, app })
        }
    }
}

/// A saved rule as clients see it.
fn view(state: &RuleState) -> RuleView {
    RuleView {
        id: state.rule.id,
        rule: match &state.rule.target {
            RuleTarget::App { path } => RuleSpec::App { path: path.clone() },
            RuleTarget::Domain { name, app } => RuleSpec::Domain {
                name: name.clone(),
                app: app.clone(),
            },
            RuleTarget::Address { ip, app } => RuleSpec::Address {
                ip: *ip,
                app: app.clone(),
            },
        },
        created_secs: unix_secs(state.rule.created),
        blocked_addresses: u64::try_from(state.learned).unwrap_or(u64::MAX),
    }
}

/// What a client asked the engine to do with the rules.
#[derive(Debug)]
pub enum RuleCommand {
    List,
    Add(RuleSpec),
    Remove(i64),
    SetPaused(bool),
}

/// The engine's blocking: started when the first rule exists, so the
/// firewall is not touched until the user blocks something.
pub struct Blocking<F: Firewalls> {
    blocker: Option<Blocker<F>>,
    open: fn() -> io::Result<F>,
}

impl<F: Firewalls> std::fmt::Debug for Blocking<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blocking")
            .field("blocker", &self.blocker)
            .finish_non_exhaustive()
    }
}

impl<F: Firewalls> Blocking<F> {
    /// Starts blocking if rules are saved; otherwise waits for the first
    /// rule. Problems are reported, not fatal: capture carries on.
    pub fn start(open: fn() -> io::Result<F>, store: Option<&Store>, now: SystemTime) -> Self {
        let mut blocking = Self {
            blocker: None,
            open,
        };
        if let Some(store) = store {
            match store.rules() {
                Ok(rules) if rules.is_empty() => {}
                Ok(_) => {
                    if let Err(error) = blocking.ensure(store, now) {
                        report!("warning: blocking rules are not applied: {error}");
                    }
                }
                Err(error) => report!("warning: could not read the blocking rules: {error}"),
            }
        }
        blocking
    }

    /// The running blocker, started if needed.
    fn ensure(&mut self, store: &Store, now: SystemTime) -> Result<&mut Blocker<F>, String> {
        if self.blocker.is_none() {
            let firewall =
                (self.open)().map_err(|e| format!("could not open the firewall: {e}"))?;
            let (blocker, warnings) = Blocker::start(firewall, store, now)?;
            for warning in warnings {
                report!("warning: blocking: {warning}");
            }
            self.blocker = Some(blocker);
        }
        self.blocker
            .as_mut()
            .ok_or_else(|| String::from("blocking did not start"))
    }

    /// Called for each answer the Windows DNS service confirmed.
    pub fn on_confirmed_answer(
        &mut self,
        name: &str,
        aliases: &[String],
        addresses: &[IpAddr],
        now: SystemTime,
    ) {
        if let Some(blocker) = self.blocker.as_mut() {
            blocker.on_confirmed_chain(name, aliases, addresses, now);
        }
    }

    /// Called on each refresh.
    pub fn expire(&mut self, now: SystemTime) {
        if let Some(blocker) = self.blocker.as_mut() {
            blocker.expire(now);
        }
    }

    /// How many rules are saved, and whether blocking is paused (for the
    /// status).
    pub fn summary(&self) -> (u64, bool) {
        self.blocker.as_ref().map_or((0, false), |b| {
            (u64::try_from(b.rules.len()).unwrap_or(u64::MAX), b.paused)
        })
    }

    /// Answers a client's rule command.
    pub fn answer(
        &mut self,
        store: Option<&mut Store>,
        command: RuleCommand,
        now: SystemTime,
    ) -> Response {
        let error = |message: String| Response::Error { message };
        let Some(store) = store else {
            return error(String::from(
                "blocking rules need the saved data, which is not available",
            ));
        };
        let listed = |blocker: Option<&Blocker<F>>, store: &Store| -> Response {
            match blocker {
                Some(blocker) => Response::Rules {
                    rules: blocker.states().iter().map(view).collect(),
                    paused: blocker.paused,
                },
                // Not started: no rules were saved yet (or applying them
                // failed); list what is saved.
                None => match (store.rules(), store.setting(PAUSED_SETTING)) {
                    (Ok(rules), Ok(paused)) => Response::Rules {
                        rules: rules
                            .into_iter()
                            .map(|rule| view(&RuleState { rule, learned: 0 }))
                            .collect(),
                        paused: paused.as_deref() == Some("true"),
                    },
                    (Err(e), _) | (_, Err(e)) => Response::Error {
                        message: format!("could not read the rules: {e}"),
                    },
                },
            }
        };
        match command {
            RuleCommand::List => listed(self.blocker.as_ref(), store),
            RuleCommand::Add(spec) => {
                let target = match checked_target(spec) {
                    Ok(target) => target,
                    Err(message) => return error(message),
                };
                match self
                    .ensure(store, now)
                    .and_then(|blocker| blocker.add(store, target, now))
                {
                    Ok((id, already)) => Response::RuleAdded { id, already },
                    Err(message) => error(message),
                }
            }
            RuleCommand::Remove(id) => {
                match self
                    .ensure(store, now)
                    .and_then(|blocker| blocker.remove(store, id, now))
                {
                    Ok(true) => listed(self.blocker.as_ref(), store),
                    Ok(false) => error(format!("there is no rule {id}")),
                    Err(message) => error(message),
                }
            }
            RuleCommand::SetPaused(paused) => {
                match self
                    .ensure(store, now)
                    .and_then(|blocker| blocker.set_paused(store, paused, now))
                {
                    Ok(warnings) => {
                        for warning in warnings {
                            report!("warning: blocking: {warning}");
                        }
                        listed(self.blocker.as_ref(), store)
                    }
                    Err(message) => error(message),
                }
            }
        }
    }
}

/// The firewall operations the blocker needs (the real firewall, or a fake
/// in tests).
pub trait Firewalls {
    fn block(&mut self, block: &Block) -> Result<(), BlockError>;
    fn unblock(&mut self, block: &Block) -> io::Result<bool>;
    fn current(&self) -> io::Result<Vec<Block>>;
    fn remove_all(&mut self) -> io::Result<usize>;
}

impl Firewalls for Firewall {
    fn block(&mut self, block: &Block) -> Result<(), BlockError> {
        Firewall::block(self, block)
    }
    fn unblock(&mut self, block: &Block) -> io::Result<bool> {
        Firewall::unblock(self, block)
    }
    fn current(&self) -> io::Result<Vec<Block>> {
        self.rules()
    }
    fn remove_all(&mut self) -> io::Result<usize> {
        Firewall::remove_all(self)
    }
}

/// An address learned for a domain rule and currently blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Learned {
    rule: i64,
    ip: IpAddr,
    app: Option<PathBuf>,
    domain: String,
    learned: u64,
}

impl Learned {
    fn block(&self) -> Block {
        Block::learned_address(self.ip, self.app.clone(), &self.domain, self.learned)
    }
}

/// A rule and what is blocked for it right now, for clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleState {
    pub rule: StoredRule,
    /// Addresses currently blocked for a domain rule.
    pub learned: usize,
}

/// The engine's blocking rules.
pub struct Blocker<F: Firewalls> {
    firewall: F,
    rules: Vec<StoredRule>,
    paused: bool,
    learned: Vec<Learned>,
    /// Addresses the DNS service confirmed for domains no "every app"
    /// domain rule covers, and when. "Every app" domain rules never block
    /// these: the address is shared (a CDN), or the blocked domain's owner
    /// pointed it at someone else's server.
    shared: HashMap<IpAddr, SystemTime>,
}

impl<F: Firewalls> std::fmt::Debug for Blocker<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Blocker")
            .field("rules", &self.rules.len())
            .field("paused", &self.paused)
            .field("learned", &self.learned.len())
            .finish()
    }
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A domain name in its one accepted spelling: lowercase ASCII letters,
/// digits, `-`, `_` and dots, with at least one dot and no empty labels.
pub fn clean_domain(name: &str) -> Result<String, String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let valid = !name.is_empty()
        && name.len() <= MAX_DOMAIN
        && name.contains('.')
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
        })
        && name
            .split('.')
            .all(|label| !label.is_empty() && label.len() <= 63);
    if valid {
        Ok(name)
    } else {
        Err(format!(
            "{name:?} is not a domain name like tracker.example.com"
        ))
    }
}

/// Whether `name` is `domain` or one of its subdomains.
fn covers(domain: &str, name: &str) -> bool {
    name == domain
        || (name.len() > domain.len()
            && name.ends_with(domain)
            && name.as_bytes()[name.len() - domain.len() - 1] == b'.')
}

impl<F: Firewalls> Blocker<F> {
    /// Loads the saved rules and makes the firewall match them.
    pub fn start(
        firewall: F,
        store: &Store,
        now: SystemTime,
    ) -> Result<(Self, Vec<String>), String> {
        let rules = store.rules().map_err(|e| e.to_string())?;
        let paused = store
            .setting(PAUSED_SETTING)
            .map_err(|e| e.to_string())?
            .as_deref()
            == Some("true");
        let mut blocker = Self {
            firewall,
            rules,
            paused,
            learned: Vec::new(),
            shared: HashMap::new(),
        };
        let warnings = blocker.reconcile(now);
        Ok((blocker, warnings))
    }

    /// Makes the firewall match the rules: keeps what is wanted (including
    /// fresh learned addresses of domain rules), adds what is missing and
    /// removes everything else. Returns warnings for rules that could not
    /// be applied.
    pub fn reconcile(&mut self, now: SystemTime) -> Vec<String> {
        let mut warnings = Vec::new();
        let current = match self.firewall.current() {
            Ok(current) => current,
            Err(error) => return vec![format!("could not read the firewall rules: {error}")],
        };
        // Learned addresses still backed by a domain rule and still fresh.
        self.learned.clear();
        if !self.paused {
            for block in &current {
                if let Block::Address {
                    ip,
                    app,
                    via: Some(domain),
                    learned,
                } = block
                    && let Some(rule) = self.domain_rule_for(domain, app.as_deref())
                    && now
                        .duration_since(UNIX_EPOCH + Duration::from_secs(*learned))
                        .is_ok_and(|age| age < LEARNED_FOR)
                {
                    self.learned.push(Learned {
                        rule,
                        ip: *ip,
                        app: app.clone(),
                        domain: domain.clone(),
                        learned: *learned,
                    });
                }
            }
        }
        let wanted: Vec<Block> = if self.paused {
            Vec::new()
        } else {
            self.static_blocks(&mut warnings)
                .into_iter()
                .chain(self.learned.iter().map(Learned::block))
                .collect()
        };
        // Remove what is not wanted (compared by identity, not by the
        // domain or time stored with it).
        for block in &current {
            if !wanted.iter().any(|w| same_rule(w, block))
                && let Err(error) = self.firewall.unblock(block)
            {
                warnings.push(format!("could not remove {}: {error}", block.describe()));
            }
        }
        for block in &wanted {
            // App blocks are always added again (harmless when complete):
            // those made by 0.2.0 have no filters for incoming connections,
            // and listing finds them by their outgoing ones.
            let missing =
                matches!(block, Block::App { .. }) || !current.iter().any(|c| same_rule(c, block));
            if missing && let Err(error) = self.firewall.block(block) {
                warnings.push(format!("could not block {}: {error}", block.describe()));
            }
        }
        warnings
    }

    /// The firewall blocks for app and address rules.
    fn static_blocks(&self, warnings: &mut Vec<String>) -> Vec<Block> {
        let mut blocks = Vec::new();
        for rule in &self.rules {
            let block = match &rule.target {
                RuleTarget::App { path } => Block::app(Path::new(path)),
                RuleTarget::Address { ip, app } => {
                    Block::address(*ip, app.as_deref().map(Path::new))
                }
                RuleTarget::Domain { .. } => continue,
            };
            match block {
                Ok(block) => blocks.push(block),
                // The program is gone (uninstalled or moved): nothing to block.
                Err(error) => warnings.push(format!("rule {} skipped: {error}", rule.id)),
            }
        }
        blocks
    }

    /// The domain rule that covers `name` for `app`, if any.
    fn domain_rule_for(&self, name: &str, app: Option<&Path>) -> Option<i64> {
        self.rules.iter().find_map(|rule| match &rule.target {
            RuleTarget::Domain {
                name: domain,
                app: rule_app,
            } if covers(domain, name) && same_app(rule_app.as_deref(), app) => Some(rule.id),
            _ => None,
        })
    }

    /// Called for each answer the Windows DNS service confirmed: blocks the
    /// addresses of blocked domains.
    #[cfg(test)]
    pub fn on_confirmed_answer(&mut self, name: &str, addresses: &[IpAddr], now: SystemTime) {
        self.on_confirmed_chain(name, &[], addresses, now);
    }

    /// Like [`Blocker::on_confirmed_answer`], with the name's CNAME aliases:
    /// a blocked domain is also blocked when another name points to it (a
    /// tracker hidden behind a site's own name).
    pub fn on_confirmed_chain(
        &mut self,
        name: &str,
        aliases: &[String],
        addresses: &[IpAddr],
        now: SystemTime,
    ) {
        if self.paused {
            return;
        }
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let mut chain = vec![name.clone()];
        chain.extend(
            aliases
                .iter()
                .map(|a| a.trim_end_matches('.').to_ascii_lowercase()),
        );
        // The name in the chain a domain covers, if any.
        let covered = |domain: &str| chain.iter().find(|n| covers(domain, n)).cloned();
        // Only names no domain rule covers (for any app) show that an
        // address is used elsewhere.
        let blocked_name = self.rules.iter().any(|rule| {
            matches!(&rule.target, RuleTarget::Domain { name: domain, .. } if covered(domain).is_some())
        });
        if !blocked_name {
            for ip in addresses {
                self.note_shared(ip.to_canonical(), now);
            }
        }
        // Each matching rule, with the name it matched (kept with learned
        // addresses, so they still match the rule after a restart).
        let matching: Vec<(i64, Option<String>, String)> = self
            .rules
            .iter()
            .filter_map(|rule| match &rule.target {
                RuleTarget::Domain { name: domain, app } => {
                    covered(domain).map(|matched| (rule.id, app.clone(), matched))
                }
                _ => None,
            })
            .collect();
        for (rule, app, matched) in matching {
            let app = match app.map(|a| normalize_path(Path::new(&a))).transpose() {
                Ok(app) => app,
                Err(_) => continue,
            };
            for ip in addresses {
                self.learn(rule, *ip, app.clone(), &matched, now);
            }
        }
    }

    /// Remembers that an unblocked domain uses `ip`, and lifts "every app"
    /// blocks learned for it.
    fn note_shared(&mut self, ip: IpAddr, now: SystemTime) {
        if self.shared.len() >= MAX_SHARED
            && !self.shared.contains_key(&ip)
            && let Some(oldest) = self
                .shared
                .iter()
                .min_by_key(|(_, seen)| **seen)
                .map(|(ip, _)| *ip)
        {
            self.shared.remove(&oldest);
        }
        self.shared.insert(ip, now);
        let (lifted, kept): (Vec<Learned>, Vec<Learned>) = std::mem::take(&mut self.learned)
            .into_iter()
            .partition(|l| l.ip == ip && l.app.is_none());
        self.learned = kept;
        for old in &lifted {
            self.release(old);
        }
    }

    /// Whether an unblocked domain was seen using `ip` recently.
    fn is_shared(&self, ip: IpAddr, now: SystemTime) -> bool {
        self.shared.get(&ip).is_some_and(|seen| {
            now.duration_since(*seen)
                .map_or(true, |age| age < LEARNED_FOR)
        })
    }

    /// Whether an address rule blocks `ip` for `app` itself (its filter is
    /// the same as a learned one's would be).
    fn address_rule_covers(&self, ip: IpAddr, app: Option<&Path>) -> bool {
        self.rules.iter().any(|rule| match &rule.target {
            RuleTarget::Address {
                ip: rule_ip,
                app: rule_app,
            } => *rule_ip == ip && same_app_path(rule_app.as_deref().map(Path::new), app),
            _ => false,
        })
    }

    fn learn(
        &mut self,
        rule: i64,
        ip: IpAddr,
        app: Option<PathBuf>,
        domain: &str,
        now: SystemTime,
    ) {
        let ip = ip.to_canonical();
        // An address rule already blocks it; never touch that filter.
        if self.address_rule_covers(ip, app.as_deref()) {
            return;
        }
        if app.is_none() && self.is_shared(ip, now) {
            return;
        }
        let now_secs = unix_secs(now);
        if let Some(index) = self
            .learned
            .iter()
            .position(|l| l.rule == rule && l.ip == ip && l.app == app)
        {
            let age = now_secs.saturating_sub(self.learned[index].learned);
            if Duration::from_secs(age) < REFRESH_AFTER {
                return;
            }
            // Re-add with a fresh time: the stored time is part of the
            // filter's data, so the filter is replaced.
            let old = self.learned.remove(index);
            let _ = self.firewall.unblock(&old.block());
        }
        let learned = Learned {
            rule,
            ip,
            app,
            domain: domain.to_owned(),
            learned: now_secs,
        };
        // Refused addresses (local network, DNS servers...) are not kept.
        if self.firewall.block(&learned.block()).is_ok() {
            self.learned.push(learned);
            self.limit(rule);
        }
    }

    /// Keeps at most [`MAX_LEARNED_PER_RULE`] addresses per rule.
    fn limit(&mut self, rule: i64) {
        loop {
            let of_rule: Vec<usize> = (0..self.learned.len())
                .filter(|&i| self.learned[i].rule == rule)
                .collect();
            if of_rule.len() <= MAX_LEARNED_PER_RULE {
                return;
            }
            let oldest = of_rule
                .into_iter()
                .min_by_key(|&i| self.learned[i].learned)
                .unwrap_or(0);
            let old = self.learned.remove(oldest);
            self.release(&old);
        }
    }

    /// Removes a learned address's filter, unless another rule still
    /// learned the same address for the same program.
    fn release(&mut self, old: &Learned) {
        let still_wanted = self
            .learned
            .iter()
            .any(|l| l.ip == old.ip && l.app == old.app)
            || self.address_rule_covers(old.ip, old.app.as_deref());
        if !still_wanted {
            let _ = self.firewall.unblock(&old.block());
        }
    }

    /// Unblocks learned addresses that were not seen for a day.
    pub fn expire(&mut self, now: SystemTime) {
        let now_secs = unix_secs(now);
        let (expired, kept): (Vec<Learned>, Vec<Learned>) = std::mem::take(&mut self.learned)
            .into_iter()
            .partition(|l| Duration::from_secs(now_secs.saturating_sub(l.learned)) >= LEARNED_FOR);
        self.learned = kept;
        for old in &expired {
            self.release(old);
        }
    }

    /// Saves and applies a new rule (checked with [`checked_target`]).
    /// Returns its ID.
    pub fn add(
        &mut self,
        store: &mut Store,
        target: RuleTarget,
        now: SystemTime,
    ) -> Result<(i64, bool), String> {
        // Saved rules are in their one spelling (checked_target), so equal
        // targets are the same rule.
        let already = self.rules.iter().any(|r| r.target == target);
        if self.rules.len() >= MAX_RULES && !already {
            return Err(format!(
                "there are already {MAX_RULES} rules; remove some first"
            ));
        }
        let block = match &target {
            RuleTarget::App { path } => Some(Block::App {
                path: PathBuf::from(path),
            }),
            RuleTarget::Address { ip, app } => Some(Block::Address {
                ip: *ip,
                app: app.as_ref().map(PathBuf::from),
                via: None,
                learned: 0,
            }),
            RuleTarget::Domain { .. } => None,
        };
        if let Some(block) = &block
            && !self.paused
        {
            self.firewall.block(block).map_err(|e| e.to_string())?;
        }
        let id = match store.add_rule(&target, now) {
            Ok(id) => id,
            Err(error) => {
                // Not saved, so not kept: make the firewall match the rules.
                let _ = self.reconcile(now);
                return Err(error.to_string());
            }
        };
        if !self.rules.iter().any(|r| r.id == id) {
            self.rules.push(StoredRule {
                id,
                target,
                created: now,
            });
        }
        Ok((id, already))
    }

    /// Deletes a rule and unblocks what it blocked. `false` if there was no
    /// such rule.
    pub fn remove(&mut self, store: &mut Store, id: i64, now: SystemTime) -> Result<bool, String> {
        if !store.remove_rule(id).map_err(|e| e.to_string())? {
            return Ok(false);
        }
        self.rules.retain(|r| r.id != id);
        let (gone, kept): (Vec<Learned>, Vec<Learned>) = std::mem::take(&mut self.learned)
            .into_iter()
            .partition(|l| l.rule == id);
        self.learned = kept;
        for old in &gone {
            self.release(old);
        }
        // App and address rules: make the firewall match the remaining
        // rules (another rule may still block the same thing).
        let _ = self.reconcile(now);
        Ok(true)
    }

    /// Pauses (removes every filter, keeps the rules) or resumes blocking,
    /// and saves the choice.
    pub fn set_paused(
        &mut self,
        store: &mut Store,
        paused: bool,
        now: SystemTime,
    ) -> Result<Vec<String>, String> {
        store
            .set_setting(PAUSED_SETTING, if paused { "true" } else { "false" })
            .map_err(|e| e.to_string())?;
        self.paused = paused;
        if paused {
            self.learned.clear();
            self.firewall.remove_all().map_err(|e| e.to_string())?;
            Ok(Vec::new())
        } else {
            Ok(self.reconcile(now))
        }
    }

    /// Whether blocking is paused.
    #[cfg(test)]
    fn paused(&self) -> bool {
        self.paused
    }

    /// The rules, with how many addresses each domain rule blocks now.
    pub fn states(&self) -> Vec<RuleState> {
        self.rules
            .iter()
            .map(|rule| RuleState {
                rule: rule.clone(),
                learned: self.learned.iter().filter(|l| l.rule == rule.id).count(),
            })
            .collect()
    }
}

/// Whether two blocks are the same rule (ignoring the domain and time a
/// learned address carries).
fn same_rule(a: &Block, b: &Block) -> bool {
    match (a, b) {
        (Block::App { path: x }, Block::App { path: y }) => same_path(x, y),
        (
            Block::Address {
                ip: ip1, app: app1, ..
            },
            Block::Address {
                ip: ip2, app: app2, ..
            },
        ) => ip1 == ip2 && same_app_path(app1.as_deref(), app2.as_deref()),
        _ => false,
    }
}

fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy()
        .eq_ignore_ascii_case(&b.to_string_lossy())
}

fn same_app_path(a: Option<&Path>, b: Option<&Path>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => same_path(a, b),
        _ => false,
    }
}

/// Whether a rule's program (as saved) is `app` (normalised).
fn same_app(rule_app: Option<&str>, app: Option<&Path>) -> bool {
    match (rule_app, app) {
        (None, None) => true,
        (Some(rule_app), Some(app)) => {
            normalize_path(Path::new(rule_app)).is_ok_and(|rule_app| same_path(&rule_app, app))
        }
        _ => false,
    }
}

/// `--unblock-all`: the emergency switch. Removes every Whereabouts block
/// from the firewall directly (so it works even if the service is stuck or
/// stopped) and pauses blocking, keeping the rules.
pub fn unblock_all() -> std::process::ExitCode {
    // Ask a running service to pause first, so it does not block again.
    let service_paused = whereabouts_client::Client::connect(whereabouts_ipc::PIPE_NAME)
        .ok()
        .and_then(|mut client| {
            client
                .ask(&whereabouts_ipc::Request::SetBlockingPaused { paused: true })
                .ok()
        })
        .is_some_and(|answer| matches!(answer, Response::Rules { .. }));
    match Firewall::open().and_then(|firewall| firewall.remove_all()) {
        Ok(removed) => println!("Removed {removed} Whereabouts blocks from the Windows firewall."),
        Err(error) => {
            eprintln!("error: could not remove the blocks ({error}); run as administrator");
            return std::process::ExitCode::FAILURE;
        }
    }
    if !service_paused {
        // Save "paused" so the rules are not applied again at the next start.
        let saved = crate::storage::open().and_then(|mut store| {
            store
                .set_setting(PAUSED_SETTING, "true")
                .map_err(|e| e.to_string())
        });
        if let Err(error) = saved {
            println!(
                "warning: could not save that blocking is paused ({error}); the service will \
                 apply the rules again when it starts"
            );
        }
    }
    println!("Blocking is paused; your rules are kept. Resume with --resume-blocking.");
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use whereabouts_store::Key;

    /// A firewall that only remembers what it was told.
    #[derive(Default)]
    struct Fake {
        blocks: Vec<Block>,
    }

    impl Firewalls for Fake {
        fn block(&mut self, block: &Block) -> Result<(), BlockError> {
            if let Block::Address { ip, .. } = block
                && ip.is_loopback()
            {
                return Err(BlockError::Refused(whereabouts_win_firewall::Refusal(
                    String::from("loopback"),
                )));
            }
            if !self.blocks.iter().any(|b| same_rule(b, block)) {
                self.blocks.push(block.clone());
            }
            Ok(())
        }
        fn unblock(&mut self, block: &Block) -> io::Result<bool> {
            let before = self.blocks.len();
            self.blocks.retain(|b| !same_rule(b, block));
            Ok(self.blocks.len() < before)
        }
        fn current(&self) -> io::Result<Vec<Block>> {
            Ok(self.blocks.clone())
        }
        fn remove_all(&mut self) -> io::Result<usize> {
            let n = self.blocks.len();
            self.blocks.clear();
            Ok(n)
        }
    }

    fn store(name: &str) -> (Store, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "whereabouts-blocking-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = Store::open(&dir.join("t.db"), &Key::from_bytes([3; 32])).unwrap();
        (store, dir)
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn this_exe() -> String {
        std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    const T0: u64 = 1_800_000_000;

    #[test]
    fn domain_names_are_checked_and_cleaned() {
        assert_eq!(
            clean_domain(" Tracker.Example.COM. ").unwrap(),
            "tracker.example.com"
        );
        for bad in ["", "localhost", "a..b", "exa mple.com", "bad/x.com", ".com"] {
            assert!(clean_domain(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn domains_cover_their_subdomains_only() {
        assert!(covers("example.com", "example.com"));
        assert!(covers("example.com", "ads.example.com"));
        assert!(!covers("example.com", "badexample.com"));
        assert!(!covers("ads.example.com", "example.com"));
    }

    #[test]
    fn app_rules_are_applied_saved_and_removed() {
        let (mut store, dir) = store("app");
        let (mut blocker, warnings) = Blocker::start(Fake::default(), &store, at(T0)).unwrap();
        assert!(warnings.is_empty());
        let (id, already) = blocker
            .add(&mut store, RuleTarget::App { path: this_exe() }, at(T0))
            .unwrap();
        assert!(!already);
        assert_eq!(blocker.firewall.blocks.len(), 1);
        assert_eq!(store.rules().unwrap().len(), 1);
        // Blocking it again is the same rule, reported as already there, so
        // the app offers no Undo that would remove the original.
        let again = blocker
            .add(&mut store, RuleTarget::App { path: this_exe() }, at(T0))
            .unwrap();
        assert_eq!(again, (id, true));
        assert_eq!(store.rules().unwrap().len(), 1);
        assert!(blocker.remove(&mut store, id, at(T0)).unwrap());
        assert!(blocker.firewall.blocks.is_empty());
        assert!(!blocker.remove(&mut store, id, at(T0)).unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    fn open_fake() -> io::Result<Fake> {
        Ok(Fake::default())
    }

    #[test]
    fn client_rules_are_checked_before_anything_is_saved() {
        let (mut store, dir) = store("checked");
        let mut blocking = Blocking::start(open_fake, Some(&store), at(T0));
        assert!(
            blocking.blocker.is_none(),
            "no rules: the firewall is not opened"
        );
        let system32 = PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32");
        let refused = [
            RuleSpec::App {
                path: String::from(r"C:\nowhere\nothing.exe"),
            },
            RuleSpec::App {
                path: system32.join("svchost.exe").to_string_lossy().into_owned(),
            },
            RuleSpec::Address {
                ip: "192.168.1.1".parse().unwrap(),
                app: None,
            },
            RuleSpec::Domain {
                name: String::from("localhost"),
                app: None,
            },
            RuleSpec::App {
                path: "x".repeat(MAX_RULE_PATH + 1),
            },
        ];
        for spec in refused {
            let answer = blocking.answer(Some(&mut store), RuleCommand::Add(spec.clone()), at(T0));
            assert!(
                matches!(answer, Response::Error { .. }),
                "{spec:?}: {answer:?}"
            );
        }
        assert!(store.rules().unwrap().is_empty(), "nothing saved");
        assert!(blocking.blocker.is_none());

        let added = blocking.answer(
            Some(&mut store),
            RuleCommand::Add(RuleSpec::Domain {
                name: String::from("Tracker.Example.com."),
                app: None,
            }),
            at(T0),
        );
        assert!(matches!(added, Response::RuleAdded { .. }), "{added:?}");
        match blocking.answer(Some(&mut store), RuleCommand::List, at(T0)) {
            Response::Rules { rules, paused } => {
                assert!(!paused);
                assert_eq!(
                    rules[0].rule,
                    RuleSpec::Domain {
                        name: String::from("tracker.example.com"),
                        app: None
                    }
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(blocking.summary(), (1, false));
        assert!(matches!(
            blocking.answer(None, RuleCommand::List, at(T0)),
            Response::Error { .. }
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn saved_rules_are_applied_at_start_up() {
        let (mut store, dir) = store("startup");
        store
            .add_rule(&RuleTarget::App { path: this_exe() }, at(T0))
            .unwrap();
        let blocking = Blocking::start(open_fake, Some(&store), at(T0));
        let blocker = blocking.blocker.as_ref().unwrap();
        assert_eq!(blocker.firewall.blocks.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn domain_rules_block_confirmed_addresses_and_they_expire() {
        let (mut store, dir) = store("domain");
        let (mut blocker, _) = Blocker::start(Fake::default(), &store, at(T0)).unwrap();
        let (id, _) = blocker
            .add(
                &mut store,
                RuleTarget::Domain {
                    name: String::from("tracker.example.com"),
                    app: None,
                },
                at(T0),
            )
            .unwrap();
        assert!(blocker.firewall.blocks.is_empty(), "nothing to block yet");
        let a: IpAddr = "203.0.113.5".parse().unwrap();
        let b: IpAddr = "2001:db8::5".parse().unwrap();
        blocker.on_confirmed_answer("cdn.tracker.example.com", &[a, b], at(T0 + 10));
        blocker.on_confirmed_answer(
            "unrelated.example.org",
            &["198.51.100.1".parse().unwrap()],
            at(T0 + 10),
        );
        // A refused address (here: loopback) is not kept.
        blocker.on_confirmed_answer(
            "tracker.example.com",
            &["127.0.0.1".parse().unwrap()],
            at(T0 + 10),
        );
        assert_eq!(blocker.firewall.blocks.len(), 2);
        assert_eq!(blocker.states()[0].learned, 2);

        // Seen again after 13 hours: refreshed, so still blocked at 30 h.
        blocker.on_confirmed_answer("tracker.example.com", &[a], at(T0 + 13 * 3600));
        blocker.expire(at(T0 + 30 * 3600));
        assert_eq!(
            blocker.firewall.blocks.len(),
            1,
            "b expired, a was refreshed"
        );
        // Removing the rule unblocks what it learned.
        assert!(blocker.remove(&mut store, id, at(T0 + 30 * 3600)).unwrap());
        assert!(blocker.firewall.blocks.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn every_app_domain_rules_skip_addresses_other_domains_use() {
        let (mut store, dir) = store("shared");
        let (mut blocker, _) = Blocker::start(Fake::default(), &store, at(T0)).unwrap();
        blocker
            .add(
                &mut store,
                RuleTarget::Domain {
                    name: String::from("tracker.example.com"),
                    app: None,
                },
                at(T0),
            )
            .unwrap();
        let bank: IpAddr = "198.51.100.7".parse().unwrap();
        let cdn: IpAddr = "203.0.113.9".parse().unwrap();
        // The blocked domain points at the bank's address: blocked at first...
        blocker.on_confirmed_answer("tracker.example.com", &[bank], at(T0 + 1));
        assert_eq!(blocker.firewall.blocks.len(), 1);
        // ...until the bank's own name is seen using it: lifted, and not
        // blocked again while it is in use.
        blocker.on_confirmed_answer("www.bank.example", &[bank], at(T0 + 2));
        assert!(blocker.firewall.blocks.is_empty());
        blocker.on_confirmed_answer("tracker.example.com", &[bank], at(T0 + 3));
        assert!(blocker.firewall.blocks.is_empty());
        // A CDN address an unblocked site used first is never blocked.
        blocker.on_confirmed_answer("site.example.org", &[cdn], at(T0 + 4));
        blocker.on_confirmed_answer("tracker.example.com", &[cdn], at(T0 + 5));
        assert!(blocker.firewall.blocks.is_empty());
        // A name covered by a per-app rule does not count as elsewhere.
        blocker
            .add(
                &mut store,
                RuleTarget::Domain {
                    name: String::from("ads.example.net"),
                    app: Some(this_exe()),
                },
                at(T0 + 4),
            )
            .unwrap();
        let other: IpAddr = "203.0.113.10".parse().unwrap();
        blocker.on_confirmed_answer("ads.example.net", &[other], at(T0 + 4));
        blocker.on_confirmed_answer("tracker.example.com", &[other], at(T0 + 4));
        assert!(
            blocker
                .firewall
                .blocks
                .iter()
                .any(|b| matches!(b, Block::Address { ip, app: None, .. } if *ip == other)),
            "{:?}",
            blocker.firewall.blocks
        );
        blocker
            .firewall
            .blocks
            .retain(|b| !matches!(b, Block::Address { ip, .. } if *ip == other));
        blocker.learned.retain(|l| l.ip != other);
        // After a day without being seen elsewhere, it can be blocked again.
        blocker.on_confirmed_answer("tracker.example.com", &[cdn], at(T0 + 5 + 86_400));
        assert_eq!(blocker.firewall.blocks.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_learned_address_never_lifts_an_address_rule() {
        let (mut store, dir) = store("collide");
        let (mut blocker, _) = Blocker::start(Fake::default(), &store, at(T0)).unwrap();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        blocker
            .add(&mut store, RuleTarget::Address { ip, app: None }, at(T0))
            .unwrap();
        blocker
            .add(
                &mut store,
                RuleTarget::Domain {
                    name: String::from("tracker.example.com"),
                    app: None,
                },
                at(T0),
            )
            .unwrap();
        blocker.on_confirmed_answer("tracker.example.com", &[ip], at(T0 + 1));
        blocker.expire(at(T0 + 3 * 86_400));
        assert_eq!(
            blocker.firewall.blocks.len(),
            1,
            "the address rule's block stays"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_blocked_domain_is_blocked_behind_another_name() {
        let (mut store, dir) = store("cname");
        let (mut blocker, _) = Blocker::start(Fake::default(), &store, at(T0)).unwrap();
        blocker
            .add(
                &mut store,
                RuleTarget::Domain {
                    name: String::from("tracker.example.com"),
                    app: None,
                },
                at(T0),
            )
            .unwrap();
        let ip: IpAddr = "203.0.113.50".parse().unwrap();
        // metrics.shop.example points to the tracker (CNAME cloaking).
        blocker.on_confirmed_chain(
            "metrics.shop.example",
            &[String::from("eu.tracker.example.com")],
            &[ip],
            at(T0 + 1),
        );
        assert_eq!(blocker.firewall.blocks.len(), 1);
        // The learned address names the tracker, so it survives a restart.
        let (restarted, _) = Blocker::start(
            Fake {
                blocks: blocker.firewall.blocks.clone(),
            },
            &store,
            at(T0 + 2),
        )
        .unwrap();
        assert_eq!(restarted.firewall.blocks.len(), 1);
        assert_eq!(restarted.states()[0].learned, 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn learned_addresses_are_capped_per_rule() {
        let (mut store, dir) = store("cap");
        let (mut blocker, _) = Blocker::start(Fake::default(), &store, at(T0)).unwrap();
        blocker
            .add(
                &mut store,
                RuleTarget::Domain {
                    name: String::from("cdn.example.com"),
                    app: None,
                },
                at(T0),
            )
            .unwrap();
        for i in 0..(MAX_LEARNED_PER_RULE as u32 + 10) {
            let ip = IpAddr::from([203, 0, (i / 250) as u8, (i % 250) as u8 + 1]);
            blocker.on_confirmed_answer("cdn.example.com", &[ip], at(T0 + u64::from(i)));
        }
        assert_eq!(blocker.firewall.blocks.len(), MAX_LEARNED_PER_RULE);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn start_up_makes_the_firewall_match_the_rules() {
        let (mut store, dir) = store("reconcile");
        store
            .add_rule(&RuleTarget::App { path: this_exe() }, at(T0))
            .unwrap();
        store
            .add_rule(
                &RuleTarget::Domain {
                    name: String::from("tracker.example.com"),
                    app: None,
                },
                at(T0),
            )
            .unwrap();
        // What a previous run left behind: one stale block with no rule, a
        // fresh learned address and an old one.
        let mut fake = Fake::default();
        fake.blocks.push(Block::Address {
            ip: "198.51.100.9".parse().unwrap(),
            app: None,
            via: None,
            learned: 0,
        });
        fake.blocks.push(Block::learned_address(
            "203.0.113.5".parse().unwrap(),
            None,
            "tracker.example.com",
            T0 - 3600,
        ));
        fake.blocks.push(Block::learned_address(
            "203.0.113.6".parse().unwrap(),
            None,
            "tracker.example.com",
            T0 - 2 * 86_400,
        ));
        let (blocker, warnings) = Blocker::start(fake, &store, at(T0)).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
        let blocks = &blocker.firewall.blocks;
        assert_eq!(blocks.len(), 2, "{blocks:?}");
        assert!(blocks.iter().any(|b| matches!(b, Block::App { .. })));
        assert!(blocks.iter().any(|b| matches!(b, Block::Address { ip, .. } if *ip == "203.0.113.5".parse::<IpAddr>().unwrap())));
        assert_eq!(blocker.states()[1].learned, 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn pausing_removes_filters_but_keeps_rules_and_is_saved() {
        let (mut store, dir) = store("pause");
        let (mut blocker, _) = Blocker::start(Fake::default(), &store, at(T0)).unwrap();
        blocker
            .add(&mut store, RuleTarget::App { path: this_exe() }, at(T0))
            .unwrap();
        blocker.set_paused(&mut store, true, at(T0)).unwrap();
        assert!(blocker.firewall.blocks.is_empty());
        assert_eq!(store.rules().unwrap().len(), 1);
        // Still paused after a restart.
        let (mut blocker, _) = Blocker::start(Fake::default(), &store, at(T0)).unwrap();
        assert!(blocker.paused());
        assert!(blocker.firewall.blocks.is_empty());
        blocker.set_paused(&mut store, false, at(T0)).unwrap();
        assert_eq!(blocker.firewall.blocks.len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
