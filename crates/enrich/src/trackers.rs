//! Tracker domains from the EasyPrivacy list (design spec §5.5).
//!
//! EasyPrivacy, by the EasyList authors (<https://easylist.to/>), is dual
//! licensed under GPL-3.0-or-later and CC BY-SA 3.0. It is written for
//! browser ad blockers, so only the rules that make sense for any app are
//! used:
//!
//! - `||example.com^`: `example.com` and its subdomains are trackers;
//! - the same with options that only name kinds of browser requests
//!   (`$third-party`, `$script`, `$xmlhttprequest`, `$image`, ...): they say
//!   which requests a browser should block, but the domain is still a
//!   tracker, and in a desktop app every connection is "third-party";
//! - `@@||example.com^` without options: exceptions.
//!
//! Rules with paths or wildcards, or options that limit them to particular
//! websites (`$domain=`) or change their meaning (`$popup`, `$csp=`, ...),
//! are skipped.

use std::collections::HashSet;

/// Longest rule line considered.
const MAX_LINE: usize = 512;

/// Options that only describe which kinds of browser requests a rule
/// applies to. A rule with only these still marks the whole domain.
const REQUEST_TYPE_OPTIONS: [&str; 18] = [
    "third-party",
    "3p",
    "script",
    "xmlhttprequest",
    "xhr",
    "image",
    "ping",
    "beacon",
    "other",
    "subdocument",
    "frame",
    "websocket",
    "media",
    "font",
    "stylesheet",
    "css",
    "object",
    "document",
];

/// A set of tracker domains with exceptions.
#[derive(Debug, Default)]
pub struct TrackerList {
    domains: HashSet<String>,
    exceptions: HashSet<String>,
}

impl TrackerList {
    /// Parses EasyPrivacy (Adblock Plus syntax) text.
    pub fn parse(text: &str) -> Self {
        let mut list = Self::default();
        for line in text.lines().map(str::trim) {
            if line.len() > MAX_LINE {
                continue;
            }
            if let Some(rule) = line.strip_prefix("@@||") {
                if let Some(domain) = parse_rule(rule, false) {
                    list.exceptions.insert(domain);
                }
            } else if let Some(rule) = line.strip_prefix("||") {
                if let Some(domain) = parse_rule(rule, true) {
                    list.domains.insert(domain);
                }
            }
        }
        list
    }

    /// Returns `true` if `name` or one of its parent domains is listed as a
    /// tracker and not excepted. The most specific match wins.
    pub fn is_tracker(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let mut candidate = name.as_str();
        loop {
            if self.exceptions.contains(candidate) {
                return false;
            }
            if self.domains.contains(candidate) {
                return true;
            }
            match candidate.split_once('.') {
                Some((_, parent)) if parent.contains('.') => candidate = parent,
                _ => return false,
            }
        }
    }

    /// Number of tracker domains.
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    /// Returns `true` if no tracker domains are loaded.
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }
}

/// Parses the part after `||` of a rule. Returns the domain if the rule
/// applies to a whole domain. `allow_request_types` accepts options from
/// [`REQUEST_TYPE_OPTIONS`] (for blocking rules); exceptions must have no
/// options.
fn parse_rule(rule: &str, allow_request_types: bool) -> Option<String> {
    let (domain, rest) = rule.split_once('^')?;
    let options_ok = match rest.strip_prefix('$') {
        None => rest.is_empty(),
        Some(options) => {
            allow_request_types
                && options
                    .split(',')
                    .all(|option| REQUEST_TYPE_OPTIONS.contains(&option.trim()))
        }
    };
    let valid_domain = domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    (options_ok && valid_domain).then(|| domain.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
[Adblock Plus 2.0]
! Title: EasyPrivacy (sample)
||tracker.example^
||third.example^$third-party
||image-only.example^$image
||script.example^$script,third-party,xmlhttprequest
||popup.example^$popup
||site-specific.example^$domain=news.example
||path.example/collect
||wild*.example^
@@||ok.tracker.example^
@@||site-exception.example^$domain=news.example
";

    #[test]
    fn whole_domain_rules_match_domains_and_subdomains() {
        let list = TrackerList::parse(SAMPLE);
        assert!(list.is_tracker("tracker.example"));
        assert!(list.is_tracker("a.b.tracker.example"));
        assert!(list.is_tracker("TRACKER.example."));
        assert!(!list.is_tracker("nottracker.example"));
        assert!(!list.is_tracker("example"));
    }

    #[test]
    fn third_party_rules_apply_to_apps() {
        let list = TrackerList::parse(SAMPLE);
        assert!(list.is_tracker("cdn.third.example"));
    }

    #[test]
    fn request_type_options_still_mark_the_domain() {
        // Like EasyPrivacy's Google Analytics rule.
        let list = TrackerList::parse(SAMPLE);
        assert!(list.is_tracker("www.script.example"));
        assert!(list.is_tracker("image-only.example"));
    }

    #[test]
    fn site_specific_path_and_other_rules_are_skipped() {
        let list = TrackerList::parse(SAMPLE);
        assert!(!list.is_tracker("site-specific.example"));
        assert!(!list.is_tracker("path.example"));
        assert!(!list.is_tracker("popup.example"));
        assert_eq!(list.len(), 4);
    }

    #[test]
    fn exceptions_win_for_more_specific_names() {
        let list = TrackerList::parse(SAMPLE);
        assert!(!list.is_tracker("ok.tracker.example"));
        assert!(!list.is_tracker("x.ok.tracker.example"));
        assert!(list.is_tracker("other.tracker.example"));
    }

    #[test]
    fn overlong_and_garbage_lines_are_ignored() {
        let long = format!("||{}.example^", "a".repeat(600));
        let list = TrackerList::parse(&format!("{long}\n||^\n||.example^\n|| bad.example^\n"));
        assert!(list.is_empty());
    }
}
