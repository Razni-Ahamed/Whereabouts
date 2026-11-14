//! Which company runs a tracking, analytics or messaging service, from
//! Whereabouts' own list (`data/companies.tsv`, GPL-3.0-or-later).

use std::collections::HashMap;
use std::fmt;

/// The list shipped with Whereabouts.
const BUILT_IN: &str = include_str!("../../../data/companies.tsv");

/// What kind of service a company's domain provides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    /// Advertising networks and ad measurement.
    Ads,
    /// Usage analytics and audience measurement.
    Analytics,
    /// Mobile app install attribution.
    Attribution,
    /// Customer data platforms that collect and share user profiles.
    CustomerData,
    /// Crash and error reporting, performance monitoring.
    Diagnostics,
    /// Customer messaging and push notifications.
    Messaging,
    /// Recording what users do in an app or page.
    SessionReplay,
    /// Social network software development kits and plugins.
    Social,
}

impl Category {
    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "ads" => Self::Ads,
            "analytics" => Self::Analytics,
            "attribution" => Self::Attribution,
            "customer-data" => Self::CustomerData,
            "diagnostics" => Self::Diagnostics,
            "messaging" => Self::Messaging,
            "session-replay" => Self::SessionReplay,
            "social" => Self::Social,
            _ => return None,
        })
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Ads => "ads",
            Self::Analytics => "analytics",
            Self::Attribution => "attribution",
            Self::CustomerData => "customer data",
            Self::Diagnostics => "diagnostics",
            Self::Messaging => "messaging",
            Self::SessionReplay => "session replay",
            Self::Social => "social",
        })
    }
}

/// A company and the kind of service a domain provides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Company {
    /// The company's name, e.g. "Google (Firebase)".
    pub name: String,
    /// What the service is.
    pub category: Category,
}

/// Domain-to-company mapping.
#[derive(Debug, Default)]
pub struct CompanyList(HashMap<String, Company>);

impl CompanyList {
    /// The list shipped with Whereabouts.
    pub fn built_in() -> Self {
        Self::parse(BUILT_IN).expect("data/companies.tsv is valid")
    }

    /// Parses `domain<TAB>company<TAB>category` lines; `#` starts a comment.
    /// Returns an error naming the first invalid line.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut map = HashMap::new();
        for (number, line) in text.lines().enumerate() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split('\t');
            let (Some(domain), Some(name), Some(category), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(format!(
                    "line {}: expected three tab-separated fields",
                    number + 1
                ));
            };
            let category = Category::parse(category)
                .ok_or_else(|| format!("line {}: unknown category {category:?}", number + 1))?;
            map.insert(
                domain.to_ascii_lowercase(),
                Company {
                    name: name.to_owned(),
                    category,
                },
            );
        }
        Ok(Self(map))
    }

    /// Returns the company for `name` or its closest listed parent domain.
    pub fn lookup(&self, name: &str) -> Option<&Company> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let mut candidate = name.as_str();
        loop {
            if let Some(company) = self.0.get(candidate) {
                return Some(company);
            }
            match candidate.split_once('.') {
                Some((_, parent)) if parent.contains('.') => candidate = parent,
                _ => return None,
            }
        }
    }

    /// Number of listed domains.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_list_is_valid() {
        let list = CompanyList::built_in();
        assert!(list.len() > 50, "{} entries", list.len());
    }

    #[test]
    fn looks_up_domains_and_subdomains() {
        let list = CompanyList::built_in();
        let firebase = list.lookup("app-measurement.com").unwrap();
        assert_eq!(firebase.name, "Google (Firebase)");
        assert_eq!(firebase.category, Category::Analytics);

        let telemetry = list.lookup("v10.events.data.microsoft.com").unwrap();
        assert_eq!(telemetry.name, "Microsoft");
        // A listed host does not make its parent domain a tracker.
        assert!(list.lookup("data.microsoft.com").is_none());
        assert!(list.lookup("microsoft.com").is_none());
    }

    #[test]
    fn rejects_malformed_lines() {
        assert!(CompanyList::parse("a.example\tA\n").is_err());
        assert!(CompanyList::parse("a.example\tA\tunknown\n").is_err());
        assert!(CompanyList::parse("a.example\tA\tads\textra\n").is_err());
        assert!(CompanyList::parse("# comment\n\na.example\tA\tads\n").is_ok());
    }
}
