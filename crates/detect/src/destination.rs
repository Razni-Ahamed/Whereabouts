//! What a behaviour profile learns about where a flow went (design spec
//! v0.3, ruling R21): one rule for live flows, saved history and the lab's
//! replay, so the lab measures what users get.

use std::net::IpAddr;

use whereabouts_core::dns::LabelSource;
use whereabouts_enrich::{Enricher, Scope, registrable_domain};
use whereabouts_store::DestinationFacts;

/// What a profile learns about a flow's destination: the registrable domain
/// of a name that was confirmed (one only the app itself reported could be
/// false), and the network's owner and country from the IP address. Local
/// and multicast addresses (and the flow-limit overflow's) have no owner or
/// country.
pub fn destination_facts(
    remote_ip: IpAddr,
    domain: Option<&str>,
    domain_source: Option<LabelSource>,
    enricher: &Enricher,
) -> DestinationFacts {
    let ip = enricher.ip(remote_ip);
    let (company, country) = match ip.scope {
        Scope::Internet => (ip.network, ip.country),
        Scope::Local | Scope::Multicast => (None, None),
    };
    DestinationFacts {
        domain: confirmed_domain(domain, domain_source),
        company: company.filter(|name| !name.is_empty()),
        country: country.filter(|code| !code.is_empty()),
    }
}

/// The registrable domain of `name`, only if it was confirmed (verified by
/// the Windows DNS service, or inferred from its answers).
pub fn confirmed_domain(name: Option<&str>, source: Option<LabelSource>) -> Option<String> {
    match source? {
        LabelSource::Verified | LabelSource::Inferred => registrable_domain(name?),
        LabelSource::Unverified => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use whereabouts_enrich::{CompanyList, GeoDatabases, TrackerList};

    fn enricher() -> Enricher {
        Enricher::from_parts(
            TrackerList::parse(""),
            CompanyList::built_in(),
            GeoDatabases::default(),
        )
    }

    #[test]
    fn only_confirmed_names_give_a_domain() {
        let e = enricher();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let domain = |source| destination_facts(ip, Some("api.chat.example"), source, &e).domain;
        assert_eq!(
            domain(Some(LabelSource::Verified)).as_deref(),
            Some("chat.example")
        );
        assert_eq!(
            domain(Some(LabelSource::Inferred)).as_deref(),
            Some("chat.example")
        );
        assert_eq!(domain(Some(LabelSource::Unverified)), None);
        assert_eq!(domain(None), None);
    }

    #[test]
    fn local_and_overflow_addresses_have_no_owner_or_country() {
        let e = enricher();
        for ip in ["192.168.1.1", "224.0.0.251", "0.0.0.0", "fe80::1"] {
            let facts = destination_facts(ip.parse().unwrap(), None, None, &e);
            assert_eq!(facts, DestinationFacts::default(), "{ip}");
        }
    }
}
