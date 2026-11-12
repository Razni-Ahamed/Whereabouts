//! Decoding of `Microsoft-Windows-DNS-Client` ETW events (design spec §5.4).
//!
//! Pure logic with no Windows calls. Facts checked against real events on
//! Windows 11 (see `examples/dns_probe.rs`):
//!
//! - Event 3008 ("query completed") is logged in the process that asked, so
//!   its header process ID is the app, not the DNS service. Events 3009-3020
//!   come from the DNS Client service (`svchost.exe`) and are not used.
//! - Event 3008 is logged for cached answers too.
//! - `QueryResults` looks like
//!   `"type: 5 alias.example.net;type: 5 cdn.example.net;23.220.98.100;"`:
//!   CNAME aliases as `type: 5 <name>`, then addresses, all ending in `;`.
//!   Some IPv4 answers appear in IPv4-mapped IPv6 form (`::ffff:1.2.3.4`).
//! - `QueryStatus` is 0 on success; failed queries have no results.
//!
//! Event 3020 ("query response") is logged by the DNS Client service itself
//! with the same `QueryName`/`QueryResults` format. Any program can write
//! events under this provider's ID, but not under the service's process ID,
//! so 3020 events from the service's process confirm what an app's own 3008
//! event claims.
//!
//! Names and results come from the network or from the app, so they are
//! validated: only characters legal in DNS names are accepted (ASCII
//! letters, digits, `-`, `_`, `.`), which also rules out control, bidi and
//! invisible Unicode characters that could spoof what the user sees.
//! Internationalised names arrive in their ASCII (punycode) form. The number
//! of answers kept per query is capped.

use std::net::IpAddr;

/// GUID of the `Microsoft-Windows-DNS-Client` ETW provider.
pub const DNS_CLIENT_PROVIDER: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";

/// Event ID of "DNS query completed", logged in the requesting process.
pub const DNS_QUERY_COMPLETED_EVENT: u16 = 3008;

/// Event ID of "DNS query response", logged by the DNS Client service.
pub const DNS_SERVICE_RESPONSE_EVENT: u16 = 3020;

/// Longest valid DNS name, in characters (RFC 1035, without trailing dot).
pub const MAX_NAME_LEN: usize = 253;

/// Most addresses kept from one answer.
pub const MAX_ADDRESSES: usize = 64;

/// Most CNAME aliases kept from one answer.
pub const MAX_ALIASES: usize = 16;

/// The useful part of one completed DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResults {
    /// Addresses in the answer, IPv4-mapped IPv6 converted to IPv4.
    pub addresses: Vec<IpAddr>,
    /// CNAME aliases in the answer, normalised like names.
    pub aliases: Vec<String>,
}

/// Normalises a DNS name: trims whitespace and a trailing dot, lowercases
/// it. Returns `None` if the name is empty, too long, or contains anything
/// other than ASCII letters, digits, `-`, `_` and `.`.
pub fn normalize_name(raw: &str) -> Option<String> {
    let name = raw.trim().trim_end_matches('.');
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    valid.then(|| name.to_ascii_lowercase())
}

/// Parses a `QueryResults` string. Unknown or invalid entries are skipped.
pub fn parse_query_results(raw: &str) -> DnsResults {
    let mut results = DnsResults {
        addresses: Vec::new(),
        aliases: Vec::new(),
    };
    for entry in raw.split(';').map(str::trim).filter(|e| !e.is_empty()) {
        if let Some(record) = entry.strip_prefix("type:") {
            // "type: 5 <name>" is a CNAME. Other record types are ignored.
            let mut parts = record.split_whitespace();
            if parts.next() == Some("5") && results.aliases.len() < MAX_ALIASES {
                if let Some(alias) = parts.next().and_then(normalize_name) {
                    results.aliases.push(alias);
                }
            }
        } else if let Ok(address) = entry.parse::<IpAddr>() {
            let address = address.to_canonical();
            if results.addresses.len() < MAX_ADDRESSES && !results.addresses.contains(&address) {
                results.addresses.push(address);
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_plain_ipv4_and_ipv6_answers() {
        // Real answers for example.com.
        let v4 = parse_query_results("172.66.147.243;104.20.23.154;");
        assert_eq!(v4.addresses, [ip("172.66.147.243"), ip("104.20.23.154")]);
        assert!(v4.aliases.is_empty());

        let v6 = parse_query_results("2606:4700:10::ac42:93f3;2606:4700:10::6814:179a;");
        assert_eq!(
            v6.addresses,
            [ip("2606:4700:10::ac42:93f3"), ip("2606:4700:10::6814:179a")]
        );
    }

    #[test]
    fn parses_cname_aliases_and_addresses() {
        // Real answer for www.microsoft.com.
        let r = parse_query_results(
            "type: 5 www.microsoft.com-c-3.edgekey.net;type: 5 e13678.dscb.akamaiedge.net;23.220.98.100;",
        );
        assert_eq!(r.addresses, [ip("23.220.98.100")]);
        assert_eq!(
            r.aliases,
            [
                "www.microsoft.com-c-3.edgekey.net",
                "e13678.dscb.akamaiedge.net"
            ]
        );
    }

    #[test]
    fn converts_ipv4_mapped_ipv6_to_ipv4() {
        // Real answer for an AAAA query that returned an IPv4-mapped address.
        let r = parse_query_results(
            "type: 5 win-global-asimov-leafs-events-data.trafficmanager.net;::ffff:20.184.175.20;",
        );
        assert_eq!(r.addresses, [ip("20.184.175.20")]);
    }

    #[test]
    fn empty_and_garbage_results_give_nothing() {
        assert!(parse_query_results("").addresses.is_empty());
        let r = parse_query_results("type: 12 ptr.example;not-an-ip;;type: 5;type:;");
        assert!(r.addresses.is_empty());
        assert!(r.aliases.is_empty());
    }

    #[test]
    fn caps_and_deduplicates_answers() {
        let many: String = (0..200)
            .map(|i| format!("10.0.{}.{};", i / 250, i % 250))
            .collect();
        assert_eq!(parse_query_results(&many).addresses.len(), MAX_ADDRESSES);

        let aliases: String = (0..50).map(|i| format!("type: 5 a{i}.example;")).collect();
        assert_eq!(parse_query_results(&aliases).aliases.len(), MAX_ALIASES);

        let dupes = parse_query_results("1.2.3.4;1.2.3.4;::ffff:1.2.3.4;");
        assert_eq!(dupes.addresses, [ip("1.2.3.4")]);
    }

    #[test]
    fn normalizes_names() {
        assert_eq!(
            normalize_name("Example.COM.").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            normalize_name("  www.example.com ").as_deref(),
            Some("www.example.com")
        );
        assert_eq!(
            normalize_name("_dmarc.example.com").as_deref(),
            Some("_dmarc.example.com")
        );
    }

    #[test]
    fn rejects_unsafe_or_invalid_names() {
        assert_eq!(normalize_name(""), None);
        assert_eq!(normalize_name("."), None);
        // Terminal escape sequences must never reach the console.
        assert_eq!(normalize_name("evil\u{1b}[2J.example"), None);
        assert_eq!(normalize_name("new\nline.example"), None);
        assert_eq!(normalize_name("has space.example"), None);
        assert_eq!(normalize_name(&"a".repeat(MAX_NAME_LEN + 1)), None);
        assert!(normalize_name(&"a".repeat(MAX_NAME_LEN)).is_some());
    }

    #[test]
    fn rejects_unicode_that_could_spoof_the_display() {
        // Right-to-left override: would display the rest reversed.
        assert_eq!(normalize_name("evil\u{202e}moc.elgoog"), None);
        // Zero-width space and soft hyphen: invisible.
        assert_eq!(normalize_name("goo\u{200b}gle.com"), None);
        assert_eq!(normalize_name("goo\u{00ad}gle.com"), None);
        // Look-alike letter: Cyrillic "a" instead of Latin "a".
        assert_eq!(normalize_name("\u{0430}pple.com"), None);
        // Punycode (the ASCII form of internationalised names) is accepted.
        assert_eq!(
            normalize_name("xn--bcher-kva.example").as_deref(),
            Some("xn--bcher-kva.example")
        );
    }
}
