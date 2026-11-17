//! What Whereabouts must never block, so a mistake cannot cut a computer
//! off: core Windows processes, Microsoft Defender, Whereabouts itself, and
//! addresses the network depends on (loopback, the local network,
//! multicast, the configured DNS servers).

use std::net::IpAddr;
use std::path::Path;

/// Why a block was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(pub String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Core Windows programs in `%SystemRoot%\System32`. Blocking any of them
/// can break name lookups, sign-in, updates or the network itself
/// (`svchost.exe` hosts the DNS client and Windows Update).
const SYSTEM_PROGRAMS: [&str; 9] = [
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "wininit.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "dwm.exe",
    "spoolsv.exe",
];

/// Microsoft Defender programs: blocking them stops security updates.
const DEFENDER_PROGRAMS: [&str; 3] = ["msmpeng.exe", "nissrv.exe", "mpcmdrun.exe"];

/// Whereabouts' own programs.
const OWN_PROGRAMS: [&str; 2] = ["whereabouts.exe", "whereabouts-service.exe"];

/// Refuses programs that must never be blocked. `path` is the program's
/// full path; `system_root` is `%SystemRoot%` (e.g. `C:\Windows`).
pub fn check_program(path: &Path, system_root: &Path) -> Result<(), Refusal> {
    let lower = path.to_string_lossy().to_lowercase();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let system32 = system_root
        .join("System32")
        .to_string_lossy()
        .to_lowercase();
    let parent = path
        .parent()
        .map(|p| p.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if parent == system32 && SYSTEM_PROGRAMS.contains(&name.as_str()) {
        return Err(Refusal(format!(
            "{name} is a core Windows program; blocking it could cut this computer off \
             (name lookups, sign-in, updates or the network itself)"
        )));
    }
    if DEFENDER_PROGRAMS.contains(&name.as_str()) && lower.contains("\\windows defender") {
        return Err(Refusal(format!(
            "{name} is Microsoft Defender; blocking it would stop its security updates"
        )));
    }
    if OWN_PROGRAMS.contains(&name.as_str()) {
        return Err(Refusal(String::from(
            "Whereabouts does not block itself; uninstall it instead",
        )));
    }
    Ok(())
}

/// Refuses addresses the network depends on. `dns_servers` are the DNS
/// servers this computer is configured to use.
pub fn check_address(ip: IpAddr, dns_servers: &[IpAddr]) -> Result<(), Refusal> {
    let ip = ip.to_canonical();
    let reason = match ip {
        _ if dns_servers.iter().any(|dns| dns.to_canonical() == ip) => {
            Some("it is one of this computer's DNS servers; blocking it would break name lookups")
        }
        IpAddr::V4(v4) if v4.is_loopback() || v4.is_unspecified() => {
            Some("it is this computer itself")
        }
        IpAddr::V4(v4) if v4.is_private() || v4.is_link_local() || is_shared(v4.octets()) => {
            Some("it is on the local network")
        }
        IpAddr::V4(v4) if v4.is_multicast() || v4.is_broadcast() => {
            Some("it is a multicast or broadcast address")
        }
        IpAddr::V6(v6) if v6.is_loopback() || v6.is_unspecified() => {
            Some("it is this computer itself")
        }
        IpAddr::V6(v6) if is_unique_local(v6.octets()) || is_link_local(v6.octets()) => {
            Some("it is on the local network")
        }
        IpAddr::V6(v6) if v6.is_multicast() => Some("it is a multicast address"),
        _ => None,
    };
    match reason {
        Some(reason) => Err(Refusal(format!("{ip} cannot be blocked: {reason}"))),
        None => Ok(()),
    }
}

/// 100.64.0.0/10, shared address space used by carriers and some routers.
fn is_shared(octets: [u8; 4]) -> bool {
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

/// fc00::/7, IPv6 unique local addresses.
fn is_unique_local(octets: [u8; 16]) -> bool {
    (octets[0] & 0xFE) == 0xFC
}

/// fe80::/10, IPv6 link-local addresses.
fn is_link_local(octets: [u8; 16]) -> bool {
    octets[0] == 0xFE && (octets[1] & 0xC0) == 0x80
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const ROOT: &str = r"C:\Windows";

    #[test]
    fn core_windows_programs_are_refused() {
        for name in ["svchost.exe", "LSASS.EXE", "winlogon.exe"] {
            let path = Path::new(ROOT).join("System32").join(name);
            assert!(check_program(&path, Path::new(ROOT)).is_err(), "{name}");
        }
        // The same name elsewhere is an ordinary program.
        let elsewhere = Path::new(r"C:\Users\me\Downloads\svchost.exe");
        assert!(check_program(elsewhere, Path::new(ROOT)).is_ok());
    }

    #[test]
    fn defender_and_whereabouts_are_refused() {
        let defender =
            Path::new(r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\MsMpEng.exe");
        assert!(check_program(defender, Path::new(ROOT)).is_err());
        let own = Path::new(r"C:\Program Files\Whereabouts\whereabouts-service.exe");
        assert!(check_program(own, Path::new(ROOT)).is_err());
    }

    #[test]
    fn ordinary_programs_are_allowed() {
        for path in [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Windows\System32\curl.exe",
            r"C:\Users\me\AppData\Local\Discord\app-1.0\Discord.exe",
        ] {
            assert!(
                check_program(Path::new(path), Path::new(ROOT)).is_ok(),
                "{path}"
            );
        }
    }

    #[test]
    fn addresses_the_network_needs_are_refused() {
        let dns: [IpAddr; 2] = [
            "1.1.1.1".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
        ];
        for ip in [
            "127.0.0.1",
            "0.0.0.0",
            "192.168.1.1",
            "10.0.0.5",
            "172.16.3.4",
            "169.254.1.1",
            "100.64.0.1",
            "224.0.0.251",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fd00::5",
            "ff02::fb",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "::ffff:192.168.1.1",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(check_address(ip, &dns).is_err(), "{ip} should be refused");
        }
    }

    #[test]
    fn public_addresses_are_allowed() {
        let dns: [IpAddr; 1] = [IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];
        for ip in [
            IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V6(
                "2606:2800:21f:cb07:6820:80da:af6b:8b2c"
                    .parse::<Ipv6Addr>()
                    .unwrap(),
            ),
        ] {
            assert!(check_address(ip, &dns).is_ok(), "{ip} should be allowed");
        }
    }
}
