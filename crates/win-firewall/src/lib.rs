//! Windows Filtering Platform rules for Whereabouts (design spec §5.6).
//!
//! Blocks a program's connections, or connections to one address (by one
//! program or by every program), with user-mode WFP filters at the ALE
//! layers: connect (outgoing) for every rule, and also receive/accept
//! (incoming) for a whole program. No kernel driver is involved.
//!
//! Safety rules:
//! - **Guard-list:** core Windows programs, Microsoft Defender and
//!   Whereabouts itself cannot be blocked, nor loopback, local-network,
//!   multicast or DNS-server addresses ([`guard`]).
//! - **Our own scope only:** every filter lives under the Whereabouts WFP
//!   provider and sublayer, so [`Firewall::remove_all`] and uninstalling
//!   remove exactly what Whereabouts added, and nothing else.
//! - **Persistent** (decision D10): blocks stay in force across restarts
//!   and while the service is stopped.
//!
//! Each rule's filter keys are derived from the rule itself, so blocking
//! twice is harmless and unblocking needs no stored IDs. Each filter also
//! carries its rule as JSON, so [`Firewall::rules`] can list what is
//! blocked straight from WFP.

#![allow(unsafe_code)]

pub mod guard;
mod webview2;
mod wfp;

use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
};
use windows::core::GUID;

pub use guard::Refusal;
pub use wfp::dns_servers;
use wfp::{Engine, FilterSpec, Scope};

/// The scope (WFP provider and sublayer) of Whereabouts' real rules.
const WHEREABOUTS: Scope = Scope {
    provider: GUID::from_u128(0x5a1f_0c2e_7d3b_4e8a_9b61_2f4c_8d0e_a301),
    sublayer: GUID::from_u128(0x5a1f_0c2e_7d3b_4e8a_9b61_2f4c_8d0e_a302),
    name: "Whereabouts",
};

/// A separate scope for tests, so they can never touch real rules.
const TESTS: Scope = Scope {
    provider: GUID::from_u128(0x5a1f_0c2e_7d3b_4e8a_9b61_2f4c_8d0e_a3f1),
    sublayer: GUID::from_u128(0x5a1f_0c2e_7d3b_4e8a_9b61_2f4c_8d0e_a3f2),
    name: "Whereabouts (tests)",
};

/// Every layer a Whereabouts filter can be in.
const ALL_LAYERS: [GUID; 4] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
];

/// Whether `layer` decides on incoming connections.
fn is_incoming(layer: GUID) -> bool {
    layer == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 || layer == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
}

/// What to block.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Block {
    /// Every connection a program makes or accepts.
    App {
        /// The program's full path.
        path: PathBuf,
    },
    /// Connections to one address: by one program, or by every program.
    Address {
        /// The remote address.
        ip: IpAddr,
        /// The program, or `None` for every program.
        app: Option<PathBuf>,
        /// The domain this address was learned for, when it comes from a
        /// domain block (not part of the rule's identity).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        via: Option<String>,
        /// When the address was learned, in seconds since 1970 (0 if it
        /// was blocked directly; not part of the rule's identity).
        #[serde(default, skip_serializing_if = "is_zero")]
        learned: u64,
    },
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl Block {
    /// Blocks every connection of the program at `path` (which must exist).
    pub fn app(path: &Path) -> io::Result<Self> {
        Ok(Self::App {
            path: normalize(path)?,
        })
    }

    /// Blocks connections to `ip`, by the program at `app` or by every
    /// program.
    pub fn address(ip: IpAddr, app: Option<&Path>) -> io::Result<Self> {
        Ok(Self::Address {
            ip: ip.to_canonical(),
            app: app.map(normalize).transpose()?,
            via: None,
            learned: 0,
        })
    }

    /// Blocks `ip` because it is an address of the blocked `domain`, learned
    /// at `learned` (seconds since 1970). `app` is an already normalised
    /// path, or `None` for every program.
    pub fn learned_address(ip: IpAddr, app: Option<PathBuf>, domain: &str, learned: u64) -> Self {
        Self::Address {
            ip: ip.to_canonical(),
            app,
            via: Some(domain.to_owned()),
            learned,
        }
    }

    /// The WFP layers (IPv4, IPv6) this rule needs a filter in. A whole
    /// program is also refused incoming connections: a blocked torrent
    /// client could otherwise keep trading with peers that connect to it
    /// (Windows Firewall usually allows that when the app is installed).
    fn layers(&self) -> Vec<GUID> {
        match self {
            Self::App { .. } => ALL_LAYERS.to_vec(),
            Self::Address { ip, .. } if ip.is_ipv4() => vec![FWPM_LAYER_ALE_AUTH_CONNECT_V4],
            Self::Address { .. } => vec![FWPM_LAYER_ALE_AUTH_CONNECT_V6],
        }
    }

    /// The rule as text for people, e.g. "chrome.exe → 203.0.113.5".
    pub fn describe(&self) -> String {
        let name = |path: &Path| {
            path.file_name().map_or_else(
                || path.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            )
        };
        match self {
            Self::App { path } => format!("{} (all connections)", name(path)),
            Self::Address {
                ip, app: Some(app), ..
            } => format!("{} → {ip}", name(app)),
            Self::Address { ip, app: None, .. } => format!("every app → {ip}"),
        }
    }
}

/// A full path in one canonical spelling (so the same program always gives
/// the same rule), without the `\\?\` prefix. The file must exist, on a
/// local drive (see [`wfp::is_local_drive_path`]).
pub fn normalize_path(path: &Path) -> io::Result<PathBuf> {
    normalize(path)
}

fn normalize(path: &Path) -> io::Result<PathBuf> {
    let not_local = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "only programs on this computer's own drives can be blocked",
        )
    };
    // Checked before touching the file system: the service must never
    // open a path on another computer.
    if !wfp::is_local_drive_path(path) {
        return Err(not_local());
    }
    refuse_links(path)?;
    let full = std::fs::canonicalize(path)?;
    let text = full.to_string_lossy();
    let normal = PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text));
    // A link on a local drive could lead elsewhere.
    if !wfp::is_local_drive_path(&normal) {
        return Err(not_local());
    }
    Ok(normal)
}

/// Refuses a path with `.` or `..` parts, or with a link or other reparse
/// point anywhere along it, **without following any of them**: a symbolic
/// link (which any user can make when Windows' Developer Mode is on) could
/// lead to another computer, and following it as SYSTEM would offer that
/// computer this computer's credentials. Paths of running programs, as
/// Windows reports them, never contain links.
fn refuse_links(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    use std::path::Component;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let mut partial = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => partial.push(component),
            Component::Normal(_) => {
                partial.push(component);
                // Reads the entry itself; a link is not followed.
                let metadata = std::fs::symlink_metadata(&partial)?;
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "{} is a link; give the program's real location",
                            partial.display()
                        ),
                    ));
                }
            }
            Component::CurDir | Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "give the program's full path, without . or .. parts",
                ));
            }
        }
    }
    Ok(())
}

/// The filter key for `block` in `layer`: the same rule always gets the
/// same key. Paths compare without regard to case, as Windows does.
fn filter_key(scope: &Scope, block: &Block, layer: GUID) -> GUID {
    let identity = match block {
        Block::App { path } => format!("app|{}", path.to_string_lossy().to_lowercase()),
        Block::Address { ip, app, .. } => format!(
            "address|{ip}|{}",
            app.as_ref()
                .map(|p| p.to_string_lossy().to_lowercase())
                .unwrap_or_default()
        ),
    };
    let digest = Sha256::new()
        .chain_update(b"whereabouts-filter-v1|")
        .chain_update(scope.provider.to_u128().to_le_bytes())
        .chain_update(identity.as_bytes())
        .chain_update(layer.to_u128().to_le_bytes())
        .finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Mark it as a name-based (version 8, RFC 9562 variant) identifier.
    bytes[6] = (bytes[6] & 0x0F) | 0x80;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    GUID::from_u128(u128::from_be_bytes(bytes))
}

/// Why a block could not be added.
#[derive(Debug)]
pub enum BlockError {
    /// The guard-list refused it.
    Refused(Refusal),
    /// Windows refused or failed.
    Io(io::Error),
}

impl std::fmt::Display for BlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "not blocked: {refusal}"),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for BlockError {}

impl From<io::Error> for BlockError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Whereabouts' blocking rules in the Windows Filtering Platform.
#[derive(Debug)]
pub struct Firewall {
    engine: Engine,
    scope: Scope,
    /// Where the WebView2 setting for blocked apps lives, under
    /// `HKEY_LOCAL_MACHINE` (see [`webview2`]).
    webview2_key: &'static str,
}

/// A registry key WebView2 never reads, for tests.
const TESTS_WEBVIEW2_KEY: &str = r"SOFTWARE\Whereabouts tests\WebView2\AdditionalBrowserArguments";

impl Firewall {
    /// Opens WFP for Whereabouts' rules. Needs administrator rights.
    pub fn open() -> io::Result<Self> {
        Self::open_scope(WHEREABOUTS, webview2::POLICY_KEY)
    }

    /// Opens WFP with a separate scope for tests, which can never touch the
    /// real rules.
    #[doc(hidden)]
    pub fn open_for_tests() -> io::Result<Self> {
        Self::open_scope(TESTS, TESTS_WEBVIEW2_KEY)
    }

    fn open_scope(scope: Scope, webview2_key: &'static str) -> io::Result<Self> {
        let engine = Engine::open()?;
        engine.transaction(|| {
            engine.ensure_scope(&scope)?;
            add_exemptions(&engine, &scope)
        })?;
        Ok(Self {
            engine,
            scope,
            webview2_key,
        })
    }

    /// Makes the WebView2 setting match the app blocks now in WFP: blocked
    /// apps' web pages stay offline from their next start (see
    /// [`webview2`]). The block calls do this themselves, best effort: the
    /// filters are what blocks the app, and they are in place either way.
    pub fn sync_webview2(&self) -> io::Result<()> {
        let wanted = self
            .rules()?
            .into_iter()
            .filter_map(|block| match block {
                Block::App { path } => path
                    .file_name()
                    .map(|name| name.to_string_lossy().to_lowercase()),
                Block::Address { .. } => None,
            })
            .collect();
        webview2::sync(self.webview2_key, &wanted)
    }

    /// Adds `block`, after checking the guard-list. Blocking something
    /// already blocked is not an error.
    pub fn block(&self, block: &Block) -> Result<(), BlockError> {
        check_guard(block).map_err(BlockError::Refused)?;
        let data = serde_json::to_vec(block).map_err(io::Error::other)?;
        let name = format!("Whereabouts: block {}", block.describe());
        let description = String::from("Added by Whereabouts at the user's request.");
        let (app, remote) = match block {
            Block::App { path } => (Some(path.as_path()), None),
            Block::Address { ip, app, .. } => (app.as_deref(), Some(*ip)),
        };
        self.engine.transaction(|| {
            for layer in block.layers() {
                self.engine.add_filter(
                    &self.scope,
                    &FilterSpec {
                        key: filter_key(&self.scope, block, layer),
                        layer,
                        name: &name,
                        description: &description,
                        data: &data,
                        app,
                        remote,
                        // An app's own window often talks to the app over
                        // loopback (uTorrent Web's does); that is not the
                        // internet. (The outgoing filters predate this and
                        // keep their keys and conditions unchanged.)
                        except_loopback: is_incoming(layer),
                        permit: false,
                    },
                )?;
            }
            Ok(())
        })?;
        if matches!(block, Block::App { .. }) {
            let _ = self.sync_webview2();
        }
        Ok(())
    }

    /// Removes `block`. Returns `false` if it was not blocked.
    pub fn unblock(&self, block: &Block) -> io::Result<bool> {
        let removed = self.engine.transaction(|| {
            let mut removed = false;
            for layer in block.layers() {
                removed |= self.engine.delete(&filter_key(&self.scope, block, layer))?;
            }
            Ok(removed)
        })?;
        if matches!(block, Block::App { .. }) {
            let _ = self.sync_webview2();
        }
        Ok(removed)
    }

    /// Everything currently blocked, read from WFP itself.
    pub fn rules(&self) -> io::Result<Vec<Block>> {
        let mut rules = Vec::new();
        for layer in [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        ] {
            for found in self.engine.list(&self.scope, layer)? {
                if let Ok(block) = serde_json::from_slice::<Block>(&found.data)
                    && !rules.contains(&block)
                {
                    rules.push(block);
                }
            }
        }
        Ok(rules)
    }

    /// Removes every Whereabouts block (the exemptions stay). Returns how
    /// many filters were removed.
    pub fn remove_all(&self) -> io::Result<usize> {
        self.remove_where(|data| serde_json::from_slice::<Block>(data).is_ok())
    }

    /// Removes our filters whose stored data `matches`.
    fn remove_where(&self, matches: impl Fn(&[u8]) -> bool) -> io::Result<usize> {
        let mut keys = Vec::new();
        for layer in ALL_LAYERS {
            keys.extend(
                self.engine
                    .list(&self.scope, layer)?
                    .into_iter()
                    .filter(|f| matches(&f.data))
                    .map(|f| f.key),
            );
        }
        let removed = self.engine.transaction(|| {
            let mut removed = 0;
            for key in &keys {
                if self.engine.delete(key)? {
                    removed += 1;
                }
            }
            Ok(removed)
        })?;
        // Removing everything (pause, the emergency switch, uninstalling)
        // must also take the WebView2 setting away, so this one reports.
        self.sync_webview2()?;
        Ok(removed)
    }

    /// Removes every rule, then Whereabouts' WFP provider and sublayer:
    /// nothing of Whereabouts is left in WFP (used when uninstalling).
    pub fn uninstall(self) -> io::Result<usize> {
        let removed = self.remove_where(|_| true)?;
        self.engine
            .transaction(|| self.engine.remove_scope(&self.scope))?;
        Ok(removed)
    }
}

/// Core Windows programs exempted from every Whereabouts block, including
/// "every app" blocks: allows that outrank our blocks in our own sublayer.
/// They never affect anyone else's firewall rules.
const EXEMPT_PROGRAMS: [&str; 6] = [
    "svchost.exe",
    "lsass.exe",
    "services.exe",
    "wininit.exe",
    "winlogon.exe",
    "spoolsv.exe",
];

/// Adds (or keeps) the exemptions for core Windows programs.
fn add_exemptions(engine: &Engine, scope: &Scope) -> io::Result<()> {
    let system32 = std::env::var_os("SystemRoot")
        .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from)
        .join("System32");
    for program in EXEMPT_PROGRAMS {
        let path = system32.join(program);
        if !path.is_file() {
            continue;
        }
        let data = serde_json::json!({ "kind": "exempt", "path": path }).to_string();
        let name = format!("Whereabouts: never block {program}");
        let identity = Block::App { path: path.clone() };
        for layer in [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        ] {
            engine.add_filter(
                scope,
                &FilterSpec {
                    key: exemption_key(scope, &identity, layer),
                    layer,
                    name: &name,
                    description: "Core Windows program: Whereabouts' blocks never apply to it.",
                    data: data.as_bytes(),
                    app: Some(&path),
                    remote: None,
                    except_loopback: false,
                    permit: true,
                },
            )?;
        }
    }
    Ok(())
}

/// The key of an exemption filter: never the same as any block's key.
fn exemption_key(scope: &Scope, program: &Block, layer: GUID) -> GUID {
    let exemptions = Scope {
        provider: GUID::from_u128(scope.provider.to_u128() ^ 0xE),
        ..*scope
    };
    filter_key(&exemptions, program, layer)
}

/// The guard-list check for `block`: whether Whereabouts refuses to block
/// it (core Windows programs, DNS servers, the local network...).
pub fn check_guard(block: &Block) -> Result<(), Refusal> {
    let system_root =
        std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    let program = match block {
        Block::App { path } => Some(path),
        Block::Address { app, .. } => app.as_ref(),
    };
    if let Some(path) = program {
        guard::check_program(path, &system_root)?;
    }
    if let Block::Address { ip, .. } = block {
        guard::check_address(*ip, &dns_servers())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(path: &str) -> Block {
        Block::App {
            path: PathBuf::from(path),
        }
    }

    #[test]
    fn the_same_rule_always_gets_the_same_keys() {
        let a = filter_key(
            &WHEREABOUTS,
            &app(r"C:\Apps\x.exe"),
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        );
        let b = filter_key(
            &WHEREABOUTS,
            &app(r"c:\apps\X.EXE"),
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        );
        assert_eq!(a, b, "paths compare without regard to case");
        let v6 = filter_key(
            &WHEREABOUTS,
            &app(r"C:\Apps\x.exe"),
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        );
        assert_ne!(a, v6, "each layer has its own filter");
        let other = filter_key(
            &WHEREABOUTS,
            &app(r"C:\Apps\y.exe"),
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        );
        assert_ne!(a, other);
        let test_scope = filter_key(
            &TESTS,
            &app(r"C:\Apps\x.exe"),
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        );
        assert_ne!(a, test_scope, "tests never share keys with real rules");
    }

    #[test]
    fn address_rules_for_one_app_and_for_all_apps_differ() {
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let one = Block::Address {
            ip,
            app: Some(PathBuf::from(r"C:\Apps\x.exe")),
            via: None,
            learned: 0,
        };
        let all = Block::Address {
            ip,
            app: None,
            via: None,
            learned: 0,
        };
        let layer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        assert_ne!(
            filter_key(&WHEREABOUTS, &one, layer),
            filter_key(&WHEREABOUTS, &all, layer)
        );
        assert_eq!(one.layers(), vec![FWPM_LAYER_ALE_AUTH_CONNECT_V4]);
        assert_eq!(
            app(r"C:\Apps\x.exe").layers(),
            ALL_LAYERS.to_vec(),
            "a whole program is blocked both ways"
        );
        let v6 = Block::Address {
            ip: "2001:db8::1".parse().unwrap(),
            app: None,
            via: None,
            learned: 0,
        };
        assert_eq!(v6.layers(), vec![FWPM_LAYER_ALE_AUTH_CONNECT_V6]);
    }

    #[test]
    fn rules_round_trip_as_json() {
        for block in [
            app(r"C:\Program Files\App\app.exe"),
            Block::Address {
                ip: "203.0.113.5".parse().unwrap(),
                app: None,
                via: None,
                learned: 0,
            },
        ] {
            let json = serde_json::to_vec(&block).unwrap();
            assert_eq!(serde_json::from_slice::<Block>(&json).unwrap(), block);
        }
        assert!(serde_json::from_str::<Block>(r#"{"kind":"app","path":"x","extra":1}"#).is_err());
    }

    #[test]
    fn where_an_address_was_learned_does_not_change_its_rule() {
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let direct = Block::Address {
            ip,
            app: None,
            via: None,
            learned: 0,
        };
        let learned = Block::learned_address(ip, None, "tracker.example.com", 1_700_000_000);
        let layer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        assert_eq!(
            filter_key(&WHEREABOUTS, &direct, layer),
            filter_key(&WHEREABOUTS, &learned, layer)
        );
        let json = serde_json::to_vec(&learned).unwrap();
        assert_eq!(serde_json::from_slice::<Block>(&json).unwrap(), learned);
        // A direct block's JSON stays as short as before.
        let direct_json = serde_json::to_string(&direct).unwrap();
        assert!(
            !direct_json.contains("via") && !direct_json.contains("learned"),
            "{direct_json}"
        );
    }

    #[test]
    fn only_programs_on_local_drives_are_accepted() {
        for remote in [
            r"\\server\share\x.exe",
            r"\\?\UNC\server\share\x.exe",
            r"\\.\pipe\x",
            r"\\?\C:\Windows\System32\curl.exe",
            r"C:Windows\x.exe",
            "C:/Windows/System32/curl.exe",
            "curl.exe",
            "",
        ] {
            assert!(!wfp::is_local_drive_path(Path::new(remote)), "{remote}");
            assert!(normalize_path(Path::new(remote)).is_err(), "{remote}");
        }
        let curl = PathBuf::from(std::env::var("SystemRoot").unwrap()).join(r"System32\curl.exe");
        assert!(wfp::is_local_drive_path(&curl));
        assert!(normalize_path(&curl).is_ok());
    }

    #[test]
    fn links_and_dot_dot_are_refused_without_following_them() {
        let system = PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32");
        assert!(normalize_path(&system.join(r"..\System32\curl.exe")).is_err());
        // A directory junction (no special rights needed to make one).
        let base = std::env::temp_dir().join(format!("wa-link-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let junction = base.join("j");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&system)
            .output()
            .is_ok_and(|out| out.status.success());
        if made {
            let through = junction.join("curl.exe");
            assert!(through.is_file());
            let error = normalize_path(&through).unwrap_err();
            assert!(error.to_string().contains("link"), "{error}");
            let _ = std::fs::remove_dir(&junction);
        }
        let _ = std::fs::remove_dir_all(&base);
        assert!(made, "could not make a junction to test with");
    }

    #[test]
    fn exemption_keys_never_collide_with_block_keys() {
        let svchost = app(r"C:\Windows\System32\svchost.exe");
        let layer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        assert_ne!(
            exemption_key(&WHEREABOUTS, &svchost, layer),
            filter_key(&WHEREABOUTS, &svchost, layer)
        );
        // An exemption's stored data is not a block, so it is never listed
        // as one, and "remove all" leaves it.
        let data = serde_json::json!({ "kind": "exempt", "path": "x" }).to_string();
        assert!(serde_json::from_str::<Block>(&data).is_err());
    }

    #[test]
    fn rules_describe_themselves() {
        assert_eq!(app(r"C:\Apps\x.exe").describe(), "x.exe (all connections)");
        let all = Block::Address {
            ip: "203.0.113.5".parse().unwrap(),
            app: None,
            via: None,
            learned: 0,
        };
        assert_eq!(all.describe(), "every app → 203.0.113.5");
    }

    #[test]
    fn the_guard_list_applies_before_windows_is_asked() {
        let svchost = Block::App {
            path: PathBuf::from(r"C:\Windows\System32\svchost.exe"),
        };
        assert!(check_guard(&svchost).is_err());
        let loopback = Block::Address {
            ip: "127.0.0.1".parse().unwrap(),
            app: None,
            via: None,
            learned: 0,
        };
        assert!(check_guard(&loopback).is_err());
    }

    #[test]
    fn normalizing_gives_one_spelling() {
        let exe = std::env::current_exe().unwrap();
        // The same file in other letter case.
        let shouted = PathBuf::from(exe.to_string_lossy().to_uppercase());
        assert_eq!(
            normalize(&exe).unwrap().to_string_lossy().to_lowercase(),
            normalize(&shouted)
                .unwrap()
                .to_string_lossy()
                .to_lowercase()
        );
        assert_eq!(normalize(&shouted).unwrap(), normalize(&exe).unwrap());
        assert!(
            !normalize(&exe)
                .unwrap()
                .to_string_lossy()
                .starts_with(r"\\?\")
        );
    }

    #[test]
    #[ignore = "needs administrator rights; run with --ignored"]
    fn an_app_block_refuses_incoming_connections_but_not_loopback() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        // A listener in this test program, which then blocks itself.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request);
                let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
            }
        });
        let firewall = Firewall::open_for_tests().expect("needs administrator rights");
        let block = Block::app(&std::env::current_exe().unwrap()).unwrap();
        let result = std::panic::catch_unwind(|| {
            firewall.block(&block).unwrap();
            for layer in ALL_LAYERS {
                let keys: Vec<GUID> = firewall
                    .engine
                    .list(&TESTS, layer)
                    .unwrap()
                    .into_iter()
                    .map(|f| f.key)
                    .collect();
                assert!(
                    keys.contains(&filter_key(&TESTS, &block, layer)),
                    "a filter in every layer"
                );
            }
            // Another program (curl) connecting over loopback still gets in.
            let curl =
                PathBuf::from(std::env::var("SystemRoot").unwrap()).join(r"System32\curl.exe");
            let status = std::process::Command::new(curl)
                .args(["--silent", "--output", "NUL", "--max-time", "5"])
                .arg(format!("http://127.0.0.1:{port}/"))
                .status()
                .unwrap();
            assert!(status.success(), "loopback is never blocked: {status}");
        });
        let exe_name = std::env::current_exe()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let set = webview2::value(TESTS_WEBVIEW2_KEY, &exe_name);
        let _ = firewall.uninstall();
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
        assert_eq!(
            set.unwrap().as_deref(),
            Some(webview2::ARGUMENTS),
            "the blocked app's WebView2 is sent nowhere"
        );
        assert_eq!(
            webview2::value(TESTS_WEBVIEW2_KEY, &exe_name).unwrap(),
            None,
            "removed with the block"
        );
    }

    #[test]
    fn this_computers_dns_servers_can_be_read() {
        // Not empty on a connected machine; never panics.
        let servers = dns_servers();
        eprintln!("DNS servers: {servers:?}");
    }
}
