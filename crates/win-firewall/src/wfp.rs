//! Calls into the Windows Filtering Platform (WFP) management API.
//!
//! Everything here works on one provider and one sublayer of our own
//! ([`Scope`]), so it only ever lists or deletes filters Whereabouts made.
//! Filters, the provider and the sublayer are *persistent*: they stay in
//! force across restarts and while the service is stopped (decision D10).

#![allow(unsafe_code)]

use std::io;
use std::net::IpAddr;
use std::path::Path;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_FRIENDLY_NAME, GAA_FLAG_SKIP_MULTICAST,
    GAA_FLAG_SKIP_UNICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB,
    FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_FILTER_ENUM_OVERLAPPING,
    FWP_MATCH_EQUAL, FWP_UINT8, FWP_UINT32, FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_ENUM_TEMPLATE0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0,
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDeleteByKey0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmProviderDeleteByKey0, FwpmSubLayerAdd0,
    FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::core::{GUID, HSTRING, PCWSTR, PWSTR};

/// Error codes WFP returns that are not failures for us.
const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;
const FWP_E_NOT_FOUND: u32 = 0x8032_0008;
const FWP_E_PROVIDER_NOT_FOUND: u32 = 0x8032_0005;
const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

/// The WFP provider and sublayer that hold one set of filters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope {
    pub provider: GUID,
    pub sublayer: GUID,
    pub name: &'static str,
}

/// One filter to add: where, what it matches, and how it is described.
pub struct FilterSpec<'a> {
    pub key: GUID,
    pub layer: GUID,
    pub name: &'a str,
    pub description: &'a str,
    /// Stored with the filter (the rule as JSON), to list rules later.
    pub data: &'a [u8],
    pub app: Option<&'a Path>,
    pub remote: Option<IpAddr>,
    /// Allow instead of block. Allows outrank our blocks (they have a
    /// higher weight in our sublayer); they never affect other sublayers.
    pub permit: bool,
}

/// Weights of our blocks and of our allows (exemptions) in our sublayer:
/// the higher weight wins when both match.
const BLOCK_WEIGHT: u8 = 1;
const PERMIT_WEIGHT: u8 = 15;

/// A filter of ours, as read back from WFP.
#[derive(Debug, Clone)]
pub struct Found {
    pub key: GUID,
    pub data: Vec<u8>,
}

fn wfp_error(code: u32, what: &str) -> io::Error {
    let kind = if code == ERROR_ACCESS_DENIED {
        io::ErrorKind::PermissionDenied
    } else {
        io::ErrorKind::Other
    };
    let text = windows::core::HRESULT(code as i32).message();
    io::Error::new(kind, format!("{what} failed: {text} (0x{code:08X})"))
}

fn check(code: u32, what: &str) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(wfp_error(code, what))
    }
}

/// A UTF-16 string WFP may borrow as a `PWSTR`.
struct Wide(Vec<u16>);

impl Wide {
    fn new(text: &str) -> Self {
        Self(text.encode_utf16().chain(std::iter::once(0)).collect())
    }
    fn as_pwstr(&mut self) -> PWSTR {
        PWSTR(self.0.as_mut_ptr())
    }
}

/// An app ID blob from `FwpmGetAppIdFromFileName0`, freed when dropped.
struct AppId(*mut FWP_BYTE_BLOB);

impl AppId {
    fn for_path(path: &Path) -> io::Result<Self> {
        let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        let name = HSTRING::from(path.as_os_str());
        // SAFETY: `name` is a valid wide string for the call; `blob`
        // receives memory WFP allocates, freed in Drop.
        let code = unsafe { FwpmGetAppIdFromFileName0(&name, &mut blob) };
        check(code, "FwpmGetAppIdFromFileName0")?;
        Ok(Self(blob))
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: allocated by FwpmGetAppIdFromFileName0; freed once.
            unsafe { FwpmFreeMemory0((&raw mut self.0).cast()) };
        }
    }
}

/// An open session with the WFP engine.
pub struct Engine(HANDLE);

// SAFETY: a WFP engine handle may be used from any thread (calls on it are
// serialised by the engine); we never share it without `&mut` or a lock.
unsafe impl Send for Engine {}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Engine")
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: the handle came from FwpmEngineOpen0 and is closed once.
        let _ = unsafe { FwpmEngineClose0(self.0) };
    }
}

impl Engine {
    /// Opens the local WFP engine. Needs administrator rights.
    pub fn open() -> io::Result<Self> {
        let mut handle = HANDLE::default();
        // SAFETY: no session or identity is passed (defaults); `handle`
        // receives the engine handle, closed in Drop.
        let code =
            unsafe { FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut handle) };
        check(code, "opening the Windows Filtering Platform")?;
        Ok(Self(handle))
    }

    /// Runs `work` in a WFP transaction: all of it happens, or none.
    pub fn transaction<T>(&self, work: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        // SAFETY: the engine handle is open.
        check(
            unsafe { FwpmTransactionBegin0(self.0, 0) },
            "starting a WFP transaction",
        )?;
        match work() {
            Ok(value) => {
                // SAFETY: a transaction was begun above.
                check(
                    unsafe { FwpmTransactionCommit0(self.0) },
                    "committing WFP changes",
                )?;
                Ok(value)
            }
            Err(error) => {
                // SAFETY: a transaction was begun above.
                let _ = unsafe { FwpmTransactionAbort0(self.0) };
                Err(error)
            }
        }
    }

    /// Adds the scope's provider and sublayer if they are not there yet.
    pub fn ensure_scope(&self, scope: &Scope) -> io::Result<()> {
        let mut name = Wide::new(scope.name);
        let mut description = Wide::new(
            "Rules created by Whereabouts at the user's request. Whereabouts removes them when it is uninstalled.",
        );
        let provider = FWPM_PROVIDER0 {
            providerKey: scope.provider,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_pwstr(),
                description: description.as_pwstr(),
            },
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            ..Default::default()
        };
        // SAFETY: `provider` and the strings it points to live for the call.
        let code = unsafe { FwpmProviderAdd0(self.0, &provider, None) };
        if code != FWP_E_ALREADY_EXISTS {
            check(code, "adding the Whereabouts WFP provider")?;
        }
        let mut provider_key = scope.provider;
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: scope.sublayer,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_pwstr(),
                description: description.as_pwstr(),
            },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: &mut provider_key,
            weight: 0x8000,
            ..Default::default()
        };
        // SAFETY: `sublayer` and everything it points to live for the call.
        let code = unsafe { FwpmSubLayerAdd0(self.0, &sublayer, None) };
        if code != FWP_E_ALREADY_EXISTS {
            check(code, "adding the Whereabouts WFP sublayer")?;
        }
        Ok(())
    }

    /// Adds one persistent filter: a block, or an allow that exempts a
    /// program from our blocks. Adding a filter that already exists (same
    /// key) is not an error.
    pub fn add_filter(&self, scope: &Scope, spec: &FilterSpec<'_>) -> io::Result<()> {
        let app_id = spec.app.map(AppId::for_path).transpose()?;
        let mut v6 = FWP_BYTE_ARRAY16::default();
        let mut conditions = Vec::new();
        if let Some(app_id) = &app_id {
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: app_id.0 },
                },
            });
        }
        match spec.remote.map(|ip| ip.to_canonical()) {
            Some(IpAddr::V4(v4)) => conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                // IPv4 addresses are compared as numbers in host order.
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint32: u32::from(v4),
                    },
                },
            }),
            Some(IpAddr::V6(addr)) => {
                v6.byteArray16 = addr.octets();
                conditions.push(FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_BYTE_ARRAY16_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            byteArray16: &mut v6,
                        },
                    },
                });
            }
            None => {}
        }
        if conditions.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a block needs a program or an address",
            ));
        }
        let mut name = Wide::new(spec.name);
        let mut description = Wide::new(spec.description);
        let mut data = spec.data.to_vec();
        let mut provider_key = scope.provider;
        let filter = FWPM_FILTER0 {
            filterKey: spec.key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_pwstr(),
                description: description.as_pwstr(),
            },
            flags: FWPM_FILTER_FLAG_PERSISTENT,
            providerKey: &mut provider_key,
            providerData: FWP_BYTE_BLOB {
                size: u32::try_from(data.len()).map_err(io::Error::other)?,
                data: data.as_mut_ptr(),
            },
            layerKey: spec.layer,
            subLayerKey: scope.sublayer,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 {
                    uint8: if spec.permit {
                        PERMIT_WEIGHT
                    } else {
                        BLOCK_WEIGHT
                    },
                },
            },
            numFilterConditions: u32::try_from(conditions.len()).map_err(io::Error::other)?,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: if spec.permit {
                    FWP_ACTION_PERMIT
                } else {
                    FWP_ACTION_BLOCK
                },
                ..Default::default()
            },
            ..Default::default()
        };
        // SAFETY: `filter` and everything it points to (strings, data,
        // conditions, the app ID blob, the IPv6 bytes) live until after
        // the call.
        let code = unsafe { FwpmFilterAdd0(self.0, &filter, None, None) };
        if code == FWP_E_ALREADY_EXISTS {
            return Ok(());
        }
        check(code, "adding a firewall rule")
    }

    /// Deletes one filter; `false` if it did not exist.
    pub fn delete(&self, key: &GUID) -> io::Result<bool> {
        // SAFETY: `key` is a valid GUID for the call.
        let code = unsafe { FwpmFilterDeleteByKey0(self.0, key) };
        match code {
            0 => Ok(true),
            FWP_E_FILTER_NOT_FOUND | FWP_E_NOT_FOUND => Ok(false),
            _ => Err(wfp_error(code, "removing a blocking rule")),
        }
    }

    /// Lists our filters in `layer`.
    pub fn list(&self, scope: &Scope, layer: GUID) -> io::Result<Vec<Found>> {
        let mut provider_key = scope.provider;
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            providerKey: &mut provider_key,
            layerKey: layer,
            enumType: FWP_FILTER_ENUM_OVERLAPPING,
            actionMask: 0xFFFF_FFFF,
            ..Default::default()
        };
        let mut enum_handle = HANDLE::default();
        // SAFETY: `template` lives for the call; the enum handle is
        // destroyed below.
        let code =
            unsafe { FwpmFilterCreateEnumHandle0(self.0, Some(&template), &mut enum_handle) };
        check(code, "listing blocking rules")?;
        let mut found = Vec::new();
        let result = (|| loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut count = 0u32;
            // SAFETY: the enum handle is open; WFP allocates `entries`,
            // which is freed below.
            let code =
                unsafe { FwpmFilterEnum0(self.0, enum_handle, 100, &mut entries, &mut count) };
            check(code, "listing blocking rules")?;
            for index in 0..usize::try_from(count).unwrap_or(0) {
                // SAFETY: WFP returned `count` valid filter pointers.
                let filter = unsafe { &**entries.add(index) };
                let blob = filter.providerData;
                let data = if blob.data.is_null() || blob.size == 0 {
                    Vec::new()
                } else {
                    // SAFETY: the blob holds `size` bytes owned by WFP,
                    // valid until `entries` is freed.
                    unsafe {
                        std::slice::from_raw_parts(
                            blob.data,
                            usize::try_from(blob.size).unwrap_or(0),
                        )
                    }
                    .to_vec()
                };
                found.push(Found {
                    key: filter.filterKey,
                    data,
                });
            }
            if !entries.is_null() {
                // SAFETY: allocated by FwpmFilterEnum0; freed once.
                unsafe { FwpmFreeMemory0((&raw mut entries).cast()) };
            }
            if count < 100 {
                return Ok(());
            }
        })();
        // SAFETY: the enum handle was created above and is destroyed once.
        let _ = unsafe { FwpmFilterDestroyEnumHandle0(self.0, enum_handle) };
        result.map(|()| found)
    }

    /// Removes the scope's sublayer and provider (after its filters).
    pub fn remove_scope(&self, scope: &Scope) -> io::Result<()> {
        // SAFETY: the keys are valid GUIDs for the calls.
        let code = unsafe { FwpmSubLayerDeleteByKey0(self.0, &scope.sublayer) };
        if code != FWP_E_SUBLAYER_NOT_FOUND && code != FWP_E_NOT_FOUND {
            check(code, "removing the Whereabouts WFP sublayer")?;
        }
        // SAFETY: as above.
        let code = unsafe { FwpmProviderDeleteByKey0(self.0, &scope.provider) };
        if code != FWP_E_PROVIDER_NOT_FOUND && code != FWP_E_NOT_FOUND {
            check(code, "removing the Whereabouts WFP provider")?;
        }
        Ok(())
    }
}

/// The DNS servers this computer is configured to use, on any adapter.
pub fn dns_servers() -> Vec<IpAddr> {
    let flags = GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_FRIENDLY_NAME;
    let mut size = 16 * 1024u32;
    for _ in 0..4 {
        // u64 elements keep the buffer aligned for IP_ADAPTER_ADDRESSES_LH.
        let mut buffer = vec![0u64; usize::try_from(size).unwrap_or(0).div_ceil(8)];
        let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        // SAFETY: `buffer` is writable for `size` bytes and suitably
        // aligned; `size` is updated if it is too small.
        let code = unsafe {
            GetAdaptersAddresses(u32::from(AF_UNSPEC.0), flags, None, Some(first), &mut size)
        };
        if code == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if code != 0 {
            return Vec::new();
        }
        let mut servers = Vec::new();
        let mut adapter = first.cast_const();
        while !adapter.is_null() {
            // SAFETY: the adapter list lives in `buffer`, filled above.
            let entry = unsafe { &*adapter };
            let mut dns = entry.FirstDnsServerAddress.cast_const();
            while !dns.is_null() {
                // SAFETY: part of the same list.
                let server = unsafe { &*dns };
                let socket = server.Address;
                let length = usize::try_from(socket.iSockaddrLength).unwrap_or(0);
                if !socket.lpSockaddr.is_null() && length >= 8 {
                    // SAFETY: the sockaddr holds `length` bytes in `buffer`.
                    let bytes = unsafe {
                        std::slice::from_raw_parts(socket.lpSockaddr.cast::<u8>(), length)
                    };
                    let family = u16::from_le_bytes([bytes[0], bytes[1]]);
                    if family == AF_INET.0 && length >= 8 {
                        servers.push(IpAddr::from([bytes[4], bytes[5], bytes[6], bytes[7]]));
                    } else if family == AF_INET6.0 && length >= 24 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&bytes[8..24]);
                        servers.push(IpAddr::from(octets));
                    }
                }
                dns = server.Next.cast_const();
            }
            adapter = entry.Next.cast_const();
        }
        servers.sort();
        servers.dedup();
        return servers;
    }
    Vec::new()
}
