//! Reads Windows' DNS client cache (v0.2, N7), like `ipconfig /displaydns`.
//!
//! Connections that started before Whereabouts did, and sites still cached
//! when a domain block is added, have no fresh DNS answer for Whereabouts
//! to see: Windows answers repeated lookups from this cache without
//! confirming them again. Reading the cache fills that gap.
//!
//! The list of cached names comes from `DnsGetCacheDataTable`, which
//! `ipconfig` uses but Windows does not document. It is looked up at run
//! time, so if a Windows version ever lacks it, this simply returns
//! nothing. Each name's records are then read with the documented
//! `DnsQuery_W` and `DNS_QUERY_NO_WIRE_QUERY`, which answers **from the
//! cache only**, never from the network; hosts-file entries are skipped.
//! The cache is filled by the Windows DNS service, so its answers are
//! trusted like the service's own answer events.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::NetworkManagement::Dns::{
    DNS_QUERY_NO_HOSTS_FILE, DNS_QUERY_NO_WIRE_QUERY, DNS_RECORDA, DNS_RECORDW, DNS_TYPE,
    DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME, DnsFree, DnsFreeFlat, DnsFreeRecordList, DnsQuery_W,
};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows::core::{BOOL, HSTRING, PWSTR, s, w};

use crate::dns::{MAX_ADDRESSES, MAX_ALIASES, normalize_name};

/// Most cached names read.
const MAX_NAMES: usize = 4096;

/// One cached answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedAnswer {
    /// The cached name, normalised.
    pub name: String,
    /// CNAME aliases it points to, normalised, in order.
    pub aliases: Vec<String>,
    /// Its addresses.
    pub addresses: Vec<IpAddr>,
}

/// An entry of `DnsGetCacheDataTable`'s list (layout used by `ipconfig`).
#[repr(C)]
struct CacheEntry {
    next: *mut CacheEntry,
    name: PWSTR,
    kind: u16,
    data_length: u16,
    flags: u32,
}

type GetCacheDataTable = unsafe extern "system" fn(*mut *mut CacheEntry) -> BOOL;

/// The names in the cache (A, AAAA and CNAME entries), normalised, without
/// repeats. Empty if the cache cannot be read.
fn cached_names() -> Vec<String> {
    // SAFETY: loads the system's own dnsapi.dll (system folder only); the
    // name is a valid wide string.
    let Ok(module) =
        (unsafe { LoadLibraryExW(w!("dnsapi.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32) })
    else {
        return Vec::new();
    };
    // SAFETY: a valid module handle and a NUL-terminated name.
    let Some(address) = (unsafe { GetProcAddress(module, s!("DnsGetCacheDataTable")) }) else {
        return Vec::new();
    };
    // SAFETY: DnsGetCacheDataTable has this signature (one out-pointer to
    // the first entry, returns BOOL), as ipconfig uses it.
    let get_table: GetCacheDataTable = unsafe { std::mem::transmute(address) };
    let mut first: *mut CacheEntry = std::ptr::null_mut();
    // SAFETY: `first` is a valid out-pointer.
    if !unsafe { get_table(&mut first) }.as_bool() {
        return Vec::new();
    }
    let mut names = Vec::new();
    let mut entry = first;
    while !entry.is_null() {
        // SAFETY: `entry` is a non-null entry of the list Windows returned,
        // valid until freed below; its name is a NUL-terminated wide string
        // or null.
        let (next, name_ptr, kind) = unsafe { ((*entry).next, (*entry).name, (*entry).kind) };
        if names.len() < MAX_NAMES
            && [DNS_TYPE_A.0, DNS_TYPE_AAAA.0, DNS_TYPE_CNAME.0].contains(&kind)
            && !name_ptr.is_null()
            // SAFETY: see above.
            && let Ok(text) = unsafe { name_ptr.to_string() }
            && let Some(name) = normalize_name(&text)
            && !names.contains(&name)
        {
            names.push(name);
        }
        // SAFETY: the name and the entry were allocated by dnsapi and are
        // freed once each, flat, as ipconfig does; nothing uses them after.
        unsafe {
            if !name_ptr.is_null() {
                DnsFree(Some(name_ptr.0 as *const c_void), DnsFreeFlat);
            }
            DnsFree(Some(entry as *const c_void), DnsFreeFlat);
        }
        entry = next;
    }
    names
}

/// Reads `name`'s cached records of type `kind` (never from the network).
fn read_cached(name: &str, kind: DNS_TYPE, answer: &mut CachedAnswer) {
    let mut records: *mut DNS_RECORDW = std::ptr::null_mut();
    // SAFETY: a valid wide name and out-pointer. The binding declares the
    // out-pointer as DNS_RECORDA, but DnsQuery_W fills it with DNS_RECORDW
    // (the same layout with wide strings).
    let code = unsafe {
        DnsQuery_W(
            &HSTRING::from(name),
            kind,
            DNS_QUERY_NO_WIRE_QUERY | DNS_QUERY_NO_HOSTS_FILE,
            None,
            std::ptr::addr_of_mut!(records).cast::<*mut DNS_RECORDA>(),
            None,
        )
    };
    if code.0 != 0 || records.is_null() {
        return;
    }
    let mut record = records;
    while !record.is_null() {
        // SAFETY: a record of the list DnsQuery_W returned, valid until the
        // list is freed below; the union member read matches its type.
        unsafe {
            match DNS_TYPE((*record).wType) {
                DNS_TYPE_A if answer.addresses.len() < MAX_ADDRESSES => {
                    let ip = IpAddr::V4(Ipv4Addr::from((*record).Data.A.IpAddress.to_ne_bytes()));
                    if !answer.addresses.contains(&ip) {
                        answer.addresses.push(ip);
                    }
                }
                DNS_TYPE_AAAA if answer.addresses.len() < MAX_ADDRESSES => {
                    let ip = IpAddr::V6(Ipv6Addr::from((*record).Data.AAAA.Ip6Address.IP6Byte))
                        .to_canonical();
                    if !answer.addresses.contains(&ip) {
                        answer.addresses.push(ip);
                    }
                }
                DNS_TYPE_CNAME if answer.aliases.len() < MAX_ALIASES => {
                    let target = (*record).Data.CNAME.pNameHost;
                    if !target.is_null()
                        && let Ok(text) = target.to_string()
                        && let Some(alias) = normalize_name(&text)
                        && alias != answer.name
                        && !answer.aliases.contains(&alias)
                    {
                        answer.aliases.push(alias);
                    }
                }
                _ => {}
            }
            record = (*record).pNext;
        }
    }
    // SAFETY: frees the list DnsQuery_W returned, once.
    unsafe { DnsFree(Some(records as *const c_void), DnsFreeRecordList) };
}

/// Everything in Windows' DNS cache that has addresses: each cached name
/// with its CNAME aliases and addresses. Empty if the cache cannot be read.
pub fn cached_answers() -> Vec<CachedAnswer> {
    let mut answers = Vec::new();
    for name in cached_names() {
        let mut answer = CachedAnswer {
            name: name.clone(),
            aliases: Vec::new(),
            addresses: Vec::new(),
        };
        read_cached(&name, DNS_TYPE_A, &mut answer);
        read_cached(&name, DNS_TYPE_AAAA, &mut answer);
        if !answer.addresses.is_empty() {
            answers.push(answer);
        }
    }
    answers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cache_can_be_read_without_touching_the_network() {
        // Look a name up so the cache holds at least one entry, then read it.
        let _ = std::net::ToSocketAddrs::to_socket_addrs(&("localhost", 80));
        let answers = cached_answers();
        for answer in &answers {
            assert!(normalize_name(&answer.name).as_deref() == Some(answer.name.as_str()));
            assert!(!answer.addresses.is_empty());
            assert!(answer.aliases.len() <= MAX_ALIASES);
        }
        eprintln!("{} cached names with addresses", answers.len());
    }

    /// Needs a working DNS client cache and the internet (some computers
    /// bypass the cache, e.g. behind some VPNs); run in CI's live job.
    #[test]
    #[ignore = "needs the internet and Windows' DNS cache; run with --ignored"]
    fn a_name_just_looked_up_is_in_the_cache() {
        let _ = std::net::ToSocketAddrs::to_socket_addrs(&("example.com", 443)).unwrap();
        let answers = cached_answers();
        let found = answers.iter().find(|a| a.name == "example.com");
        assert!(
            found.is_some_and(|a| !a.addresses.is_empty()),
            "{} cached names",
            answers.len()
        );
    }
}
