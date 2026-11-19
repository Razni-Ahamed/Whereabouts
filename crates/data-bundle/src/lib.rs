//! Signed data updates for Whereabouts (v0.2, N6; design spec §7).
//!
//! A **bundle** is the offline data files (tracker list, company list,
//! country and network databases) plus a **manifest** listing each file's
//! name, size and SHA-256, and an **Ed25519 signature** over the manifest's
//! exact bytes. Whereabouts ships only the public key; anything not signed
//! by the matching private key is rejected, and so is any bundle not newer
//! than the one in use (its `sequence`), so an old bundle cannot be
//! replayed.
//!
//! The private key lives only in a GitHub Actions secret (plus the
//! maintainer's offline backup). CI builds and signs a bundle each week with
//! the `whereabouts-data-bundle` tool in this crate.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The public half of Whereabouts' data signing key (hex).
pub const PUBLIC_KEY_HEX: &str = "a4faba8d2736e5b789411d7d256ed2824db6ec676fff2555123b1514d117df00";

/// The manifest format this version understands.
pub const FORMAT: u32 = 1;

/// The manifest's file name in a bundle.
pub const MANIFEST: &str = "manifest.json";

/// The signature's file name in a bundle (64 raw bytes).
pub const SIGNATURE: &str = "manifest.sig";

/// The files a bundle carries, and nothing else.
pub const FILES: [&str; 4] = [
    "easyprivacy.txt",
    "dbip-country-lite.mmdb",
    "dbip-asn-lite.mmdb",
    "companies.tsv",
];

/// Largest file accepted in a bundle.
pub const MAX_FILE: u64 = 64 * 1024 * 1024;

/// Largest manifest accepted.
pub const MAX_MANIFEST: u64 = 64 * 1024;

/// What a bundle is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Always [`FORMAT`].
    pub format: u32,
    /// Grows with each bundle (e.g. `202611200300`); a bundle is used only
    /// if its sequence is higher than the one in use.
    pub sequence: u64,
    /// When it was built (UTC, RFC 3339), for people.
    pub created: String,
    /// The files, each exactly once.
    pub files: Vec<FileEntry>,
    /// Where each file came from, for people (and licence credits).
    pub sources: Vec<String>,
}

/// One file in a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    /// One of [`FILES`].
    pub name: String,
    /// Its size in bytes.
    pub size: u64,
    /// Its SHA-256, lowercase hex.
    pub sha256: String,
}

/// Why a bundle was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    /// The signature is missing, malformed or does not match.
    BadSignature,
    /// The manifest is not valid.
    BadManifest(String),
    /// A file does not match the manifest.
    BadFile(String),
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadSignature => write!(f, "the data update is not signed by Whereabouts"),
            Self::BadManifest(why) => write!(f, "the data update's manifest is not valid: {why}"),
            Self::BadFile(why) => write!(f, "a data update file does not match: {why}"),
        }
    }
}

impl std::error::Error for BundleError {}

/// The built-in public key.
pub fn public_key() -> [u8; 32] {
    from_hex::<32>(PUBLIC_KEY_HEX).unwrap_or([0; 32])
}

/// Checks `signature` over `manifest` with `public_key`, then the
/// manifest itself. Returns the manifest only if both are right.
pub fn verify(
    manifest: &[u8],
    signature: &[u8],
    public_key: &[u8; 32],
) -> Result<Manifest, BundleError> {
    if manifest.len() as u64 > MAX_MANIFEST {
        return Err(BundleError::BadManifest(String::from("too large")));
    }
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| BundleError::BadSignature)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| BundleError::BadSignature)?;
    key.verify_strict(manifest, &Signature::from_bytes(&signature))
        .map_err(|_| BundleError::BadSignature)?;
    let parsed: Manifest =
        serde_json::from_slice(manifest).map_err(|e| BundleError::BadManifest(e.to_string()))?;
    check_manifest(&parsed)?;
    Ok(parsed)
}

fn check_manifest(manifest: &Manifest) -> Result<(), BundleError> {
    let bad = |why: &str| Err(BundleError::BadManifest(why.to_owned()));
    if manifest.format != FORMAT {
        return bad("unknown format");
    }
    if manifest.files.len() != FILES.len() {
        return bad("wrong number of files");
    }
    for name in FILES {
        let count = manifest.files.iter().filter(|f| f.name == name).count();
        if count != 1 {
            return Err(BundleError::BadManifest(format!("{name} must appear once")));
        }
    }
    for file in &manifest.files {
        if file.size == 0 || file.size > MAX_FILE {
            return Err(BundleError::BadManifest(format!(
                "{} has a bad size",
                file.name
            )));
        }
        if file.sha256.len() != 64
            || !file
                .sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(BundleError::BadManifest(format!(
                "{} has a bad hash",
                file.name
            )));
        }
    }
    if manifest.created.len() > 64
        || manifest.sources.len() > 32
        || manifest.sources.iter().any(|s| s.len() > 512)
    {
        return bad("too much text");
    }
    Ok(())
}

/// Checks a downloaded file against its manifest entry.
pub fn check_file(entry: &FileEntry, bytes: &[u8]) -> Result<(), BundleError> {
    if bytes.len() as u64 != entry.size {
        return Err(BundleError::BadFile(format!(
            "{} has the wrong size",
            entry.name
        )));
    }
    if to_hex(&Sha256::digest(bytes)) != entry.sha256 {
        return Err(BundleError::BadFile(format!(
            "{} has the wrong hash",
            entry.name
        )));
    }
    Ok(())
}

/// Builds the manifest for the files in `dir`.
pub fn build_manifest(
    dir: &Path,
    sequence: u64,
    created: &str,
    sources: Vec<String>,
) -> std::io::Result<Manifest> {
    let mut files = Vec::new();
    for name in FILES {
        let bytes = std::fs::read(dir.join(name))?;
        files.push(FileEntry {
            name: name.to_owned(),
            size: bytes.len() as u64,
            sha256: to_hex(&Sha256::digest(&bytes)),
        });
    }
    let manifest = Manifest {
        format: FORMAT,
        sequence,
        created: created.to_owned(),
        files,
        sources,
    };
    check_manifest(&manifest).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(manifest)
}

/// Signs `manifest` (its exact bytes) with the private key `seed`.
pub fn sign(manifest: &[u8], seed: &[u8; 32]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(manifest).to_bytes()
}

/// The public key for the private key `seed`.
pub fn public_key_of(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// A new private key from the system's secure random number generator.
pub fn new_seed() -> std::io::Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(seed)
}

/// Lowercase hex.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Exactly `N` bytes from hex.
pub fn from_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let text = text.trim();
    if text.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, pair) in text.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("wa-bundle-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for file in FILES {
            std::fs::write(dir.join(file), format!("contents of {file}")).unwrap();
        }
        dir
    }

    #[test]
    fn a_signed_bundle_verifies_and_anything_else_is_rejected() {
        let dir = bundle_dir("sign");
        let seed = [7u8; 32];
        let key = public_key_of(&seed);
        let manifest = build_manifest(&dir, 202611200300, "2026-11-20T03:00:00Z", vec![]).unwrap();
        let bytes = serde_json::to_vec(&manifest).unwrap();
        let signature = sign(&bytes, &seed);
        assert_eq!(verify(&bytes, &signature, &key).unwrap(), manifest);

        // Another key, a changed manifest, a broken signature: rejected.
        let other = public_key_of(&[8u8; 32]);
        assert_eq!(
            verify(&bytes, &signature, &other),
            Err(BundleError::BadSignature)
        );
        let mut changed = bytes.clone();
        let at = changed.iter().position(|&b| b == b'2').unwrap();
        changed[at] = b'3';
        assert_eq!(
            verify(&changed, &signature, &key),
            Err(BundleError::BadSignature)
        );
        assert_eq!(
            verify(&bytes, &signature[..63], &key),
            Err(BundleError::BadSignature)
        );

        // Every file must match its entry.
        for entry in &manifest.files {
            let real = std::fs::read(dir.join(&entry.name)).unwrap();
            check_file(entry, &real).unwrap();
            assert!(check_file(entry, b"tampered").is_err());
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn signed_but_invalid_manifests_are_rejected() {
        let seed = [9u8; 32];
        let key = public_key_of(&seed);
        let dir = bundle_dir("invalid");
        let good = build_manifest(&dir, 1, "now", vec![]).unwrap();
        let mut missing = good.clone();
        missing.files.pop();
        let mut extra_name = good.clone();
        extra_name.files[0].name = String::from("..\\evil.dll");
        let mut wrong_format = good.clone();
        wrong_format.format = 2;
        for manifest in [missing, extra_name, wrong_format] {
            let bytes = serde_json::to_vec(&manifest).unwrap();
            let signature = sign(&bytes, &seed);
            assert!(matches!(
                verify(&bytes, &signature, &key),
                Err(BundleError::BadManifest(_))
            ));
        }
        let unknown_field =
            br#"{"format":1,"sequence":1,"created":"","files":[],"sources":[],"run":"x"}"#;
        let signature = sign(unknown_field, &seed);
        assert!(matches!(
            verify(unknown_field, &signature, &key),
            Err(BundleError::BadManifest(_))
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn hex_round_trips() {
        let seed = new_seed().unwrap();
        assert_eq!(from_hex::<32>(&to_hex(&seed)), Some(seed));
        assert_eq!(from_hex::<32>("abc"), None);
        assert_eq!(from_hex::<2>("zzzz"), None);
    }

    #[test]
    fn the_built_in_key_is_set() {
        assert_ne!(
            public_key(),
            [0u8; 32],
            "PUBLIC_KEY_HEX is still the placeholder"
        );
    }
}
