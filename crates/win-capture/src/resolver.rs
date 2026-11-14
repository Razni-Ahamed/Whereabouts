//! Works out app identities on a background thread.
//!
//! Hashing a file and checking its signature can take a while, so it must
//! not happen on the thread that reads network events.
//!
//! Every process is checked on its own: each request names one process
//! instance (a caller-chosen token), and the file is opened, locked and
//! hashed again for it. Signature results are cached **by content hash**,
//! so a swapped file always gets a new hash and a fresh signature check,
//! while the same program started many times (e.g. a browser's helper
//! processes) is only verified once. Files too large to hash are verified
//! every time.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread;

use whereabouts_core::model::{AppIdentity, Signature};

use crate::identity::{open_locked, package_family_name, size_and_hash, verify_signature_of};

/// Most identity requests waiting at once. Further requests are refused
/// and should be retried later.
const MAX_PENDING: usize = 1_024;

/// Most signature results kept in the worker's cache.
const MAX_CACHED: usize = 10_000;

struct Request {
    token: u64,
    path: String,
    /// The file, already opened and locked by the caller, if it could be.
    file: Option<File>,
    pid: Option<u32>,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("token", &self.token)
            .field("path", &self.path)
            .finish()
    }
}

/// Resolves app identities in the background.
#[derive(Debug)]
pub struct IdentityResolver {
    requests: SyncSender<Request>,
    results: Receiver<(u64, AppIdentity)>,
    pending: HashSet<u64>,
}

impl IdentityResolver {
    /// Starts the background worker. It stops when the resolver is dropped.
    pub fn start() -> Self {
        let (requests, worker_requests) = mpsc::sync_channel::<Request>(MAX_PENDING);
        let (worker_results, results) = mpsc::channel();
        thread::Builder::new()
            .name(String::from("whereabouts-identity"))
            .spawn(move || {
                let mut cache: HashMap<String, Signature> = HashMap::new();
                for request in worker_requests {
                    let identity = identify_cached(&mut cache, &request);
                    if worker_results.send((request.token, identity)).is_err() {
                        break;
                    }
                }
            })
            .expect("can start the identity thread");
        Self {
            requests,
            results,
            pending: HashSet::new(),
        }
    }

    /// Asks for the identity of the program at `path` (a drive-letter
    /// path) for one process instance, identified by `token`.
    ///
    /// Pass `file` if the caller already opened and locked the program file
    /// (see [`crate::identity::open_locked`]), ideally while the process was
    /// still running; it is then checked instead of reopening `path`.
    ///
    /// Returns `true` if the request is queued or already waiting, `false`
    /// if the queue is full (ask again later).
    pub fn request(
        &mut self,
        token: u64,
        path: &str,
        file: Option<File>,
        pid: Option<u32>,
    ) -> bool {
        if self.pending.contains(&token) {
            return true;
        }
        let request = Request {
            token,
            path: path.to_owned(),
            file,
            pid,
        };
        match self.requests.try_send(request) {
            Ok(()) => {
                self.pending.insert(token);
                true
            }
            Err(TrySendError::Full(_)) => false,
            // The worker has stopped; there is no point in asking again.
            Err(TrySendError::Disconnected(_)) => true,
        }
    }

    /// Returns the identities finished since the last call, with the token
    /// each was requested for.
    pub fn finished(&mut self) -> Vec<(u64, AppIdentity)> {
        let done: Vec<(u64, AppIdentity)> = self.results.try_iter().collect();
        for (token, _) in &done {
            self.pending.remove(token);
        }
        done
    }

    /// Returns `true` if no requests are waiting.
    pub fn is_idle(&self) -> bool {
        self.pending.is_empty()
    }
}

/// Opens, locks and hashes the file for this request; reuses a cached
/// signature result only for identical content.
fn identify_cached(cache: &mut HashMap<String, Signature>, request: &Request) -> AppIdentity {
    let path = Path::new(&request.path);
    let package_family_name = request.pid.and_then(package_family_name);
    let opened = match &request.file {
        Some(file) => file.try_clone(),
        None => open_locked(path),
    };
    let Ok(file) = opened else {
        return AppIdentity {
            path: request.path.clone(),
            signature: Signature::Unknown,
            sha256: None,
            size: None,
            package_family_name,
        };
    };
    let (size, sha256) = size_and_hash(&file);
    let signature = match &sha256 {
        Some(hash) => {
            if let Some(known) = cache.get(hash) {
                known.clone()
            } else {
                let signature = verify_signature_of(&file, path);
                if cache.len() >= MAX_CACHED {
                    cache.clear();
                }
                cache.insert(hash.clone(), signature.clone());
                signature
            }
        }
        None => verify_signature_of(&file, path),
    };
    AppIdentity {
        path: request.path.clone(),
        signature,
        sha256,
        size,
        package_family_name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn wait_for(resolver: &mut IdentityResolver, count: usize) -> Vec<(u64, AppIdentity)> {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut done = Vec::new();
        while done.len() < count && Instant::now() < deadline {
            done.extend(resolver.finished());
            std::thread::sleep(Duration::from_millis(20));
        }
        done
    }

    fn curl() -> String {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| String::from(r"C:\Windows"));
        format!(r"{root}\System32\curl.exe")
    }

    #[test]
    fn resolves_each_process_in_the_background() {
        let mut resolver = IdentityResolver::start();
        assert!(resolver.request(1, &curl(), None, None));
        assert!(resolver.request(1, &curl(), None, None)); // already pending
        assert!(resolver.request(2, &curl(), None, None)); // another process

        let mut done = wait_for(&mut resolver, 2);
        done.sort_by_key(|(token, _)| *token);
        assert_eq!(done.len(), 2);
        assert_eq!(done[0].0, 1);
        assert_eq!(done[1].0, 2);
        assert!(matches!(done[0].1.signature, Signature::Signed { .. }));
        assert_eq!(done[0].1.signature, done[1].1.signature);
        assert!(resolver.is_idle());
    }

    #[test]
    fn a_swapped_file_at_the_same_path_is_checked_again() {
        let dir = std::env::temp_dir().join(format!("whereabouts-swap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let app = dir.join("app.exe");
        let path = app.to_string_lossy().into_owned();

        // First the genuine, signed program...
        std::fs::copy(curl(), &app).unwrap();
        let mut resolver = IdentityResolver::start();
        resolver.request(1, &path, None, None);
        let first = wait_for(&mut resolver, 1);
        assert!(matches!(first[0].1.signature, Signature::Signed { .. }));

        // ...then an unsigned file put in its place, with the same size and
        // modification time, as an attacker who can write there might do.
        let original = std::fs::metadata(&app).unwrap();
        let mut fake = std::fs::read(&app).unwrap();
        let middle = fake.len() / 2;
        fake[middle] ^= 0xff;
        std::fs::write(&app, &fake).unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&app).unwrap();
        file.set_modified(original.modified().unwrap()).unwrap();
        drop(file);

        resolver.request(2, &path, None, None);
        let second = wait_for(&mut resolver, 1);
        assert!(
            !matches!(second[0].1.signature, Signature::Signed { .. }),
            "the swapped file must not inherit the original's signature: {:?}",
            second[0].1.signature
        );
        assert_ne!(first[0].1.sha256, second[0].1.sha256);
        let _ = std::fs::remove_dir_all(dir);
    }
}
