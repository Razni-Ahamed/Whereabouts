//! Works out app identities on a background thread, with a cache.
//!
//! Hashing a file and checking its signature can take a while, so it must
//! not happen on the thread that reads network events. Each program file is
//! checked once; the result is reused until the file's size or modification
//! time changes (for example after an update).

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread;
use std::time::SystemTime;

use whereabouts_core::model::AppIdentity;

use crate::identity::identify;

/// Most identity requests waiting at once. Further requests are dropped and
/// retried the next time the program is seen.
const MAX_PENDING: usize = 1_024;

/// Most identities kept in the worker's cache.
const MAX_CACHED: usize = 10_000;

struct Request {
    path: String,
    pid: Option<u32>,
}

/// Resolves app identities in the background.
#[derive(Debug)]
pub struct IdentityResolver {
    requests: SyncSender<Request>,
    results: Receiver<AppIdentity>,
    pending: HashSet<String>,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request").field("path", &self.path).finish()
    }
}

impl IdentityResolver {
    /// Starts the background worker. It stops when the resolver is dropped.
    pub fn start() -> Self {
        let (requests, worker_requests) = mpsc::sync_channel::<Request>(MAX_PENDING);
        let (worker_results, results) = mpsc::channel();
        thread::Builder::new()
            .name(String::from("whereabouts-identity"))
            .spawn(move || {
                let mut cache: HashMap<(String, Option<u64>, Option<SystemTime>), AppIdentity> =
                    HashMap::new();
                for request in worker_requests {
                    let identity = cached_identify(&mut cache, &request);
                    if worker_results.send(identity).is_err() {
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
    /// path). Returns `true` if the request is queued or already waiting,
    /// `false` if the queue is full (ask again later).
    pub fn request(&mut self, path: &str, pid: Option<u32>) -> bool {
        let key = path.to_ascii_lowercase();
        if self.pending.contains(&key) {
            return true;
        }
        let request = Request {
            path: path.to_owned(),
            pid,
        };
        match self.requests.try_send(request) {
            Ok(()) => {
                self.pending.insert(key);
                true
            }
            // Disconnected means the worker has stopped; there is no point
            // in asking again either.
            Err(TrySendError::Full(_)) => false,
            Err(TrySendError::Disconnected(_)) => true,
        }
    }

    /// Returns `true` if no requests are waiting.
    pub fn is_idle(&self) -> bool {
        self.pending.is_empty()
    }

    /// Returns the identities finished since the last call.
    pub fn finished(&mut self) -> Vec<AppIdentity> {
        let done: Vec<AppIdentity> = self.results.try_iter().collect();
        for identity in &done {
            self.pending.remove(&identity.path.to_ascii_lowercase());
        }
        done
    }
}

fn cached_identify(
    cache: &mut HashMap<(String, Option<u64>, Option<SystemTime>), AppIdentity>,
    request: &Request,
) -> AppIdentity {
    let metadata = std::fs::metadata(Path::new(&request.path)).ok();
    let key = (
        request.path.to_ascii_lowercase(),
        metadata.as_ref().map(std::fs::Metadata::len),
        metadata.and_then(|m| m.modified().ok()),
    );
    if let Some(known) = cache.get(&key) {
        return known.clone();
    }
    let identity = identify(&request.path, request.pid);
    if cache.len() >= MAX_CACHED {
        cache.clear();
    }
    cache.insert(key, identity.clone());
    identity
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use whereabouts_core::model::Signature;

    fn wait_for(resolver: &mut IdentityResolver, count: usize) -> Vec<AppIdentity> {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut done = Vec::new();
        while done.len() < count && Instant::now() < deadline {
            done.extend(resolver.finished());
            std::thread::sleep(Duration::from_millis(20));
        }
        done
    }

    #[test]
    fn resolves_in_the_background_and_deduplicates() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| String::from(r"C:\Windows"));
        let curl = format!(r"{root}\System32\curl.exe");
        let mut resolver = IdentityResolver::start();
        resolver.request(&curl, None);
        resolver.request(&curl, None); // ignored: already pending
        resolver.request(&curl.to_uppercase(), None); // same file, other case

        let done = wait_for(&mut resolver, 1);
        assert_eq!(done.len(), 1);
        assert!(matches!(done[0].signature, Signature::Signed { .. }));
        // Nothing else arrives.
        std::thread::sleep(Duration::from_millis(200));
        assert!(resolver.finished().is_empty());

        // Asking again later is answered (from the cache).
        resolver.request(&curl, None);
        assert_eq!(wait_for(&mut resolver, 1).len(), 1);
    }
}
