//! One process-wide deadline worker for sessions whose carrier never attaches.

use std::cmp::Ordering as CmpOrdering;
use std::collections::{BinaryHeap, HashMap};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::Error;
use crate::session::{Session, State};
use crate::wire;

use super::Registry;

struct Deadline {
    when: Instant,
    serial: u64,
    session_id: String,
    session: Weak<Session>,
    registry: Weak<Registry>,
}

impl PartialEq for Deadline {
    fn eq(&self, other: &Self) -> bool {
        self.when == other.when && self.serial == other.serial
    }
}
impl Eq for Deadline {}
impl PartialOrd for Deadline {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}
impl Ord for Deadline {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        // BinaryHeap is a max-heap; reverse the key so the earliest deadline is
        // at the top, with the serial providing deterministic tie breaking.
        other
            .when
            .cmp(&self.when)
            .then_with(|| other.serial.cmp(&self.serial))
    }
}

#[derive(Default)]
struct Queue {
    deadlines: BinaryHeap<Deadline>,
    active: HashMap<String, u64>,
    next_serial: u64,
}

struct Timer {
    queue: Mutex<Queue>,
    changed: Condvar,
}

static TIMER: OnceLock<Option<Arc<Timer>>> = OnceLock::new();

fn timer() -> Option<&'static Arc<Timer>> {
    TIMER
        .get_or_init(|| {
            let timer = Arc::new(Timer {
                queue: Mutex::new(Queue::default()),
                changed: Condvar::new(),
            });
            let worker = timer.clone();
            match thread::Builder::new()
                .name("dbb-unattached-deadlines".to_string())
                .spawn(move || worker.run())
            {
                Ok(_) => Some(timer),
                Err(_) => None,
            }
        })
        .as_ref()
}

pub(super) fn schedule(registry: &Arc<Registry>, session: &Arc<Session>, timeout: Duration) {
    let Some(timer) = timer() else {
        session.close(Error::new(
            wire::ERR_SESSION_CLOSED,
            "unattached session timer unavailable",
        ));
        registry.remove(&session.id);
        return;
    };
    let mut queue = timer.queue.lock().unwrap();
    let serial = queue.next_serial;
    queue.next_serial = queue.next_serial.wrapping_add(1);
    queue.active.insert(session.id.clone(), serial);
    queue.deadlines.push(Deadline {
        when: Instant::now() + timeout,
        serial,
        session_id: session.id.clone(),
        session: Arc::downgrade(session),
        registry: Arc::downgrade(registry),
    });
    drop(queue);
    timer.changed.notify_one();
}

pub(super) fn schedule_recovery(registry: &Arc<Registry>, session: &Arc<Session>) {
    let Some(when) = session.recovery_deadline() else {
        return;
    };
    let Some(timer) = timer() else {
        session.close(Error::new(
            wire::ERR_RESUME_EXPIRED,
            "recovery deadline timer unavailable",
        ));
        registry.remove(&session.id);
        return;
    };
    let mut queue = timer.queue.lock().unwrap();
    let serial = queue.next_serial;
    queue.next_serial = queue.next_serial.wrapping_add(1);
    queue.active.insert(session.id.clone(), serial);
    queue.deadlines.push(Deadline {
        when,
        serial,
        session_id: session.id.clone(),
        session: Arc::downgrade(session),
        registry: Arc::downgrade(registry),
    });
    drop(queue);
    timer.changed.notify_one();
}

pub(super) fn cancel(session_id: &str) {
    let Some(timer) = TIMER.get().and_then(Option::as_ref) else {
        return;
    };
    timer.queue.lock().unwrap().active.remove(session_id);
    timer.changed.notify_one();
}

impl Timer {
    fn run(self: Arc<Self>) {
        loop {
            let mut queue = self.queue.lock().unwrap();
            let entry = loop {
                if let Some(next) = queue.deadlines.peek() {
                    let now = Instant::now();
                    if next.when <= now {
                        break queue.deadlines.pop();
                    }
                    let wait = next.when.saturating_duration_since(now);
                    let (next_queue, _) = self.changed.wait_timeout(queue, wait).unwrap();
                    queue = next_queue;
                } else {
                    queue = self.changed.wait(queue).unwrap();
                }
            };
            let Some(entry) = entry else {
                continue;
            };
            let current = queue.active.remove(&entry.session_id) == Some(entry.serial);
            drop(queue);
            if !current {
                continue;
            }
            let Some(session) = entry.session.upgrade() else {
                continue;
            };
            if let Some(deadline) = session.recovery_deadline() {
                if Instant::now() >= deadline {
                    let _ = session.expire_recovery();
                    if session.is_closed() {
                        if let Some(registry) = entry.registry.upgrade() {
                            registry.remove(&entry.session_id);
                        }
                    }
                } else if let Some(registry) = entry.registry.upgrade() {
                    schedule_recovery(&registry, &session);
                }
                continue;
            }
            match session.wait_while_attaching(Duration::ZERO) {
                State::Active => {}
                State::Closed => {
                    if let Some(registry) = entry.registry.upgrade() {
                        registry.remove(&entry.session_id);
                    }
                }
                State::Attaching => {
                    session.close(Error::new(
                        wire::ERR_SESSION_CLOSED,
                        "carrier never attached",
                    ));
                    if let Some(registry) = entry.registry.upgrade() {
                        registry.remove(&entry.session_id);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::time::Duration;

    use crate::metrics::Metrics;
    use crate::session::Session;
    use crate::wire::{Limits, Mode};

    use super::{schedule, schedule_recovery, Registry};

    #[test]
    fn shared_deadline_worker_closes_and_reclaims_unattached_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (backend, _) = listener.accept().unwrap();
        drop(client);
        let registry = Arc::new(Registry::new(Arc::new(Metrics::new())));
        let session = Session::new(
            "unattached-test".to_string(),
            "token".to_string(),
            "instance".to_string(),
            "peer".to_string(),
            "target".to_string(),
            Mode::HttpSse,
            Limits {
                max_frame_size: 1024,
                up_max_inflight_frames: 1,
                up_window_bytes: 1024,
                down_buffer_bytes: 1024,
                up_receipt_limit: 8,
                down_max_frames: 8,
            },
            8,
            backend,
            Arc::new(Metrics::new()),
        );
        registry.insert(session.clone());
        schedule(&registry, &session, Duration::from_millis(10));
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while registry.get(&session.id).is_some() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(registry.get(&session.id).is_none());
        assert!(session.is_closed());
    }

    #[test]
    fn shared_deadline_worker_expires_suspended_recovery_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (backend, _) = listener.accept().unwrap();
        drop(client);
        let registry = Arc::new(Registry::new(Arc::new(Metrics::new())));
        let session = Session::new(
            "recovery-expiry-test".to_string(),
            "token".to_string(),
            "instance".to_string(),
            "peer".to_string(),
            "target".to_string(),
            Mode::HttpSse,
            Limits {
                max_frame_size: 1024,
                up_max_inflight_frames: 1,
                up_window_bytes: 1024,
                down_buffer_bytes: 1024,
                up_receipt_limit: 8,
                down_max_frames: 8,
            },
            8,
            backend,
            Arc::new(Metrics::new()),
        );
        session.enable_recovery(Duration::from_millis(30));
        session.attach("old-stream").unwrap();
        registry.insert(session.clone());
        assert!(session.suspend(1));
        schedule_recovery(&registry, &session);

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while registry.get(&session.id).is_some() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(registry.get(&session.id).is_none());
        assert!(session.is_closed());
        assert_eq!(
            session.terminal_error().unwrap().code,
            crate::wire::ERR_RESUME_EXPIRED
        );
    }
}
