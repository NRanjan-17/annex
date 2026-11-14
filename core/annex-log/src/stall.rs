//! Stall warnings. A step that should take a moment (handling an event, an encoder job) holds a
//! [`Watch`] while it runs. If it's still running after [`SLOW`], the log names it, the thread it's
//! on and how long it has run, and the flight recorder is saved; once it finishes, the log says how
//! long it took. A step that hangs never writes its own line, so without this the log only shows
//! when things went quiet, not what was stuck.
//!
//! The watchdog is a plain thread, so a stuck async runtime can't silence it, and it takes no lock
//! but this module's.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, Once};
use std::thread::{Thread, ThreadId};
use std::time::{Duration, Instant};

/// How long a watched step may run before the log says so.
const SLOW: Duration = Duration::from_secs(5);
/// How often the watchdog looks.
const TICK: Duration = Duration::from_secs(1);
const TARGET: &str = "annex::stall";

struct Running {
    id: u64,
    part: &'static str,
    what: &'static str,
    thread: Thread,
    since: Instant,
    reported: bool,
}

/// The steps running now: a handful at most, so a list.
static RUNNING: Mutex<Vec<Running>> = Mutex::new(Vec::new());
static NEXT: AtomicU64 = AtomicU64::new(0);
static WATCHDOG: Once = Once::new();

/// Held while a watched step runs; see [`watch`].
#[must_use = "the step is watched only while this is held"]
pub struct Watch(u64);

/// Watches the step that runs until the returned [`Watch`] is dropped. `part`: the part of Annex
/// (`"sharing"`); `what`: the step (an event's name). Fixed names only, never what a step works
/// on, which may be private. Cheap enough for every event and frame: no allocation, no log line.
pub fn watch(part: &'static str, what: &'static str) -> Watch {
    WATCHDOG.call_once(|| {
        let spawned = std::thread::Builder::new().name("annex-watchdog".into()).spawn(|| {
            loop {
                std::thread::sleep(TICK);
                check(Instant::now());
            }
        });
        if let Err(e) = spawned {
            tracing::warn!(target: TARGET, "no watchdog for stuck steps: {e}");
        }
    });
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let running = Running { id, part, what, thread: std::thread::current(), since: Instant::now(), reported: false };
    super::lock(&RUNNING).push(running);
    Watch(id)
}

impl Drop for Watch {
    fn drop(&mut self) {
        let done = {
            let mut running = super::lock(&RUNNING);
            running.iter().position(|r| r.id == self.0).map(|i| running.swap_remove(i))
        };
        if let Some(r) = done.filter(|r| r.reported) {
            let secs = r.since.elapsed().as_secs_f32();
            tracing::warn!(target: TARGET, "{}: {} finished after {secs:.1} s", r.part, r.what);
        }
    }
}

/// Logs the steps that have just run past [`SLOW`], and saves the flight recorder if any did.
fn check(now: Instant) {
    // The list is let go before logging: a log line may take a while (the disk).
    let late = overdue(&mut super::lock(&RUNNING), now, SLOW);
    for l in &late {
        tracing::warn!(
            target: TARGET,
            "{}: {} still running after {:.0} s on thread {} ({:?})",
            l.part,
            l.what,
            l.secs,
            l.thread_name,
            l.thread_id
        );
    }
    if !late.is_empty() && super::take_recording_turn() {
        super::save_recording("stall");
    }
}

struct Late {
    part: &'static str,
    what: &'static str,
    thread_name: String,
    thread_id: ThreadId,
    secs: f32,
}

/// The steps that have run for `slow` or longer and weren't reported yet, marked reported.
fn overdue(running: &mut [Running], now: Instant, slow: Duration) -> Vec<Late> {
    running
        .iter_mut()
        .filter(|r| !r.reported && now.duration_since(r.since) >= slow)
        .map(|r| {
            r.reported = true;
            Late {
                part: r.part,
                what: r.what,
                thread_name: r.thread.name().unwrap_or("unnamed").to_owned(),
                thread_id: r.thread.id(),
                secs: now.duration_since(r.since).as_secs_f32(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running(id: u64, since: Instant) -> Running {
        Running { id, part: "sharing", what: "keyframe", thread: std::thread::current(), since, reported: false }
    }

    #[test]
    fn a_step_is_reported_once_it_runs_too_long_and_only_once() {
        let start = Instant::now();
        let mut list = vec![running(1, start), running(2, start + Duration::from_secs(4))];
        assert!(overdue(&mut list, start + Duration::from_secs(4), SLOW).is_empty(), "not yet");

        let late = overdue(&mut list, start + Duration::from_secs(6), SLOW);
        assert_eq!(late.len(), 1, "only the one that started 6 s ago");
        assert_eq!((late[0].part, late[0].what), ("sharing", "keyframe"));
        assert_eq!(late[0].thread_id, std::thread::current().id(), "names the stuck thread, not the watchdog");
        assert!(late[0].secs >= 6.0);

        assert!(overdue(&mut list, start + Duration::from_secs(7), SLOW).is_empty(), "said once");
        assert_eq!(overdue(&mut list, start + Duration::from_secs(9), SLOW).len(), 1, "then the other one");
    }

    #[test]
    fn a_step_is_watched_while_the_guard_is_held() {
        let held = |id: u64| super::super::lock(&RUNNING).iter().any(|r| r.id == id);
        let w = watch("test", "step");
        let id = w.0;
        assert!(held(id));
        drop(w);
        assert!(!held(id), "forgotten once it finishes");
    }
}
