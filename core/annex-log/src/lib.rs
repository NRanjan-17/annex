//! The debug log, shared by the core and every app. Local only: never uploaded; users attach it
//! to bug reports themselves.
//!
//! - `annex.log` in the data folder: Annex's own steps at debug, the libraries under it at info;
//!   with verbose logging on, everything Annex logs at trace. Past 10 MB it becomes
//!   `annex.old.log`, so the two never take more than about 20 MB.
//! - A flight recorder: the last few thousand lines, kept in memory. When an error is logged or a
//!   thread panics, they're saved to `crashes/annex-<time>-<why>.log`, so what led up to it stays
//!   together even after the log has moved on.
//! - Stall warnings ([`watch`]): a step that should take a moment says so if it's still running
//!   after a few seconds, and on which thread, since a step that hangs never logs its own line.
//!
//! Each line says when, how serious, which part of Annex (the module, e.g.
//! `annex_session::transfer`), which thread, and the session it belongs to. Secrets (PINs, codes,
//! passphrases, relay logins) and what's copied or sent never go in.

use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tracing::{Level, Metadata};
use tracing_subscriber::Layer as _;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod stall;

pub use stall::{Watch, watch};

const FILE_MAX: u64 = 10 * 1024 * 1024;
/// Lines the flight recorder keeps.
const RECORDER_LINES: usize = 4000;
/// Recordings kept in `crashes/`; older ones are removed.
const RECORDINGS_KEPT: usize = 10;
/// At most one recording per this long, so a burst of errors makes one.
const RECORDING_GAP: Duration = Duration::from_secs(30);

static ENABLED: AtomicBool = AtomicBool::new(true);
static VERBOSE: AtomicBool = AtomicBool::new(false);
static STDERR: AtomicBool = AtomicBool::new(false);
static LAST_RECORDING_S: AtomicU64 = AtomicU64::new(0);

struct LogFile {
    dir: Option<PathBuf>,
    /// The open file and how many bytes it holds.
    file: Option<(File, u64)>,
}

static FILE: Mutex<LogFile> = Mutex::new(LogFile { dir: None, file: None });
static RECORDER: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());

/// Starts logging into `<data_dir>/annex.log` (once per process; later calls only move the log
/// to `data_dir`). `stderr`: also print each line (apps started from a terminal). `ANNEX_LOG=0`
/// turns the file off, `ANNEX_LOG=verbose` turns verbose logging on.
pub fn init(data_dir: &Path, stderr: bool) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    let _ = std::fs::create_dir_all(data_dir);
    {
        let mut f = lock(&FILE);
        if f.dir.as_deref() != Some(data_dir) {
            f.dir = Some(data_dir.to_path_buf());
            f.file = None;
        }
    }
    STDERR.store(stderr, Ordering::Relaxed);
    ONCE.call_once(|| {
        match std::env::var("ANNEX_LOG").as_deref() {
            Ok("0") => ENABLED.store(false, Ordering::Relaxed),
            Ok("verbose") => VERBOSE.store(true, Ordering::Relaxed),
            _ => {}
        }
        let layer = tracing_subscriber::fmt::layer()
            .with_writer(Out)
            .with_ansi(false)
            .with_target(true)
            .with_thread_names(true)
            .with_filter(tracing_subscriber::filter::filter_fn(wanted));
        let _ = tracing_subscriber::registry().with(layer).try_init();
        // Panics on background threads don't end the process, but they explain what stopped working.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let thread = std::thread::current();
            let trace = std::backtrace::Backtrace::force_capture();
            tracing::error!(target: "annex::panic", thread = thread.name().unwrap_or("?"), "panic: {info}\n{trace}");
            previous(info);
        }));
        tracing::info!(
            target: "annex::log",
            version = env!("CARGO_PKG_VERSION"),
            os = std::env::consts::OS,
            arch = std::env::consts::ARCH,
            verbose = VERBOSE.load(Ordering::Relaxed),
            "logging started"
        );
    });
}

/// Turns the log file on or off (on by default). The flight recorder keeps going either way.
pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
    if enabled {
        tracing::info!(target: "annex::log", version = env!("CARGO_PKG_VERSION"), "logging on");
    } else {
        lock(&FILE).file = None;
    }
}

/// Verbose logging: everything Annex logs, at trace (every input event, every progress step).
/// For chasing a problem; the log fills faster.
pub fn set_verbose(verbose: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
    tracing::info!(target: "annex::log", verbose, "verbose logging");
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Where the log goes, once [`init`] ran.
pub fn dir() -> Option<PathBuf> {
    lock(&FILE).dir.clone()
}

/// Saves the flight recorder to `crashes/` now (`why`: a word for the file name). Returns the
/// file.
pub fn save_recording(why: &str) -> Option<PathBuf> {
    let dir = dir()?.join("crashes");
    std::fs::create_dir_all(&dir).ok()?;
    let why: String = why.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).take(32).collect();
    let path = dir.join(format!("annex-{}-{why}.log", file_time(SystemTime::now())));
    let lines: Vec<String> = lock(&RECORDER).iter().cloned().collect();
    let mut f = open_private(&path, false)?;
    let _ = writeln!(
        f,
        "Annex {} on {} ({}): the last {} log lines.\n",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        lines.len()
    );
    for line in &lines {
        let _ = f.write_all(line.as_bytes());
    }
    prune(&dir);
    Some(path)
}

/// Whether a line is logged: Annex's own at debug (trace when verbose), the libraries at info.
fn wanted(meta: &Metadata<'_>) -> bool {
    let ours = meta.target().starts_with("annex") || meta.target().starts_with("app");
    let max = match (ours, VERBOSE.load(Ordering::Relaxed)) {
        (true, true) => Level::TRACE,
        (true, false) => Level::DEBUG,
        (false, _) => Level::INFO,
    };
    *meta.level() <= max
}

struct Out;

impl<'a> MakeWriter<'a> for Out {
    type Writer = Line;

    fn make_writer(&'a self) -> Line {
        Line { error: false }
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Line {
        Line { error: *meta.level() == Level::ERROR }
    }
}

/// One formatted line, to stderr, the file and the flight recorder.
struct Line {
    error: bool,
}

impl Write for Line {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if STDERR.load(Ordering::Relaxed) {
            let _ = std::io::stderr().write_all(buf);
        }
        {
            let mut r = lock(&RECORDER);
            if r.len() >= RECORDER_LINES {
                r.pop_front();
            }
            r.push_back(String::from_utf8_lossy(buf).into_owned());
        }
        if ENABLED.load(Ordering::Relaxed) {
            write_file(buf);
        }
        if self.error && take_recording_turn() {
            save_recording("error");
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn write_file(buf: &[u8]) {
    let mut log = lock(&FILE);
    let Some(path) = log.dir.as_ref().map(|d| d.join("annex.log")) else { return };
    if log.file.as_ref().is_some_and(|(_, len)| *len > FILE_MAX) {
        log.file = None;
    }
    if log.file.is_none() {
        if std::fs::metadata(&path).is_ok_and(|m| m.len() > FILE_MAX) {
            let _ = std::fs::rename(&path, path.with_file_name("annex.old.log"));
        }
        log.file = open_private(&path, true).map(|f| {
            let len = f.metadata().map_or(0, |m| m.len());
            (f, len)
        });
    }
    if let Some((f, len)) = log.file.as_mut()
        && f.write_all(buf).is_ok()
    {
        *len += buf.len() as u64;
    }
}

/// Opens a log file readable only by this account: it names the devices and addresses Annex talks
/// to, and other accounts on a shared computer shouldn't see them.
fn open_private(path: &Path, append: bool) -> Option<File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true);
    if append {
        opts.append(true);
    } else {
        opts.write(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        opts.mode(0o600);
        // Logs from before 0.3.1 were created readable by everyone.
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    opts.open(path).ok()
}

fn take_recording_turn() -> bool {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let last = LAST_RECORDING_S.load(Ordering::Relaxed);
    now >= last + RECORDING_GAP.as_secs()
        && LAST_RECORDING_S.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok()
}

/// Keeps the newest recordings.
fn prune(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "log"))
        .collect();
    // Names start with the time, so they sort oldest first.
    files.sort();
    let extra = files.len().saturating_sub(RECORDINGS_KEPT);
    for old in &files[..extra] {
        let _ = std::fs::remove_file(old);
    }
}

/// `2026-10-27T08-41-56Z`: UTC, sortable, safe in file names everywhere.
fn file_time(t: SystemTime) -> String {
    let s = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let (days, rest) = (s / 86_400, s % 86_400);
    // Days since 1970-01-01 to a date (Howard Hinnant's civil_from_days).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}-{:02}-{:02}Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_times_are_utc_dates() {
        assert_eq!(file_time(UNIX_EPOCH), "1970-01-01T00-00-00Z");
        assert_eq!(file_time(UNIX_EPOCH + Duration::from_secs(1_793_090_516)), "2026-10-27T08-41-56Z");
        assert_eq!(file_time(UNIX_EPOCH + Duration::from_secs(951_782_400)), "2000-02-29T00-00-00Z");
    }

    #[test]
    fn an_error_saves_what_led_up_to_it() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path(), false);
        tracing::debug!(target: "annex::test", "step one");
        tracing::trace!(target: "annex::test", "too fine without verbose");
        tracing::info!(target: "quinn", "a library");
        tracing::debug!(target: "quinn", "a library's detail");
        tracing::error!(target: "annex::test", "it broke");

        let log = std::fs::read_to_string(dir.path().join("annex.log")).unwrap();
        assert!(log.contains("step one") && log.contains("it broke") && log.contains("a library"));
        assert!(!log.contains("too fine") && !log.contains("detail"));
        assert!(log.contains("annex::test"), "lines name the part of Annex: {log}");

        let crashes: Vec<_> = std::fs::read_dir(dir.path().join("crashes")).unwrap().collect();
        assert_eq!(crashes.len(), 1);
        let saved_path = crashes[0].as_ref().unwrap().path();
        let saved = std::fs::read_to_string(&saved_path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [dir.path().join("annex.log"), saved_path] {
                let mode = std::fs::metadata(&p).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "only this account reads {}", p.display());
            }
        }
        assert!(saved.contains("step one") && saved.contains("it broke"));

        set_verbose(true);
        tracing::trace!(target: "annex::test", "fine detail");
        set_verbose(false);
        assert!(std::fs::read_to_string(dir.path().join("annex.log")).unwrap().contains("fine detail"));
    }
}
