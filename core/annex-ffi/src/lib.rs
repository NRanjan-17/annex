//! C ABI for the native apps. The matching header is `include/annex.h`; keep them in sync
//! (the `header_declares_every_export` test checks the function names).
//!
//! Conventions:
//! - Functions returning `int32_t` use `ANNEX_OK` (0) for success and negative values for
//!   errors; `annex_last_error()` describes the most recent error on the calling thread.
//! - Strings returned as `char *` are owned by the caller and freed with `annex_string_free`.
//! - Callbacks may run on any thread. They must not call the `*_free` function of the object
//!   that is calling them. After a `*_free` function returns, its callbacks are never called again.
//! - Events are UTF-8 JSON objects with a `type` field, documented in `docs/PROTOCOL.md`.

#![allow(clippy::missing_safety_doc)]

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use annex_discovery::{Advertisement, Browser, Discovery};
use annex_session::{
    Codec, Core, DEFAULT_STUN, DisplayInfo, Event, EventSink, FrameOut, FrameSink, HostConfig, HostHandle, InputEvent,
    InternetServers, JoinCode, Mode, MouseButton, OwnRelay, Quality, StreamConfig, SubmitResult, TrustPolicy,
    ViewerConfig, ViewerHandle, keys, share_code,
};

pub const ANNEX_OK: i32 = 0;
pub const ANNEX_ERR_INVALID_ARGUMENT: i32 = -1;
pub const ANNEX_ERR_FAILED: i32 = -2;
pub const ANNEX_ERR_PANIC: i32 = -3;

pub const ANNEX_SUBMIT_SENT: i32 = 0;
pub const ANNEX_SUBMIT_NO_SESSION: i32 = 1;
pub const ANNEX_SUBMIT_DROPPED: i32 = 2;

/// Passed as `capture_ts_local_us` when the clock offset is not known yet.
pub const ANNEX_TS_UNKNOWN: i64 = i64::MIN;

pub type AnnexEventCallback = Option<unsafe extern "C" fn(ctx: *mut c_void, event_json: *const c_char)>;
pub type AnnexFrameCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        data: *const u8,
        len: usize,
        frame_id: u32,
        capture_ts_local_us: i64,
        keyframe: bool,
    ),
>;

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

fn set_error(msg: impl Into<String>) {
    let s = CString::new(msg.into().replace('\0', " ")).unwrap_or_default();
    LAST_ERROR.with(|e| *e.borrow_mut() = s);
}

/// Runs `f`, converting errors and panics into return codes.
fn guard(f: impl FnOnce() -> Result<i32, (i32, String)>) -> i32 {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => v,
        Ok(Err((code, msg))) => {
            tracing::warn!(target: "annex::ffi", code, "call failed: {msg}");
            set_error(msg);
            code
        }
        Err(_) => {
            set_error("internal panic");
            ANNEX_ERR_PANIC
        }
    }
}

fn invalid(msg: &str) -> (i32, String) {
    (ANNEX_ERR_INVALID_ARGUMENT, msg.to_string())
}

fn failed(e: impl std::fmt::Display) -> (i32, String) {
    (ANNEX_ERR_FAILED, e.to_string())
}

unsafe fn str_arg<'a>(p: *const c_char, name: &str) -> Result<&'a str, (i32, String)> {
    if p.is_null() {
        return Err(invalid(&format!("{name} is null")));
    }
    // SAFETY: caller guarantees a valid NUL-terminated string.
    unsafe { CStr::from_ptr(p) }.to_str().map_err(|_| invalid(&format!("{name} is not UTF-8")))
}

unsafe fn opt_str_arg<'a>(p: *const c_char, name: &str) -> Result<Option<&'a str>, (i32, String)> {
    if p.is_null() { Ok(None) } else { unsafe { str_arg(p, name) }.map(Some) }
}

fn out_string(s: &str) -> *mut c_char {
    CString::new(s.replace('\0', " ")).unwrap_or_default().into_raw()
}

fn parse_codec(s: &str) -> Result<Codec, (i32, String)> {
    match s {
        "h264" => Ok(Codec::H264),
        "hevc" => Ok(Codec::Hevc),
        "raw" => Ok(Codec::Raw),
        _ => Err(invalid("codec must be h264, hevc or raw")),
    }
}

/// A raw context pointer the native side promised is safe to use from any thread.
#[derive(Clone, Copy)]
struct Ctx(*mut c_void);
unsafe impl Send for Ctx {}
unsafe impl Sync for Ctx {}

/// Callback registration that can be revoked; invocations hold the lock, so once `clear`
/// returns no callback is running or will run.
struct Callbacks {
    inner: Mutex<Option<(AnnexEventCallback, AnnexFrameCallback, Ctx)>>,
}

impl Callbacks {
    fn new(ev: AnnexEventCallback, fr: AnnexFrameCallback, ctx: *mut c_void) -> Arc<Self> {
        Arc::new(Callbacks { inner: Mutex::new(Some((ev, fr, Ctx(ctx)))) })
    }

    fn clear(&self) {
        *self.inner.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn event_json(&self, json: &str) {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((Some(cb), _, ctx)) = *g {
            let c = CString::new(json).unwrap_or_default();
            // SAFETY: native callback contract.
            unsafe { cb(ctx.0, c.as_ptr()) };
        }
    }

    fn event_sink(self: &Arc<Self>) -> EventSink {
        let me = self.clone();
        Arc::new(move |e: Event| {
            annex_session::log_event(&e);
            if let Ok(json) = serde_json::to_string(&e) {
                me.event_json(&json);
            }
        })
    }

    fn frame_sink(self: &Arc<Self>) -> FrameSink {
        let me = self.clone();
        Arc::new(move |f: FrameOut<'_>| {
            let g = me.inner.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((_, Some(cb), ctx)) = *g {
                // SAFETY: native callback contract; `data` is valid for the call.
                unsafe {
                    cb(
                        ctx.0,
                        f.data.as_ptr(),
                        f.data.len(),
                        f.frame_id,
                        f.capture_ts_local_us.unwrap_or(ANNEX_TS_UNKNOWN),
                        f.keyframe,
                    )
                };
            }
        })
    }
}

pub struct AnnexCore {
    rt: tokio::runtime::Runtime,
    core: Arc<Core>,
    discovery: Mutex<Option<Arc<Discovery>>>,
    /// The "Annex is open here" advertisement (not sharing), while enabled and no host advertises.
    presence: Mutex<Presence>,
}

#[derive(Default)]
struct Presence {
    enabled: bool,
    /// A host is advertising this device (as sharing) instead.
    hosting: bool,
    advert: Option<Advertisement>,
}

impl AnnexCore {
    /// (Re-)registers or drops the not-sharing advertisement to match the current state.
    fn refresh_presence(&self) {
        self.replace_presence(None);
    }

    /// Same, taking over from `outgoing` (a stopped host's record). Records with the same name
    /// are updated in place rather than withdrawn and re-registered; see `Advertisement::replaced_by`.
    fn replace_presence(&self, outgoing: Option<Advertisement>) {
        let mut p = self.presence.lock().unwrap();
        let old: Vec<Advertisement> = p.advert.take().into_iter().chain(outgoing).collect();
        if p.enabled && !p.hosting {
            match self.advertise_presence() {
                Ok(new) => {
                    for a in old {
                        a.replaced_by(&new);
                    }
                    p.advert = Some(new);
                    return;
                }
                Err(e) => tracing::warn!("presence advertisement failed: {e}"),
            }
        }
        drop(old); // not replaced: withdraw
    }

    fn advertise_presence(&self) -> Result<Advertisement, String> {
        let d = self.discovery().map_err(|(_, e)| e)?;
        d.advertise(&self.core.device_name(), annex_session::DEFAULT_PORT, false, false).map_err(|e| e.to_string())
    }

    /// A host starts advertising this device as sharing. Returns the presence record, which the
    /// host's record replaces (`Advertisement::replaced_by`).
    fn begin_hosting(&self) -> Option<Advertisement> {
        let mut p = self.presence.lock().unwrap();
        p.hosting = true;
        p.advert.take()
    }

    /// `begin_hosting` plus the host's own record. If that can't be registered, the presence
    /// record is restored (the device would otherwise vanish from other computers' Nearby lists).
    fn advertise_host(&self, port: u16, extend: bool) -> Result<Advertisement, (i32, String)> {
        let presence = self.begin_hosting();
        let advert =
            self.discovery().and_then(|d| d.advertise(&self.core.device_name(), port, true, extend).map_err(failed));
        match advert {
            Ok(advert) => {
                if let Some(old) = presence {
                    old.replaced_by(&advert);
                }
                Ok(advert)
            }
            Err(e) => {
                // Never withdrawn (begin_hosting only took it), so put it back as it was rather
                // than re-register, which would likely fail the same way and withdraw it.
                let mut p = self.presence.lock().unwrap();
                p.hosting = false;
                p.advert = presence;
                Err(e)
            }
        }
    }

    /// The host stopped; its record (if any) is replaced by the presence record.
    fn end_hosting(&self, host_advert: Option<Advertisement>) {
        self.presence.lock().unwrap().hosting = false;
        self.replace_presence(host_advert);
    }

    fn discovery(&self) -> Result<Arc<Discovery>, (i32, String)> {
        let mut d = self.discovery.lock().unwrap();
        if let Some(d) = d.as_ref() {
            return Ok(d.clone());
        }
        let new = Arc::new(Discovery::new(self.core.fingerprint()).map_err(failed)?);
        *d = Some(new.clone());
        Ok(new)
    }
}

pub struct AnnexHost {
    handle: Arc<HostHandle>,
    callbacks: Arc<Callbacks>,
    _advert: Option<Advertisement>,
    core: *const AnnexCore,
    /// Sharing over the internet with a code (annex_host_share_code), while it runs.
    internet: Mutex<Option<tokio::task::AbortHandle>>,
    /// Windows: the capture/encode pipeline owned by the core (annex_host_start_screen).
    #[cfg(windows)]
    screen: Option<Arc<win_host::ScreenState>>,
}

pub struct AnnexViewer {
    handle: Arc<ViewerHandle>,
    callbacks: Arc<Callbacks>,
    core: *const AnnexCore,
    #[cfg(windows)]
    window: Option<Arc<annex_media_win::VideoWindow>>,
}

pub struct AnnexDiscovery {
    browser: Browser,
    callbacks: Arc<Callbacks>,
}

/// Turns the log file (`<data_dir>/annex.log`) on or off (on by default; the apps leave it on).
/// Takes effect immediately. See the `annex-log` crate for what goes in it.
#[unsafe(no_mangle)]
pub extern "C" fn annex_set_log_enabled(enabled: bool) {
    annex_log::set_enabled(enabled);
}

/// Verbose logging: everything at trace (each input event, each progress step), for chasing a
/// problem. Off by default.
#[unsafe(no_mangle)]
pub extern "C" fn annex_set_log_verbose(verbose: bool) {
    annex_log::set_verbose(verbose);
}

/// Saves the last few thousand log lines to `<data_dir>/crashes/` now, as happens by itself on
/// each error. `why`: a word for the file name (may be null). Returns the file (free with
/// `annex_string_free`), or null before a core was created.
///
/// # Safety
/// `why` must be a valid NUL-terminated string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_log_save_recording(why: *const c_char) -> *mut c_char {
    let why = unsafe { opt_str_arg(why, "why") }.ok().flatten().unwrap_or("saved");
    match annex_log::save_recording(why) {
        Some(path) => out_string(&path.to_string_lossy()),
        None => std::ptr::null_mut(),
    }
}

/// Writes one line from the app to the log: `level` 0 = info, 1 = warning, 2 = error (also saves
/// what led up to it), 3 = debug, 4 = trace (verbose only). Start `message` with the feature in
/// brackets, e.g. "[clipboard] copied text, 12 bytes". The app's own steps (capture, encoding,
/// clipboard, drag and drop) explain what the core can't. Never log what's copied or a secret.
///
/// # Safety
/// `message` must be a valid NUL-terminated string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_log(level: i32, message: *const c_char) {
    let Ok(message) = (unsafe { str_arg(message, "message") }) else { return };
    match level {
        2 => tracing::error!(target: "app", "{message}"),
        1 => tracing::warn!(target: "app", "{message}"),
        3 => tracing::debug!(target: "app", "{message}"),
        4 => tracing::trace!(target: "app", "{message}"),
        _ => tracing::info!(target: "app", "{message}"),
    }
}

fn new_core(core: Arc<Core>, out: *mut *mut AnnexCore) -> Result<i32, (i32, String)> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("annex-core")
        .enable_all()
        .build()
        .map_err(failed)?;
    let boxed = Box::new(AnnexCore { rt, core, discovery: Mutex::new(None), presence: Mutex::default() });
    // SAFETY: checked non-null by callers.
    unsafe { *out = Box::into_raw(boxed) };
    Ok(ANNEX_OK)
}

// ---------------------------------------------------------------------------------------
// Library / core
// ---------------------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn annex_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

// ---------------------------------------------------------------------------------------
// Updates (the apps download; the core decides what to offer and checks signatures)
// ---------------------------------------------------------------------------------------

/// URL of the releases list the apps fetch (GitHub's API; send a User-Agent header).
#[unsafe(no_mangle)]
pub extern "C" fn annex_update_releases_url() -> *const c_char {
    annex_update::RELEASES_URL.as_ptr()
}

/// Picks the release to offer from the releases list. On success `*out` is JSON to free with
/// annex_string_free: `null` when this version is current, else `{version, prerelease, downgrade,
/// notes, page_url, asset_name, asset_url, sums_url, sig_url}`. `asset_suffix` names this
/// platform's file: `-macos-universal.dmg`, `-x64.exe` or `-arm64.exe`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_update_pick(
    releases_json: *const c_char,
    beta: bool,
    asset_suffix: *const c_char,
    out: *mut *mut c_char,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return Err(invalid("out is null"));
        }
        let (json, suffix) =
            unsafe { (str_arg(releases_json, "releases_json")?, str_arg(asset_suffix, "asset_suffix")?) };
        let update = annex_update::pick(json, env!("CARGO_PKG_VERSION"), beta, suffix).map_err(failed)?;
        let text = serde_json::to_string(&update).map_err(failed)?;
        unsafe { *out = out_string(&text) };
        Ok(ANNEX_OK)
    })
}

/// What's new since `last_seen` (the version this app last ran, or null on a first install): a
/// JSON array of {version, items: [{kind, title, detail}]}, newest first, empty when there's
/// nothing to show. Show it once, then remember this version (`annex_version`). Free with
/// `annex_string_free`.
///
/// # Safety
/// `last_seen` must be a valid NUL-terminated string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_whats_new_json(last_seen: *const c_char) -> *mut c_char {
    let last = unsafe { opt_str_arg(last_seen, "last_seen") }.ok().flatten();
    let notes = annex_update::whats_new::since(last, env!("CARGO_PKG_VERSION"));
    out_string(&serde_json::to_string(&notes).unwrap_or_else(|_| "[]".into()))
}

/// Every release's notes, newest first, in the same shape (for a "What's new" button). Free with
/// `annex_string_free`.
#[unsafe(no_mangle)]
pub extern "C" fn annex_whats_new_all_json() -> *mut c_char {
    out_string(&serde_json::to_string(&annex_update::whats_new::all()).unwrap_or_else(|_| "[]".into()))
}

/// Checks a downloaded update against its release's signed checksums (all three files already
/// downloaded). ANNEX_OK only if the signature is genuine and the file's SHA-256 is listed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_update_verify(
    sums_path: *const c_char,
    sig_path: *const c_char,
    file_path: *const c_char,
    asset_name: *const c_char,
) -> i32 {
    guard(|| {
        let (sums, sig, file, name) = unsafe {
            (
                str_arg(sums_path, "sums_path")?,
                str_arg(sig_path, "sig_path")?,
                str_arg(file_path, "file_path")?,
                str_arg(asset_name, "asset_name")?,
            )
        };
        let sums = std::fs::read(sums).map_err(failed)?;
        let sig = std::fs::read(sig).map_err(failed)?;
        annex_update::verify(&sums, &sig, std::path::Path::new(file), name).map_err(failed)?;
        tracing::info!(asset = name, "update verified");
        Ok(ANNEX_OK)
    })
}

/// Message for the last error on this thread. Valid until the next failing call on this thread.
#[unsafe(no_mangle)]
pub extern "C" fn annex_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: produced by CString::into_raw in this library.
        drop(unsafe { CString::from_raw(s) });
    }
}

/// Microseconds on the core's monotonic clock; use it for `capture_ts_us`.
#[unsafe(no_mangle)]
pub extern "C" fn annex_now_us() -> i64 {
    annex_session::clock::now_us()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_new(
    data_dir: *const c_char,
    device_name: *const c_char,
    out: *mut *mut AnnexCore,
) -> i32 {
    guard(|| {
        if out.is_null() {
            return Err(invalid("out is null"));
        }
        let dir = PathBuf::from(unsafe { str_arg(data_dir, "data_dir") }?);
        let name = unsafe { str_arg(device_name, "device_name") }?;
        annex_log::init(&dir, false);
        let core = Core::open(&dir, name, TrustPolicy::Pair).map_err(failed)?;
        new_core(core, out)
    })
}

/// In-memory identity and trust store (tests). Unknown peers still require PIN pairing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_new_ephemeral(device_name: *const c_char, out: *mut *mut AnnexCore) -> i32 {
    guard(|| {
        if out.is_null() {
            return Err(invalid("out is null"));
        }
        let name = unsafe { str_arg(device_name, "device_name") }?;
        new_core(Core::ephemeral(name, TrustPolicy::Pair).map_err(failed)?, out)
    })
}

/// Frees the core. All hosts, viewers and discovery handles created from it must be freed first.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_free(core: *mut AnnexCore) {
    if !core.is_null() {
        // SAFETY: produced by annex_core_new*.
        let c = unsafe { Box::from_raw(core) };
        c.rt.shutdown_timeout(std::time::Duration::from_secs(2));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_fingerprint(core: *const AnnexCore) -> *mut c_char {
    match unsafe { core.as_ref() } {
        Some(c) => out_string(c.core.fingerprint()),
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_device_name(core: *const AnnexCore) -> *mut c_char {
    match unsafe { core.as_ref() } {
        Some(c) => out_string(&c.core.device_name()),
        None => std::ptr::null_mut(),
    }
}

/// Renames this device (shown to other devices on their next connection; advertisements
/// update when hosting restarts). Returns the stored name (cleaned and shortened).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_set_device_name(core: *const AnnexCore, name: *const c_char) -> *mut c_char {
    let Some(c) = (unsafe { core.as_ref() }) else { return std::ptr::null_mut() };
    match unsafe { str_arg(name, "name") } {
        Ok(n) => out_string(&c.core.set_device_name(n)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Shows this device under "Nearby" on other computers while Annex is open (as "not sharing"
/// until a host starts). Call with `visible = true` once at startup, and again after a rename.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_set_presence(core: *const AnnexCore, visible: bool) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        c.presence.lock().unwrap().enabled = visible;
        c.refresh_presence();
        Ok(ANNEX_OK)
    })
}

/// `AB12 CD34 ...` form of a fingerprint, for display.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_display_fingerprint(fingerprint: *const c_char) -> *mut c_char {
    match unsafe { str_arg(fingerprint, "fingerprint") } {
        Ok(fp) => out_string(&annex_crypto::display_fingerprint(fp)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// JSON array of `{fingerprint, name, added_at, last_seen}`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_trusted_peers_json(core: *const AnnexCore) -> *mut c_char {
    match unsafe { core.as_ref() } {
        Some(c) => out_string(&serde_json::to_string(&c.core.trusted_peers()).unwrap_or_else(|_| "[]".into())),
        None => std::ptr::null_mut(),
    }
}

/// Revokes a trusted peer. Returns 1 if removed, 0 if it wasn't trusted, negative on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_untrust(core: *const AnnexCore, fingerprint: *const c_char) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        let fp = unsafe { str_arg(fingerprint, "fingerprint") }?;
        Ok(c.core.untrust(fp).map_err(failed)? as i32)
    })
}

/// Host: lets a trusted device control this computer's mouse and keyboard (off by default).
/// Returns 1 if changed, 0 if the device isn't trusted, negative on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_set_allow_input(
    core: *const AnnexCore,
    fingerprint: *const c_char,
    allow: bool,
) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        let fp = unsafe { str_arg(fingerprint, "fingerprint") }?;
        Ok(c.core.set_allow_input(fp, allow).map_err(failed)? as i32)
    })
}

/// Host: lets a trusted device hear this computer's sound (on by default). Returns 1 if changed,
/// 0 if the device isn't trusted, negative on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_set_allow_sound(
    core: *const AnnexCore,
    fingerprint: *const c_char,
    allow: bool,
) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        let fp = unsafe { str_arg(fingerprint, "fingerprint") }?;
        Ok(c.core.set_allow_sound(fp, allow).map_err(failed)? as i32)
    })
}

/// Host: lets a trusted device's microphone play here (on by default). Returns 1 if changed, 0 if
/// the device isn't trusted, negative on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_set_allow_mic(
    core: *const AnnexCore,
    fingerprint: *const c_char,
    allow: bool,
) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        let fp = unsafe { str_arg(fingerprint, "fingerprint") }?;
        Ok(c.core.set_allow_mic(fp, allow).map_err(failed)? as i32)
    })
}

/// Headless (nobody at this screen): pairing PINs are also written to `<data>/pairing-pin.txt`,
/// and paired devices may use the mouse and keyboard without being allowed one by one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_set_headless(core: *const AnnexCore, on: bool) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        c.core.set_headless(on);
        Ok(0)
    })
}

/// Where files from the other computer are saved (usually Downloads); NULL refuses them (the
/// default). Applies to sessions that start afterwards.
///
/// # Safety
/// `core` must be valid; `dir` a NUL-terminated string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_set_downloads(core: *const AnnexCore, dir: *const c_char) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        let dir = unsafe { opt_str_arg(dir, "dir") }?.filter(|d| !d.is_empty()).map(PathBuf::from);
        c.core.set_downloads(dir);
        Ok(0)
    })
}

/// The sound switches, applied at once to running sessions too: share this computer's sound with
/// viewers, play what the other computer sends, send this computer's microphone, and turn a
/// viewer's microphone into "Annex Microphone" (where supported) instead of playing it aloud.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_set_audio(
    core: *const AnnexCore,
    share_sound: bool,
    hear_sound: bool,
    send_mic: bool,
    virtual_mic: bool,
) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        c.core.set_audio(annex_session::audio::AudioSettings { share_sound, hear_sound, send_mic, virtual_mic });
        Ok(0)
    })
}

/// This computer's own sound, from an app that captures it itself (the Mac): `frames` frames of
/// `channels` interleaved float samples at `rate` Hz. Cheap and ignored while nobody listens.
///
/// # Safety
/// `core` must be valid; `samples` must point to `frames * channels` floats (or be null with 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_push_sound(
    core: *const AnnexCore,
    samples: *const f32,
    frames: usize,
    channels: u32,
    rate: u32,
) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        let len = frames.saturating_mul(channels as usize);
        if len == 0 {
            return Ok(0);
        }
        if samples.is_null() {
            return Err(invalid("samples is null"));
        }
        let samples = unsafe { std::slice::from_raw_parts(samples, len) };
        c.core.push_system_sound(samples, channels.min(u16::MAX as u32) as u16, rate);
        Ok(0)
    })
}

/// 1 while a viewer is listening to this computer's sound (capture it only then), else 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_sound_wanted(core: *const AnnexCore) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        Ok(c.core.sound_wanted() as i32)
    })
}

/// Whether "Annex Microphone" can be made on this computer (Linux for now; Mac and Windows need a
/// driver, coming later).
#[unsafe(no_mangle)]
pub extern "C" fn annex_virtual_microphone_supported() -> bool {
    annex_session::audio::virtual_microphone_here()
}

/// `data`/`len` as bytes (empty allowed).
unsafe fn bytes_arg<'a>(data: *const u8, len: usize) -> Result<&'a [u8], (i32, String)> {
    if len == 0 {
        return Ok(&[]);
    }
    if data.is_null() {
        return Err(invalid("data is null"));
    }
    Ok(unsafe { std::slice::from_raw_parts(data, len) })
}

/// This platform's key code (macOS virtual key code, Windows scancode with 0xE0xx for extended
/// keys, Linux evdev code) for a HID usage from an `input` event, or -1 if it has no such key.
#[unsafe(no_mangle)]
pub extern "C" fn annex_key_native_from_hid(usage: u16) -> i32 {
    native_from_hid(usage).map_or(-1, i32::from)
}

fn native_from_hid(usage: u16) -> Option<u16> {
    if cfg!(windows) {
        keys::windows_from_hid(usage)
    } else if cfg!(target_os = "linux") {
        keys::linux_from_hid(usage)
    } else {
        keys::mac_from_hid(usage)
    }
}

fn hid_from_native(code: u16) -> Option<u16> {
    if cfg!(windows) {
        keys::hid_from_windows(code)
    } else if cfg!(target_os = "linux") {
        keys::hid_from_linux(code)
    } else {
        keys::hid_from_mac(code)
    }
}

/// Answers a `pairing_pin_required` event with the PIN the user typed.
/// Returns 1 if the request was pending, 0 if unknown/expired.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_submit_pin(core: *const AnnexCore, request_id: u64, pin: *const c_char) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        let pin = unsafe { str_arg(pin, "pin") }?;
        Ok(c.core.submit_pin(request_id, pin) as i32)
    })
}

/// Cancels a pending pairing (`pairing_pin` on the host, `pairing_pin_required` on the viewer).
/// Returns 1 if the request was pending.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_core_cancel_request(core: *const AnnexCore, request_id: u64) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        Ok(c.core.cancel_request(request_id) as i32)
    })
}

// ---------------------------------------------------------------------------------------
// Host
// ---------------------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn annex_host_start(
    core: *const AnnexCore,
    port: u16,
    codec: *const c_char,
    width: u32,
    height: u32,
    fps: u32,
    advertise: bool,
    extend: bool,
    on_event: AnnexEventCallback,
    ctx: *mut c_void,
    out: *mut *mut AnnexHost,
) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        if out.is_null() {
            return Err(invalid("out is null"));
        }
        let codec = parse_codec(unsafe { str_arg(codec, "codec") }?)?;
        if width == 0 || height == 0 || fps == 0 {
            return Err(invalid("width, height and fps must be non-zero"));
        }
        let callbacks = Callbacks::new(on_event, None, ctx);
        let cfg = HostConfig { port, stream: StreamConfig { codec, width, height, fps }, extend, udp: None };
        let handle =
            c.rt.block_on(annex_session::start_host(c.core.clone(), cfg, callbacks.event_sink())).map_err(failed)?;
        let advert = if advertise {
            match c.advertise_host(handle.port(), extend) {
                Ok(a) => Some(a),
                Err(e) => {
                    // The caller never gets this host, so nothing else would stop it.
                    c.rt.block_on(handle.stop());
                    callbacks.clear();
                    return Err(e);
                }
            }
        } else {
            None
        };
        let host = Box::new(AnnexHost {
            handle: Arc::new(handle),
            callbacks,
            _advert: advert,
            core,
            internet: Mutex::default(),
            #[cfg(windows)]
            screen: None,
        });
        unsafe { *out = Box::into_raw(host) };
        Ok(ANNEX_OK)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_port(host: *const AnnexHost) -> u16 {
    unsafe { host.as_ref() }.map(|h| h.handle.port()).unwrap_or(0)
}

/// Whether this computer encodes HEVC (see `HostHandle::set_hevc`). Extend sessions then use
/// HEVC with viewers that decode it; the app chooses the mirror stream's codec itself.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_set_hevc(host: *const AnnexHost, on: bool) -> i32 {
    guard(|| {
        let h = unsafe { host.as_ref() }.ok_or_else(|| invalid("host is null"))?;
        h.handle.set_hevc(on);
        Ok(ANNEX_OK)
    })
}

/// The HEVC setting. Viewers started after this offer HEVC as well as H.264 when `on` (on Windows
/// only if Windows has an HEVC decoder; the Mac app checks for itself), and a Windows screen host
/// started after it uses HEVC with viewers that decode it, when the PC has a hardware HEVC
/// encoder. Off by default.
static VIEWER_HEVC: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether this computer decodes HEVC. Windows: it has an HEVC decoder (checked once: that
/// activates one). Elsewhere the app decided before turning the setting on.
fn decodes_hevc_here() -> bool {
    #[cfg(windows)]
    {
        static FOUND: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *FOUND.get_or_init(annex_media_win::hevc_decoder_available)
    }
    #[cfg(not(windows))]
    {
        true
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn annex_viewer_set_hevc(on: bool) {
    VIEWER_HEVC.store(on, std::sync::atomic::Ordering::Relaxed);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_set_stream(
    host: *const AnnexHost,
    codec: *const c_char,
    width: u32,
    height: u32,
    fps: u32,
) -> i32 {
    guard(|| {
        let h = unsafe { host.as_ref() }.ok_or_else(|| invalid("host is null"))?;
        let codec = parse_codec(unsafe { str_arg(codec, "codec") }?)?;
        if width == 0 || height == 0 || fps == 0 {
            return Err(invalid("width, height and fps must be non-zero"));
        }
        h.handle.set_stream(StreamConfig { codec, width, height, fps });
        Ok(ANNEX_OK)
    })
}

/// Queues one encoded access unit (Annex B for H.264/HEVC) for every **mirror** session.
/// Never blocks. Returns `ANNEX_SUBMIT_*` or a negative error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_submit_frame(
    host: *const AnnexHost,
    data: *const u8,
    len: usize,
    capture_ts_us: i64,
    keyframe: bool,
) -> i32 {
    guard(|| {
        let h = unsafe { host.as_ref() }.ok_or_else(|| invalid("host is null"))?;
        if data.is_null() || len == 0 {
            return Err(invalid("empty frame"));
        }
        // SAFETY: caller guarantees `data` points to `len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(data, len) };
        Ok(match h.handle.submit_frame(bytes, capture_ts_us, keyframe) {
            SubmitResult::Sent => ANNEX_SUBMIT_SENT,
            SubmitResult::NoSession => ANNEX_SUBMIT_NO_SESSION,
            SubmitResult::Dropped => ANNEX_SUBMIT_DROPPED,
        })
    })
}

/// Queues one encoded access unit for one session (Extend). Never blocks.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_submit_session_frame(
    host: *const AnnexHost,
    session_id: u64,
    data: *const u8,
    len: usize,
    capture_ts_us: i64,
    keyframe: bool,
) -> i32 {
    guard(|| {
        let h = unsafe { host.as_ref() }.ok_or_else(|| invalid("host is null"))?;
        if data.is_null() || len == 0 {
            return Err(invalid("empty frame"));
        }
        let bytes = unsafe { std::slice::from_raw_parts(data, len) };
        Ok(match h.handle.submit_session_frame(session_id, bytes, capture_ts_us, keyframe) {
            SubmitResult::Sent => ANNEX_SUBMIT_SENT,
            SubmitResult::NoSession => ANNEX_SUBMIT_NO_SESSION,
            SubmitResult::Dropped => ANNEX_SUBMIT_DROPPED,
        })
    })
}

/// Changes one session's stream (e.g. the user picked another resolution for its virtual display).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_set_session_stream(
    host: *const AnnexHost,
    session_id: u64,
    codec: *const c_char,
    width: u32,
    height: u32,
    fps: u32,
) -> i32 {
    guard(|| {
        let h = unsafe { host.as_ref() }.ok_or_else(|| invalid("host is null"))?;
        let codec = parse_codec(unsafe { str_arg(codec, "codec") }?)?;
        if width == 0 || height == 0 || fps == 0 {
            return Err(invalid("width, height and fps must be non-zero"));
        }
        Ok(h.handle.set_session_stream(session_id, StreamConfig { codec, width, height, fps }) as i32)
    })
}

/// Adaptive bitrate's smaller picture, for a mirror host: `width`×`height` at `fps` is the full
/// stream, `effective_bps` the encoder's target now and `reduced` whether it sends the smaller
/// picture now. Writes the picture to encode (full or smaller) to the non-null out parameters and
/// returns whether it is the smaller one. The bitrate stays as it is.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn annex_mirror_picture(
    effective_bps: u64,
    reduced: bool,
    width: u32,
    height: u32,
    fps: u32,
    out_width: *mut u32,
    out_height: *mut u32,
    out_fps: *mut u32,
) -> bool {
    let full = StreamConfig { codec: Codec::H264, width, height, fps };
    let (smaller, picture) = annex_session::rate::mirror_picture(&full, effective_bps, reduced);
    // SAFETY: the caller passes null or a writable u32 for each.
    unsafe {
        if let Some(w) = out_width.as_mut() {
            *w = picture.width;
        }
        if let Some(h) = out_height.as_mut() {
            *h = picture.height;
        }
        if let Some(f) = out_fps.as_mut() {
            *f = picture.fps;
        }
    }
    smaller
}

/// Ends one session (its viewer gets `host_ended_session`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_end_session(host: *const AnnexHost, session_id: u64) {
    if let Some(h) = unsafe { host.as_ref() } {
        h.handle.end_session(session_id);
    }
}

/// Puts a clipboard item (`mime` "text/plain;charset=utf-8" or "image/png") on one viewer's
/// clipboard. Returns 1 if it's on its way; 0 if that viewer can't take it (older Annex, TCP
/// session) or it's too big for the link (32 MB, 1 MB through our relay).
///
/// # Safety
/// `host` must be valid; `mime` a NUL-terminated string; `data` `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_send_clipboard(
    host: *const AnnexHost,
    session_id: u64,
    mime: *const c_char,
    data: *const u8,
    len: usize,
) -> i32 {
    guard(|| {
        let h = unsafe { host.as_ref() }.ok_or_else(|| invalid("host is null"))?;
        let mime = unsafe { str_arg(mime, "mime") }?;
        let data = unsafe { bytes_arg(data, len) }?.to_vec();
        Ok(i32::from(h.handle.send_clipboard(session_id, mime, data)))
    })
}

/// Sends a file to one viewer. `*out_id` is the id in its `transfer_*` events. Fails (with
/// `annex_last_error`) if the viewer can't take files.
///
/// # Safety
/// `host` must be valid; `path` a NUL-terminated string; `out_id` writable or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_send_file(
    host: *const AnnexHost,
    session_id: u64,
    path: *const c_char,
    out_id: *mut u64,
) -> i32 {
    guard(|| {
        let h = unsafe { host.as_ref() }.ok_or_else(|| invalid("host is null"))?;
        let path = unsafe { str_arg(path, "path") }?;
        let id = h.handle.send_file(session_id, std::path::Path::new(path)).map_err(failed)?;
        if let Some(out) = unsafe { out_id.as_mut() } {
            *out = id;
        }
        Ok(0)
    })
}

/// Pauses (or resumes) a file being sent to the viewer. Returns 1 if it is being sent, else 0.
///
/// # Safety
/// `host` must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_pause_transfer(
    host: *const AnnexHost,
    session_id: u64,
    id: u64,
    paused: bool,
) -> i32 {
    unsafe { host.as_ref() }.is_some_and(|h| h.handle.pause_transfer(session_id, id, paused)) as i32
}

/// Stops a file going either way (`incoming`: from the viewer).
///
/// # Safety
/// `host` must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_cancel_transfer(host: *const AnnexHost, session_id: u64, incoming: bool, id: u64) {
    if let Some(h) = unsafe { host.as_ref() } {
        h.handle.cancel_transfer(session_id, incoming, id);
    }
}

/// Shares this host over the internet with one code, through the rendezvous server
/// `rendezvous` (`wss://…`). `stun` (nullable: Cloudflare's) is `host:port`. `turn_url`
/// (nullable or empty: none) is the user's own relay, `turn:host:port`, with `turn_username` and
/// `turn_password`. Events: `internet_code`, `internet_joined`, `internet_relay`, and
/// `internet_code_ended` last. Replaces a code still running.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_share_code(
    host: *const AnnexHost,
    rendezvous: *const c_char,
    stun: *const c_char,
    turn_url: *const c_char,
    turn_username: *const c_char,
    turn_password: *const c_char,
) -> i32 {
    guard(|| {
        let h = unsafe { host.as_ref() }.ok_or_else(|| invalid("host is null"))?;
        let c = unsafe { h.core.as_ref() }.ok_or_else(|| invalid("core is gone"))?;
        let rendezvous = unsafe { str_arg(rendezvous, "rendezvous") }?.trim().to_string();
        if rendezvous.is_empty() {
            return Err(invalid("rendezvous is empty"));
        }
        let stun = unsafe { opt_str_arg(stun, "stun") }?.filter(|s| !s.is_empty()).unwrap_or(DEFAULT_STUN);
        let own_relay = match unsafe { opt_str_arg(turn_url, "turn_url") }?.map(str::trim).filter(|s| !s.is_empty()) {
            Some(url) => Some(OwnRelay {
                url: url.to_string(),
                username: unsafe { opt_str_arg(turn_username, "turn_username") }?.unwrap_or_default().to_string(),
                password: unsafe { opt_str_arg(turn_password, "turn_password") }?.unwrap_or_default().to_string(),
            }),
            None => None,
        };
        let servers = InternetServers { rendezvous, stun: stun.to_string() };
        let task = c.rt.spawn(share_code(
            h.handle.clone(),
            c.core.device_name(),
            servers,
            own_relay,
            h.callbacks.event_sink(),
        ));
        if let Some(old) = h.internet.lock().unwrap().replace(task.abort_handle()) {
            old.abort();
        }
        Ok(ANNEX_OK)
    })
}

/// Stops sharing over the internet: the code stops working (`internet_code_ended`, "stopped").
/// Sessions already connected carry on.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_stop_code(host: *const AnnexHost) {
    if let Some(h) = unsafe { host.as_ref() }
        && let Some(task) = h.internet.lock().unwrap().take()
    {
        task.abort();
        (h.callbacks.event_sink())(Event::InternetCodeEnded { reason: "stopped".into() });
    }
}

/// Stops hosting (ends all sessions, stops advertising) and frees the host.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_free(host: *mut AnnexHost) {
    if host.is_null() {
        return;
    }
    let mut h = unsafe { Box::from_raw(host) };
    #[cfg(windows)]
    if let Some(s) = &h.screen {
        s.stop();
    }
    let advert = h._advert.take();
    if let Some(task) = h.internet.lock().unwrap().take() {
        task.abort();
    }
    if let Some(c) = unsafe { h.core.as_ref() } {
        c.rt.block_on(h.handle.stop());
    }
    h.callbacks.clear();
    let core = h.core;
    drop(h);
    // Back to "open, not sharing" on other computers' Nearby lists: the presence record takes
    // over the host's (same name, updated in place).
    if advert.is_some()
        && let Some(c) = unsafe { core.as_ref() }
    {
        c.end_hosting(advert);
    }
}

/// Windows: JSON array of monitors `[{index, name, width, height, refresh_hz, primary}]`,
/// primary first.
#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "C" fn annex_win_monitors_json() -> *mut c_char {
    let list: Vec<serde_json::Value> = annex_media_win::monitors()
        .iter()
        .enumerate()
        .map(|(i, m)| {
            serde_json::json!({
                "index": i, "name": m.name, "width": m.width, "height": m.height,
                "refresh_hz": m.refresh_hz, "primary": m.primary,
            })
        })
        .collect();
    out_string(&serde_json::Value::Array(list).to_string())
}

/// Windows: why Extend (this PC as a host adding extra displays) is or isn't available:
/// `{"state": "ready" | "not_running" | "not_installed", "problem": <Device Manager code>, "test_signing": bool}`.
#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "C" fn annex_win_extend_status_json() -> *mut c_char {
    let (state, test_signing) = annex_media_win::driver_state();
    let (state, problem) = match state {
        annex_media_win::DriverState::Ready => ("ready", 0),
        annex_media_win::DriverState::NotRunning { problem } => ("not_running", problem),
        annex_media_win::DriverState::NotInstalled => ("not_installed", 0),
    };
    out_string(&serde_json::json!({ "state": state, "problem": problem, "test_signing": test_signing }).to_string())
}

/// Windows: graphics cards to choose from for sharing, `[{name, luid}]` (the first is the default).
#[cfg(windows)]
#[unsafe(no_mangle)]
pub extern "C" fn annex_win_gpus_json() -> *mut c_char {
    let list: Vec<serde_json::Value> =
        annex_media_win::gpus().into_iter().map(|g| serde_json::json!({ "name": g.name, "luid": g.luid })).collect();
    out_string(&serde_json::Value::Array(list).to_string())
}

/// Windows: host a monitor. The core captures (Windows.Graphics.Capture), encodes (hardware
/// H.264 when available) and streams while a viewer is connected. Events are the same as
/// annex_host_start's.
#[cfg(windows)]
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn annex_host_start_screen(
    core: *const AnnexCore,
    monitor_index: u32,
    port: u16,
    advertise: bool,
    prefer_hardware: bool,
    gpu_luid: u64,
    on_event: AnnexEventCallback,
    ctx: *mut c_void,
    out: *mut *mut AnnexHost,
) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        if out.is_null() {
            return Err(invalid("out is null"));
        }
        let gpu = (gpu_luid != 0).then_some(gpu_luid);
        let monitor = annex_media_win::monitors()
            .into_iter()
            .nth(monitor_index as usize)
            .ok_or_else(|| invalid("no such monitor"))?;
        let callbacks = Callbacks::new(on_event, None, ctx);
        let (host, screen) =
            win_host::start(c, monitor, port, prefer_hardware, gpu, callbacks.event_sink()).map_err(failed)?;
        let advert = if advertise {
            match c.advertise_host(host.port(), host.extend_supported()) {
                Ok(a) => Some(a),
                Err(e) => {
                    // The caller never gets this host, so nothing else would stop it.
                    screen.stop();
                    c.rt.block_on(host.stop());
                    callbacks.clear();
                    return Err(e);
                }
            }
        } else {
            None
        };
        let h = Box::new(AnnexHost {
            handle: host,
            callbacks,
            _advert: advert,
            core,
            internet: Mutex::default(),
            screen: Some(screen),
        });
        unsafe { *out = Box::into_raw(h) };
        Ok(ANNEX_OK)
    })
}

#[cfg(windows)]
mod win_host {
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, OnceLock, Weak, mpsc};
    use std::time::Duration;

    use annex_media_win::{
        EncodedFrame, HostPipeline, HostPipelineConfig, Injector, Monitor, VirtualDisplayDriver,
        hevc_encoder_available, idd, monitor_size, stream_size,
    };
    use annex_session::{Codec, DisplayInfo, Event, EventSink, HostConfig, HostHandle, MAX_H264, Mode, StreamConfig};

    use crate::AnnexCore;

    type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

    fn clock() -> Clock {
        Arc::new(annex_session::clock::now_us)
    }

    /// One Extend session: a virtual monitor from the AnnexIdd driver, captured for one viewer.
    /// Registered when the session starts, before the monitor exists, so that a session ending
    /// during setup is seen (`start_extend` then removes the monitor itself).
    struct ExtendSession {
        /// Set once the driver added the monitor.
        connector: Option<u32>,
        /// Where this viewer's pointer lands (once the monitor is active).
        monitor: Option<Monitor>,
        stop: Arc<AtomicBool>,
        pipeline: Arc<Mutex<Option<HostPipeline>>>,
    }

    /// Capture lifecycles follow the sessions: one shared mirror pipeline for all mirror viewers,
    /// one virtual monitor + pipeline per extend viewer.
    pub struct ScreenState {
        mirror_cfg: HostPipelineConfig,
        prefer_hardware: bool,
        host: OnceLock<Weak<HostHandle>>,
        mirror: Mutex<Option<HostPipeline>>,
        mirror_sessions: Mutex<HashSet<u64>>,
        /// Latest adaptive-bitrate hint per mirror session; the shared encoder follows the lowest.
        mirror_scales: Mutex<HashMap<u64, u32>>,
        /// The mirror pipeline sends adaptive bitrate's smaller picture (guarded with `mirror`).
        mirror_reduced: Mutex<bool>,
        /// The HEVC setting is on and this PC has a hardware HEVC encoder. Cleared if it fails.
        hevc: AtomicBool,
        /// The codecs each mirror viewer decodes; the one pipeline is HEVC only while all do.
        mirror_codecs: Mutex<HashMap<u64, Vec<Codec>>>,
        /// The mirror pipeline's codec now (the core has the same).
        mirror_codec: Mutex<Codec>,
        driver: Option<Arc<VirtualDisplayDriver>>,
        extends: Mutex<HashMap<u64, ExtendSession>>,
        injector: Mutex<Injector>,
        /// Pipeline work that events ask for, done on the `annex-host-work` thread (see [`Work`]).
        work: mpsc::Sender<Work>,
    }

    /// What a keyframe request or a bitrate hint does to a pipeline. Never done where the event
    /// comes from: the encoder's own thread sends KeyframeRequested from inside its output when the
    /// frame queue is full (a congested link, like the relay), while the session's network task
    /// sends BitrateHint and holds the pipeline during the encoder call. Each then waited for the
    /// other, and the session froze for good: no picture, no input, and Quit couldn't end it
    /// (0.4.2, Mac viewing Windows through the relay). With the software encoder, the capture thread
    /// even waited for itself (it holds the pipeline while encoding, and the output asked again).
    enum Work {
        /// A keyframe from the session's pipeline: its extend pipeline, or the shared mirror one.
        Keyframe(u64),
        /// The extend session's pipeline at this bitrate scale (%).
        ExtendBitrate(u64, u32),
        /// The mirror pipeline at the slowest viewer's scale, and the picture size that fits it.
        MirrorBitrate,
    }

    /// Runs [`Work`] in order until the state goes away (its sender with it).
    fn spawn_worker(state: &Arc<ScreenState>, jobs: mpsc::Receiver<Work>) {
        let state = Arc::downgrade(state);
        let spawned = std::thread::Builder::new().name("annex-host-work".into()).spawn(move || {
            while let Ok(job) = jobs.recv() {
                let Some(state) = state.upgrade() else { return };
                state.run(job);
            }
        });
        if let Err(e) = spawned {
            tracing::error!("sharing: no thread for keyframes and bitrate changes: {e}");
        }
    }

    fn bitrate(w: u32, h: u32, fps: u32) -> u32 {
        // Frames get more alike as the rate goes up, so above 60 fps the bitrate grows half as fast.
        let rate = fps.min(60) + fps.saturating_sub(60) / 2;
        (w * h * rate / 8).clamp(4_000_000, 40_000_000)
    }

    impl ScreenState {
        fn new(mirror_cfg: HostPipelineConfig, driver: Option<Arc<VirtualDisplayDriver>>) -> Arc<Self> {
            let prefer_hardware = mirror_cfg.prefer_hardware;
            let (work, jobs) = mpsc::channel();
            let state = Arc::new(ScreenState {
                mirror_cfg,
                prefer_hardware,
                host: OnceLock::new(),
                mirror: Mutex::new(None),
                mirror_sessions: Mutex::new(HashSet::new()),
                mirror_scales: Mutex::new(HashMap::new()),
                mirror_reduced: Mutex::new(false),
                hevc: AtomicBool::new(
                    prefer_hardware && crate::VIEWER_HEVC.load(Ordering::Relaxed) && hevc_encoder_available(),
                ),
                mirror_codecs: Mutex::new(HashMap::new()),
                mirror_codec: Mutex::new(Codec::H264),
                extends: Mutex::new(HashMap::new()),
                driver,
                injector: Mutex::new(Injector::default()),
                work,
            });
            spawn_worker(&state, jobs);
            state
        }

        fn host(&self) -> Option<Arc<HostHandle>> {
            self.host.get().and_then(|w| w.upgrade())
        }

        fn start_mirror(self: &Arc<Self>, session_id: u64) {
            let mut slot = self.mirror.lock().unwrap();
            if let Some(p) = slot.as_ref() {
                // Another mirror viewer joined: one capture feeds everyone; just resync. It was
                // told the full size: tell it the smaller picture's if that's what goes out.
                p.request_keyframe();
                let reduced = *self.mirror_reduced.lock().unwrap();
                if reduced && let Some(host) = self.host() {
                    let (_, picture) = self.mirror_picture(self.lowest_mirror_scale(), true);
                    host.set_session_stream(session_id, picture);
                }
                return;
            }
            // The last viewer may have left before this thread got here.
            if self.mirror_sessions.lock().unwrap().is_empty() {
                return;
            }
            // On a link that's already slow, start with the smaller picture.
            let lowest = self.lowest_mirror_scale();
            let (reduced, picture) = self.mirror_picture(lowest, false);
            *self.mirror_reduced.lock().unwrap() = reduced;
            if reduced {
                self.log_picture(true, lowest, &picture);
                self.announce_mirror_picture(&picture);
            }
            match self.start_mirror_pipeline(&picture, lowest) {
                Ok(p) => *slot = Some(p),
                Err(e) => tracing::error!("screen capture failed to start: {e}"),
            }
        }

        /// The full mirror stream, in the codec the pipeline uses now.
        fn full_mirror_stream(&self) -> StreamConfig {
            let c = &self.mirror_cfg;
            StreamConfig { codec: *self.mirror_codec.lock().unwrap(), width: c.width, height: c.height, fps: c.fps }
        }

        /// HEVC while it's on and every mirror viewer decodes it, else H.264.
        fn desired_mirror_codec(&self) -> Codec {
            let codecs = self.mirror_codecs.lock().unwrap();
            let all = !codecs.is_empty() && codecs.values().all(|c| c.contains(&Codec::Hevc));
            if self.hevc.load(Ordering::Relaxed) && all { Codec::Hevc } else { Codec::H264 }
        }

        /// A viewer joined or left: if the pipeline's codec should change, tell the core (so
        /// frames go only to viewers that decode them) and restart a running pipeline.
        fn follow_mirror_codec(self: &Arc<Self>) {
            let want = self.desired_mirror_codec();
            {
                let mut now = self.mirror_codec.lock().unwrap();
                if *now == want {
                    return;
                }
                *now = want;
            }
            tracing::info!(codec = ?want, "sharing: the mirror stream switches codec");
            if let Some(host) = self.host() {
                host.set_stream(self.full_mirror_stream());
            }
            if self.mirror.lock().unwrap().is_some() {
                let me = self.clone();
                std::thread::spawn(move || me.restart_mirror());
            }
        }

        /// Restarts the running mirror pipeline as it should be now (codec, picture size).
        fn restart_mirror(&self) {
            let mut slot = self.mirror.lock().unwrap();
            if slot.is_none() {
                return;
            }
            let lowest = self.lowest_mirror_scale();
            let reduced = *self.mirror_reduced.lock().unwrap();
            let (_, picture) = self.mirror_picture(lowest, reduced);
            slot.take();
            match self.start_mirror_pipeline(&picture, lowest) {
                Ok(p) => {
                    *slot = Some(p);
                    self.announce_mirror_picture(&picture);
                }
                Err(e) => tracing::error!("screen capture failed to restart: {e}"),
            }
        }

        fn lowest_mirror_scale(&self) -> u32 {
            self.mirror_scales.lock().unwrap().values().copied().min().unwrap_or(100)
        }

        /// What the mirror pipeline should send at `scale` % of its normal bitrate, given whether
        /// it sends the smaller picture now: (smaller, picture).
        fn mirror_picture(&self, scale: u32, reduced: bool) -> (bool, StreamConfig) {
            let bps = u64::from(self.mirror_cfg.bitrate) * u64::from(scale) / 100;
            annex_session::rate::mirror_picture(&self.full_mirror_stream(), bps, reduced)
        }

        fn log_picture(&self, reduced: bool, scale: u32, picture: &StreamConfig) {
            let bitrate = u64::from(self.mirror_cfg.bitrate) * u64::from(scale) / 100;
            tracing::info!(
                "sharing: smaller picture {} bitrate={bitrate} size={}x{} fps={}",
                if reduced { "on" } else { "off" },
                picture.width,
                picture.height,
                picture.fps
            );
        }

        /// Tells every mirror viewer the picture's size (their decoders follow the keyframe by
        /// themselves; this is for their stats and pointer).
        fn announce_mirror_picture(&self, picture: &StreamConfig) {
            let Some(host) = self.host() else { return };
            for id in self.mirror_sessions.lock().unwrap().iter() {
                host.set_session_stream(*id, picture.clone());
            }
        }

        /// A mirror pipeline sending `picture` (the full stream or the smaller one) at the full
        /// stream's bitrate, scaled to `scale` %.
        fn start_mirror_pipeline(
            &self,
            picture: &StreamConfig,
            scale: u32,
        ) -> Result<HostPipeline, annex_media_win::MediaError> {
            let host =
                self.host.get().cloned().ok_or_else(|| annex_media_win::MediaError::Other("sharing stopped".into()))?;
            // Weak: the host owns this pipeline (via the event sink), not the other way round.
            let output = Arc::new(move |f: EncodedFrame| {
                if let Some(h) = host.upgrade() {
                    h.submit_frame(&f.data, f.capture_us, f.keyframe);
                }
            });
            let full = &self.mirror_cfg;
            let cfg = HostPipelineConfig {
                width: picture.width,
                height: picture.height,
                fps: picture.fps,
                max_fps: (picture.fps < full.fps).then_some(picture.fps),
                hevc: picture.codec == Codec::Hevc,
                ..full.clone()
            };
            let p = match HostPipeline::start(cfg.clone(), clock(), output.clone()) {
                Err(e) if cfg.hevc => {
                    // The HEVC encoder wouldn't start: H.264 for everyone from now on.
                    tracing::warn!("HEVC encoder failed ({e}); using H.264");
                    self.hevc.store(false, Ordering::Relaxed);
                    *self.mirror_codec.lock().unwrap() = Codec::H264;
                    if let Some(h) = self.host() {
                        h.set_hevc(false);
                        h.set_stream(self.full_mirror_stream());
                    }
                    HostPipeline::start(HostPipelineConfig { hevc: false, ..cfg }, clock(), output)?
                }
                r => r?,
            };
            if scale != 100 {
                p.set_bitrate_scale(scale);
            }
            Ok(p)
        }

        /// The shared encoder's bitrate changed (a hint, or the slowest viewer left): switch to
        /// the smaller picture or back if it crossed the line. The rebuild runs on its own thread
        /// (capture setup touches COM/WinRT).
        fn update_mirror_picture(self: &Arc<Self>) {
            let reduced = *self.mirror_reduced.lock().unwrap();
            let (want, _) = self.mirror_picture(self.lowest_mirror_scale(), reduced);
            if want != reduced && self.mirror.lock().unwrap().is_some() {
                let me = self.clone();
                std::thread::spawn(move || me.resize_mirror());
            }
        }

        fn resize_mirror(&self) {
            let mut slot = self.mirror.lock().unwrap();
            // Stopped meanwhile: the next capture starts at the right size by itself.
            if slot.is_none() {
                return;
            }
            let lowest = self.lowest_mirror_scale();
            let (reduced, picture) = {
                let mut now = self.mirror_reduced.lock().unwrap();
                let (want, picture) = self.mirror_picture(lowest, *now);
                // Another thread did it, or the bitrate went back.
                if want == *now {
                    return;
                }
                *now = want;
                (want, picture)
            };
            self.log_picture(reduced, lowest, &picture);
            // The old pipeline stops before capturing at the new size, as for Extend resizes.
            slot.take();
            match self.start_mirror_pipeline(&picture, lowest) {
                Ok(p) => {
                    *slot = Some(p);
                    self.announce_mirror_picture(&picture);
                }
                Err(e) => {
                    tracing::error!("screen capture failed to restart at {}x{}: {e}", picture.width, picture.height);
                    // The full picture worked before: back to it.
                    *self.mirror_reduced.lock().unwrap() = false;
                    let full = self.full_mirror_stream();
                    match self.start_mirror_pipeline(&full, lowest) {
                        Ok(p) => {
                            *slot = Some(p);
                            self.announce_mirror_picture(&full);
                        }
                        Err(e) => tracing::error!("screen capture failed to start: {e}"),
                    }
                }
            }
        }

        pub fn stop(&self) {
            self.mirror.lock().unwrap().take();
            let ids: Vec<u64> = self.extends.lock().unwrap().keys().copied().collect();
            for id in ids {
                self.end_extend(id);
            }
        }

        fn start_extend(
            self: &Arc<Self>,
            id: u64,
            display: DisplayInfo,
            fingerprint: String,
            stop: Arc<AtomicBool>,
            pipeline: Arc<Mutex<Option<HostPipeline>>>,
            hevc: bool,
        ) {
            let Some(host) = self.host() else {
                self.extends.lock().unwrap().remove(&id);
                return;
            };
            let fail = |e: String| {
                tracing::error!("extend session {id} failed: {e}");
                host.end_session(id);
            };
            let Some(driver) = self.driver.clone() else {
                self.extends.lock().unwrap().remove(&id);
                return fail("no display driver".into());
            };
            let serial = idd::serial_for(&fingerprint);
            // The viewer's refresh rate, like a monitor; Windows Settings also offers 60 Hz.
            let hz = if display.refresh_hz == 0 { 60 } else { display.refresh_hz.clamp(24, 240) };
            let connector = match driver.add_monitor(
                serial,
                display.width_px.max(640),
                display.height_px.max(480),
                hz,
                display.width_mm,
                display.height_mm,
            ) {
                Ok(c) => c,
                Err(e) => {
                    self.extends.lock().unwrap().remove(&id);
                    return fail(e.to_string());
                }
            };
            // Ended meanwhile: end_extend found no monitor to remove.
            match self.extends.lock().unwrap().get_mut(&id) {
                Some(s) => s.connector = Some(connector),
                None => {
                    let _ = driver.remove_monitor(connector);
                    return;
                }
            }
            // (Plain locals: inside tracing's macros `display` names tracing's display() helper.)
            let (asked_w, asked_h) = (display.width_px, display.height_px);
            tracing::info!(id, connector, width = asked_w, height = asked_h, hz, "extend: virtual monitor added");
            let monitor = match driver.wait_for_monitor(connector, Duration::from_secs(8)) {
                Ok(m) => {
                    tracing::info!(id, name = %m.name, width = m.width, height = m.height, "extend: monitor is active");
                    m
                }
                Err(e) => {
                    // Unless end_extend already removed it.
                    if self.extends.lock().unwrap().remove(&id).is_some() {
                        let _ = driver.remove_monitor(connector);
                        fail(e.to_string());
                    }
                    return;
                }
            };
            match self.extends.lock().unwrap().get_mut(&id) {
                Some(s) => s.monitor = Some(monitor.clone()),
                None => return, // ended while the monitor came up; end_extend removed it
            }
            let weak_host = Arc::downgrade(&host);
            let prefer_hardware = self.prefer_hardware;
            let gpu = self.mirror_cfg.gpu;
            let slot = pipeline.clone();
            // The core chose HEVC for this viewer; H.264 from the first failure on.
            let hevc = AtomicBool::new(hevc);
            let start = move |m: &Monitor| -> Option<(u32, u32)> {
                let host = weak_host.upgrade()?;
                // The virtual monitor's size, within what H.264 can carry (a 4.5K or 5K viewer
                // screen is bigger: the encoder would reject every frame).
                let (w, h) = stream_size(m.width, m.height, MAX_H264.0, MAX_H264.1);
                let use_hevc = hevc.load(Ordering::Relaxed);
                let codec = if use_hevc { Codec::Hevc } else { Codec::H264 };
                host.set_session_stream(id, StreamConfig { codec, width: w, height: h, fps: hz });
                let weak = weak_host.clone();
                let output = Arc::new(move |f: EncodedFrame| {
                    if let Some(h) = weak.upgrade() {
                        h.submit_session_frame(id, &f.data, f.capture_us, f.keyframe);
                    }
                });
                let cfg = HostPipelineConfig {
                    monitor: m.clone(),
                    width: w,
                    height: h,
                    fps: hz,
                    bitrate: bitrate(w, h, hz),
                    prefer_hardware,
                    gpu,
                    max_fps: None,
                    hevc: use_hevc,
                };
                let started = match HostPipeline::start(cfg.clone(), clock(), output.clone()) {
                    Err(e) if use_hevc => {
                        tracing::warn!(id, "extend: HEVC encoder failed ({e}); using H.264");
                        hevc.store(false, Ordering::Relaxed);
                        host.set_session_stream(id, StreamConfig { codec: Codec::H264, width: w, height: h, fps: hz });
                        HostPipeline::start(HostPipelineConfig { hevc: false, ..cfg }, clock(), output)
                    }
                    r => r,
                };
                match started {
                    Ok(p) => {
                        tracing::info!(id, w, h, "extend: capturing the virtual monitor");
                        *pipeline.lock().unwrap() = Some(p);
                        Some((w, h))
                    }
                    Err(e) => {
                        tracing::error!("capturing the virtual monitor failed: {e}");
                        None
                    }
                }
            };
            let mut current = start(&monitor);
            // Follow resolution changes made in Settings → Display (viewer updates within ~0.5 s).
            while !stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(250));
                let Some((w, h)) = monitor_size(&monitor.name) else { continue };
                // Compared the way `start` sizes the stream: a monitor beyond H.264's limit is
                // streamed smaller, and isn't a resize.
                if current != Some(stream_size(w, h, MAX_H264.0, MAX_H264.1)) {
                    // Stop the old pipeline before capturing at the new size.
                    slot.lock().unwrap().take();
                    let resized = Monitor { width: w, height: h, ..monitor.clone() };
                    current = start(&resized);
                }
            }
            // A pipeline started after end_extend took the last one.
            slot.lock().unwrap().take();
        }

        fn end_extend(&self, id: u64) {
            let Some(session) = self.extends.lock().unwrap().remove(&id) else { return };
            session.stop.store(true, Ordering::Release);
            session.pipeline.lock().unwrap().take();
            if let (Some(driver), Some(connector)) = (&self.driver, session.connector) {
                // Windows moves the monitor's windows back to the remaining displays.
                let _ = driver.remove_monitor(connector);
            }
        }

        fn on_event(self: &Arc<Self>, e: &Event) {
            match e {
                Event::SessionStarted { session_id, mode: Mode::Mirror, codecs, .. } => {
                    self.mirror_sessions.lock().unwrap().insert(*session_id);
                    let codecs = if codecs.is_empty() { vec![Codec::H264] } else { codecs.clone() };
                    self.mirror_codecs.lock().unwrap().insert(*session_id, codecs);
                    self.follow_mirror_codec();
                    // Capture setup touches COM/WinRT; keep it off the async runtime threads.
                    let me = self.clone();
                    let id = *session_id;
                    std::thread::spawn(move || me.start_mirror(id));
                }
                Event::SessionStarted {
                    session_id, mode: Mode::Extend, viewer_display, fingerprint, stream, ..
                } => {
                    // Registered now, before SessionEnded can run end_extend.
                    let stop = Arc::new(AtomicBool::new(false));
                    let pipeline: Arc<Mutex<Option<HostPipeline>>> = Arc::default();
                    self.extends.lock().unwrap().insert(
                        *session_id,
                        ExtendSession {
                            connector: None,
                            monitor: None,
                            stop: stop.clone(),
                            pipeline: pipeline.clone(),
                        },
                    );
                    let me = self.clone();
                    let (id, display, fp) = (
                        *session_id,
                        viewer_display.clone().unwrap_or(DisplayInfo {
                            width_px: 1920,
                            height_px: 1080,
                            width_mm: 0,
                            height_mm: 0,
                            refresh_hz: 60,
                            scale_percent: 100,
                            refresh_rates: vec![],
                        }),
                        fingerprint.clone(),
                    );
                    let hevc = stream.codec == Codec::Hevc;
                    std::thread::spawn(move || me.start_extend(id, display, fp, stop, pipeline, hevc));
                }
                Event::SessionEnded { session_id, .. } => {
                    if self.mirror_sessions.lock().unwrap().remove(session_id) {
                        self.mirror_scales.lock().unwrap().remove(session_id);
                        self.mirror_codecs.lock().unwrap().remove(session_id);
                        if self.mirror_sessions.lock().unwrap().is_empty() {
                            self.mirror.lock().unwrap().take();
                            *self.mirror_reduced.lock().unwrap() = false;
                        } else {
                            // The only viewer that needed H.264 may have left.
                            self.follow_mirror_codec();
                            // The slowest viewer may have left: the encoder follows the next one.
                            self.later(Work::MirrorBitrate);
                        }
                    } else {
                        let me = self.clone();
                        let id = *session_id;
                        std::thread::spawn(move || me.end_extend(id));
                    }
                }
                // The scales are noted here, in order with SessionEnded; the pipelines change on
                // the work thread (see `Work`).
                Event::BitrateHint { session_id, scale_percent } => {
                    if self.extends.lock().unwrap().contains_key(session_id) {
                        self.later(Work::ExtendBitrate(*session_id, *scale_percent));
                    } else {
                        self.mirror_scales.lock().unwrap().insert(*session_id, *scale_percent);
                        self.later(Work::MirrorBitrate);
                    }
                }
                Event::Input { session_id, event } => {
                    let monitor = self.extends.lock().unwrap().get(session_id).and_then(|e| e.monitor.clone());
                    let monitor = monitor.unwrap_or_else(|| self.mirror_cfg.monitor.clone());
                    if let Err(e) = self.injector.lock().unwrap().inject(&monitor, *event) {
                        tracing::debug!("input not injected: {e}");
                    }
                }
                Event::KeyframeRequested { session_id } => self.later(Work::Keyframe(*session_id)),
                _ => {}
            }
        }

        fn later(&self, job: Work) {
            // Fails only once the work thread is gone, and with it the pipelines.
            let _ = self.work.send(job);
        }

        fn run(self: &Arc<Self>, job: Work) {
            match job {
                Work::Keyframe(id) => {
                    let extend = self.extends.lock().unwrap().get(&id).map(|e| e.pipeline.clone());
                    match extend {
                        Some(p) => {
                            if let Some(p) = p.lock().unwrap().as_ref() {
                                p.request_keyframe();
                            }
                        }
                        None => {
                            if let Some(p) = self.mirror.lock().unwrap().as_ref() {
                                p.request_keyframe();
                            }
                        }
                    }
                }
                Work::ExtendBitrate(id, scale) => {
                    let extend = self.extends.lock().unwrap().get(&id).map(|e| e.pipeline.clone());
                    if let Some(p) = extend
                        && let Some(p) = p.lock().unwrap().as_ref()
                    {
                        p.set_bitrate_scale(scale);
                    }
                }
                Work::MirrorBitrate => {
                    let lowest = self.lowest_mirror_scale();
                    if let Some(p) = self.mirror.lock().unwrap().as_ref() {
                        p.set_bitrate_scale(lowest);
                    }
                    self.update_mirror_picture();
                }
            }
        }
    }

    pub fn start(
        c: &AnnexCore,
        monitor: Monitor,
        port: u16,
        prefer_hardware: bool,
        gpu: Option<u64>,
        app_events: EventSink,
    ) -> Result<(Arc<HostHandle>, Arc<ScreenState>), annex_session::SessionError> {
        // Hardware encoders handle 1440p60 comfortably; the software fallback is sized for 1080p.
        let (max_w, max_h) = if prefer_hardware { (2560, 1600) } else { (1920, 1200) };
        let (width, height) = stream_size(monitor.width, monitor.height, max_w, max_h);
        let fps = monitor.refresh_hz.clamp(30, 60);
        // Extend needs the AnnexIdd driver (installed with the "Extend mode" installer option).
        let driver = match VirtualDisplayDriver::open() {
            Ok(d) => Some(Arc::new(d)),
            Err(e) => {
                tracing::info!("extend mode unavailable: {e}");
                None
            }
        };
        let mirror_cfg = HostPipelineConfig {
            monitor,
            width,
            height,
            fps,
            bitrate: bitrate(width, height, fps),
            prefer_hardware,
            gpu,
            max_fps: None,
            hevc: false,
        };
        let state = ScreenState::new(mirror_cfg, driver);
        let events: EventSink = {
            let state = state.clone();
            Arc::new(move |e: Event| {
                // Wi-Fi low-latency mode while any viewer is connected (host sessions always pair
                // SessionStarted with SessionEnded).
                match &e {
                    Event::SessionStarted { .. } => annex_media_win::wifi_low_latency(true),
                    Event::SessionEnded { .. } => annex_media_win::wifi_low_latency(false),
                    _ => {}
                }
                state.on_event(&e);
                app_events(e);
            })
        };
        let extend = state.driver.is_some();
        let cfg =
            HostConfig { port, stream: StreamConfig { codec: Codec::H264, width, height, fps }, extend, udp: None };
        let handle = Arc::new(c.rt.block_on(annex_session::start_host(c.core.clone(), cfg, events))?);
        let hevc = state.hevc.load(Ordering::Relaxed);
        handle.set_hevc(hevc);
        tracing::info!(hevc, "sharing: HEVC with viewers that decode it");
        let _ = state.host.set(Arc::downgrade(&handle));
        Ok((handle, state))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn state() -> Arc<ScreenState> {
            let monitor = Monitor {
                handle: Default::default(),
                name: String::new(),
                width: 1440,
                height: 900,
                refresh_hz: 60,
                primary: true,
            };
            let cfg = HostPipelineConfig {
                monitor,
                width: 1440,
                height: 900,
                fps: 60,
                bitrate: bitrate(1440, 900, 60),
                prefer_hardware: false,
                gpu: None,
                max_fps: None,
                hevc: false,
            };
            ScreenState::new(cfg, None)
        }

        /// The 0.4.2 freeze: the encoder's thread asked for a keyframe from inside its output while
        /// the session held the pipeline, and each waited for the other. Events now return at once
        /// whoever holds the pipeline, and the work is done once it's free.
        #[test]
        fn keyframe_and_bitrate_events_never_wait_for_the_pipeline() {
            let state = state();
            state.mirror_sessions.lock().unwrap().insert(1);
            let held = state.mirror.lock().unwrap();
            let (done, returned) = mpsc::channel();
            let events = state.clone();
            std::thread::spawn(move || {
                events.on_event(&Event::KeyframeRequested { session_id: 1 });
                events.on_event(&Event::BitrateHint { session_id: 1, scale_percent: 50 });
                let _ = done.send(());
            });
            let waited = returned.recv_timeout(Duration::from_secs(5)).is_err();
            drop(held);
            assert!(!waited, "an event waited for the pipeline");
            assert_eq!(state.lowest_mirror_scale(), 50, "the viewer's scale is noted right away");
        }
    }
}

// ---------------------------------------------------------------------------------------
// Viewer
// ---------------------------------------------------------------------------------------

unsafe fn viewer_config(
    address: *const c_char,
    expected_fingerprint: *const c_char,
    display_json: *const c_char,
    extend: bool,
    input: bool,
    quality: u32,
) -> Result<ViewerConfig, (i32, String)> {
    let address = unsafe { str_arg(address, "address") }?.to_string();
    let expected = unsafe { opt_str_arg(expected_fingerprint, "expected_fingerprint") }?
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase());
    let display = match unsafe { opt_str_arg(display_json, "display_json") }? {
        Some(j) => serde_json::from_str::<DisplayInfo>(j).map_err(|e| invalid(&format!("display_json: {e}")))?,
        None => DisplayInfo {
            width_px: 1920,
            height_px: 1080,
            width_mm: 0,
            height_mm: 0,
            refresh_hz: 60,
            scale_percent: 100,
            refresh_rates: vec![],
        },
    };
    Ok(ViewerConfig {
        address,
        display,
        // HEVC first when this computer decodes it; H.264 always, which every host sends.
        codecs: if VIEWER_HEVC.load(std::sync::atomic::Ordering::Relaxed) && decodes_hevc_here() {
            vec![Codec::Hevc, Codec::H264]
        } else {
            vec![Codec::H264]
        },
        expected_fingerprint: expected,
        mode: if extend { Mode::Extend } else { Mode::Mirror },
        input,
        quality: match quality {
            1 => Quality::Balanced,
            2 => Quality::Fast,
            _ => Quality::Best,
        },
        latency_csv: std::env::var_os("ANNEX_LATENCY_CSV").map(PathBuf::from),
        internet: None,
        join: None,
    })
}

/// Connects to a host in the background and delivers frames to `on_frame`.
/// `expected_fingerprint` (nullable) pins the host certificate; `display_json` (nullable) is a
/// DisplayInfo object describing the screen the stream will be shown on. `input`: ask to control
/// the host (see `annex_viewer_send_*`); `session_started.input` says whether the host agreed.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn annex_viewer_connect(
    core: *const AnnexCore,
    address: *const c_char,
    expected_fingerprint: *const c_char,
    display_json: *const c_char,
    extend: bool,
    input: bool,
    quality: u32,
    on_event: AnnexEventCallback,
    on_frame: AnnexFrameCallback,
    ctx: *mut c_void,
    out: *mut *mut AnnexViewer,
) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        if out.is_null() {
            return Err(invalid("out is null"));
        }
        let cfg = unsafe { viewer_config(address, expected_fingerprint, display_json, extend, input, quality) }?;
        let callbacks = Callbacks::new(on_event, on_frame, ctx);
        let _enter = c.rt.enter();
        let handle = Arc::new(annex_session::connect_viewer(
            c.core.clone(),
            cfg,
            callbacks.event_sink(),
            callbacks.frame_sink(),
        ));
        let v = Box::new(AnnexViewer {
            handle,
            callbacks,
            core,
            #[cfg(windows)]
            window: None,
        });
        unsafe { *out = Box::into_raw(v) };
        Ok(ANNEX_OK)
    })
}

/// Connects by a code from a computer sharing over the internet (see `annex_host_share_code`),
/// otherwise like `annex_viewer_connect`. `stun` is nullable (Cloudflare's). A wrong, used or
/// expired code ends with `session_ended` reason "unknown_code"; too many tries,
/// "too_many_attempts". `session_started.link` is "internet" or "relayed".
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn annex_viewer_connect_code(
    core: *const AnnexCore,
    rendezvous: *const c_char,
    stun: *const c_char,
    code: *const c_char,
    display_json: *const c_char,
    extend: bool,
    input: bool,
    quality: u32,
    on_event: AnnexEventCallback,
    on_frame: AnnexFrameCallback,
    ctx: *mut c_void,
    out: *mut *mut AnnexViewer,
) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        if out.is_null() {
            return Err(invalid("out is null"));
        }
        let mut cfg = unsafe { code_viewer_config(rendezvous, stun, code, display_json, extend, input, quality) }?;
        cfg.address = String::new();
        let callbacks = Callbacks::new(on_event, on_frame, ctx);
        let _enter = c.rt.enter();
        let handle = Arc::new(annex_session::connect_viewer(
            c.core.clone(),
            cfg,
            callbacks.event_sink(),
            callbacks.frame_sink(),
        ));
        let v = Box::new(AnnexViewer {
            handle,
            callbacks,
            core,
            #[cfg(windows)]
            window: None,
        });
        unsafe { *out = Box::into_raw(v) };
        Ok(ANNEX_OK)
    })
}

/// A viewer config for a code (shared by the plain and the Windows windowed connect).
unsafe fn code_viewer_config(
    rendezvous: *const c_char,
    stun: *const c_char,
    code: *const c_char,
    display_json: *const c_char,
    extend: bool,
    input: bool,
    quality: u32,
) -> Result<ViewerConfig, (i32, String)> {
    let rendezvous = unsafe { str_arg(rendezvous, "rendezvous") }?.trim().to_string();
    let code = unsafe { str_arg(code, "code") }?.trim().to_string();
    if rendezvous.is_empty() || code.is_empty() {
        return Err(invalid("rendezvous and code must be non-empty"));
    }
    let stun = unsafe { opt_str_arg(stun, "stun") }?.filter(|s| !s.is_empty()).unwrap_or(DEFAULT_STUN);
    // The address is unused with a code; any valid string will do for the shared parser.
    let mut cfg = unsafe { viewer_config(c"".as_ptr(), std::ptr::null(), display_json, extend, input, quality) }?;
    cfg.join = Some(JoinCode { code, servers: InternetServers { rendezvous, stun: stun.to_string() } });
    Ok(cfg)
}

/// Windows only: connects and shows the stream in a full-screen window rendered by the core
/// (Media Foundation decode + Direct3D 11). Closing the window (Esc, or Ctrl+Alt+Shift+Q while
/// controlling the host) ends the session. With `input`, the window forwards mouse and keyboard.
#[cfg(windows)]
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn annex_viewer_connect_windowed(
    core: *const AnnexCore,
    address: *const c_char,
    expected_fingerprint: *const c_char,
    extend: bool,
    input: bool,
    quality: u32,
    on_event: AnnexEventCallback,
    ctx: *mut c_void,
    out: *mut *mut AnnexViewer,
) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        if out.is_null() {
            return Err(invalid("out is null"));
        }
        let cfg = unsafe { viewer_config(address, expected_fingerprint, std::ptr::null(), extend, input, quality) }?;
        unsafe { connect_windowed(c, core, cfg, input, on_event, ctx, out) }
    })
}

/// Windows only: `annex_viewer_connect_code` shown like `annex_viewer_connect_windowed`.
#[cfg(windows)]
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn annex_viewer_connect_code_windowed(
    core: *const AnnexCore,
    rendezvous: *const c_char,
    stun: *const c_char,
    code: *const c_char,
    extend: bool,
    input: bool,
    quality: u32,
    on_event: AnnexEventCallback,
    ctx: *mut c_void,
    out: *mut *mut AnnexViewer,
) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        if out.is_null() {
            return Err(invalid("out is null"));
        }
        let mut cfg = unsafe { code_viewer_config(rendezvous, stun, code, std::ptr::null(), extend, input, quality) }?;
        cfg.address = String::new();
        unsafe { connect_windowed(c, core, cfg, input, on_event, ctx, out) }
    })
}

/// The core's own window for a viewer: frames go to it, its input and close come back.
#[cfg(windows)]
unsafe fn connect_windowed(
    c: &AnnexCore,
    core: *const AnnexCore,
    mut cfg: ViewerConfig,
    input: bool,
    on_event: AnnexEventCallback,
    ctx: *mut c_void,
    out: *mut *mut AnnexViewer,
) -> Result<i32, (i32, String)> {
    {
        cfg.display = annex_media_win::primary_display_info();
        let callbacks = Callbacks::new(on_event, None, ctx);
        let events = callbacks.event_sink();

        // The window needs the viewer handle (keyframe requests, presented reports) and the
        // viewer needs the window (frames); tie them together through a late-bound slot.
        let slot: Arc<Mutex<Option<std::sync::Weak<ViewerHandle>>>> = Arc::new(Mutex::new(None));
        let hooks = annex_media_win::WindowHooks {
            on_presented: {
                let slot = slot.clone();
                Box::new(move |id| with_viewer(&slot, |v| v.frame_presented(id)))
            },
            on_need_keyframe: {
                let slot = slot.clone();
                Box::new(move || with_viewer(&slot, |v| v.request_keyframe()))
            },
            on_input: if input {
                let slot = slot.clone();
                Some(Box::new(move |e| with_viewer(&slot, |v| v.send_input(e))))
            } else {
                None
            },
            on_closed: {
                let slot = slot.clone();
                let rt = c.rt.handle().clone();
                Box::new(move || {
                    if let Some(v) = slot.lock().unwrap().as_ref().and_then(|w| w.upgrade()) {
                        rt.spawn(async move { v.disconnect().await });
                    }
                })
            },
        };
        let window = Arc::new(annex_media_win::VideoWindow::open("Annex", hooks).map_err(failed)?);
        let frames: FrameSink = {
            let window = window.clone();
            Arc::new(move |f: FrameOut<'_>| window.submit(f.data, f.frame_id, f.keyframe))
        };
        let events: EventSink = {
            let window = window.clone();
            // Wi-Fi low-latency mode while the session runs (only undo what this viewer turned on).
            let wifi_on = Arc::new(std::sync::atomic::AtomicBool::new(false));
            Arc::new(move |e: Event| {
                match &e {
                    Event::SessionStarted { .. } if !wifi_on.swap(true, std::sync::atomic::Ordering::AcqRel) => {
                        annex_media_win::wifi_low_latency(true)
                    }
                    Event::SessionEnded { .. } if wifi_on.swap(false, std::sync::atomic::Ordering::AcqRel) => {
                        annex_media_win::wifi_low_latency(false)
                    }
                    _ => {}
                }
                match &e {
                    Event::SessionEnded { .. } => window.close(),
                    Event::SessionStarted { input, mode, pointer_deltas, .. } => {
                        window.set_relative_pointer(*mode == Mode::Extend && *pointer_deltas);
                        window.set_input_active(*input);
                        window.show();
                    }
                    Event::InputAllowed { allowed, .. } => window.set_input_active(*allowed),
                    _ => {}
                }
                events(e)
            })
        };
        let _enter = c.rt.enter();
        let handle = Arc::new(annex_session::connect_viewer(c.core.clone(), cfg, events, frames));
        *slot.lock().unwrap() = Some(Arc::downgrade(&handle));
        let v = Box::new(AnnexViewer { handle, callbacks, core, window: Some(window) });
        unsafe { *out = Box::into_raw(v) };
        Ok(ANNEX_OK)
    }
}

#[cfg(windows)]
fn with_viewer(slot: &Mutex<Option<std::sync::Weak<ViewerHandle>>>, f: impl FnOnce(&ViewerHandle)) {
    if let Some(v) = slot.lock().unwrap().as_ref().and_then(|w| w.upgrade()) {
        f(&v);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_viewer_request_keyframe(viewer: *const AnnexViewer) {
    if let Some(v) = unsafe { viewer.as_ref() } {
        v.handle.request_keyframe();
    }
}

/// Reports that a frame reached the screen; drives `latency_stats` events.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_viewer_frame_presented(viewer: *const AnnexViewer, frame_id: u32) {
    if let Some(v) = unsafe { viewer.as_ref() } {
        v.handle.frame_presented(frame_id);
    }
}

/// Pointer position over the video, normalized: (0, 0) top-left, (1, 1) bottom-right of the
/// stream. Ignored unless the host allows input.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_viewer_send_mouse_move(viewer: *const AnnexViewer, x: f64, y: f64) {
    if let Some(v) = unsafe { viewer.as_ref() } {
        let n = |f: f64| (f.clamp(0.0, 1.0) * f64::from(u16::MAX)).round() as u16;
        v.handle.send_input(InputEvent::MouseMove { x: n(x), y: n(y) });
    }
}

/// The pointer moved by this much (raw mouse movement, in pixels), for Extend: the host's pointer
/// can then leave the extended display. Ignored unless the host allows input, and never sent to
/// hosts older than protocol 1.2 (session_started's `pointer_deltas` says which).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_viewer_send_mouse_delta(viewer: *const AnnexViewer, dx: i32, dy: i32) {
    if let Some(v) = unsafe { viewer.as_ref() } {
        v.handle.send_input(InputEvent::MouseDelta { dx: dx.clamp(-10_000, 10_000), dy: dy.clamp(-10_000, 10_000) });
    }
}

/// `button`: 0 left, 1 right, 2 middle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_viewer_send_mouse_button(viewer: *const AnnexViewer, button: u32, down: bool) {
    let button = match button {
        0 => MouseButton::Left,
        1 => MouseButton::Right,
        2 => MouseButton::Middle,
        _ => return,
    };
    if let Some(v) = unsafe { viewer.as_ref() } {
        v.handle.send_input(InputEvent::MouseButton { button, down });
    }
}

/// Scroll in pixels; positive `dy` scrolls up (content moves down), positive `dx` scrolls left.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_viewer_send_scroll(viewer: *const AnnexViewer, dx: i32, dy: i32) {
    if let Some(v) = unsafe { viewer.as_ref() } {
        v.handle.send_input(InputEvent::Scroll { dx: dx.clamp(-100_000, 100_000), dy: dy.clamp(-100_000, 100_000) });
    }
}

/// Puts a clipboard item on the host's clipboard (see `annex_host_send_clipboard`). Returns 1 if
/// it's on its way, 0 if the host can't take it or it's too big for the link.
///
/// # Safety
/// `viewer` must be valid; `mime` a NUL-terminated string; `data` `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_viewer_send_clipboard(
    viewer: *const AnnexViewer,
    mime: *const c_char,
    data: *const u8,
    len: usize,
) -> i32 {
    guard(|| {
        let v = unsafe { viewer.as_ref() }.ok_or_else(|| invalid("viewer is null"))?;
        let mime = unsafe { str_arg(mime, "mime") }?;
        let data = unsafe { bytes_arg(data, len) }?.to_vec();
        Ok(i32::from(v.handle.send_clipboard(mime, data)))
    })
}

/// Sends a file to the host. `*out_id` is the id in its `transfer_*` events. The host takes
/// files only while this viewer has control.
///
/// # Safety
/// `viewer` must be valid; `path` a NUL-terminated string; `out_id` writable or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_viewer_send_file(
    viewer: *const AnnexViewer,
    path: *const c_char,
    out_id: *mut u64,
) -> i32 {
    guard(|| {
        let v = unsafe { viewer.as_ref() }.ok_or_else(|| invalid("viewer is null"))?;
        let path = unsafe { str_arg(path, "path") }?;
        let id = v.handle.send_file(std::path::Path::new(path)).map_err(failed)?;
        if let Some(out) = unsafe { out_id.as_mut() } {
            *out = id;
        }
        Ok(0)
    })
}

/// Pauses (or resumes) a file being sent to the host. Returns 1 if it is being sent, else 0.
///
/// # Safety
/// `viewer` must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_viewer_pause_transfer(viewer: *const AnnexViewer, id: u64, paused: bool) -> i32 {
    unsafe { viewer.as_ref() }.is_some_and(|v| v.handle.pause_transfer(id, paused)) as i32
}

/// Stops a file going either way (`incoming`: from the host).
///
/// # Safety
/// `viewer` must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_viewer_cancel_transfer(viewer: *const AnnexViewer, incoming: bool, id: u64) {
    if let Some(v) = unsafe { viewer.as_ref() } {
        v.handle.cancel_transfer(incoming, id);
    }
}

/// A key press or release, as this platform's key code (see `annex_key_native_from_hid`).
/// Returns 1 if sent, 0 if the key has no cross-platform code.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_viewer_send_key(viewer: *const AnnexViewer, native_code: u32, down: bool) -> i32 {
    let Some(v) = (unsafe { viewer.as_ref() }) else { return ANNEX_ERR_INVALID_ARGUMENT };
    match u16::try_from(native_code).ok().and_then(hid_from_native) {
        Some(usage) => {
            v.handle.send_input(InputEvent::Key { usage, down });
            1
        }
        None => 0,
    }
}

/// Asks the host for a direct Wi-Fi link; answered by a `direct_link_offer` or
/// `direct_link_unavailable` event.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_viewer_request_direct_link(viewer: *const AnnexViewer) {
    if let Some(v) = unsafe { viewer.as_ref() } {
        v.handle.request_direct_link();
    }
}

/// This computer runs a hotspot: tells the host to join it for a direct link.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_viewer_offer_direct_link(
    viewer: *const AnnexViewer,
    ssid: *const c_char,
    passphrase: *const c_char,
) -> i32 {
    guard(|| {
        let v = unsafe { viewer.as_ref() }.ok_or_else(|| invalid("viewer is null"))?;
        let (ssid, pass) = unsafe { (str_arg(ssid, "ssid")?, str_arg(passphrase, "passphrase")?) };
        v.handle.offer_direct_link(ssid, pass);
        Ok(ANNEX_OK)
    })
}

/// Host: answers a `direct_link_requested` event with this computer's hotspot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_offer_direct_link(
    host: *const AnnexHost,
    session_id: u64,
    ssid: *const c_char,
    passphrase: *const c_char,
) -> i32 {
    guard(|| {
        let h = unsafe { host.as_ref() }.ok_or_else(|| invalid("host is null"))?;
        let (ssid, pass) = unsafe { (str_arg(ssid, "ssid")?, str_arg(passphrase, "passphrase")?) };
        Ok(h.handle.offer_direct_link(session_id, ssid, pass) as i32)
    })
}

/// Host: answers a `direct_link_requested` event that can't be met (`reason` is shown to the viewer).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_refuse_direct_link(
    host: *const AnnexHost,
    session_id: u64,
    reason: *const c_char,
) -> i32 {
    guard(|| {
        let h = unsafe { host.as_ref() }.ok_or_else(|| invalid("host is null"))?;
        let reason = unsafe { str_arg(reason, "reason") }?;
        Ok(h.handle.refuse_direct_link(session_id, reason) as i32)
    })
}

/// Viewer: answers a host's `direct_link_requested` event that can't be met (`reason` is shown to the host).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_viewer_refuse_direct_link(viewer: *const AnnexViewer, reason: *const c_char) -> i32 {
    guard(|| {
        let v = unsafe { viewer.as_ref() }.ok_or_else(|| invalid("viewer is null"))?;
        v.handle.refuse_direct_link(unsafe { str_arg(reason, "reason") }?);
        Ok(ANNEX_OK)
    })
}

/// Host: asks the viewer of `session_id` to set up a direct Wi-Fi link; answered by a
/// `direct_link_offer` or `direct_link_unavailable` event. Returns 1 if the request was sent.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_host_request_direct_link(host: *const AnnexHost, session_id: u64) -> i32 {
    guard(|| {
        let h = unsafe { host.as_ref() }.ok_or_else(|| invalid("host is null"))?;
        Ok(h.handle.request_direct_link(session_id) as i32)
    })
}

/// Disconnects (if connected) and frees the viewer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_viewer_free(viewer: *mut AnnexViewer) {
    if viewer.is_null() {
        return;
    }
    let v = unsafe { Box::from_raw(viewer) };
    // The window goes first: disconnecting waits for the bye to go out.
    #[cfg(windows)]
    if let Some(w) = &v.window {
        w.close();
    }
    if let Some(c) = unsafe { v.core.as_ref() } {
        c.rt.block_on(v.handle.disconnect());
    }
    v.callbacks.clear();
}

// ---------------------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------------------

/// Browses the LAN for hosts. Events: `peer_found` / `peer_lost`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_discovery_start(
    core: *const AnnexCore,
    on_event: AnnexEventCallback,
    ctx: *mut c_void,
    out: *mut *mut AnnexDiscovery,
) -> i32 {
    guard(|| {
        let c = unsafe { core.as_ref() }.ok_or_else(|| invalid("core is null"))?;
        if out.is_null() {
            return Err(invalid("out is null"));
        }
        let callbacks = Callbacks::new(on_event, None, ctx);
        let cb = callbacks.clone();
        let browser = c
            .discovery()?
            .browse(move |e| {
                if let Ok(json) = serde_json::to_string(&e) {
                    tracing::debug!(target: "annex::discovery", "{json}");
                    cb.event_json(&json);
                }
            })
            .map_err(failed)?;
        unsafe { *out = Box::into_raw(Box::new(AnnexDiscovery { browser, callbacks })) };
        Ok(ANNEX_OK)
    })
}

/// Re-checks every listed device and asks the network again (the Nearby refresh button).
/// Devices that don't answer within a few seconds arrive as `peer_lost`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_discovery_refresh(d: *const AnnexDiscovery) {
    if let Some(d) = unsafe { d.as_ref() } {
        d.browser.refresh();
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn annex_discovery_free(d: *mut AnnexDiscovery) {
    if !d.is_null() {
        let d = unsafe { Box::from_raw(d) };
        d.callbacks.clear();
        drop(d);
    }
}
