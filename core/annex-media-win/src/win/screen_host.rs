//! Windows host pipeline: capture a monitor, convert to NV12 at stream size on the GPU, encode
//! H.264 (hardware if available) or HEVC (hardware only), hand access units to the caller.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::LUID;
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_UNKNOWN};
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::{CreateDXGIFactory1, DXGI_ADAPTER_FLAG_SOFTWARE, IDXGIAdapter, IDXGIFactory4};

use super::MediaError;
use super::capture::ScreenCapture;
use super::convert::Converter;
use super::display::Monitor;
use super::encoder::{EncoderConfig, HardwareEncoder, OutputFn, SoftwareEncoder};

pub use super::encoder::EncodedFrame;

#[derive(Debug, Clone)]
pub struct HostPipelineConfig {
    pub monitor: Monitor,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate: u32,
    pub prefer_hardware: bool,
    /// Graphics card to capture and encode on (adapter LUID); None = Windows' default.
    pub gpu: Option<u64>,
    /// Encode at most this many frames a second (adaptive bitrate's smaller picture); None:
    /// every frame Windows captures.
    pub max_fps: Option<u32>,
    /// HEVC instead of H.264. Needs a hardware encoder: starting fails without one, and the
    /// caller falls back to H.264.
    pub hevc: bool,
}

/// A graphics card the user can pick for sharing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gpu {
    pub name: String,
    /// Adapter LUID, packed as (HighPart << 32) | LowPart.
    pub luid: u64,
}

/// Hardware graphics cards, in Windows' order (the first is the default).
pub fn gpus() -> Vec<Gpu> {
    let mut out: Vec<Gpu> = Vec::new();
    // Windows can list one physical GPU several times under different LUIDs (virtual display
    // drivers such as Annex's or Duet's appear as extra adapters reusing the GPU they render on).
    // Keep the first entry per piece of hardware: it's the real adapter.
    let mut seen: Vec<(u32, u32, u32, u32)> = Vec::new();
    // SAFETY: plain DXGI enumeration.
    unsafe {
        let Ok(factory) = CreateDXGIFactory1::<IDXGIFactory4>() else { return out };
        for i in 0.. {
            let Ok(adapter) = factory.EnumAdapters1(i) else { break };
            let Ok(desc) = adapter.GetDesc1() else { continue };
            if desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32 != 0 {
                continue;
            }
            let len = desc.Description.iter().position(|c| *c == 0).unwrap_or(desc.Description.len());
            let luid = ((desc.AdapterLuid.HighPart as u32 as u64) << 32) | desc.AdapterLuid.LowPart as u64;
            let hardware = (desc.VendorId, desc.DeviceId, desc.SubSysId, desc.Revision);
            if !seen.contains(&hardware) && !out.iter().any(|g| g.luid == luid) {
                seen.push(hardware);
                out.push(Gpu { name: String::from_utf16_lossy(&desc.Description[..len]), luid });
            }
        }
    }
    out
}

enum Encoder {
    Hardware(HardwareEncoder),
    Software { enc: SoftwareEncoder, scratch: Vec<u8> },
}

/// How long a hardware encoder may hold its first frame before it counts as broken. Real ones
/// answer within a few frames.
const FIRST_OUTPUT: Duration = Duration::from_secs(2);
/// How long to wait for Windows to capture anything at all; without a frame the encoder can't be judged.
const FIRST_CAPTURE: Duration = Duration::from_secs(3);

/// Set once the hardware H.264 encoder took frames and gave nothing back: later pipelines in this
/// process go straight to the software one instead of showing black for two seconds each time.
static HARDWARE_H264_SILENT: AtomicBool = AtomicBool::new(false);

/// Frames handed to the encoder and frames that came out, for [`HostPipeline::encoder_answers`].
#[derive(Default)]
struct Counts {
    submitted: AtomicU32,
    encoded: AtomicU32,
}

// SAFETY: the D3D11 device is created multithread-protected and every access to the converter
// and encoder goes through `Inner`'s mutex.
struct Inner {
    converter: Converter,
    encoder: Encoder,
    last: Option<ID3D11Texture2D>,
    /// With `max_fps`: when the last frame was encoded, and whether a newer one was skipped.
    last_encoded_us: i64,
    skipped: bool,
    counts: Arc<Counts>,
}
unsafe impl Send for Inner {}

/// With `max_fps`, sends a skipped frame once its turn comes if no newer one arrives: Windows
/// captures only when the screen changes, so the last change could otherwise never be shown.
struct Pacer {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Pacer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

pub struct HostPipeline {
    /// First: stopped (and joined) before the rest goes.
    _pacer: Option<Pacer>,
    inner: Arc<Mutex<Inner>>,
    base_bitrate: u32,
    clock: Arc<dyn Fn() -> i64 + Send + Sync>,
    hardware: bool,
    _capture: SendCapture,
}

struct SendCapture(#[allow(dead_code)] ScreenCapture);
// SAFETY: WinRT capture objects are agile.
unsafe impl Send for SendCapture {}
unsafe impl Sync for SendCapture {}

fn create_device(gpu: Option<u64>) -> Result<ID3D11Device, MediaError> {
    unsafe {
        // The chosen graphics card, if it's still there; otherwise Windows' default.
        let adapter: Option<IDXGIAdapter> = gpu.and_then(|luid| {
            let factory = CreateDXGIFactory1::<IDXGIFactory4>().ok()?;
            let luid = LUID { LowPart: luid as u32, HighPart: (luid >> 32) as i32 };
            factory.EnumAdapterByLuid::<IDXGIAdapter>(luid).ok()
        });
        let mut device = None;
        D3D11CreateDevice(
            adapter.as_ref(),
            if adapter.is_some() { D3D_DRIVER_TYPE_UNKNOWN } else { D3D_DRIVER_TYPE_HARDWARE },
            Default::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            None,
        )?;
        let device: ID3D11Device = device.ok_or_else(|| MediaError::Other("no D3D11 device".into()))?;
        let mt: ID3D11Multithread = windows::core::Interface::cast(&device)?;
        let _ = mt.SetMultithreadProtected(true);
        Ok(device)
    }
}

fn encode(inner: &mut Inner, nv12: &ID3D11Texture2D, ts: i64) -> Result<(), MediaError> {
    if inner.counts.submitted.fetch_add(1, Ordering::Relaxed) == 0 {
        tracing::info!("first frame captured, into the encoder");
    }
    match &mut inner.encoder {
        Encoder::Hardware(h) => {
            h.submit(nv12, ts);
            Ok(())
        }
        Encoder::Software { enc, scratch } => {
            inner.converter.read_back(nv12, scratch)?;
            enc.encode(scratch, ts)
        }
    }
}

impl HostPipeline {
    /// `clock` supplies capture timestamps (µs, the core's monotonic clock).
    ///
    /// A hardware encoder must give back its first frame: some start without an error and then
    /// never return one (on a laptop with AMD and NVIDIA graphics, the HEVC encoder Windows offered
    /// took every frame and produced nothing, and the viewer stayed black). Then HEVC fails, so the
    /// caller falls back to H.264, and H.264 falls back to the software encoder.
    pub fn start(
        cfg: HostPipelineConfig,
        clock: Arc<dyn Fn() -> i64 + Send + Sync>,
        output: OutputFn,
    ) -> Result<Self, MediaError> {
        let hardware = cfg.hevc || (cfg.prefer_hardware && !HARDWARE_H264_SILENT.load(Ordering::Relaxed));
        let p = Self::launch(cfg.clone(), clock.clone(), output.clone(), hardware)?;
        if !p.hardware || p.encoder_answers() {
            return Ok(p);
        }
        drop(p);
        let name = if cfg.hevc { "HEVC" } else { "H.264" };
        tracing::warn!("hardware {name} encoder took frames for {}s and returned none", FIRST_OUTPUT.as_secs());
        if cfg.hevc {
            return Err(MediaError::Other("the hardware HEVC encoder returns no frames".into()));
        }
        HARDWARE_H264_SILENT.store(true, Ordering::Relaxed);
        tracing::warn!("using the software H.264 encoder from now on");
        Self::launch(cfg, clock, output, false)
    }

    /// Waits for the hardware encoder's first frame: false if it took frames and returned none
    /// within [`FIRST_OUTPUT`]. A still screen is captured once, and an encoder may hold a frame
    /// until the next arrives, so the last capture is handed over again while waiting.
    fn encoder_answers(&self) -> bool {
        let counts = self.inner.lock().unwrap().counts.clone();
        let started = Instant::now();
        let mut first_submit: Option<Instant> = None;
        loop {
            if counts.encoded.load(Ordering::Relaxed) > 0 {
                return true;
            }
            if counts.submitted.load(Ordering::Relaxed) > 0 {
                let since = *first_submit.get_or_insert_with(Instant::now);
                if since.elapsed() >= FIRST_OUTPUT {
                    return false;
                }
            } else if started.elapsed() >= FIRST_CAPTURE {
                // Nothing captured yet (a locked or sleeping screen): no verdict on the encoder.
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
            if first_submit.is_some_and(|t| t.elapsed() >= Duration::from_millis(300)) {
                let mut g = self.inner.lock().unwrap();
                if let Some(last) = g.last.clone() {
                    let ts = (self.clock)();
                    let _ = encode(&mut g, &last, ts);
                }
            }
        }
    }

    fn launch(
        cfg: HostPipelineConfig,
        clock: Arc<dyn Fn() -> i64 + Send + Sync>,
        output: OutputFn,
        hardware: bool,
    ) -> Result<Self, MediaError> {
        let device = create_device(cfg.gpu)?;
        let ecfg =
            EncoderConfig { width: cfg.width, height: cfg.height, fps: cfg.fps, bitrate: cfg.bitrate, hevc: cfg.hevc };
        let counts = Arc::new(Counts::default());
        let output: OutputFn = {
            let counts = counts.clone();
            Arc::new(move |f: EncodedFrame| {
                if counts.encoded.fetch_add(1, Ordering::Relaxed) == 0 {
                    tracing::info!(keyframe = f.keyframe, bytes = f.data.len(), "first frame out of the encoder");
                }
                output(f)
            })
        };
        let encoder = if cfg.hevc {
            Encoder::Hardware(HardwareEncoder::new(&device, ecfg, output.clone())?)
        } else if hardware {
            match HardwareEncoder::new(&device, ecfg, output.clone()) {
                Ok(h) => Encoder::Hardware(h),
                Err(e) => {
                    tracing::warn!("hardware H.264 encoder unavailable, using software: {e}");
                    Encoder::Software { enc: SoftwareEncoder::new(ecfg, output)?, scratch: Vec::new() }
                }
            }
        } else {
            Encoder::Software { enc: SoftwareEncoder::new(ecfg, output)?, scratch: Vec::new() }
        };
        let hardware = matches!(encoder, Encoder::Hardware(_));
        let inner = Arc::new(Mutex::new(Inner {
            converter: Converter::new(&device, cfg.width, cfg.height)?,
            encoder,
            last: None,
            last_encoded_us: 0,
            skipped: false,
            counts,
        }));
        // A little under the frame time, so a screen refreshing at exactly twice the rate isn't
        // cut to a third by timing jitter. 0: every frame.
        let min_gap_us: i64 = cfg.max_fps.map_or(0, |f| 900_000 / i64::from(f.max(1)));
        let capture = {
            let inner = inner.clone();
            let clock = clock.clone();
            ScreenCapture::start(
                &device,
                cfg.monitor.handle,
                Arc::new(move |bgra| {
                    let ts = clock();
                    let mut g = inner.lock().unwrap();
                    let result = g.converter.convert(bgra).and_then(|nv12| {
                        g.last = Some(nv12.clone());
                        if min_gap_us > 0 && ts - g.last_encoded_us < min_gap_us {
                            // Too soon after the last one: the pacer sends it if nothing newer comes.
                            g.skipped = true;
                            return Ok(());
                        }
                        g.skipped = false;
                        g.last_encoded_us = ts;
                        encode(&mut g, &nv12, ts)
                    });
                    if let Err(e) = result {
                        tracing::warn!("frame dropped: {e}");
                    }
                }),
            )?
        };
        let pacer = if min_gap_us > 0 {
            let stop = Arc::new(AtomicBool::new(false));
            let (inner, clock, stop2) = (inner.clone(), clock.clone(), stop.clone());
            let thread = std::thread::Builder::new()
                .name("annex-frame-pacer".into())
                .spawn(move || {
                    while !stop2.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_micros(min_gap_us as u64));
                        let mut g = inner.lock().unwrap();
                        let ts = clock();
                        if !g.skipped || ts - g.last_encoded_us < min_gap_us {
                            continue;
                        }
                        let Some(last) = g.last.clone() else { continue };
                        g.skipped = false;
                        g.last_encoded_us = ts;
                        if let Err(e) = encode(&mut g, &last, ts) {
                            tracing::warn!("frame dropped: {e}");
                        }
                    }
                })
                .map_err(|e| MediaError::Other(e.to_string()))?;
            Some(Pacer { stop, thread: Some(thread) })
        } else {
            None
        };
        tracing::info!(
            hardware,
            hevc = cfg.hevc,
            width = cfg.width,
            height = cfg.height,
            max_fps = ?cfg.max_fps,
            "Windows host pipeline started"
        );
        Ok(HostPipeline {
            _pacer: pacer,
            inner,
            base_bitrate: cfg.bitrate,
            clock,
            hardware,
            _capture: SendCapture(capture),
        })
    }

    pub fn is_hardware(&self) -> bool {
        self.hardware
    }

    /// Adaptive bitrate: run the encoder at `percent` % of the configured bitrate.
    pub fn set_bitrate_scale(&self, percent: u32) {
        let bitrate = (self.base_bitrate as u64 * percent as u64 / 100).clamp(500_000, u32::MAX as u64) as u32;
        // The hardware encoder's change is made after the lock is let go, so capture never waits
        // for it (see `HardwareEncoder::rate_control`). The software one runs under the lock.
        let hardware = match &self.inner.lock().unwrap().encoder {
            Encoder::Hardware(h) => Some(h.rate_control()),
            Encoder::Software { enc, .. } => {
                enc.set_bitrate(bitrate);
                None
            }
        };
        if let Some(rate) = hardware {
            rate.set_bitrate(bitrate);
        }
    }

    /// Forces an IDR and, because a static screen produces no new frames, re-encodes the last one.
    pub fn request_keyframe(&self) {
        let mut g = self.inner.lock().unwrap();
        match &g.encoder {
            Encoder::Hardware(h) => h.request_keyframe(),
            Encoder::Software { enc, .. } => enc.request_keyframe(),
        }
        if let Some(last) = g.last.clone() {
            let ts = (self.clock)();
            if let Err(e) = encode(&mut g, &last, ts) {
                tracing::warn!("keyframe re-encode failed: {e}");
            }
        }
    }
}

pub use crate::geometry::stream_size;
