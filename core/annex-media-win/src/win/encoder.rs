//! H.264 or HEVC encoding with Media Foundation (HEVC only on a hardware encoder).
//!
//! Prefers a hardware encoder MFT (NVENC / Quick Sync / AMF expose themselves as async MFTs)
//! fed with D3D11 textures; falls back to Microsoft's software encoder (sync MFT, system
//! memory). Both are configured for low latency: no B-frames, keyframes on demand.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::Graphics::Direct3D11::{ID3D11Device, ID3D11Multithread, ID3D11Texture2D};
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance, CoTaskMemFree};
use windows::Win32::System::Variant::{VARIANT, VARIANT_0, VARIANT_0_0, VARIANT_0_0_0, VT_BOOL, VT_UI4};
use windows::core::Interface;

use super::MediaError;
use crate::annexb::{is_keyframe, with_hevc_parameter_sets, with_parameter_sets};

/// One encoded access unit (Annex B; keyframes carry SPS/PPS).
#[derive(Debug, Clone)]
pub struct EncodedFrame {
    pub data: Vec<u8>,
    pub keyframe: bool,
    pub capture_us: i64,
}

pub type OutputFn = Arc<dyn Fn(EncodedFrame) + Send + Sync>;

fn var_u32(v: u32) -> VARIANT {
    VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: std::mem::ManuallyDrop::new(VARIANT_0_0 {
                vt: VT_UI4,
                wReserved1: 0,
                wReserved2: 0,
                wReserved3: 0,
                Anonymous: VARIANT_0_0_0 { ulVal: v },
            }),
        },
    }
}

fn var_true() -> VARIANT {
    VARIANT {
        Anonymous: VARIANT_0 {
            Anonymous: std::mem::ManuallyDrop::new(VARIANT_0_0 {
                vt: VT_BOOL,
                wReserved1: 0,
                wReserved2: 0,
                wReserved3: 0,
                Anonymous: VARIANT_0_0_0 { boolVal: VARIANT_TRUE },
            }),
        },
    }
}

fn pack(hi: u32, lo: u32) -> u64 {
    ((hi as u64) << 32) | lo as u64
}

#[derive(Debug, Clone, Copy)]
pub struct EncoderConfig {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate: u32,
    /// HEVC instead of H.264 (hardware encoders only).
    pub hevc: bool,
}

unsafe fn configure(mft: &IMFTransform, cfg: EncoderConfig) -> Result<(), MediaError> {
    unsafe {
        let out = MFCreateMediaType()?;
        out.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        out.SetGUID(&MF_MT_SUBTYPE, if cfg.hevc { &MFVideoFormat_HEVC } else { &MFVideoFormat_H264 })?;
        out.SetUINT32(&MF_MT_AVG_BITRATE, cfg.bitrate)?;
        out.SetUINT64(&MF_MT_FRAME_SIZE, pack(cfg.width, cfg.height))?;
        out.SetUINT64(&MF_MT_FRAME_RATE, pack(cfg.fps, 1))?;
        out.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack(1, 1))?;
        out.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
        // HEVC: the encoder's default profile (Main).
        if !cfg.hevc {
            out.SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_High.0 as u32)?;
        }
        mft.SetOutputType(0, &out, 0)?;

        let input = MFCreateMediaType()?;
        input.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        input.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
        input.SetUINT64(&MF_MT_FRAME_SIZE, pack(cfg.width, cfg.height))?;
        input.SetUINT64(&MF_MT_FRAME_RATE, pack(cfg.fps, 1))?;
        input.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack(1, 1))?;
        input.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
        mft.SetInputType(0, &input, 0)?;

        if let Ok(api) = mft.cast::<ICodecAPI>() {
            // Not every encoder supports every knob; each is best-effort.
            let _ = api.SetValue(&CODECAPI_AVLowLatencyMode, &var_true());
            let _ = api.SetValue(&CODECAPI_AVEncMPVDefaultBPictureCount, &var_u32(0));
            let _ = api.SetValue(&CODECAPI_AVEncMPVGOPSize, &var_u32(cfg.fps * 30));
            if api
                .SetValue(
                    &CODECAPI_AVEncCommonRateControlMode,
                    &var_u32(eAVEncCommonRateControlMode_LowDelayVBR.0 as u32),
                )
                .is_err()
            {
                let _ = api
                    .SetValue(&CODECAPI_AVEncCommonRateControlMode, &var_u32(eAVEncCommonRateControlMode_CBR.0 as u32));
            }
            let _ = api.SetValue(&CODECAPI_AVEncCommonMeanBitRate, &var_u32(cfg.bitrate));
        }
        Ok(())
    }
}

fn set_mean_bitrate(mft: &IMFTransform, bitrate: u32) {
    if let Ok(api) = mft.cast::<ICodecAPI>() {
        unsafe {
            let _ = api.SetValue(&CODECAPI_AVEncCommonMeanBitRate, &var_u32(bitrate));
        }
    }
}

/// SPS/PPS (Annex B) the encoder reports in its output type, if any.
unsafe fn sequence_header(mft: &IMFTransform) -> Vec<u8> {
    unsafe {
        let Ok(t) = mft.GetOutputCurrentType(0) else { return Vec::new() };
        let Ok(size) = t.GetBlobSize(&MF_MT_MPEG_SEQUENCE_HEADER) else { return Vec::new() };
        let mut buf = vec![0u8; size as usize];
        if t.GetBlob(&MF_MT_MPEG_SEQUENCE_HEADER, &mut buf, None).is_err() {
            return Vec::new();
        }
        buf
    }
}

unsafe fn sample_to_frame(sample: &IMFSample, seq: &[u8], hevc: bool) -> Result<EncodedFrame, MediaError> {
    unsafe {
        let buf = sample.ConvertToContiguousBuffer()?;
        let mut p = std::ptr::null_mut();
        let mut len = 0u32;
        buf.Lock(&mut p, None, Some(&mut len))?;
        let data = std::slice::from_raw_parts(p, len as usize).to_vec();
        buf.Unlock()?;
        // Not every encoder marks its keyframes (CleanPoint); the bitstream always says. An
        // unmarked keyframe would never be sent: the host waits for one after every drop.
        let keyframe = sample.GetUINT32(&MFSampleExtension_CleanPoint).unwrap_or(0) != 0 || is_keyframe(&data, hevc);
        let capture_us = sample.GetSampleTime().unwrap_or(0) / 10;
        let data = match (keyframe, hevc) {
            (false, _) => data,
            (true, false) => with_parameter_sets(data, seq),
            (true, true) => with_hevc_parameter_sets(data, seq),
        };
        Ok(EncodedFrame { data, keyframe, capture_us })
    }
}

/// Software encoder: Microsoft H.264 encoder MFT, synchronous, system-memory NV12 input.
pub struct SoftwareEncoder {
    mft: IMFTransform,
    cfg: EncoderConfig,
    force_key: AtomicBool,
    output: OutputFn,
}

impl SoftwareEncoder {
    pub fn new(cfg: EncoderConfig, output: OutputFn) -> Result<Self, MediaError> {
        unsafe {
            super::mf_startup()?;
            let mft: IMFTransform = CoCreateInstance(&CLSID_MSH264EncoderMFT, None, CLSCTX_INPROC_SERVER)?;
            configure(&mft, cfg)?;
            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
            Ok(SoftwareEncoder { mft, cfg, force_key: AtomicBool::new(true), output })
        }
    }

    pub fn request_keyframe(&self) {
        self.force_key.store(true, Ordering::Release);
    }

    /// Changes the target bitrate mid-stream (adaptive bitrate).
    pub fn set_bitrate(&self, bitrate: u32) {
        set_mean_bitrate(&self.mft, bitrate);
    }

    /// `nv12` is a tightly packed NV12 image (`width * height * 3 / 2` bytes).
    pub fn encode(&self, nv12: &[u8], capture_us: i64) -> Result<(), MediaError> {
        let expected = (self.cfg.width * self.cfg.height * 3 / 2) as usize;
        if nv12.len() < expected {
            return Err(MediaError::Other(format!("NV12 buffer too small: {} < {expected}", nv12.len())));
        }
        unsafe {
            if self.force_key.swap(false, Ordering::AcqRel)
                && let Ok(api) = self.mft.cast::<ICodecAPI>()
            {
                let _ = api.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &var_u32(1));
            }
            let buffer = MFCreateMemoryBuffer(expected as u32)?;
            let mut p = std::ptr::null_mut();
            buffer.Lock(&mut p, None, None)?;
            std::ptr::copy_nonoverlapping(nv12.as_ptr(), p, expected);
            buffer.Unlock()?;
            buffer.SetCurrentLength(expected as u32)?;
            let sample = MFCreateSample()?;
            sample.AddBuffer(&buffer)?;
            sample.SetSampleTime(capture_us * 10)?;
            sample.SetSampleDuration(10_000_000 / self.cfg.fps as i64)?;
            self.mft.ProcessInput(0, &sample, 0)?;
            self.drain()
        }
    }

    unsafe fn drain(&self) -> Result<(), MediaError> {
        let seq = unsafe { sequence_header(&self.mft) };
        loop {
            let info = unsafe { self.mft.GetOutputStreamInfo(0)? };
            let provides = info.dwFlags & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32) != 0;
            let sample = if provides {
                None
            } else {
                unsafe {
                    let s = MFCreateSample()?;
                    s.AddBuffer(&MFCreateMemoryBuffer(info.cbSize.max(1 << 20))?)?;
                    Some(s)
                }
            };
            let mut out = [MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                pSample: std::mem::ManuallyDrop::new(sample),
                dwStatus: 0,
                pEvents: std::mem::ManuallyDrop::new(None),
            }];
            let mut status = 0;
            let r = unsafe { self.mft.ProcessOutput(0, &mut out, &mut status) };
            let sample = unsafe { std::mem::ManuallyDrop::take(&mut out[0].pSample) };
            drop(unsafe { std::mem::ManuallyDrop::take(&mut out[0].pEvents) });
            match r {
                Ok(()) => {
                    if let Some(s) = sample {
                        (self.output)(unsafe { sample_to_frame(&s, &seq, false)? });
                    }
                }
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(()),
                Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => unsafe { configure(&self.mft, self.cfg)? },
                Err(e) => return Err(e.into()),
            }
        }
    }
}

impl Drop for SoftwareEncoder {
    fn drop(&mut self) {
        unsafe {
            let _ = self.mft.ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
    }
}

/// Latest frame waiting for the hardware encoder (newer frames replace older ones).
struct Slot {
    frame: Mutex<Option<(ID3D11Texture2D, i64)>>,
    ready: Condvar,
    stop: AtomicBool,
}

/// Hardware encoder: async MFT with D3D11 texture input, driven by its own event thread.
pub struct HardwareEncoder {
    mft: IMFTransform,
    slot: Arc<Slot>,
    force_key: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    _manager: IMFDXGIDeviceManager,
    /// Last field: dropped after Drop::drop shut the MFT down and joined its thread.
    _activate: ShutdownOnDrop,
}

/// The activation object of the MFT in use; ShutdownObject releases what ActivateObject made.
struct ShutdownOnDrop(IMFActivate);

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        unsafe {
            let _ = self.0.ShutdownObject();
        }
    }
}

// SAFETY: the MFT and manager are free-threaded COM objects; access is synchronised by MF.
unsafe impl Send for HardwareEncoder {}
unsafe impl Sync for HardwareEncoder {}

impl HardwareEncoder {
    pub fn new(device: &ID3D11Device, cfg: EncoderConfig, output: OutputFn) -> Result<Self, MediaError> {
        unsafe {
            super::mf_startup()?;
            let mt: ID3D11Multithread = device.cast()?;
            let _ = mt.SetMultithreadProtected(true);
            let mut token = 0u32;
            let mut manager = None;
            MFCreateDXGIDeviceManager(&mut token, &mut manager)?;
            let manager = manager.ok_or_else(|| MediaError::Other("no DXGI device manager".into()))?;
            manager.ResetDevice(device, token)?;

            // Encoders on the GPU that captures first (on hybrid laptops the first one listed is
            // often the other GPU, e.g. NVENC while the Intel GPU drives the screen, and fails
            // with E_UNEXPECTED). Then any other hardware encoder; the first that accepts our
            // device wins.
            let mut candidates = hardware_encoders(Some(adapter_luid(device)?), cfg.hevc)?;
            let on_this_gpu = candidates.len();
            candidates.extend(hardware_encoders(None, cfg.hevc)?);
            let name = if cfg.hevc { "HEVC" } else { "H.264" };
            let mut last = MediaError::Other(format!("no hardware {name} encoder"));
            let mut chosen = None;
            let mut candidates = candidates.into_iter().enumerate();
            for (i, activate) in candidates.by_ref() {
                let gpu = if i < on_this_gpu { "the capturing GPU" } else { "any GPU" };
                match try_activate(&activate, &manager) {
                    Ok(mft) => {
                        tracing::info!("hardware {name} encoder: {} (from {gpu})", friendly_name(&activate));
                        chosen = Some((ShutdownOnDrop(activate), mft));
                        break;
                    }
                    Err(e) => {
                        tracing::info!(
                            "hardware encoder candidate rejected: {} (from {gpu}): {e}",
                            friendly_name(&activate)
                        );
                        let _ = activate.ShutdownObject();
                        last = e;
                    }
                }
            }
            for (_, untried) in candidates {
                let _ = untried.ShutdownObject();
            }
            let (activate, mft) = chosen.ok_or(last)?;

            configure(&mft, cfg)?;
            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;

            let slot = Arc::new(Slot { frame: Mutex::new(None), ready: Condvar::new(), stop: AtomicBool::new(false) });
            let force_key = Arc::new(AtomicBool::new(true));
            let thread = {
                let (mft, slot, force_key) = (SendMft(mft.clone()), slot.clone(), force_key.clone());
                std::thread::Builder::new()
                    .name("annex-hw-encoder".into())
                    .spawn(move || {
                        let mft = mft;
                        if let Err(e) = event_loop(&mft.0, &slot, &force_key, cfg, &output)
                            && !slot.stop.load(Ordering::Acquire)
                        {
                            tracing::error!("hardware encoder stopped: {e}");
                        }
                    })
                    .map_err(|e| MediaError::Other(e.to_string()))?
            };
            Ok(HardwareEncoder { mft, slot, force_key, thread: Some(thread), _manager: manager, _activate: activate })
        }
    }

    pub fn request_keyframe(&self) {
        self.force_key.store(true, Ordering::Release);
    }

    /// The encoder's bitrate control (adaptive bitrate), to use without holding the pipeline: an
    /// asynchronous MFT is free-threaded, and its own thread uses it without that lock anyway. A
    /// vendor's encoder may make the change wait for its thread, which can be waiting for a frame
    /// from capture.
    pub fn rate_control(&self) -> RateControl {
        RateControl(SendMft(self.mft.clone()))
    }

    /// Queues an NV12 texture (stream size). If the encoder is busy, the previous queued frame
    /// is replaced; the texture must not be written again until a later frame replaces it.
    pub fn submit(&self, nv12: &ID3D11Texture2D, capture_us: i64) {
        *self.slot.frame.lock().unwrap() = Some((nv12.clone(), capture_us));
        self.slot.ready.notify_one();
    }
}

struct SendMft(IMFTransform);
// SAFETY: see HardwareEncoder.
unsafe impl Send for SendMft {}

/// See [`HardwareEncoder::rate_control`].
pub struct RateControl(SendMft);

impl RateControl {
    pub fn set_bitrate(&self, bitrate: u32) {
        set_mean_bitrate(&self.0.0, bitrate);
    }
}

fn event_loop(
    mft: &IMFTransform,
    slot: &Slot,
    force_key: &AtomicBool,
    cfg: EncoderConfig,
    output: &OutputFn,
) -> Result<(), MediaError> {
    unsafe {
        let events: IMFMediaEventGenerator = mft.cast()?;
        loop {
            let event = events.GetEvent(MEDIA_EVENT_GENERATOR_GET_EVENT_FLAGS(0))?;
            let kind = MF_EVENT_TYPE(event.GetType()? as i32);
            if kind == METransformNeedInput {
                {
                    let (texture, ts) = {
                        let mut g = slot.frame.lock().unwrap();
                        loop {
                            if slot.stop.load(Ordering::Acquire) {
                                return Ok(());
                            }
                            if let Some(f) = g.take() {
                                break f;
                            }
                            g = slot.ready.wait(g).unwrap();
                        }
                    };
                    if force_key.swap(false, Ordering::AcqRel)
                        && let Ok(api) = mft.cast::<ICodecAPI>()
                    {
                        let _ = api.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &var_u32(1));
                    }
                    let buffer = MFCreateDXGISurfaceBuffer(&ID3D11Texture2D::IID, &texture, 0, false)?;
                    let sample = MFCreateSample()?;
                    sample.AddBuffer(&buffer)?;
                    sample.SetSampleTime(ts * 10)?;
                    sample.SetSampleDuration(10_000_000 / cfg.fps as i64)?;
                    mft.ProcessInput(0, &sample, 0)?;
                }
            } else if kind == MEError {
                // The encoder gave up (a lost device, a GPU it can't use): say so instead of
                // waiting for events that never come.
                return Err(windows::core::Error::from_hresult(event.GetStatus()?).into());
            } else if kind == METransformHaveOutput {
                {
                    let mut out = [MFT_OUTPUT_DATA_BUFFER {
                        dwStreamID: 0,
                        pSample: std::mem::ManuallyDrop::new(None),
                        dwStatus: 0,
                        pEvents: std::mem::ManuallyDrop::new(None),
                    }];
                    let mut status = 0;
                    let r = mft.ProcessOutput(0, &mut out, &mut status);
                    let sample = std::mem::ManuallyDrop::take(&mut out[0].pSample);
                    drop(std::mem::ManuallyDrop::take(&mut out[0].pEvents));
                    match r {
                        Ok(()) => {
                            if let Some(s) = sample {
                                output(sample_to_frame(&s, &sequence_header(mft), cfg.hevc)?);
                            }
                        }
                        Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => configure(mft, cfg)?,
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
    }
}

impl Drop for HardwareEncoder {
    fn drop(&mut self) {
        {
            // Under the frame lock: the event thread checks `stop` and then waits while holding
            // it, so the wake-up can't land between the two and be lost.
            let _g = self.slot.frame.lock().unwrap_or_else(|e| e.into_inner());
            self.slot.stop.store(true, Ordering::Release);
            self.slot.ready.notify_all();
        }
        unsafe {
            // Unblocks GetEvent in the event thread.
            if let Ok(s) = self.mft.cast::<IMFShutdown>() {
                let _ = s.Shutdown();
            }
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The adapter LUID of a D3D11 device, packed the way MFT_ENUM_ADAPTER_LUID expects.
fn adapter_luid(device: &ID3D11Device) -> Result<u64, MediaError> {
    unsafe {
        let dxgi: windows::Win32::Graphics::Dxgi::IDXGIDevice = device.cast()?;
        let desc = dxgi.GetAdapter()?.GetDesc()?;
        Ok(((desc.AdapterLuid.HighPart as u32 as u64) << 32) | desc.AdapterLuid.LowPart as u64)
    }
}

/// Hardware NV12 → H.264 encoders, optionally only those on one adapter.
/// Whether this PC has a hardware HEVC encoder (NVENC, Quick Sync, AMF). There's no software one.
pub fn hevc_encoder_available() -> bool {
    if super::mf_startup().is_err() {
        return false;
    }
    match hardware_encoders(None, true) {
        Ok(list) => {
            let found = !list.is_empty();
            for a in list {
                // SAFETY: enumerated, never activated.
                let _ = unsafe { a.ShutdownObject() };
            }
            found
        }
        Err(_) => false,
    }
}

fn hardware_encoders(adapter: Option<u64>, hevc: bool) -> Result<Vec<IMFActivate>, MediaError> {
    unsafe {
        let input = MFT_REGISTER_TYPE_INFO { guidMajorType: MFMediaType_Video, guidSubtype: MFVideoFormat_NV12 };
        let subtype = if hevc { MFVideoFormat_HEVC } else { MFVideoFormat_H264 };
        let output = MFT_REGISTER_TYPE_INFO { guidMajorType: MFMediaType_Video, guidSubtype: subtype };
        let mut attrs = None;
        if let Some(luid) = adapter {
            MFCreateAttributes(&mut attrs, 1)?;
            if let Some(a) = &attrs {
                a.SetUINT64(&MFT_ENUM_ADAPTER_LUID, luid)?;
            }
        }
        let mut activates: *mut Option<IMFActivate> = std::ptr::null_mut();
        let mut count = 0u32;
        let flags = MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER;
        if MFTEnum2(
            MFT_CATEGORY_VIDEO_ENCODER,
            flags,
            Some(&input),
            Some(&output),
            attrs.as_ref(),
            &mut activates,
            &mut count,
        )
        .is_err()
        {
            return Ok(Vec::new());
        }
        let list = std::slice::from_raw_parts_mut(activates, count as usize);
        let out: Vec<IMFActivate> = list.iter_mut().filter_map(|a| a.take()).collect();
        CoTaskMemFree(Some(activates.cast()));
        Ok(out)
    }
}

/// An encoder's name as Windows lists it ("NVIDIA HEVC Encoder MFT"), for the log.
fn friendly_name(activate: &IMFActivate) -> String {
    unsafe {
        let Ok(len) = activate.GetStringLength(&MFT_FRIENDLY_NAME_Attribute) else { return "unnamed".into() };
        let mut buf = vec![0u16; len as usize + 1];
        if activate.GetString(&MFT_FRIENDLY_NAME_Attribute, &mut buf, None).is_err() {
            return "unnamed".into();
        }
        String::from_utf16_lossy(&buf[..len as usize])
    }
}

/// Activates one encoder and hands it our D3D device; fails if it can't use that GPU.
fn try_activate(activate: &IMFActivate, manager: &IMFDXGIDeviceManager) -> Result<IMFTransform, MediaError> {
    unsafe {
        let mft: IMFTransform = activate.ActivateObject()?;
        let attrs = mft.GetAttributes()?;
        attrs.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1)?;
        let _ = attrs.SetUINT32(&MF_LOW_LATENCY, 1);
        mft.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, manager.as_raw() as usize)?;
        Ok(mft)
    }
}
