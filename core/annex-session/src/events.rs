use std::sync::Arc;

use annex_proto::{Codec, DisplayInfo, InputEvent, Mode, StreamConfig};
use serde::Serialize;

pub use crate::transport::TransportKind;

/// "direct": the peers talk over a link-local address (a cable between the two computers);
/// "network": through the LAN.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinkKind {
    Direct,
    Network,
    /// "internet": across the internet, found through the rendezvous server.
    Internet,
    /// "relayed": across the internet through a relay (TURN), when a direct path wasn't possible.
    Relayed,
}

impl LinkKind {
    /// A banner in the log where a session starts, so a relayed session stands out from a direct
    /// one when reading `annex.log`.
    pub fn log_banner(self, peer: &str) {
        let (word, how) = match self {
            LinkKind::Relayed => ("RELAY", "through the relay, still end to end encrypted"),
            LinkKind::Internet => ("DIRECT", "over the internet, no relay"),
            LinkKind::Direct => ("DIRECT", "over a cable"),
            LinkKind::Network => ("DIRECT", "on the local network"),
        };
        tracing::info!("==================== {word}: session with {peer}, {how} ====================");
    }
}

use crate::LatencyStats;

/// Everything the native UI needs to know, delivered as JSON through the FFI.
/// Field names are part of the app ↔ core contract; see `docs/PROTOCOL.md` (FFI events).
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Listening {
        port: u16,
    },
    /// Host, sharing over the internet: the code for the viewer to type, valid `expires_in`
    /// seconds and once.
    InternetCode {
        code: String,
        expires_in: u32,
    },
    /// Host: a viewer typed the code and is connecting.
    InternetJoined {
        peer_name: String,
    },
    /// Host: the viewer couldn't connect directly. `relayed`: it was given this computer's
    /// address on a relay (`limited`: ours, with its time and bitrate limits); otherwise there was
    /// no relay to give. When ours was asked: `relay_left` of `relay_per_day` sessions on it are
    /// left today (0: used up, which is why there was no relay).
    InternetRelay {
        relayed: bool,
        limited: bool,
        relay_left: Option<u32>,
        relay_per_day: Option<u32>,
    },
    /// Host: the code no longer works. `reason`: "used", "expired", "stopped", or what went wrong.
    InternetCodeEnded {
        reason: String,
    },
    Connecting {
        address: String,
    },
    /// Host: show this PIN so the user can type it on the viewer. Cancel with
    /// `Core::cancel_request`.
    PairingPin {
        request_id: u64,
        pin: String,
        peer_name: String,
        fingerprint_display: String,
    },
    /// Viewer: ask the user for the PIN shown on the host; answer with `Core::submit_pin`.
    PairingPinRequired {
        request_id: u64,
        peer_name: String,
        fingerprint_display: String,
    },
    /// Pairing finished on this side (dismiss the PIN UI).
    PairingFinished {
        request_id: u64,
        success: bool,
        peer_name: String,
    },
    /// `session_id` is 0 on the viewer side (a viewer has one session).
    SessionStarted {
        session_id: u64,
        mode: Mode,
        peer_name: String,
        fingerprint: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        viewer_display: Option<DisplayInfo>,
        stream: StreamConfig,
        transport: TransportKind,
        link: LinkKind,
        /// The viewer's mouse and keyboard control the host in this session.
        input: bool,
        /// The host understands pointer movement ([`annex_proto::InputEvent::MouseDelta`],
        /// protocol 1.2), so the viewer may send that instead of positions.
        pointer_deltas: bool,
        /// Host side: the video codecs the viewer decodes (empty on the viewer side).
        #[serde(skip_serializing_if = "Vec::is_empty")]
        codecs: Vec<Codec>,
        /// The other computer's system ("macos", "windows", "linux"); absent from older versions.
        #[serde(skip_serializing_if = "Option::is_none")]
        peer_os: Option<String>,
    },
    /// Input was allowed or revoked during a session (both sides).
    InputAllowed {
        session_id: u64,
        allowed: bool,
    },
    /// Host: the viewer wants to control this computer but its device isn't allowed yet. Ask the
    /// user; allowing it (`Core::set_allow_input`) takes effect within about a second.
    InputRequested {
        session_id: u64,
        peer_name: String,
        fingerprint: String,
    },
    /// The other side asks for a direct Wi-Fi link. Answer with an offer (start a hotspot) or
    /// "unavailable".
    DirectLinkRequested {
        session_id: u64,
    },
    /// The other side runs a hotspot for a direct link: join it, then reconnect (viewer) or keep
    /// sharing (host). The passphrase only travels inside the encrypted session.
    DirectLinkOffer {
        session_id: u64,
        ssid: String,
        passphrase: String,
    },
    /// The other side can't set up a direct link.
    DirectLinkUnavailable {
        session_id: u64,
        reason: String,
    },
    /// Host: inject this input into the session's display. Only delivered while allowed.
    Input {
        session_id: u64,
        event: InputEvent,
    },
    StreamConfig {
        stream: StreamConfig,
    },
    KeyframeRequested {
        session_id: u64,
    },
    /// Host: adaptive bitrate. Set the session's encoder to `scale_percent` % of its normal bitrate.
    BitrateHint {
        session_id: u64,
        scale_percent: u32,
    },
    LatencyStats {
        #[serde(flatten)]
        stats: LatencyStats,
        #[serde(skip_serializing_if = "Option::is_none")]
        clock_rtt_ms: Option<f64>,
    },
    SessionEnded {
        session_id: u64,
        reason: String,
    },
    /// The other computer copied something: put it on this one's clipboard (if the user shares
    /// the clipboard). `mime`: "text/plain;charset=utf-8" or "image/png". `data` is base64 in JSON.
    ClipboardReceived {
        session_id: u64,
        mime: String,
        #[serde(serialize_with = "base64")]
        data: Vec<u8>,
    },
    /// A file started going either way. `incoming`: from the other computer to this one.
    TransferStarted {
        session_id: u64,
        id: u64,
        incoming: bool,
        name: String,
        size: u64,
    },
    /// Bytes done so far, about four times a second.
    TransferProgress {
        session_id: u64,
        id: u64,
        incoming: bool,
        done: u64,
    },
    /// Finished. `path`: where a received file was saved. `error`: why it failed, for the user.
    TransferEnded {
        session_id: u64,
        id: u64,
        incoming: bool,
        ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    Error {
        message: String,
    },
}

impl Event {
    /// The event's name, as its JSON `type`: for logs that must not show what it carries.
    pub fn name(&self) -> &'static str {
        match self {
            Event::Listening { .. } => "listening",
            Event::InternetCode { .. } => "internet_code",
            Event::InternetJoined { .. } => "internet_joined",
            Event::InternetRelay { .. } => "internet_relay",
            Event::InternetCodeEnded { .. } => "internet_code_ended",
            Event::Connecting { .. } => "connecting",
            Event::PairingPin { .. } => "pairing_pin",
            Event::PairingPinRequired { .. } => "pairing_pin_required",
            Event::PairingFinished { .. } => "pairing_finished",
            Event::SessionStarted { .. } => "session_started",
            Event::InputAllowed { .. } => "input_allowed",
            Event::InputRequested { .. } => "input_requested",
            Event::DirectLinkRequested { .. } => "direct_link_requested",
            Event::DirectLinkOffer { .. } => "direct_link_offer",
            Event::DirectLinkUnavailable { .. } => "direct_link_unavailable",
            Event::Input { .. } => "input",
            Event::StreamConfig { .. } => "stream_config",
            Event::KeyframeRequested { .. } => "keyframe_requested",
            Event::BitrateHint { .. } => "bitrate_hint",
            Event::LatencyStats { .. } => "latency_stats",
            Event::SessionEnded { .. } => "session_ended",
            Event::ClipboardReceived { .. } => "clipboard_received",
            Event::TransferStarted { .. } => "transfer_started",
            Event::TransferProgress { .. } => "transfer_progress",
            Event::TransferEnded { .. } => "transfer_ended",
            Event::Error { .. } => "error",
        }
    }
}

pub type EventSink = Arc<dyn Fn(Event) + Send + Sync>;

/// Logs an event the core hands to the app, without what must stay private: PINs, internet codes,
/// Wi-Fi passphrases, clipboard contents and which keys were pressed are left out. Input,
/// progress and latency (many a second) only show with verbose logging.
pub fn log_event(e: &Event) {
    const T: &str = "annex::event";
    match e {
        // A code to connect by stays out; addresses are fine.
        Event::Connecting { address } if !address.contains(['.', ':']) => {
            tracing::debug!(target: T, "connecting by internet code")
        }
        Event::InternetCode { expires_in, .. } => tracing::debug!(target: T, expires_in, "internet code ready"),
        Event::PairingPin { request_id, peer_name, fingerprint_display, .. } => {
            tracing::debug!(target: T, request_id, peer_name, fingerprint_display, "showing a pairing PIN")
        }
        Event::DirectLinkOffer { session_id, ssid, .. } => {
            tracing::debug!(target: T, session_id, ssid, "direct link offered")
        }
        Event::ClipboardReceived { session_id, mime, data } => {
            tracing::debug!(target: T, session_id, mime, bytes = data.len(), "clipboard received")
        }
        Event::Input { session_id, event } => {
            let kind = match event {
                InputEvent::MouseMove { .. } => "mouse move",
                InputEvent::MouseButton { .. } => "mouse button",
                InputEvent::Scroll { .. } => "scroll",
                InputEvent::Key { .. } => "key",
                InputEvent::MouseDelta { .. } => "mouse delta",
            };
            tracing::trace!(target: T, session_id, kind, "input")
        }
        Event::TransferProgress { .. } | Event::LatencyStats { .. } => tracing::trace!(target: T, "{e:?}"),
        Event::SessionEnded { session_id, reason } => tracing::info!(target: T, session_id, reason, "session ended"),
        Event::Error { message } => tracing::warn!(target: T, "error for the app: {message}"),
        Event::TransferEnded { ok: false, .. } => tracing::warn!(target: T, "{e:?}"),
        _ => tracing::debug!(target: T, "{e:?}"),
    }
}

/// Standard base64 with padding, for bytes inside JSON events.
fn base64<S: serde::Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n =
            (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            out.push(if i <= c.len() { A[(n >> shift & 63) as usize] as char } else { '=' });
        }
    }
    s.serialize_str(&out)
}

/// A received video frame, borrowed for the duration of the callback.
#[derive(Debug)]
pub struct FrameOut<'a> {
    pub frame_id: u32,
    /// Capture time converted to the local monotonic clock, once clock sync has converged.
    pub capture_ts_local_us: Option<i64>,
    pub keyframe: bool,
    pub data: &'a [u8],
}

pub type FrameSink = Arc<dyn Fn(FrameOut<'_>) + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_event_s_name_is_its_json_type() {
        let events = [
            Event::KeyframeRequested { session_id: 1 },
            Event::BitrateHint { session_id: 1, scale_percent: 50 },
            Event::SessionEnded { session_id: 1, reason: "quit".into() },
            Event::Error { message: "x".into() },
        ];
        for e in events {
            let json = serde_json::to_value(&e).unwrap();
            assert_eq!(json["type"], e.name());
        }
    }
}
