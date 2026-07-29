//! USB Audio Class (UAC 1.0) decoder plugin.
//!
//! Detects USB audio devices and decodes:
//! - Audio Control topology: input/output terminals, feature units,
//!   mixer units, and selector units parsed from configuration descriptors.
//! - Audio Streaming format: sample rate, channel count, and bit depth.
//! - Isochronous PCM data arriving as BulkIn/Interrupt transactions on
//!   identified audio endpoints.
//!
//! The content pane is split into two regions:
//!   TOP — scrollable topology / stream info text.
//!   BOTTOM — live braille waveform (Canvas) + playback controls.
//!
//! Key bindings (active while this plugin is selected):
//!   Space  — play / stop captured audio
//!   [  /  ] — cycle through captured streams

use crate::{PluginLine, PluginNavRequest, UsbPlugin, dbg_log};
use crate::models::{PacketType, TransactionInfo, TransactionKind, UsbDeviceInfo};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Paragraph,
        canvas::{Canvas, Context as CanvasContext, Line as CanvasLine},
    },
    Frame,
};
use std::collections::HashMap;
#[cfg(feature = "audio-playback")]
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

// ── UAC class codes ──────────────────────────────────────────────────────────
const CLASS_AUDIO:             u8 = 0x01;
const SUBCLASS_AUDIOCONTROL:   u8 = 0x01;
const SUBCLASS_AUDIOSTREAMING: u8 = 0x02;

// ── UAC descriptor types ─────────────────────────────────────────────────────
const CS_INTERFACE: u8 = 0x24;

// ── AudioControl interface subtypes ──────────────────────────────────────────
const AC_INPUT_TERMINAL:  u8 = 0x02;
const AC_OUTPUT_TERMINAL: u8 = 0x03;
const AC_MIXER_UNIT:      u8 = 0x04;
const AC_SELECTOR_UNIT:   u8 = 0x05;
const AC_FEATURE_UNIT:    u8 = 0x06;

// ── AudioStreaming interface subtypes ─────────────────────────────────────────
const AS_GENERAL:     u8 = 0x01;
const AS_FORMAT_TYPE: u8 = 0x02;

// ── Terminal type names ───────────────────────────────────────────────────────
fn terminal_type_name(wtype: u16) -> &'static str {
    match wtype {
        0x0101 => "USB Streaming",
        0x0200 => "Input (undefined)",
        0x0201 => "Microphone",
        0x0202 => "Desktop Microphone",
        0x0203 => "Personal Microphone",
        0x0204 => "Omni Microphone",
        0x0205 => "Microphone Array",
        0x0300 => "Output (undefined)",
        0x0301 => "Speaker",
        0x0302 => "Headphones",
        0x0303 => "Head-Mounted Audio",
        0x0304 => "Desktop Speaker",
        0x0305 => "Room Speaker",
        0x0306 => "Communication Speaker",
        0x0307 => "LFE / Subwoofer",
        0x0401 => "Handset",
        0x0402 => "Headset",
        0x0601 => "Analog Connector",
        0x0602 => "Digital Audio Interface",
        0x0603 => "Line Connector",
        0x0605 => "S/PDIF Interface",
        _ => "Unknown",
    }
}

// ── Feature-unit control bitmap → human-readable list ────────────────────────
fn feature_controls_str(bma: &[u8]) -> String {
    if bma.is_empty() { return "—".to_string(); }
    let bits = bma[0];
    let mut v = Vec::new();
    if bits & 0x01 != 0 { v.push("Mute"); }
    if bits & 0x02 != 0 { v.push("Volume"); }
    if bits & 0x04 != 0 { v.push("Bass"); }
    if bits & 0x08 != 0 { v.push("Mid"); }
    if bits & 0x10 != 0 { v.push("Treble"); }
    if bits & 0x20 != 0 { v.push("EQ"); }
    if bits & 0x40 != 0 { v.push("AGC"); }
    if bits & 0x80 != 0 { v.push("Delay"); }
    if v.is_empty() { "—".to_string() } else { v.join(" ") }
}

// ── Topology structures ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct InputTerminal {
    id: u8,
    terminal_type: u16,
    nr_channels: u8,
}

#[derive(Debug, Clone)]
struct OutputTerminal {
    id: u8,
    terminal_type: u16,
    source_id: u8,
}

#[derive(Debug, Clone)]
struct FeatureUnit {
    id: u8,
    source_id: u8,
    master_controls: Vec<u8>,
}

#[derive(Debug, Clone)]
struct MixerUnit {
    id: u8,
    source_ids: Vec<u8>,
    nr_out_channels: u8,
}

#[derive(Debug, Clone)]
struct SelectorUnit {
    id: u8,
    source_ids: Vec<u8>,
}

#[derive(Debug, Clone)]
struct AudioStreamInfo {
    interface_num: u8,
    /// Which alternate setting of `interface_num` this format belongs to.
    /// An interface commonly has several alt settings, each with its own
    /// format (16-bit vs 24-bit, different sample rates, etc.) — only the
    /// one actually selected via `SET_INTERFACE` is the one really on the
    /// wire, so this is needed to tell them apart.
    alt_setting: u8,
    terminal_link: u8,
    format_tag: u16,
    nr_channels: u8,
    subframe_size: u8,
    bit_resolution: u8,
    sample_rates: Vec<u32>,
    ep_addr: u8,
}

impl AudioStreamInfo {
    fn primary_sample_rate(&self) -> u32 {
        self.sample_rates.first().copied().unwrap_or(0)
    }

    fn format_desc(&self) -> String {
        let sr = self.primary_sample_rate();
        let ch = match self.nr_channels {
            1 => "Mono".to_string(),
            2 => "Stereo".to_string(),
            n => format!("{n}ch"),
        };
        let tag = match self.format_tag {
            0x0001 => "PCM",
            0x0002 => "PCM8",
            0x0003 => "IEEE_FLOAT",
            0x0004 => "ALAW",
            0x0005 => "MULAW",
            _ => "Unknown",
        };
        if sr > 0 {
            format!("{tag}  {} Hz  {}-bit  {}", sr, self.bit_resolution, ch)
        } else {
            format!("{tag}  {}-bit  {}", self.bit_resolution, ch)
        }
    }
}

// ── Per-device audio topology ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct AudioDevice {
    address: u8,
    input_terminals:  Vec<InputTerminal>,
    output_terminals: Vec<OutputTerminal>,
    feature_units:    Vec<FeatureUnit>,
    mixer_units:      Vec<MixerUnit>,
    selector_units:   Vec<SelectorUnit>,
    streams:          Vec<AudioStreamInfo>,
}

impl AudioDevice {
    fn new(address: u8) -> Self {
        Self {
            address,
            input_terminals:  Vec::new(),
            output_terminals: Vec::new(),
            feature_units:    Vec::new(),
            mixer_units:      Vec::new(),
            selector_units:   Vec::new(),
            streams:          Vec::new(),
        }
    }

    fn has_topology(&self) -> bool {
        !self.input_terminals.is_empty() || !self.output_terminals.is_empty()
    }
}

// ── Captured PCM stream ───────────────────────────────────────────────────────

struct CapturedStream {
    dev_addr:       u8,
    ep_addr:        u8,     // with direction bit
    channels:       u8,
    bit_depth:      u8,
    /// Wire byte stride per sample (`bSubframeSize` from the Format Type
    /// descriptor). This is what actually determines where one sample ends
    /// and the next begins on the wire — it can differ from
    /// `ceil(bit_depth / 8)` (e.g. 16 significant bits packed in a 3-byte
    /// subframe), and decoding by `bit_depth` alone in that case reads every
    /// sample at the wrong offset, which sounds like pure noise.
    subframe_size:  u8,
    sample_rate:    u32,
    /// All captured samples, normalised to i16.
    samples:        Vec<i16>,
    bytes_received: usize,
}

impl CapturedStream {
    fn new(dev_addr: u8, ep_addr: u8, channels: u8, bit_depth: u8, subframe_size: u8, sample_rate: u32) -> Self {
        Self {
            dev_addr,
            ep_addr,
            channels,
            bit_depth,
            subframe_size,
            sample_rate,
            samples: Vec::new(),
            bytes_received: 0,
        }
    }

    fn push_bytes(&mut self, data: &[u8]) {
        self.bytes_received += data.len();
        let bytes_per_sample = if self.subframe_size > 0 {
            self.subframe_size as usize
        } else {
            ((self.bit_depth as usize + 7) / 8).max(1)
        };

        let mut i = 0;
        while i + bytes_per_sample <= data.len() {
            let s: i16 = match bytes_per_sample {
                1 => {
                    // PCM8: unsigned 0..255 → centre at 128
                    ((data[i] as i16) - 128) << 8
                }
                2 => i16::from_le_bytes([data[i], data[i + 1]]),
                3 => {
                    let raw = i32::from_le_bytes([data[i], data[i + 1], data[i + 2], 0]);
                    // Sign-extend the 24-bit value by shifting its sign bit into bit 31,
                    // then take the top 16 bits.  >> 24 would keep only 8 bits (256× too quiet).
                    ((raw << 8) >> 16) as i16
                }
                4 => {
                    let raw = i32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                    (raw >> 16) as i16
                }
                _ => 0,
            };
            self.samples.push(s);
            i += bytes_per_sample;
        }
    }

    fn duration_secs(&self) -> f32 {
        let denom = self.sample_rate as f32 * self.channels as f32;
        if denom == 0.0 { 0.0 } else { self.samples.len() as f32 / denom }
    }

    /// Return up to `n` most-recent samples for channel `ch`, normalised to [-1.0, 1.0].
    fn recent_channel_f64(&self, ch: usize, n: usize) -> Vec<f64> {
        let stride = self.channels as usize;
        if stride == 0 { return vec![0.0; n]; }
        let ch = ch.min(stride - 1);
        let total_frames = self.samples.len() / stride;
        let take = n.min(total_frames);
        let start = total_frames.saturating_sub(take);
        (start..start + take)
            .map(|f| self.samples[f * stride + ch] as f64 / 32768.0)
            .collect()
    }

    fn label(&self) -> String {
        let dir = if self.ep_addr & 0x80 != 0 { "IN" } else { "OUT" };
        let ch = match self.channels {
            1 => "Mono".to_string(),
            2 => "Stereo".to_string(),
            n => format!("{n}ch"),
        };
        format!("EP 0x{:02X} {} — {} Hz  {}-bit  {}", self.ep_addr, dir,
            self.sample_rate, self.bit_depth, ch)
    }
}

// ── Plugin events (text log) ──────────────────────────────────────────────────

#[derive(Debug)]
enum AudioEvent {
    DeviceDetected { addr: u8, label: String },
    StreamStarted  { label: String },
}

// ── Media control events ──────────────────────────────────────────────────────

/// A single observable media-control event detected on the bus.
#[derive(Debug, Clone)]
struct MediaEvent {
    /// Timestamp of the originating transaction (nanoseconds from capture start).
    timestamp_ns: u64,
    /// Human-readable one-line description.
    label: String,
}

// ── Main plugin struct ────────────────────────────────────────────────────────

pub struct AudioPlugin {
    events:        Vec<AudioEvent>,
    devices:       HashMap<u8, AudioDevice>,
    /// Captured PCM audio keyed by (dev_addr, ep_number_without_dir_bit).
    streams:       HashMap<(u8, u8), CapturedStream>,
    announced:     Vec<u8>,
    /// Audio endpoints identified from streaming descriptors:
    ///   (dev_addr, ep_num) → (channels, bit_depth, subframe_size, sample_rate)
    audio_eps:     HashMap<(u8, u8), (u8, u8, u8, u32)>,

    // Stream selection
    selected_idx:  usize,

    // Playback
    #[cfg(feature = "audio-playback")]
    playback_thread: Option<std::thread::JoinHandle<()>>,
    #[cfg(feature = "audio-playback")]
    stop_flag:       Option<Arc<AtomicBool>>,
    /// Current playback position in frames (updated by background thread).
    #[cfg(feature = "audio-playback")]
    playback_pos:    Option<Arc<AtomicUsize>>,
    /// Frame position saved when the user pauses; `None` when stopped or playing.
    #[cfg(feature = "audio-playback")]
    paused_frame:    Option<usize>,

    // Media events list
    media_events:    Vec<MediaEvent>,
    /// First transaction timestamp seen; used to compute relative times.
    first_ts_ns:     Option<u64>,
    /// `true` when the events list is shown instead of topology in the top pane.
    events_view:     bool,
    /// Selected row in the events list.
    events_selected: usize,
    /// Scroll offset for the events list.
    events_scroll:   usize,
    /// Pending navigation request to hand back to the app.
    pending_nav:     Option<PluginNavRequest>,
}

impl AudioPlugin {
    pub fn new() -> Self {
        Self {
            events:          Vec::new(),
            devices:         HashMap::new(),
            streams:         HashMap::new(),
            announced:       Vec::new(),
            audio_eps:       HashMap::new(),
            selected_idx:    0,
            #[cfg(feature = "audio-playback")]
            playback_thread: None,
            #[cfg(feature = "audio-playback")]
            stop_flag:       None,
            #[cfg(feature = "audio-playback")]
            playback_pos:    None,
            #[cfg(feature = "audio-playback")]
            paused_frame:    None,
            media_events:    Vec::new(),
            first_ts_ns:     None,
            events_view:     false,
            events_selected: 0,
            events_scroll:   0,
            pending_nav:     None,
        }
    }

    fn is_playing(&self) -> bool {
        #[cfg(feature = "audio-playback")]
        return self.playback_thread.as_ref().map(|t| !t.is_finished()).unwrap_or(false);
        #[cfg(not(feature = "audio-playback"))]
        false
    }

    /// Signal the background thread to stop.  Does NOT clear `paused_frame`.
    fn signal_stop(&mut self) {
        #[cfg(feature = "audio-playback")]
        if let Some(flag) = &self.stop_flag {
            flag.store(true, Ordering::Relaxed);
        }
    }

    /// Returns the current playback frame index, or `None` when not playing.
    /// When paused, returns `paused_frame`.
    fn current_playback_frame(&self) -> Option<usize> {
        #[cfg(feature = "audio-playback")]
        {
            if self.is_playing() {
                return self.playback_pos.as_ref().map(|p| p.load(Ordering::Relaxed));
            }
            return self.paused_frame;
        }
        #[cfg(not(feature = "audio-playback"))]
        None
    }

    /// Launch a playback thread starting at `start_frame`.
    #[cfg(feature = "audio-playback")]
    fn start_playback_from(&mut self, samples: Vec<i16>, channels: u8, sample_rate: u32, start_frame: usize) {
        if let Some(f) = &self.stop_flag { f.store(true, Ordering::Relaxed); }
        let flag = Arc::new(AtomicBool::new(false));
        let flag2 = flag.clone();
        let pos = Arc::new(AtomicUsize::new(start_frame));
        let pos2 = pos.clone();
        self.stop_flag       = Some(flag);
        self.playback_pos    = Some(pos);
        self.paused_frame    = None;
        self.playback_thread = Some(std::thread::spawn(move || {
            play_audio(samples, channels, sample_rate, start_frame, flag2, pos2);
        }));
    }

    fn sorted_keys(&self) -> Vec<(u8, u8)> {
        let mut keys: Vec<(u8, u8)> = self.streams.keys().copied().collect();
        keys.sort();
        keys
    }

    // ── Device detection ────────────────────────────────────────────────────

    fn refresh_from_devices(&mut self, devices: &[UsbDeviceInfo]) {
        for dev in devices {
            if self.announced.contains(&dev.address) { continue; }
            let is_audio = dev.configurations.iter()
                .flat_map(|c| c.interfaces.iter())
                .any(|i| i.class == CLASS_AUDIO);
            if !is_audio { continue; }

            self.announced.push(dev.address);
            let name = dev.product.as_deref()
                .or(dev.manufacturer.as_deref())
                .unwrap_or("Unknown Audio Device");
            self.events.push(AudioEvent::DeviceDetected {
                addr:  dev.address,
                label: format!("addr={:03}  {:04X}:{:04X}  \"{}\"",
                    dev.address, dev.vendor_id, dev.product_id, name),
            });
        }
    }

    // ── Control transfer handler ─────────────────────────────────────────────

    fn handle_control(&mut self, txn: &TransactionInfo) {
        let data_pkts: Vec<&[u8]> = txn.packets.iter()
            .filter(|p| p.packet_type == PacketType::Data && !p.raw_bytes.is_empty())
            .map(|p| p.raw_bytes.as_slice())
            .collect();

        let setup = match data_pkts.first() {
            Some(d) if d.len() >= 8 => *d,
            _ => return,
        };

        let bm     = setup[0];
        let req    = setup[1];
        let wvalue = u16::from_le_bytes([setup[2], setup[3]]);
        let windex = u16::from_le_bytes([setup[4], setup[5]]);
        let addr = txn.label.split("dev=").nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(0);

        // ── Standard SET_INTERFACE (stream start / stop) ──────────────────
        // bmRequestType=0x01: host→device, standard, interface
        if bm == 0x01 && req == 0x0B {
            let alt   = (wvalue & 0xFF) as u8;
            let iface = (windex & 0xFF) as u8;
            // The interface can have several alt settings (different bit
            // depths/sample rates sharing the same endpoint); find the one
            // actually being selected here and make it authoritative for
            // that endpoint — otherwise whichever alt happened to be parsed
            // first from the descriptor stays "active" even if a different
            // one is what's actually streaming, which decodes as noise.
            let selected = self.devices
                .get(&addr)
                .and_then(|d| d.streams.iter().find(|s| s.interface_num == iface && s.alt_setting == alt));
            if let Some(s) = selected {
                let ep_num = s.ep_addr & 0x0F;
                let key = (s.nr_channels, s.bit_resolution, s.subframe_size, s.primary_sample_rate());
                let format_changed = self.audio_eps.insert((addr, ep_num), key) != Some(key);
                // Only drop an already-captured stream if the format this
                // `SET_INTERFACE` selects is actually *different* from what
                // was already active — some hosts re-assert the same alt
                // setting repeatedly (e.g. on resume), and resetting on
                // every one of those would throw away everything captured
                // so far each time, leaving only whatever arrived after the
                // last (often very late, or redundant) reset.
                if format_changed {
                    self.streams.remove(&(addr, ep_num));
                }
            }
            let is_audio_iface = selected.is_some() || self.devices.values()
                .flat_map(|d| d.streams.iter())
                .any(|s| s.interface_num == iface);
            if is_audio_iface {
                let label = if alt == 0 {
                    format!("Stream Stop  — IF{iface}")
                } else {
                    let fmt = selected.map(|s| s.format_desc()).unwrap_or_default();
                    format!("Stream Start — IF{iface}  alt={alt}  {fmt}")
                };
                self.media_events.push(MediaEvent { timestamp_ns: txn.timestamp_ns, label });
            }
            return;
        }

        // ── UAC class control: SET_CUR (volume / mute) ────────────────────
        // bmRequestType=0x21: host→device, class, interface
        if bm == 0x21 && req == 0x01 {
            let cs      = (wvalue >> 8) as u8;   // control selector
            let channel = (wvalue & 0xFF) as u8;
            let unit_id = (windex >> 8) as u8;
            let payload = data_pkts.get(1).copied().unwrap_or(&[]);
            let ch_name = if channel == 0 { "Master".to_string() }
                          else { format!("Ch{channel}") };
            match cs {
                0x01 => { // Mute Control
                    let muted = payload.first().copied().unwrap_or(0) != 0;
                    self.media_events.push(MediaEvent {
                        timestamp_ns: txn.timestamp_ns,
                        label: format!("{}  — {}  (FU{unit_id})",
                            if muted { "Mute ON " } else { "Mute OFF" }, ch_name),
                    });
                }
                0x02 => { // Volume Control
                    if payload.len() >= 2 {
                        let vol = i16::from_le_bytes([payload[0], payload[1]]);
                        let db  = vol as f32 / 256.0;
                        self.media_events.push(MediaEvent {
                            timestamp_ns: txn.timestamp_ns,
                            label: format!("Volume {db:+.1} dB  — {}  (FU{unit_id})", ch_name),
                        });
                    }
                }
                _ => {}
            }
            return;
        }

        // ── GET_DESCRIPTOR(CONFIGURATION) ────────────────────────────────
        let desc_typ = (wvalue >> 8) as u8;
        if bm != 0x80 || req != 0x06 || desc_typ != 0x02 { return; }

        let resp: Vec<u8> = data_pkts[1..].iter()
            .flat_map(|d| d.iter().copied())
            .collect();
        if resp.len() < 9 { return; }

        self.parse_audio_config(addr, &resp);
    }

    // ── Configuration-descriptor parser ─────────────────────────────────────

    fn parse_audio_config(&mut self, addr: u8, data: &[u8]) {
        let dev = self.devices.entry(addr).or_insert_with(|| AudioDevice::new(addr));

        let mut i               = 0usize;
        let mut cur_if_class    = 0u8;
        let mut cur_if_subclass = 0u8;
        let mut cur_if_num      = 0u8;
        let mut cur_alt         = 0u8;
        let mut in_as_iface     = false;

        // Accumulated info for the current AudioStreaming alt setting.
        let mut as_link:       u8       = 0;
        let mut as_format_tag: u16      = 0;
        let mut as_channels:   u8       = 0;
        let mut as_subframe:   u8       = 0;
        let mut as_bits:       u8       = 0;
        let mut as_rates:      Vec<u32> = Vec::new();
        let mut as_ep_addr:    u8       = 0;

        macro_rules! flush_as {
            () => {
                if in_as_iface && cur_alt > 0 && as_channels > 0 && as_ep_addr != 0 {
                    let stream = AudioStreamInfo {
                        interface_num: cur_if_num,
                        alt_setting:   cur_alt,
                        terminal_link: as_link,
                        format_tag:    as_format_tag,
                        nr_channels:   as_channels,
                        subframe_size: as_subframe,
                        bit_resolution: as_bits,
                        sample_rates:  as_rates.clone(),
                        ep_addr:       as_ep_addr,
                    };
                    let ep_num = as_ep_addr & 0x0F;
                    let sr = stream.primary_sample_rate();
                    // An interface commonly has several alt settings (e.g.
                    // 16-bit vs 24-bit), each reusing the same endpoint
                    // address — keep every one (keyed by interface+alt, not
                    // just endpoint) so `SET_INTERFACE` can later look up
                    // exactly which alt's format is actually active, instead
                    // of silently keeping whichever alt happened to be
                    // parsed first even if a different one gets selected.
                    if !dev.streams.iter().any(|s| s.interface_num == cur_if_num && s.alt_setting == cur_alt) {
                        dev.streams.push(stream);
                        // Best-effort default in case a stream is somehow
                        // never seen going through `SET_INTERFACE` (e.g. the
                        // capture started mid-stream); the SET_INTERFACE
                        // handler below corrects this once observed.
                        self.audio_eps.entry((addr, ep_num)).or_insert((as_channels, as_bits, as_subframe, sr));
                    }
                }
            };
        }

        while i < data.len() {
            let blen = data[i] as usize;
            if blen < 2 || i + blen > data.len() { break; }
            let btype = data[i + 1];
            let d     = &data[i..i + blen];

            match btype {
                // Standard Interface Descriptor
                0x04 if blen >= 9 => {
                    flush_as!();
                    cur_if_num      = d[2];
                    cur_alt         = d[3];
                    cur_if_class    = d[5];
                    cur_if_subclass = d[6];
                    in_as_iface     = cur_if_class == CLASS_AUDIO
                                   && cur_if_subclass == SUBCLASS_AUDIOSTREAMING;
                    if in_as_iface {
                        as_link = 0; as_format_tag = 0; as_channels = 0;
                        as_subframe = 0; as_bits = 0;
                        as_rates.clear(); as_ep_addr = 0;
                    }
                }

                // Class-Specific Interface Descriptor
                CS_INTERFACE if blen >= 3 && cur_if_class == CLASS_AUDIO => {
                    let sub = d[2];
                    match cur_if_subclass {
                        SUBCLASS_AUDIOCONTROL => match sub {
                            AC_INPUT_TERMINAL if blen >= 12 => {
                                let id    = d[3];
                                let wtype = u16::from_le_bytes([d[4], d[5]]);
                                let nch   = d[7];
                                if !dev.input_terminals.iter().any(|t| t.id == id) {
                                    dev.input_terminals.push(InputTerminal {
                                        id, terminal_type: wtype, nr_channels: nch,
                                    });
                                }
                            }
                            AC_OUTPUT_TERMINAL if blen >= 9 => {
                                let id    = d[3];
                                let wtype = u16::from_le_bytes([d[4], d[5]]);
                                let src   = d[7];
                                if !dev.output_terminals.iter().any(|t| t.id == id) {
                                    dev.output_terminals.push(OutputTerminal {
                                        id, terminal_type: wtype, source_id: src,
                                    });
                                }
                            }
                            AC_FEATURE_UNIT if blen >= 6 => {
                                let id       = d[3];
                                let src      = d[4];
                                let ctrl_sz  = d[5] as usize;
                                let master   = if blen >= 6 + ctrl_sz {
                                    d[6..6 + ctrl_sz].to_vec()
                                } else {
                                    vec![]
                                };
                                if !dev.feature_units.iter().any(|u| u.id == id) {
                                    dev.feature_units.push(FeatureUnit {
                                        id, source_id: src, master_controls: master,
                                    });
                                }
                            }
                            AC_MIXER_UNIT if blen >= 5 => {
                                let id     = d[3];
                                let nr_in  = d[4] as usize;
                                let srcs   = d.get(5..5 + nr_in).unwrap_or(&[]).to_vec();
                                let nr_out = d.get(5 + nr_in).copied().unwrap_or(0);
                                if !dev.mixer_units.iter().any(|u| u.id == id) {
                                    dev.mixer_units.push(MixerUnit {
                                        id, source_ids: srcs, nr_out_channels: nr_out,
                                    });
                                }
                            }
                            AC_SELECTOR_UNIT if blen >= 5 => {
                                let id    = d[3];
                                let nr_in = d[4] as usize;
                                let srcs  = d.get(5..5 + nr_in).unwrap_or(&[]).to_vec();
                                if !dev.selector_units.iter().any(|u| u.id == id) {
                                    dev.selector_units.push(SelectorUnit {
                                        id, source_ids: srcs,
                                    });
                                }
                            }
                            _ => {}
                        },
                        SUBCLASS_AUDIOSTREAMING => match sub {
                            AS_GENERAL if blen >= 7 => {
                                as_link       = d[3];
                                as_format_tag = u16::from_le_bytes([d[5], d[6]]);
                            }
                            AS_FORMAT_TYPE if blen >= 8 && d[3] == 1 => {
                                // TYPE_I
                                as_channels = d[4];
                                as_subframe = d[5];
                                as_bits     = d[6];
                                let n_sr    = d[7] as usize;
                                as_rates.clear();
                                if n_sr == 0 {
                                    // Continuous: store lower bound
                                    if blen >= 14 {
                                        as_rates.push(u32::from_le_bytes([d[8], d[9], d[10], 0]));
                                    }
                                } else {
                                    for k in 0..n_sr {
                                        let o = 8 + k * 3;
                                        if o + 3 <= blen {
                                            as_rates.push(u32::from_le_bytes(
                                                [d[o], d[o+1], d[o+2], 0]));
                                        }
                                    }
                                }
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }

                // Standard Endpoint Descriptor inside an AudioStreaming alt setting
                0x05 if blen >= 7 && in_as_iface && cur_alt > 0 => {
                    as_ep_addr = d[2];
                }

                _ => {}
            }

            i += blen;
        }

        flush_as!();
    }

    // ── Audio data handler ───────────────────────────────────────────────────

    fn handle_audio_data(&mut self, txn: &TransactionInfo) {
        let addr = txn.label.split("dev=").nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(0);
        let ep_num = txn.label.split("ep=").nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(0);

        let (channels, bit_depth, subframe_size, sample_rate) = match self.audio_eps.get(&(addr, ep_num)) {
            Some(&v) => v,
            None => return,
        };

        let payload: Vec<u8> = txn.packets.iter()
            .filter(|p| p.packet_type == PacketType::Data && !p.raw_bytes.is_empty())
            .flat_map(|p| p.raw_bytes.iter().copied())
            .collect();
        if payload.is_empty() { return; }

        // Determine the direction bit from the device's streaming descriptor.
        let ep_with_dir = self.devices.values()
            .flat_map(|dev| dev.streams.iter())
            .find(|s| s.ep_addr & 0x0F == ep_num)
            .map(|s| s.ep_addr)
            .unwrap_or(ep_num);

        let is_new = !self.streams.contains_key(&(addr, ep_num));
        let stream = self.streams.entry((addr, ep_num)).or_insert_with(|| {
            CapturedStream::new(addr, ep_with_dir, channels, bit_depth, subframe_size, sample_rate)
        });
        stream.push_bytes(&payload);

        if is_new {
            let lbl = stream.label();
            self.events.push(AudioEvent::StreamStarted { label: lbl });
        }
    }

    // ── Topology text builder ────────────────────────────────────────────────

    fn build_topology_lines(&self) -> Vec<PluginLine> {
        let mut lines = Vec::new();

        for dev in self.devices.values() {
            if !dev.has_topology() && dev.streams.is_empty() { continue; }
            lines.push(PluginLine::separator());
            lines.push(PluginLine::header(format!(
                "  USB Audio Device  (dev {:03})", dev.address)));

            // Input Terminals
            if !dev.input_terminals.is_empty() {
                lines.push(PluginLine::colored(
                    "  ── Input Terminals ─────────────────", Color::Yellow));
                for it in &dev.input_terminals {
                    lines.push(PluginLine::colored(
                        format!("    [IT{:02}]  {}  ({} ch)",
                            it.id, terminal_type_name(it.terminal_type), it.nr_channels),
                        Color::White));
                }
            }

            // Output Terminals
            if !dev.output_terminals.is_empty() {
                lines.push(PluginLine::colored(
                    "  ── Output Terminals ────────────────", Color::Yellow));
                for ot in &dev.output_terminals {
                    lines.push(PluginLine::colored(
                        format!("    [OT{:02}]  {}  ← src[{:02}]",
                            ot.id, terminal_type_name(ot.terminal_type), ot.source_id),
                        Color::White));
                }
            }

            // Feature Units
            if !dev.feature_units.is_empty() {
                lines.push(PluginLine::colored(
                    "  ── Feature Units ───────────────────", Color::Yellow));
                for fu in &dev.feature_units {
                    lines.push(PluginLine::colored(
                        format!("    [FU{:02}]  src[{:02}]  controls: {}",
                            fu.id, fu.source_id,
                            feature_controls_str(&fu.master_controls)),
                        Color::White));
                }
            }

            // Mixer Units
            if !dev.mixer_units.is_empty() {
                lines.push(PluginLine::colored(
                    "  ── Mixer Units ─────────────────────", Color::Yellow));
                for mu in &dev.mixer_units {
                    let srcs: Vec<String> = mu.source_ids.iter()
                        .map(|s| format!("[{:02}]", s)).collect();
                    lines.push(PluginLine::colored(
                        format!("    [MU{:02}]  {} → {} ch",
                            mu.id, srcs.join(" + "), mu.nr_out_channels),
                        Color::White));
                }
            }

            // Selector Units
            if !dev.selector_units.is_empty() {
                lines.push(PluginLine::colored(
                    "  ── Selector Units ──────────────────", Color::Yellow));
                for su in &dev.selector_units {
                    let srcs: Vec<String> = su.source_ids.iter()
                        .map(|s| format!("[{:02}]", s)).collect();
                    lines.push(PluginLine::colored(
                        format!("    [SU{:02}]  select from {}",
                            su.id, srcs.join(", ")),
                        Color::White));
                }
            }

            // Audio Streams
            if !dev.streams.is_empty() {
                lines.push(PluginLine::colored(
                    "  ── Audio Streams ───────────────────", Color::Yellow));
                for s in &dev.streams {
                    let dir = if s.ep_addr & 0x80 != 0 { "IN " } else { "OUT" };
                    lines.push(PluginLine::colored(
                        format!("    [IF{:02}]  EP 0x{:02X} {}  {}",
                            s.interface_num, s.ep_addr, dir, s.format_desc()),
                        Color::Cyan));
                }
            }
        }

        if lines.is_empty() {
            lines.push(PluginLine::plain(""));
            lines.push(PluginLine::colored(
                "  No audio topology detected yet.", Color::DarkGray));
            lines.push(PluginLine::colored(
                "  Waiting for GET_DESCRIPTOR(CONFIGURATION) response…", Color::DarkGray));
        }

        lines
    }

    fn render_events_list(&self, f: &mut Frame<'_>, area: Rect) {
        if area.height < 3 { return; }

        let hint_h   = 1u16;
        let list_h   = area.height.saturating_sub(2 + hint_h); // 1 header + 1 separator
        let header_h = 2u16;

        let [header_area, list_area, hint_area] = Layout::vertical([
            Constraint::Length(header_h),
            Constraint::Length(list_h),
            Constraint::Length(hint_h),
        ]).areas(area);

        // Header
        f.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    "  Media Control Events",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    "─".repeat(80),
                    Style::default().fg(Color::DarkGray),
                )),
            ]),
            header_area,
        );

        // Events list
        let n = self.media_events.len();
        if n == 0 {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "  No media control events captured yet.",
                    Style::default().fg(Color::DarkGray),
                ))),
                list_area,
            );
        } else {
            // Auto-clamp scroll so selected row stays visible
            let visible_rows = list_h as usize;
            let scroll = {
                let mut s = self.events_scroll;
                if self.events_selected < s {
                    s = self.events_selected;
                }
                if self.events_selected >= s + visible_rows {
                    s = self.events_selected + 1 - visible_rows;
                }
                s
            };

            let first_ts = self.first_ts_ns.unwrap_or(0);
            let lines: Vec<Line> = self.media_events.iter()
                .enumerate()
                .skip(scroll)
                .take(visible_rows)
                .map(|(i, ev)| {
                    let rel_secs = (ev.timestamp_ns.saturating_sub(first_ts)) as f64 / 1_000_000_000.0;
                    let ts_str   = format!("+{:.3}s", rel_secs);
                    let text     = format!("  {:>9}  {}", ts_str, ev.label);
                    if i == self.events_selected {
                        Line::from(Span::styled(
                            text,
                            Style::default()
                                .fg(Color::Black)
                                .bg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        ))
                    } else {
                        Line::from(Span::styled(text, Style::default().fg(Color::White)))
                    }
                })
                .collect();

            f.render_widget(Paragraph::new(lines), list_area);
        }

        // Hint line
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" e", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled("=topology  ", Style::default().fg(Color::DarkGray)),
                Span::styled("j/k", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled("=navigate  ", Style::default().fg(Color::DarkGray)),
                Span::styled("Enter", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled("=goto transaction", Style::default().fg(Color::DarkGray)),
            ])),
            hint_area,
        );
    }
}

// ── UsbPlugin impl ────────────────────────────────────────────────────────────

impl UsbPlugin for AudioPlugin {
    fn name(&self)        -> &str { "USB Audio" }
    fn description(&self) -> &str { "Decodes UAC topology, stream format, and PCM audio data" }

    fn on_transaction(&mut self, txn: &TransactionInfo, devices: &[UsbDeviceInfo]) {
        if self.first_ts_ns.is_none() {
            self.first_ts_ns = Some(txn.timestamp_ns);
        }
        self.refresh_from_devices(devices);
        match txn.kind {
            TransactionKind::Control => self.handle_control(txn),
            TransactionKind::Isochronous
            | TransactionKind::BulkIn
            | TransactionKind::Interrupt => self.handle_audio_data(txn),
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.signal_stop();
        self.events.clear();
        self.devices.clear();
        self.streams.clear();
        self.announced.clear();
        self.audio_eps.clear();
        self.selected_idx = 0;
        self.media_events.clear();
        self.first_ts_ns     = None;
        self.events_view     = false;
        self.events_selected = 0;
        self.events_scroll   = 0;
        self.pending_nav     = None;
        #[cfg(feature = "audio-playback")]
        { self.playback_thread = None; self.stop_flag = None; self.playback_pos = None; self.paused_frame = None; }
    }

    fn is_active(&self) -> bool { !self.events.is_empty() }

    // render_lines is the fallback used when the area is too small for
    // render_custom (shouldn't normally happen).
    fn render_lines(&self) -> Vec<PluginLine> {
        let mut lines = Vec::new();
        lines.push(PluginLine::header("  USB Audio Class Monitor"));
        lines.push(PluginLine::colored(
            "  Decodes UAC 1.0 topology, streaming format, and captured PCM audio",
            Color::DarkGray));
        lines.push(PluginLine::separator());
        if self.events.is_empty() {
            lines.push(PluginLine::plain(""));
            lines.push(PluginLine::colored(
                "  No USB audio activity detected.", Color::DarkGray));
            lines.push(PluginLine::colored(
                "  Connect a USB audio device (class 0x01) and capture.", Color::DarkGray));
            return lines;
        }
        lines.extend(self.build_topology_lines());
        lines
    }

    // ── Custom render: topology top + waveform bottom ──────────────────────
    fn render_custom(&self, f: &mut Frame<'_>, area: Rect, scroll: usize) -> bool {
        let keys      = self.sorted_keys();
        let n_streams = keys.len();
        let sel       = if n_streams > 0 { self.selected_idx.min(n_streams - 1) } else { 0 };

        // Decide how to split the area.
        let wave_h: u16 = if n_streams > 0 && area.height >= 14 {
            (area.height / 3).clamp(8, 14)
        } else {
            0
        };
        let top_h = area.height.saturating_sub(wave_h);

        let areas = if wave_h > 0 {
            Layout::vertical([
                Constraint::Length(top_h),
                Constraint::Length(wave_h),
            ]).split(area)
        } else {
            Layout::vertical([Constraint::Min(0)]).split(area)
        };

        let top_area  = areas[0];
        let wave_area = if wave_h > 0 { areas[1] } else { Rect::default() };

        if self.events_view {
            // ── Media Events list ──────────────────────────────────────────
            self.render_events_list(f, top_area);
        } else {
            // ── Topology / header section ──────────────────────────────────
            let mut header = Vec::new();
            header.push(Line::from(Span::styled(
                "  USB Audio Class Monitor",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )));
            header.push(Line::from(Span::styled(
                "  Decodes UAC 1.0 topology, streaming format, and captured PCM audio",
                Style::default().fg(Color::DarkGray),
            )));
            header.push(Line::from(Span::styled(
                "─".repeat(80),
                Style::default().fg(Color::DarkGray),
            )));

            let topo_text: Vec<Line> = self.build_topology_lines()
                .into_iter()
                .map(|l| l.into_ratatui_line())
                .collect();

            let all_lines: Vec<Line> = header.into_iter().chain(topo_text).collect();
            let max_scroll = all_lines.len().saturating_sub(top_h as usize);
            let skip       = scroll.min(max_scroll);

            let visible: Vec<Line> = all_lines.into_iter().skip(skip).take(top_h as usize).collect();
            f.render_widget(Paragraph::new(visible), top_area);
        }

        // ── Waveform section ───────────────────────────────────────────────
        if wave_h > 0 && n_streams > 0 {
            if let Some(stream) = self.streams.get(&keys[sel]) {
                let pb_frame = self.current_playback_frame();
                render_waveform(f, wave_area, stream, self.is_playing(), pb_frame, sel, n_streams);
            }
        }

        true
    }

    fn help_keys(&self) -> Vec<(&'static str, &'static str)> {
        if self.events_view {
            vec![
                ("e",            "Back to topology view"),
                ("j / k",        "Select next / previous event"),
                ("Enter",        "Jump to event in Traffic view"),
            ]
        } else {
            vec![
                ("Space",        "Play / pause captured audio"),
                ("← / →",        "Seek backward / forward 5 seconds"),
                ("[",            "Select previous stream"),
                ("]",            "Select next stream"),
                ("w",            "Save stream to .wav file"),
                ("e",            "Show media control events"),
            ]
        }
    }

    fn captures_navigation(&self) -> bool {
        self.events_view
    }

    fn take_nav_request(&mut self) -> Option<PluginNavRequest> {
        self.pending_nav.take()
    }

    fn on_key(&mut self, key: char) {
        match key {
            ' ' => {
                #[cfg(feature = "audio-playback")]
                {
                    if self.is_playing() {
                        // Playing → Pause: save position and signal thread to stop.
                        let saved = self.playback_pos
                            .as_ref()
                            .map(|p| p.load(Ordering::Relaxed))
                            .unwrap_or(0);
                        self.signal_stop();
                        self.paused_frame = Some(saved);
                    } else {
                        // Paused or stopped → resume/start from saved position (or 0).
                        let start = self.paused_frame.unwrap_or(0);
                        let keys = self.sorted_keys();
                        if keys.is_empty() { return; }
                        let sel = self.selected_idx.min(keys.len() - 1);
                        if let Some(stream) = self.streams.get(&keys[sel]) {
                            let samples     = stream.samples.clone();
                            let channels    = stream.channels;
                            let sample_rate = stream.sample_rate;
                            if !samples.is_empty() {
                                self.start_playback_from(samples, channels, sample_rate, start);
                            }
                        }
                    }
                }
            }
            '[' => {
                if self.selected_idx > 0 { self.selected_idx -= 1; }
            }
            ']' => {
                let n = self.streams.len();
                if n > 0 { self.selected_idx = (self.selected_idx + 1).min(n - 1); }
            }
            'w' => {
                let keys = self.sorted_keys();
                if !keys.is_empty() {
                    let sel = self.selected_idx.min(keys.len() - 1);
                    if let Some(stream) = self.streams.get(&keys[sel]) {
                        let path = format!("audio_stream_{}_{}.wav", stream.dev_addr, stream.ep_addr);
                        match write_wav(&stream.samples, stream.channels, stream.sample_rate, &path) {
                            Ok(()) => dbg_log!("write_wav: saved {}", path),
                            Err(e) => dbg_log!("write_wav: error: {e}"),
                        }
                    }
                }
            }
            'e' => {
                self.events_view = !self.events_view;
                self.events_selected = self.events_selected.min(
                    self.media_events.len().saturating_sub(1)
                );
            }
            // Events list navigation (only meaningful when events_view is active,
            // but harmless otherwise since app only routes j/k/Enter here when
            // captures_navigation() returns true).
            'j' => {
                let n = self.media_events.len();
                if n > 0 { self.events_selected = (self.events_selected + 1).min(n - 1); }
            }
            'k' => {
                if self.events_selected > 0 { self.events_selected -= 1; }
            }
            '\r' => {
                // Enter: request navigation to the selected event's transaction.
                if let Some(ev) = self.media_events.get(self.events_selected) {
                    self.pending_nav = Some(PluginNavRequest::GotoTimestamp(ev.timestamp_ns));
                }
            }
            _ => {}
        }
    }

    fn on_key_code(&mut self, key: crossterm::event::KeyCode) {
        #[cfg(feature = "audio-playback")]
        {
            use crossterm::event::KeyCode;
            let seek_delta: i64 = match key {
                KeyCode::Left  => -5,
                KeyCode::Right =>  5,
                _ => return,
            };

            let keys = self.sorted_keys();
            if keys.is_empty() { return; }
            let sel = self.selected_idx.min(keys.len() - 1);
            let (total_frames, channels, sample_rate) = if let Some(s) = self.streams.get(&keys[sel]) {
                (s.samples.len() / s.channels.max(1) as usize, s.channels, s.sample_rate)
            } else { return; };

            let seek_frames = (seek_delta * sample_rate as i64).unsigned_abs() as usize;
            let current = if self.is_playing() {
                self.playback_pos.as_ref().map(|p| p.load(Ordering::Relaxed)).unwrap_or(0)
            } else {
                self.paused_frame.unwrap_or(0)
            };

            let new_frame = if seek_delta < 0 {
                current.saturating_sub(seek_frames)
            } else {
                (current + seek_frames).min(total_frames.saturating_sub(1))
            };

            if self.is_playing() {
                // Restart playback from the new position.
                let samples = self.streams.get(&keys[sel]).map(|s| s.samples.clone()).unwrap_or_default();
                self.start_playback_from(samples, channels, sample_rate, new_frame);
            } else {
                // Just update the cursor position.
                self.paused_frame = if new_frame == 0 && self.paused_frame.is_none() {
                    None
                } else {
                    Some(new_frame)
                };
            }
            let _ = (total_frames, channels);
        }
        #[cfg(not(feature = "audio-playback"))]
        let _ = key;
    }
}

// ── Waveform renderer ─────────────────────────────────────────────────────────

fn render_waveform(
    f:             &mut Frame<'_>,
    area:          Rect,
    stream:        &CapturedStream,
    playing:       bool,
    playback_frame: Option<usize>,
    sel_idx:       usize,
    n_streams:     usize,
) {
    let total_frames = (stream.samples.len() / stream.channels.max(1) as usize).max(1);

    // Build title with playback position when playing or paused.
    let pos_tag = if let Some(frame) = playback_frame {
        let elapsed = frame as f32 / stream.sample_rate as f32;
        let icon = if playing { "▶" } else { "⏸" };
        format!("  {} {:.1}s / {:.1}s", icon, elapsed, stream.duration_secs())
    } else {
        format!("  {:.1}s captured", stream.duration_secs())
    };
    let title = format!(" EP 0x{:02X}{} ", stream.ep_addr, pos_tag);

    let paused = !playing && playback_frame.is_some();
    let border_color = if playing { Color::Green } else if paused { Color::Yellow } else { Color::DarkGray };
    let block = Block::default()
        .title(title)
        .title_style(Style::default().fg(if playing { Color::Green } else if paused { Color::Yellow } else { Color::Cyan }))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 3 { return; }

    // Reserve one line at the bottom for controls / stream info.
    let [wav_area, info_area] = {
        let s = Layout::vertical([
            Constraint::Min(2),
            Constraint::Length(1),
        ]).split(inner);
        [s[0], s[1]]
    };

    // One display column per terminal column: using the `HalfBlock` marker
    // (solid ▀/▄/█ glyphs, 1x2 "pixels" per cell) instead of `Braille`. Dense
    // Braille fills are prone to a periodic horizontal seam in terminals
    // whose font/line-height doesn't tile the dot glyphs with zero gap
    // between rows — every row of the waveform (every 4 braille dots) shows
    // a faint gap, which is exactly what a solid full-width waveform doesn't
    // want. Half-block glyphs are simple filled rectangles that every
    // monospace font renders identically with no such seam.
    let n_pts = (wav_area.width as usize).max(4);
    let w     = n_pts as f64;

    // Cursor x in display coordinates (0..w), if playing.
    let cursor_x: Option<f64> = playback_frame.map(|frame| {
        (frame as f64 / total_frames as f64 * w).clamp(0.0, w)
    });

    let is_stereo = stream.channels >= 2;
    // Auto-scale to the loudest sample actually captured instead of the
    // fixed i16 range, so quiet audio still fills the display height.
    let norm = peak_amplitude(stream);

    if is_stereo {
        let [left_area, right_area] = {
            let s = Layout::vertical([
                Constraint::Percentage(50),
                Constraint::Percentage(50),
            ]).split(wav_area);
            [s[0], s[1]]
        };

        let env_l = channel_envelope(stream, 0, n_pts, norm);
        let env_r = channel_envelope(stream, 1, n_pts, norm);

        f.render_widget(
            Canvas::default()
                .marker(ratatui::symbols::Marker::HalfBlock)
                .x_bounds([0.0, w])
                .y_bounds([-1.0, 1.0])
                .paint(move |ctx| {
                    draw_envelope(ctx, &env_l, Color::LightGreen);
                    if let Some(cx) = cursor_x {
                        ctx.draw(&CanvasLine { x1: cx, y1: -1.0, x2: cx, y2: 1.0, color: Color::White });
                    }
                }),
            left_area,
        );
        f.render_widget(
            Canvas::default()
                .marker(ratatui::symbols::Marker::HalfBlock)
                .x_bounds([0.0, w])
                .y_bounds([-1.0, 1.0])
                .paint(move |ctx| {
                    draw_envelope(ctx, &env_r, Color::LightBlue);
                    if let Some(cx) = cursor_x {
                        ctx.draw(&CanvasLine { x1: cx, y1: -1.0, x2: cx, y2: 1.0, color: Color::White });
                    }
                }),
            right_area,
        );
    } else {
        let env = channel_envelope(stream, 0, n_pts, norm);
        f.render_widget(
            Canvas::default()
                .marker(ratatui::symbols::Marker::HalfBlock)
                .x_bounds([0.0, w])
                .y_bounds([-1.0, 1.0])
                .paint(move |ctx| {
                    draw_envelope(ctx, &env, Color::LightGreen);
                    if let Some(cx) = cursor_x {
                        ctx.draw(&CanvasLine { x1: cx, y1: -1.0, x2: cx, y2: 1.0, color: Color::White });
                    }
                }),
            wav_area,
        );
    }

    // Info / controls line.
    let stream_nav = if n_streams > 1 {
        format!("  [ / ]: stream {}/{}", sel_idx + 1, n_streams)
    } else {
        String::new()
    };
    let info = format!(
        "  SPACE: {}  │  {} Hz  {}-bit  {}{}",
        if playing { "stop" } else { "play" },
        stream.sample_rate,
        stream.bit_depth,
        if is_stereo { "Stereo" } else { "Mono" },
        stream_nav,
    );
    f.render_widget(
        Paragraph::new(info).style(Style::default().fg(Color::DarkGray)),
        info_area,
    );
}

/// Draw a `(x, min_y, max_y)` envelope as a filled-looking waveform: a
/// vertical bar per column, extended ("dilated") to cover the tallest
/// high/lowest low of its immediate neighbours as well as its own.
///
/// A bar drawn only over each column's own (min, max) leaves no way to
/// connect to a neighbour whose range doesn't overlap — columns are only
/// one dot apart, so a Bresenham line "connecting" two such bars is nearly
/// vertical over a 1-pixel run, and steep Bresenham lines alternate which
/// of the two endpoints' x gets each y row. That painted only about half
/// the rows needed to extend the shorter column's bar up to the taller
/// one, producing a periodic dashed/perforated edge instead of a solid
/// fill wherever the amplitude changes column to column (i.e. almost
/// continuously, in real audio). Dilating each column's own bar to match
/// its neighbours guarantees adjacent bars overlap and the fill is solid,
/// with no separate connecting lines needed at all.
fn draw_envelope(ctx: &mut CanvasContext, envelope: &[(f64, f64, f64)], color: Color) {
    let n = envelope.len();
    for i in 0..n {
        let (x, mut lo, mut hi) = envelope[i];
        if i > 0 {
            lo = lo.min(envelope[i - 1].1);
            hi = hi.max(envelope[i - 1].2);
        }
        if i + 1 < n {
            lo = lo.min(envelope[i + 1].1);
            hi = hi.max(envelope[i + 1].2);
        }
        ctx.draw(&CanvasLine { x1: x, y1: lo, x2: x, y2: hi, color });
    }
}

/// Build a per-column min/max envelope covering the *entire* capture,
/// downsampled to `n` display columns — the standard technique waveform
/// editors use (Audacity, DAWs, etc.) so the true shape of the waveform is
/// visible even when a column spans thousands of samples: each column's
/// vertical line spans the full amplitude range that occurred within it,
/// rather than a single peak sample, which is what turned the display into
/// a scatter of disconnected dots instead of a recognisable waveform.
fn channel_envelope(stream: &CapturedStream, ch: usize, n: usize, norm: f64) -> Vec<(f64, f64, f64)> {
    let stride = stream.channels as usize;
    if stride == 0 || n == 0 { return vec![]; }
    let ch = ch.min(stride - 1);
    let total_frames = stream.samples.len() / stride;
    if total_frames == 0 { return vec![]; }

    if total_frames <= n {
        // Enough room to plot every frame directly — one column, one sample.
        (0..total_frames)
            .map(|f| {
                let x = f as f64 * n as f64 / total_frames as f64;
                let y = stream.samples[f * stride + ch] as f64 / norm;
                (x, y, y)
            })
            .collect()
    } else {
        // Downsample: each column spans the min..max of every frame in its bin.
        (0..n)
            .map(|col| {
                let start = col * total_frames / n;
                let end   = ((col + 1) * total_frames / n).min(total_frames);
                let (mut lo, mut hi) = (0i16, 0i16);
                for f in start..end {
                    let s = stream.samples[f * stride + ch];
                    if s < lo { lo = s; }
                    if s > hi { hi = s; }
                }
                (col as f64, lo as f64 / norm, hi as f64 / norm)
            })
            .collect()
    }
}

/// Normalisation factor for the waveform display: the 99.5th percentile of
/// `|sample|` across the whole (all-channel) capture, with a bit of headroom
/// added on top, and a floor so a silent/near-silent stream doesn't get
/// divided by ~0 and blown up into full-scale-looking noise.
///
/// This used to be the *maximum* sample, to auto-scale the waveform to fill
/// the available height regardless of how quiet the source audio is (fixed
/// i16-range normalisation compressed everything into a thin line hugging
/// the centre). But real audio has a high crest factor — brief transients
/// (drum hits, clicks) many times louder than the sustained level around
/// them — so normalising to the single loudest sample in the whole capture
/// made every quieter, perfectly normal-level passage collapse to a barely
/// visible line, with only the rare transient reaching full height: visually
/// almost the same "empty" look as the original bug, just with occasional
/// spikes instead of none. A high percentile ignores that top sliver of
/// outliers, so the display scales to what the audio is *usually* doing.
/// A too-low percentile overcorrects the other way though — most of the
/// waveform then routinely exceeds the display's own scale and clips flat
/// against the top/bottom edge, looking distorted/"too loud" — so this
/// sits close to the true peak (99.5th, not 98th) and adds 15% headroom on
/// top so ordinary peaks don't ride the very edge of the display.
fn peak_amplitude(stream: &CapturedStream) -> f64 {
    const FLOOR: i16 = 200;
    if stream.samples.is_empty() {
        return FLOOR as f64;
    }
    let mut abs: Vec<u16> = stream.samples.iter().map(|&s| s.unsigned_abs()).collect();
    let idx = ((abs.len() as f64 * 0.995) as usize).min(abs.len() - 1);
    let (_, &mut nth, _) = abs.select_nth_unstable(idx);
    (nth as f64 * 1.15).max(FLOOR as f64)
}

// ── WAV export ────────────────────────────────────────────────────────────────

/// Write raw i16 samples to a minimal PCM WAV file.
/// Returns the path written or an error string.
fn write_wav(samples: &[i16], channels: u8, sample_rate: u32, path: &str) -> Result<(), String> {
    use std::io::Write as _;
    let ch        = channels as u16;
    let sr        = sample_rate;
    let bps: u16  = 16;
    let block_align = ch * (bps / 8);
    let byte_rate   = sr * block_align as u32;
    let data_size   = (samples.len() * 2) as u32;
    let riff_size   = 36 + data_size;

    let mut f = std::fs::File::create(path).map_err(|e| e.to_string())?;

    // RIFF header
    f.write_all(b"RIFF").map_err(|e| e.to_string())?;
    f.write_all(&riff_size.to_le_bytes()).map_err(|e| e.to_string())?;
    f.write_all(b"WAVE").map_err(|e| e.to_string())?;

    // fmt chunk
    f.write_all(b"fmt ").map_err(|e| e.to_string())?;
    f.write_all(&16u32.to_le_bytes()).map_err(|e| e.to_string())?;  // chunk size
    f.write_all(&1u16.to_le_bytes()).map_err(|e| e.to_string())?;   // PCM
    f.write_all(&ch.to_le_bytes()).map_err(|e| e.to_string())?;
    f.write_all(&sr.to_le_bytes()).map_err(|e| e.to_string())?;
    f.write_all(&byte_rate.to_le_bytes()).map_err(|e| e.to_string())?;
    f.write_all(&block_align.to_le_bytes()).map_err(|e| e.to_string())?;
    f.write_all(&bps.to_le_bytes()).map_err(|e| e.to_string())?;

    // data chunk
    f.write_all(b"data").map_err(|e| e.to_string())?;
    f.write_all(&data_size.to_le_bytes()).map_err(|e| e.to_string())?;
    for s in samples {
        f.write_all(&s.to_le_bytes()).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ── Audio playback (background thread) ───────────────────────────────────────

#[cfg(feature = "audio-playback")]
fn play_audio(
    samples:     Vec<i16>,
    channels:    u8,
    sample_rate: u32,
    start_frame: usize,
    stop:        Arc<AtomicBool>,
    pos:         Arc<AtomicUsize>,
) {
    let total_frames = samples.len() / channels.max(1) as usize;
    let start_frame  = start_frame.min(total_frames.saturating_sub(1));
    dbg_log!(
        "play_audio: start — {} samples ({} frames), {} ch, {} Hz, start_frame={}",
        samples.len(), total_frames, channels, sample_rate, start_frame
    );

    let (_stream, handle) = match rodio::OutputStream::try_default() {
        Ok(s) => s,
        Err(e) => {
            dbg_log!("play_audio: OutputStream::try_default failed: {e}");
            return;
        }
    };
    let sink = match rodio::Sink::try_new(&handle) {
        Ok(s) => s,
        Err(e) => {
            dbg_log!("play_audio: Sink::try_new failed: {e}");
            return;
        }
    };

    // Skip to start_frame by slicing the sample slice.
    let skip_samples = start_frame * channels.max(1) as usize;
    let source = rodio::buffer::SamplesBuffer::new(
        channels as u16,
        sample_rate,
        samples[skip_samples..].to_vec(),
    );
    sink.append(source);
    dbg_log!("play_audio: sink started");

    let wall_start = std::time::Instant::now();
    while !sink.empty() && !stop.load(Ordering::Relaxed) {
        let frame = start_frame + (wall_start.elapsed().as_secs_f64() * sample_rate as f64) as usize;
        pos.store(frame.min(total_frames), Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(16));
    }
    sink.stop();
    dbg_log!("play_audio: done (stop_flag={})", stop.load(Ordering::Relaxed));
}
