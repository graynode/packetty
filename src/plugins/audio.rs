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

use super::{PluginLine, UsbPlugin};
use crate::models::{PacketType, TransactionInfo, TransactionKind, UsbDeviceInfo};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, Paragraph,
        canvas::{Canvas, Line as CanvasLine, Points},
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
    sample_rate:    u32,
    /// All captured samples, normalised to i16.
    samples:        Vec<i16>,
    bytes_received: usize,
}

impl CapturedStream {
    fn new(dev_addr: u8, ep_addr: u8, channels: u8, bit_depth: u8, sample_rate: u32) -> Self {
        Self {
            dev_addr,
            ep_addr,
            channels,
            bit_depth,
            sample_rate,
            samples: Vec::new(),
            bytes_received: 0,
        }
    }

    fn push_bytes(&mut self, data: &[u8]) {
        self.bytes_received += data.len();
        let bytes_per_sample = ((self.bit_depth as usize + 7) / 8).max(1);

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
                    // 24-bit signed → shift to 16-bit
                    ((raw << 8) >> 24) as i16
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

// ── Main plugin struct ────────────────────────────────────────────────────────

pub struct AudioPlugin {
    events:        Vec<AudioEvent>,
    devices:       HashMap<u8, AudioDevice>,
    /// Captured PCM audio keyed by (dev_addr, ep_number_without_dir_bit).
    streams:       HashMap<(u8, u8), CapturedStream>,
    announced:     Vec<u8>,
    /// Audio endpoints identified from streaming descriptors:
    ///   (dev_addr, ep_num) → (channels, bit_depth, sample_rate)
    audio_eps:     HashMap<(u8, u8), (u8, u8, u32)>,

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
        }
    }

    fn is_playing(&self) -> bool {
        #[cfg(feature = "audio-playback")]
        return self.playback_thread.as_ref().map(|t| !t.is_finished()).unwrap_or(false);
        #[cfg(not(feature = "audio-playback"))]
        false
    }

    fn stop_playback(&mut self) {
        #[cfg(feature = "audio-playback")]
        {
            if let Some(flag) = &self.stop_flag {
                flag.store(true, Ordering::Relaxed);
            }
            if let Some(pos) = &self.playback_pos {
                pos.store(0, Ordering::Relaxed);
            }
        }
    }

    /// Returns the current playback frame index, or `None` when not playing.
    fn current_playback_frame(&self) -> Option<usize> {
        #[cfg(feature = "audio-playback")]
        if self.is_playing() {
            return self.playback_pos.as_ref().map(|p| p.load(Ordering::Relaxed));
        }
        None
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

        // Only GET_DESCRIPTOR(CONFIGURATION) responses are useful here.
        let bm       = setup[0];
        let req      = setup[1];
        let desc_typ = (u16::from_le_bytes([setup[2], setup[3]]) >> 8) as u8;
        if bm != 0x80 || req != 0x06 || desc_typ != 0x02 { return; }

        let resp: Vec<u8> = data_pkts[1..].iter()
            .flat_map(|d| d.iter().copied())
            .collect();
        if resp.len() < 9 { return; }

        let addr = txn.label.split("dev=").nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(0);

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
                    if !dev.streams.iter().any(|s| s.ep_addr == as_ep_addr) {
                        dev.streams.push(stream);
                        // Register endpoint for data capture.
                        self.audio_eps.insert((addr, ep_num), (as_channels, as_bits, sr));
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

        let (channels, bit_depth, sample_rate) = match self.audio_eps.get(&(addr, ep_num)) {
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
            CapturedStream::new(addr, ep_with_dir, channels, bit_depth, sample_rate)
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
}

// ── UsbPlugin impl ────────────────────────────────────────────────────────────

impl UsbPlugin for AudioPlugin {
    fn name(&self)        -> &str { "USB Audio" }
    fn description(&self) -> &str { "Decodes UAC topology, stream format, and PCM audio data" }

    fn on_transaction(&mut self, txn: &TransactionInfo, devices: &[UsbDeviceInfo]) {
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
        self.stop_playback();
        self.events.clear();
        self.devices.clear();
        self.streams.clear();
        self.announced.clear();
        self.audio_eps.clear();
        self.selected_idx = 0;
        #[cfg(feature = "audio-playback")]
        { self.playback_thread = None; self.stop_flag = None; self.playback_pos = None; }
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
        let keys     = self.sorted_keys();
        let n_streams = keys.len();
        let sel      = if n_streams > 0 { self.selected_idx.min(n_streams - 1) } else { 0 };

        // Decide how to split the area.
        let wave_h: u16 = if n_streams > 0 && area.height >= 14 {
            (area.height / 3).clamp(8, 14)
        } else {
            0
        };
        let topo_h = area.height.saturating_sub(wave_h);

        let areas = if wave_h > 0 {
            Layout::vertical([
                Constraint::Length(topo_h),
                Constraint::Length(wave_h),
            ]).split(area)
        } else {
            Layout::vertical([Constraint::Min(0)]).split(area)
        };

        let topo_area = areas[0];
        let wave_area = if wave_h > 0 { areas[1] } else { Rect::default() };

        // ── Topology / header section ──────────────────────────────────────
        {
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
            let max_scroll = all_lines.len().saturating_sub(topo_h as usize);
            let skip       = scroll.min(max_scroll);

            let visible: Vec<Line> = all_lines.into_iter().skip(skip).take(topo_h as usize).collect();
            f.render_widget(Paragraph::new(visible), topo_area);
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
        vec![
            ("Space",        "Play / stop captured audio"),
            ("[",            "Select previous stream"),
            ("]",            "Select next stream"),
            ("w",            "Save stream to .wav file"),
        ]
    }

    fn on_key(&mut self, key: char) {
        match key {
            ' ' => {
                #[cfg(feature = "audio-playback")]
                {
                    if self.is_playing() {
                        self.stop_playback();
                        if let Some(t) = self.playback_thread.take() {
                            let _ = t;
                        }
                    } else {
                        let keys = self.sorted_keys();
                        if keys.is_empty() { return; }
                        let sel = self.selected_idx.min(keys.len() - 1);
                        if let Some(stream) = self.streams.get(&keys[sel]) {
                            let samples     = stream.samples.clone();
                            let channels    = stream.channels;
                            let sample_rate = stream.sample_rate;
                            if !samples.is_empty() {
                                if let Some(f) = &self.stop_flag {
                                    f.store(true, Ordering::Relaxed);
                                }
                                let flag  = Arc::new(AtomicBool::new(false));
                                let flag2 = flag.clone();
                                let pos   = Arc::new(AtomicUsize::new(0));
                                let pos2  = pos.clone();
                                self.stop_flag       = Some(flag);
                                self.playback_pos    = Some(pos);
                                self.playback_thread = Some(std::thread::spawn(move || {
                                    play_audio(samples, channels, sample_rate, flag2, pos2);
                                }));
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
                            Ok(()) => crate::dbg_log!("write_wav: saved {}", path),
                            Err(e) => crate::dbg_log!("write_wav: error: {e}"),
                        }
                    }
                }
            }
            _ => {}
        }
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

    // Build title with playback position when playing.
    let pos_tag = if let Some(frame) = playback_frame {
        let elapsed = frame as f32 / stream.sample_rate as f32;
        format!("  ▶ {:.1}s / {:.1}s", elapsed, stream.duration_secs())
    } else {
        format!("  {:.1}s captured", stream.duration_secs())
    };
    let title = format!(" EP 0x{:02X}{} ", stream.ep_addr, pos_tag);

    let border_color = if playing { Color::Green } else { Color::DarkGray };
    let block = Block::default()
        .title(title)
        .title_style(Style::default().fg(if playing { Color::Green } else { Color::Cyan }))
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

    // Number of display columns; braille cells are 2 dots wide.
    let n_pts = (wav_area.width as usize * 2).max(4);
    let w     = n_pts as f64;

    // Cursor x in display coordinates (0..w), if playing.
    let cursor_x: Option<f64> = playback_frame.map(|frame| {
        (frame as f64 / total_frames as f64 * w).clamp(0.0, w)
    });

    let is_stereo = stream.channels >= 2;

    if is_stereo {
        let [left_area, right_area] = {
            let s = Layout::vertical([
                Constraint::Percentage(50),
                Constraint::Percentage(50),
            ]).split(wav_area);
            [s[0], s[1]]
        };

        let pts_l = all_channel_points(stream, 0, n_pts);
        let pts_r = all_channel_points(stream, 1, n_pts);

        f.render_widget(
            Canvas::default()
                .x_bounds([0.0, w])
                .y_bounds([-1.0, 1.0])
                .paint(move |ctx| {
                    ctx.draw(&Points { coords: &pts_l, color: Color::LightGreen });
                    if let Some(cx) = cursor_x {
                        ctx.draw(&CanvasLine { x1: cx, y1: -1.0, x2: cx, y2: 1.0, color: Color::White });
                    }
                }),
            left_area,
        );
        f.render_widget(
            Canvas::default()
                .x_bounds([0.0, w])
                .y_bounds([-1.0, 1.0])
                .paint(move |ctx| {
                    ctx.draw(&Points { coords: &pts_r, color: Color::LightBlue });
                    if let Some(cx) = cursor_x {
                        ctx.draw(&CanvasLine { x1: cx, y1: -1.0, x2: cx, y2: 1.0, color: Color::White });
                    }
                }),
            right_area,
        );
    } else {
        let pts = all_channel_points(stream, 0, n_pts);
        f.render_widget(
            Canvas::default()
                .x_bounds([0.0, w])
                .y_bounds([-1.0, 1.0])
                .paint(move |ctx| {
                    ctx.draw(&Points { coords: &pts, color: Color::LightGreen });
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

/// Build (x, y) pairs covering the *entire* capture downsampled to `n` display columns.
/// Each column takes the peak-amplitude sample in its bin so transients stay visible.
fn all_channel_points(stream: &CapturedStream, ch: usize, n: usize) -> Vec<(f64, f64)> {
    let stride = stream.channels as usize;
    if stride == 0 || n == 0 { return vec![]; }
    let ch = ch.min(stride - 1);
    let total_frames = stream.samples.len() / stride;
    if total_frames == 0 { return vec![]; }

    if total_frames <= n {
        // Enough room to plot every frame directly.
        (0..total_frames)
            .map(|f| {
                let x = f as f64 * n as f64 / total_frames as f64;
                let y = stream.samples[f * stride + ch] as f64 / 32768.0;
                (x, y)
            })
            .collect()
    } else {
        // Downsample: pick the peak-amplitude sample per display column.
        (0..n)
            .map(|col| {
                let start = col * total_frames / n;
                let end   = ((col + 1) * total_frames / n).min(total_frames);
                let peak  = (start..end)
                    .map(|f| stream.samples[f * stride + ch])
                    .max_by_key(|s| s.unsigned_abs())
                    .unwrap_or(0);
                (col as f64, peak as f64 / 32768.0)
            })
            .collect()
    }
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
    stop:        Arc<AtomicBool>,
    pos:         Arc<AtomicUsize>,
) {
    let total_frames = samples.len() / channels.max(1) as usize;
    crate::dbg_log!(
        "play_audio: start — {} samples ({} frames), {} ch, {} Hz",
        samples.len(), total_frames, channels, sample_rate
    );

    let (_stream, handle) = match rodio::OutputStream::try_default() {
        Ok(s) => s,
        Err(e) => {
            crate::dbg_log!("play_audio: OutputStream::try_default failed: {e}");
            return;
        }
    };
    let sink = match rodio::Sink::try_new(&handle) {
        Ok(s) => s,
        Err(e) => {
            crate::dbg_log!("play_audio: Sink::try_new failed: {e}");
            return;
        }
    };

    let source = rodio::buffer::SamplesBuffer::new(
        channels as u16,
        sample_rate,
        samples,
    );
    sink.append(source);
    crate::dbg_log!("play_audio: sink started");

    let start = std::time::Instant::now();
    while !sink.empty() && !stop.load(Ordering::Relaxed) {
        let frame = (start.elapsed().as_secs_f64() * sample_rate as f64) as usize;
        pos.store(frame.min(total_frames), Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(16));
    }
    sink.stop();
    pos.store(0, Ordering::Relaxed);
    crate::dbg_log!("play_audio: done (stop_flag={})", stop.load(Ordering::Relaxed));
}
