//! USB HID Keyboard decoder plugin.
//!
//! Detects HID keyboard interfaces (class 0x03, protocol 0x01) and decodes
//! interrupt IN reports into key-press and key-release events.
//!
//! Supports the standard 8-byte boot-protocol keyboard report:
//!   byte 0  – modifier bitmask (LCtrl, LShift, LAlt, LGUI, RCtrl, RShift, RAlt, RGUI)
//!   byte 1  – reserved (0)
//!   bytes 2–7 – up to 6 simultaneous keycodes (USB HID Usage Page 0x07)
//!
//! Also decodes:
//!   - SET_REPORT output reports: keyboard LED state (NumLk, CapsLk, ScrLk)
//!   - SET_PROTOCOL, SET_IDLE control requests

use super::{UsbPlugin, PluginLine};
use crate::models::{PacketType, TransactionInfo, TransactionKind, UsbDeviceInfo};
use ratatui::style::Color;

const CLASS_HID:         u8 = 0x03;
const PROTOCOL_KEYBOARD: u8 = 0x01;

const BMRT_HID_OUT: u8 = 0x21;
const BMRT_HID_IN:  u8 = 0xA1;

const REQ_GET_REPORT:   u8 = 0x01;
const REQ_GET_IDLE:     u8 = 0x02;
const REQ_GET_PROTOCOL: u8 = 0x03;
const REQ_SET_REPORT:   u8 = 0x09;
const REQ_SET_IDLE:     u8 = 0x0A;
const REQ_SET_PROTOCOL: u8 = 0x0B;

// wValue high byte for SET_REPORT: report type
const REPORT_TYPE_OUTPUT: u8 = 0x02;

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum KeyboardEvent {
    DeviceDetected { #[allow(dead_code)] addr: u8, label: String },
    SetProtocol    { addr: u8, boot: bool, timestamp_ns: u64 },
    SetIdle        { addr: u8, duration_4ms: u8, report_id: u8, timestamp_ns: u64 },
    LedState       { addr: u8, num_lock: bool, caps_lock: bool, scroll_lock: bool, timestamp_ns: u64 },
    KeyDown        { addr: u8, modifiers: u8, key: u8, timestamp_ns: u64 },
    KeyUp          { addr: u8, modifiers: u8, key: u8, timestamp_ns: u64 },
    ModChange      { addr: u8, modifiers: u8, timestamp_ns: u64 },
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

pub struct HidKeyboardPlugin {
    events: Vec<KeyboardEvent>,
    hid_eps: Vec<(u8, u8)>,
    hid_devs: Vec<u8>,
    announced: Vec<u8>,
    /// Previous report state for diffing.
    prev_modifiers: u8,
    prev_keys: [u8; 6],
}

impl HidKeyboardPlugin {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            hid_eps: Vec::new(),
            hid_devs: Vec::new(),
            announced: Vec::new(),
            prev_modifiers: 0,
            prev_keys: [0u8; 6],
        }
    }

    fn refresh_from_devices(&mut self, devices: &[UsbDeviceInfo]) {
        self.hid_eps.clear();
        self.hid_devs.clear();
        for dev in devices {
            let mut is_kbd = false;
            for cfg in &dev.configurations {
                for iface in &cfg.interfaces {
                    if iface.class == CLASS_HID && iface.protocol == PROTOCOL_KEYBOARD {
                        is_kbd = true;
                        for ep in &iface.endpoints {
                            if ep.address & 0x80 != 0 && ep.attributes & 0x03 == 3 {
                                let entry = (dev.address, ep.address);
                                if !self.hid_eps.contains(&entry) {
                                    self.hid_eps.push(entry);
                                }
                            }
                        }
                    }
                }
            }
            if is_kbd {
                if !self.hid_devs.contains(&dev.address) {
                    self.hid_devs.push(dev.address);
                }
                if !self.announced.contains(&dev.address) {
                    self.announced.push(dev.address);
                    let name = dev.product.as_deref()
                        .or(dev.manufacturer.as_deref())
                        .unwrap_or("Unknown HID Keyboard");
                    self.events.push(KeyboardEvent::DeviceDetected {
                        addr: dev.address,
                        label: format!(
                            "addr={:03}  {:04X}:{:04X}  \"{}\"",
                            dev.address, dev.vendor_id, dev.product_id, name
                        ),
                    });
                }
            }
        }
    }

    fn is_kbd_ep(&self, dev: u8, ep_with_dir: u8) -> bool {
        self.hid_eps.iter().any(|&(d, e)| d == dev && e == ep_with_dir)
    }

    fn parse_dev(label: &str) -> Option<u8> {
        label.split("dev=").nth(1)?.split_whitespace().next()?.parse().ok()
    }

    fn parse_ep(label: &str) -> Option<u8> {
        label.split("ep=").nth(1)?.split_whitespace().next()?.parse().ok()
    }

    // ── Control request handler ─────────────────────────────────────────────

    fn handle_control(&mut self, txn: &TransactionInfo) {
        let data_pkts: Vec<&[u8]> = txn.packets.iter()
            .filter(|p| p.packet_type == PacketType::Data && !p.raw_bytes.is_empty())
            .map(|p| p.raw_bytes.as_slice())
            .collect();

        let setup = match data_pkts.first() {
            Some(d) if d.len() >= 8 => *d,
            _ => return,
        };

        let bm_req_type = setup[0];
        let b_request   = setup[1];
        let w_value     = u16::from_le_bytes([setup[2], setup[3]]);

        if bm_req_type != BMRT_HID_OUT && bm_req_type != BMRT_HID_IN { return; }

        let addr = Self::parse_dev(&txn.label).unwrap_or(0);
        if !self.hid_devs.contains(&addr) { return; }

        match b_request {
            REQ_SET_PROTOCOL => {
                let boot = (w_value & 0xFF) == 0;
                self.events.push(KeyboardEvent::SetProtocol { addr, boot, timestamp_ns: txn.timestamp_ns });
            }
            REQ_SET_IDLE => {
                let duration_4ms = (w_value >> 8) as u8;
                let report_id    = (w_value & 0xFF) as u8;
                self.events.push(KeyboardEvent::SetIdle {
                    addr, duration_4ms, report_id, timestamp_ns: txn.timestamp_ns,
                });
            }
            REQ_SET_REPORT => {
                let report_type = (w_value >> 8) as u8;
                if report_type == REPORT_TYPE_OUTPUT {
                    // Output report = LED state. Second DATA packet is the 1-byte payload.
                    if let Some(d) = data_pkts.get(1).filter(|d| !d.is_empty()) {
                        let leds = d[0];
                        self.events.push(KeyboardEvent::LedState {
                            addr,
                            num_lock:    leds & 0x01 != 0,
                            caps_lock:   leds & 0x02 != 0,
                            scroll_lock: leds & 0x04 != 0,
                            timestamp_ns: txn.timestamp_ns,
                        });
                    }
                }
            }
            REQ_GET_REPORT | REQ_GET_IDLE | REQ_GET_PROTOCOL => {}
            _ => {}
        }
    }

    // ── Interrupt IN handler ────────────────────────────────────────────────

    fn handle_interrupt_in(&mut self, txn: &TransactionInfo) {
        let addr   = match Self::parse_dev(&txn.label) { Some(a) => a, None => return };
        let ep_num = match Self::parse_ep(&txn.label)  { Some(e) => e, None => return };
        let ep_with_dir = ep_num | 0x80;

        let accept = self.is_kbd_ep(addr, ep_with_dir)
            || (self.hid_eps.is_empty() && self.hid_devs.contains(&addr));
        if !accept { return; }

        // Each DATA packet is one keyboard report.
        for pkt in &txn.packets {
            if pkt.packet_type != PacketType::Data || pkt.raw_bytes.is_empty() { continue; }
            let d = &pkt.raw_bytes;

            // Standard boot keyboard report: exactly 8 bytes.
            //   [modifiers, reserved, key0, key1, key2, key3, key4, key5]
            if d.len() < 3 { continue; }

            let modifiers = d[0];
            let keys: [u8; 6] = {
                let mut k = [0u8; 6];
                let src = if d.len() >= 8 { &d[2..8] } else { &d[2..] };
                let n = src.len().min(6);
                k[..n].copy_from_slice(&src[..n]);
                k
            };

            // Diff against previous state.
            let ts = pkt.timestamp_ns;

            // Modifier changes.
            if modifiers != self.prev_modifiers {
                self.events.push(KeyboardEvent::ModChange { addr, modifiers, timestamp_ns: ts });
            }

            // Key releases: in prev but not in current.
            for &k in &self.prev_keys {
                if k != 0 && !keys.contains(&k) {
                    self.events.push(KeyboardEvent::KeyUp { addr, modifiers, key: k, timestamp_ns: ts });
                }
            }

            // Key presses: in current but not in prev.
            for &k in &keys {
                if k != 0 && !self.prev_keys.contains(&k) {
                    self.events.push(KeyboardEvent::KeyDown { addr, modifiers, key: k, timestamp_ns: ts });
                }
            }

            self.prev_modifiers = modifiers;
            self.prev_keys = keys;
        }
    }
}

// ---------------------------------------------------------------------------
// HID Usage Page 0x07 — Keyboard/Keypad keycode table
// ---------------------------------------------------------------------------

fn keycode_name(code: u8) -> &'static str {
    match code {
        0x00 => "(none)",
        0x01 => "Err/Rollover",
        0x02 => "POSTFail",
        0x03 => "Err/Undef",
        0x04 => "A",  0x05 => "B",  0x06 => "C",  0x07 => "D",
        0x08 => "E",  0x09 => "F",  0x0A => "G",  0x0B => "H",
        0x0C => "I",  0x0D => "J",  0x0E => "K",  0x0F => "L",
        0x10 => "M",  0x11 => "N",  0x12 => "O",  0x13 => "P",
        0x14 => "Q",  0x15 => "R",  0x16 => "S",  0x17 => "T",
        0x18 => "U",  0x19 => "V",  0x1A => "W",  0x1B => "X",
        0x1C => "Y",  0x1D => "Z",
        0x1E => "1",  0x1F => "2",  0x20 => "3",  0x21 => "4",
        0x22 => "5",  0x23 => "6",  0x24 => "7",  0x25 => "8",
        0x26 => "9",  0x27 => "0",
        0x28 => "Enter",    0x29 => "Esc",      0x2A => "Backspace", 0x2B => "Tab",
        0x2C => "Space",    0x2D => "-",        0x2E => "=",         0x2F => "[",
        0x30 => "]",        0x31 => "\\",       0x32 => "#",         0x33 => ";",
        0x34 => "'",        0x35 => "`",        0x36 => ",",         0x37 => ".",
        0x38 => "/",        0x39 => "CapsLock",
        0x3A => "F1",   0x3B => "F2",   0x3C => "F3",   0x3D => "F4",
        0x3E => "F5",   0x3F => "F6",   0x40 => "F7",   0x41 => "F8",
        0x42 => "F9",   0x43 => "F10",  0x44 => "F11",  0x45 => "F12",
        0x46 => "PrintScr", 0x47 => "ScrollLock", 0x48 => "Pause",
        0x49 => "Insert",   0x4A => "Home",       0x4B => "PageUp",
        0x4C => "Delete",   0x4D => "End",        0x4E => "PageDown",
        0x4F => "Right",    0x50 => "Left",       0x51 => "Down",     0x52 => "Up",
        0x53 => "NumLock",
        0x54 => "Num/",   0x55 => "Num*",   0x56 => "Num-",   0x57 => "Num+",
        0x58 => "NumEnter",
        0x59 => "Num1",  0x5A => "Num2",  0x5B => "Num3",  0x5C => "Num4",
        0x5D => "Num5",  0x5E => "Num6",  0x5F => "Num7",  0x60 => "Num8",
        0x61 => "Num9",  0x62 => "Num0",  0x63 => "Num.",
        0x64 => "\\|",  0x65 => "App",   0x66 => "Power", 0x67 => "Num=",
        0x68 => "F13",  0x69 => "F14",   0x6A => "F15",   0x6B => "F16",
        0x6C => "F17",  0x6D => "F18",   0x6E => "F19",   0x6F => "F20",
        0x70 => "F21",  0x71 => "F22",   0x72 => "F23",   0x73 => "F24",
        0x74 => "Execute",  0x75 => "Help",    0x76 => "Menu",    0x77 => "Select",
        0x78 => "Stop",     0x79 => "Again",   0x7A => "Undo",    0x7B => "Cut",
        0x7C => "Copy",     0x7D => "Paste",   0x7E => "Find",    0x7F => "Mute",
        0x80 => "VolUp",    0x81 => "VolDown",
        0xE0 => "LCtrl",    0xE1 => "LShift",  0xE2 => "LAlt",    0xE3 => "LGUI",
        0xE4 => "RCtrl",    0xE5 => "RShift",  0xE6 => "RAlt",    0xE7 => "RGUI",
        _ => "?",
    }
}

fn modifier_names(mods: u8) -> String {
    const NAMES: [&str; 8] = ["LCtrl", "LShift", "LAlt", "LGUI", "RCtrl", "RShift", "RAlt", "RGUI"];
    let parts: Vec<&str> = (0..8).filter(|&i| mods & (1 << i) != 0).map(|i| NAMES[i]).collect();
    if parts.is_empty() { String::new() } else { parts.join("+") }
}

fn fmt_ts(ns: u64) -> String {
    format!("{}.{:09}", ns / 1_000_000_000, ns % 1_000_000_000)
}

// ---------------------------------------------------------------------------
// UsbPlugin impl
// ---------------------------------------------------------------------------

impl UsbPlugin for HidKeyboardPlugin {
    fn name(&self) -> &str { "HID Keyboard" }
    fn description(&self) -> &str { "Decodes USB HID keyboard key-press and key-release events" }

    fn on_transaction(&mut self, txn: &TransactionInfo, devices: &[UsbDeviceInfo]) {
        self.refresh_from_devices(devices);
        match txn.kind {
            TransactionKind::Control => self.handle_control(txn),
            TransactionKind::BulkIn  => self.handle_interrupt_in(txn),
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.events.clear();
        self.hid_eps.clear();
        self.hid_devs.clear();
        self.announced.clear();
        self.prev_modifiers = 0;
        self.prev_keys = [0u8; 6];
    }

    fn is_active(&self) -> bool { !self.events.is_empty() }

    fn render_lines(&self) -> Vec<PluginLine> {
        let mut lines = Vec::new();
        lines.push(PluginLine::header("  HID Keyboard Monitor"));
        lines.push(PluginLine::colored(
            "  Decodes key-press/release events from HID boot-protocol keyboard reports",
            Color::DarkGray,
        ));
        lines.push(PluginLine::separator());

        if self.events.is_empty() {
            lines.push(PluginLine::plain(""));
            lines.push(PluginLine::colored("  No HID keyboard activity detected.", Color::DarkGray));
            lines.push(PluginLine::colored(
                "  Connect a USB keyboard (class 0x03, protocol 0x01) and capture.",
                Color::DarkGray,
            ));
            return lines;
        }

        for event in &self.events {
            match event {
                KeyboardEvent::DeviceDetected { label, .. } => {
                    lines.push(PluginLine::separator());
                    lines.push(PluginLine::colored(format!("  ○ Keyboard: {label}"), Color::Green));
                }
                KeyboardEvent::SetProtocol { addr, boot, timestamp_ns } => {
                    lines.push(PluginLine::colored(
                        format!(
                            "  [{}] dev={addr}  SET_PROTOCOL  {}",
                            fmt_ts(*timestamp_ns),
                            if *boot { "Boot" } else { "Report" },
                        ),
                        Color::Yellow,
                    ));
                }
                KeyboardEvent::SetIdle { addr, duration_4ms, report_id, timestamp_ns } => {
                    let idle_str = if *duration_4ms == 0 {
                        "Indefinite (NAK until change)".to_string()
                    } else {
                        format!("{}ms", *duration_4ms as u16 * 4)
                    };
                    lines.push(PluginLine::colored(
                        format!(
                            "  [{}] dev={addr}  SET_IDLE  report={report_id}  interval={}",
                            fmt_ts(*timestamp_ns), idle_str,
                        ),
                        Color::Yellow,
                    ));
                }
                KeyboardEvent::LedState { addr, num_lock, caps_lock, scroll_lock, timestamp_ns } => {
                    let num  = if *num_lock    { "ON " } else { "off" };
                    let caps = if *caps_lock   { "ON " } else { "off" };
                    let scrl = if *scroll_lock { "ON " } else { "off" };
                    lines.push(PluginLine::colored(
                        format!(
                            "  [{}] dev={addr}  LED  NumLk={}  CapsLk={}  ScrLk={}",
                            fmt_ts(*timestamp_ns), num, caps, scrl,
                        ),
                        Color::Magenta,
                    ));
                }
                KeyboardEvent::ModChange { addr, modifiers, timestamp_ns } => {
                    let names = modifier_names(*modifiers);
                    let display = if names.is_empty() { "(all released)".to_string() } else { names };
                    lines.push(PluginLine::colored(
                        format!("  [{}] dev={addr}  MOD  {display}", fmt_ts(*timestamp_ns)),
                        Color::Blue,
                    ));
                }
                KeyboardEvent::KeyDown { addr, modifiers, key, timestamp_ns } => {
                    let mods = modifier_names(*modifiers);
                    let key_name = keycode_name(*key);
                    let combo = if mods.is_empty() {
                        key_name.to_string()
                    } else {
                        format!("{mods}+{key_name}")
                    };
                    lines.push(PluginLine::colored(
                        format!(
                            "  [{}] dev={addr}  ↓  {combo:<24}  (0x{:02X})",
                            fmt_ts(*timestamp_ns), key,
                        ),
                        Color::Cyan,
                    ));
                }
                KeyboardEvent::KeyUp { addr, modifiers, key, timestamp_ns } => {
                    let mods = modifier_names(*modifiers);
                    let key_name = keycode_name(*key);
                    let combo = if mods.is_empty() {
                        key_name.to_string()
                    } else {
                        format!("{mods}+{key_name}")
                    };
                    lines.push(PluginLine::colored(
                        format!(
                            "  [{}] dev={addr}  ↑  {combo:<24}  (0x{:02X})",
                            fmt_ts(*timestamp_ns), key,
                        ),
                        Color::White,
                    ));
                }
            }
        }
        lines
    }
}
