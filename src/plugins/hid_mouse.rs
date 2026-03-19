//! USB HID Mouse decoder plugin.
//!
//! Detects HID mouse interfaces (class 0x03, protocol 0x02) and decodes
//! interrupt IN reports: button state, relative X/Y movement, and wheel.
//!
//! Supports the standard boot-protocol mouse report (3–4 bytes) as well as
//! common 5-byte reports that include a horizontal wheel byte.
//!
//! HID control requests (SET_PROTOCOL, SET_IDLE) are also decoded.

use super::{UsbPlugin, PluginLine};
use crate::models::{PacketType, TransactionInfo, TransactionKind, UsbDeviceInfo};
use ratatui::style::Color;

const CLASS_HID:      u8 = 0x03;
const PROTOCOL_MOUSE: u8 = 0x02;

// HID class-specific bmRequestType values
const BMRT_HID_OUT: u8 = 0x21; // Class | Interface | Host→Device
const BMRT_HID_IN:  u8 = 0xA1; // Class | Interface | Device→Host

// HID class-specific request codes
const REQ_GET_REPORT:   u8 = 0x01;
const REQ_GET_IDLE:     u8 = 0x02;
const REQ_GET_PROTOCOL: u8 = 0x03;
const REQ_SET_REPORT:   u8 = 0x09;
const REQ_SET_IDLE:     u8 = 0x0A;
const REQ_SET_PROTOCOL: u8 = 0x0B;

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum MouseEvent {
    DeviceDetected { #[allow(dead_code)] addr: u8, label: String },
    SetProtocol    { addr: u8, boot: bool,  timestamp_ns: u64 },
    SetIdle        { addr: u8, duration_4ms: u8, report_id: u8, timestamp_ns: u64 },
    Report         { addr: u8, buttons: u8, dx: i8, dy: i8, wheel: i8, timestamp_ns: u64 },
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

pub struct HidMousePlugin {
    events: Vec<MouseEvent>,
    /// Interrupt IN endpoints that belong to HID mouse interfaces.
    hid_eps: Vec<(u8, u8)>,   // (dev_addr, ep_addr_with_dir_bit)
    hid_devs: Vec<u8>,
    announced: Vec<u8>,
    /// Previous button state — used to show ↑/↓ transitions.
    last_buttons: u8,
}

impl HidMousePlugin {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            hid_eps: Vec::new(),
            hid_devs: Vec::new(),
            announced: Vec::new(),
            last_buttons: 0,
        }
    }

    fn refresh_from_devices(&mut self, devices: &[UsbDeviceInfo]) {
        self.hid_eps.clear();
        self.hid_devs.clear();
        for dev in devices {
            let mut is_mouse = false;
            for cfg in &dev.configurations {
                for iface in &cfg.interfaces {
                    if iface.class == CLASS_HID && iface.protocol == PROTOCOL_MOUSE {
                        is_mouse = true;
                        for ep in &iface.endpoints {
                            // Interrupt IN only (bit 7 = IN, bits 0-1 = transfer type 3 = interrupt).
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
            if is_mouse {
                if !self.hid_devs.contains(&dev.address) {
                    self.hid_devs.push(dev.address);
                }
                if !self.announced.contains(&dev.address) {
                    self.announced.push(dev.address);
                    let name = dev.product.as_deref()
                        .or(dev.manufacturer.as_deref())
                        .unwrap_or("Unknown HID Mouse");
                    self.events.push(MouseEvent::DeviceDetected {
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

    fn is_mouse_ep(&self, dev: u8, ep_with_dir: u8) -> bool {
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
                self.events.push(MouseEvent::SetProtocol { addr, boot, timestamp_ns: txn.timestamp_ns });
            }
            REQ_SET_IDLE => {
                let duration_4ms = (w_value >> 8) as u8;
                let report_id    = (w_value & 0xFF) as u8;
                self.events.push(MouseEvent::SetIdle { addr, duration_4ms, report_id, timestamp_ns: txn.timestamp_ns });
            }
            REQ_GET_REPORT | REQ_GET_IDLE | REQ_GET_PROTOCOL | REQ_SET_REPORT => {}
            _ => {}
        }
    }

    // ── Interrupt IN handler ────────────────────────────────────────────────

    fn handle_interrupt_in(&mut self, txn: &TransactionInfo) {
        let addr   = match Self::parse_dev(&txn.label) { Some(a) => a, None => return };
        let ep_num = match Self::parse_ep(&txn.label)  { Some(e) => e, None => return };
        let ep_with_dir = ep_num | 0x80; // BulkIn → interrupt IN has bit 7 set

        let accept = self.is_mouse_ep(addr, ep_with_dir)
            || (self.hid_eps.is_empty() && self.hid_devs.contains(&addr));
        if !accept { return; }

        // Each DATA packet is one mouse report.
        for pkt in &txn.packets {
            if pkt.packet_type != PacketType::Data || pkt.raw_bytes.is_empty() { continue; }
            let d = &pkt.raw_bytes;

            // Standard boot / common mouse report: ≥3 bytes
            //   byte 0: buttons bitmask
            //   byte 1: X delta (signed)
            //   byte 2: Y delta (signed)
            //   byte 3: wheel  (signed, optional)
            if d.len() < 3 { continue; }

            let buttons = d[0];
            let dx      = d[1] as i8;
            let dy      = d[2] as i8;
            let wheel   = if d.len() >= 4 { d[3] as i8 } else { 0 };

            // Skip pure idle reports (nothing changed, no movement).
            if buttons == self.last_buttons && dx == 0 && dy == 0 && wheel == 0 {
                continue;
            }
            self.last_buttons = buttons;
            self.events.push(MouseEvent::Report {
                addr, buttons, dx, dy, wheel, timestamp_ns: pkt.timestamp_ns,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

fn fmt_ts(ns: u64) -> String {
    format!("{}.{:09}", ns / 1_000_000_000, ns % 1_000_000_000)
}

fn fmt_buttons(b: u8) -> String {
    let l = if b & 0x01 != 0 { 'L' } else { '·' };
    let r = if b & 0x02 != 0 { 'R' } else { '·' };
    let m = if b & 0x04 != 0 { 'M' } else { '·' };
    let extra: String = (3..8)
        .filter(|&i| b & (1 << i) != 0)
        .map(|i| char::from_digit(i, 10).unwrap_or('?'))
        .collect();
    if extra.is_empty() {
        format!("[{l}{r}{m}]")
    } else {
        format!("[{l}{r}{m}{extra}]")
    }
}

fn fmt_delta(v: i8) -> String {
    if v >= 0 { format!("+{v:4}") } else { format!("{v:4}") }  // e.g. "+  5" or "  -3"
}

// ---------------------------------------------------------------------------
// UsbPlugin impl
// ---------------------------------------------------------------------------

impl UsbPlugin for HidMousePlugin {
    fn name(&self) -> &str { "HID Mouse" }
    fn description(&self) -> &str { "Decodes USB HID mouse button, movement, and wheel reports" }

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
        self.last_buttons = 0;
    }

    fn is_active(&self) -> bool { !self.events.is_empty() }

    fn render_lines(&self) -> Vec<PluginLine> {
        let mut lines = Vec::new();
        lines.push(PluginLine::header("  HID Mouse Monitor"));
        lines.push(PluginLine::colored(
            "  Decodes button state, X/Y movement, and wheel from HID interrupt IN reports",
            Color::DarkGray,
        ));
        lines.push(PluginLine::separator());

        if self.events.is_empty() {
            lines.push(PluginLine::plain(""));
            lines.push(PluginLine::colored("  No HID mouse activity detected.", Color::DarkGray));
            lines.push(PluginLine::colored(
                "  Connect a USB mouse (class 0x03, protocol 0x02) and capture.",
                Color::DarkGray,
            ));
            return lines;
        }

        for event in &self.events {
            match event {
                MouseEvent::DeviceDetected { label, .. } => {
                    lines.push(PluginLine::separator());
                    lines.push(PluginLine::colored(format!("  ○ Mouse: {label}"), Color::Green));
                }
                MouseEvent::SetProtocol { addr, boot, timestamp_ns } => {
                    lines.push(PluginLine::colored(
                        format!(
                            "  [{}] dev={addr}  SET_PROTOCOL  {}",
                            fmt_ts(*timestamp_ns),
                            if *boot { "Boot" } else { "Report" },
                        ),
                        Color::Yellow,
                    ));
                }
                MouseEvent::SetIdle { addr, duration_4ms, report_id, timestamp_ns } => {
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
                MouseEvent::Report { addr, buttons, dx, dy, wheel, timestamp_ns } => {
                    lines.push(PluginLine::colored(
                        format!(
                            "  [{}] dev={addr}  {}  dX:{}  dY:{}  W:{}",
                            fmt_ts(*timestamp_ns),
                            fmt_buttons(*buttons),
                            fmt_delta(*dx),
                            fmt_delta(*dy),
                            fmt_delta(*wheel),
                        ),
                        Color::Cyan,
                    ));
                }
            }
        }
        lines
    }
}
