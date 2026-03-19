//! USB CDC (Communications Device Class) decoder plugin.
//!
//! Detects CDC ACM devices on the bus and decodes:
//! - Control requests: SET_LINE_CODING, GET_LINE_CODING, SET_CONTROL_LINE_STATE, SEND_BREAK
//! - Bulk data on CDC data endpoints: shown as TX (host→device) and RX (device→host)
//!
//! # Packet layout in `PacketItem`
//! The backend stores data packet payloads in `PacketItem.raw_bytes` **without** the
//! PID byte and without the CRC bytes.  Token and handshake packets have empty
//! `raw_bytes`.  Use `pkt.packet_type == PacketType::Data` to identify data packets.
//!
//! For a control transfer the first non-empty DATA packet is the 8-byte SETUP header;
//! subsequent non-empty DATA packets carry the data-stage payload.

use super::{UsbPlugin, PluginLine};
use crate::models::{PacketType, TransactionInfo, TransactionKind, UsbDeviceInfo};
use ratatui::style::Color;

// USB CDC class codes
const CLASS_CDC_CTRL: u8 = 0x02; // CDC Control interface
const CLASS_CDC_DATA: u8 = 0x0A; // CDC Data interface

// CDC class-specific request codes (bRequest)
const REQ_SET_LINE_CODING:        u8 = 0x20;
const REQ_GET_LINE_CODING:        u8 = 0x21;
const REQ_SET_CONTROL_LINE_STATE: u8 = 0x22;
const REQ_SEND_BREAK:             u8 = 0x23;

// bmRequestType values for CDC class requests
const BMRT_CLASS_IFACE_OUT: u8 = 0x21; // Class | Interface | Host→Device
const BMRT_CLASS_IFACE_IN:  u8 = 0xA1; // Class | Interface | Device→Host

// ---------------------------------------------------------------------------
// Events recorded by the plugin
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum CdcEvent {
    DeviceDetected { #[allow(dead_code)] addr: u8, label: String },
    LineCoding     { addr: u8, baud: u32, data_bits: u8, parity: u8, stop_bits: u8, timestamp_ns: u64 },
    ControlLineState { addr: u8, dtr: bool, rts: bool, timestamp_ns: u64 },
    SendBreak      { addr: u8, duration_ms: u16, timestamp_ns: u64 },
    TxData         { addr: u8, data: Vec<u8>, timestamp_ns: u64 },
    RxData         { addr: u8, data: Vec<u8>, timestamp_ns: u64 },
}

// ---------------------------------------------------------------------------
// CdcPlugin
// ---------------------------------------------------------------------------

pub struct CdcPlugin {
    events: Vec<CdcEvent>,
    /// CDC data endpoint addresses: (dev_addr, ep_addr_with_dir_bit).
    cdc_data_eps: Vec<(u8, u8)>,
    /// Device addresses that have at least one CDC interface.
    cdc_dev_addrs: Vec<u8>,
    announced: Vec<u8>,
}

impl CdcPlugin {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            cdc_data_eps: Vec::new(),
            cdc_dev_addrs: Vec::new(),
            announced: Vec::new(),
        }
    }

    fn refresh_from_devices(&mut self, devices: &[UsbDeviceInfo]) {
        self.cdc_data_eps.clear();
        self.cdc_dev_addrs.clear();
        for dev in devices {
            let mut is_cdc = false;
            for cfg in &dev.configurations {
                for iface in &cfg.interfaces {
                    if iface.class == CLASS_CDC_CTRL || iface.class == CLASS_CDC_DATA {
                        is_cdc = true;
                    }
                    if iface.class == CLASS_CDC_DATA {
                        for ep in &iface.endpoints {
                            let entry = (dev.address, ep.address);
                            if !self.cdc_data_eps.contains(&entry) {
                                self.cdc_data_eps.push(entry);
                            }
                        }
                    }
                }
            }
            if is_cdc {
                if !self.cdc_dev_addrs.contains(&dev.address) {
                    self.cdc_dev_addrs.push(dev.address);
                }
                if !self.announced.contains(&dev.address) {
                    self.announced.push(dev.address);
                    let name = dev.product.as_deref()
                        .or(dev.manufacturer.as_deref())
                        .unwrap_or("Unknown CDC device");
                    self.events.push(CdcEvent::DeviceDetected {
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

    fn is_cdc_ep(&self, dev: u8, ep_with_dir: u8) -> bool {
        self.cdc_data_eps.iter().any(|&(d, e)| d == dev && e == ep_with_dir)
    }

    fn parse_dev(label: &str) -> Option<u8> {
        label.split("dev=").nth(1)?.split_whitespace().next()?.parse().ok()
    }

    fn parse_ep(label: &str) -> Option<u8> {
        label.split("ep=").nth(1)?.split_whitespace().next()?.parse().ok()
    }

    // ── Control transfer handler ────────────────────────────────────────────
    //
    // Layout of PacketItem.raw_bytes in a control transfer:
    //   - Token packets (SETUP/IN/OUT): raw_bytes = [] (empty)
    //   - First DATA packet: 8-byte SETUP header (bmRequestType .. wLength)
    //   - Subsequent DATA packets: data-stage payload (or ZLP = empty)
    //   - Handshake (ACK/NAK/STALL): raw_bytes = [] (empty)

    fn handle_control(&mut self, txn: &TransactionInfo) {
        // Collect all DATA packets that have payload bytes.
        let data_pkts: Vec<&[u8]> = txn.packets.iter()
            .filter(|p| p.packet_type == PacketType::Data && !p.raw_bytes.is_empty())
            .map(|p| p.raw_bytes.as_slice())
            .collect();

        // First entry is the 8-byte SETUP header.
        let setup = match data_pkts.first() {
            Some(d) if d.len() >= 8 => *d,
            _ => return,
        };

        let bm_req_type = setup[0];
        let b_request   = setup[1];
        let w_value     = u16::from_le_bytes([setup[2], setup[3]]);

        if bm_req_type != BMRT_CLASS_IFACE_OUT && bm_req_type != BMRT_CLASS_IFACE_IN {
            return;
        }

        let addr = Self::parse_dev(&txn.label).unwrap_or(0);

        match b_request {
            REQ_SET_LINE_CODING | REQ_GET_LINE_CODING => {
                // Second DATA packet = data-stage payload (7-byte LineCoding struct).
                if let Some(d) = data_pkts.get(1).filter(|d| d.len() >= 7) {
                    let baud      = u32::from_le_bytes([d[0], d[1], d[2], d[3]]);
                    let stop_bits = d[4];
                    let parity    = d[5];
                    let data_bits = d[6];
                    self.events.push(CdcEvent::LineCoding {
                        addr, baud, data_bits, parity, stop_bits,
                        timestamp_ns: txn.timestamp_ns,
                    });
                }
            }
            REQ_SET_CONTROL_LINE_STATE => {
                let dtr = w_value & 0x0001 != 0;
                let rts = w_value & 0x0002 != 0;
                self.events.push(CdcEvent::ControlLineState {
                    addr, dtr, rts, timestamp_ns: txn.timestamp_ns,
                });
            }
            REQ_SEND_BREAK => {
                self.events.push(CdcEvent::SendBreak {
                    addr, duration_ms: w_value, timestamp_ns: txn.timestamp_ns,
                });
            }
            _ => {}
        }
    }

    // ── Bulk transfer handler ───────────────────────────────────────────────

    fn handle_bulk(&mut self, txn: &TransactionInfo) {
        let addr   = match Self::parse_dev(&txn.label) { Some(a) => a, None => return };
        let ep_num = match Self::parse_ep(&txn.label)  { Some(e) => e, None => return };

        let ep_with_dir = match txn.kind {
            TransactionKind::BulkIn  => ep_num | 0x80,
            TransactionKind::BulkOut => ep_num & 0x7F,
            _ => return,
        };

        let accept = self.is_cdc_ep(addr, ep_with_dir)
            || (self.cdc_data_eps.is_empty() && self.cdc_dev_addrs.contains(&addr));
        if !accept { return; }

        // Collect payload from all DATA packets.
        let payload: Vec<u8> = txn.packets.iter()
            .filter(|p| p.packet_type == PacketType::Data && !p.raw_bytes.is_empty())
            .flat_map(|p| p.raw_bytes.iter().copied())
            .collect();
        if payload.is_empty() { return; }

        match txn.kind {
            TransactionKind::BulkOut => self.events.push(CdcEvent::TxData {
                addr, data: payload, timestamp_ns: txn.timestamp_ns,
            }),
            TransactionKind::BulkIn => self.events.push(CdcEvent::RxData {
                addr, data: payload, timestamp_ns: txn.timestamp_ns,
            }),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn fmt_stop_bits(v: u8) -> &'static str {
    match v { 0 => "1", 1 => "1.5", 2 => "2", _ => "?" }
}

fn fmt_parity(v: u8) -> &'static str {
    match v { 0 => "N", 1 => "O", 2 => "E", 3 => "M", 4 => "S", _ => "?" }
}

fn fmt_ts(ns: u64) -> String {
    format!("{}.{:09}", ns / 1_000_000_000, ns % 1_000_000_000)
}

fn bytes_as_text(data: &[u8]) -> String {
    data.iter().map(|&b| match b {
        b'\r'       => '↩',
        b'\n'       => '↵',
        b'\t'       => '→',
        0x20..=0x7E => b as char,
        _           => '·',
    }).collect()
}

fn render_data_lines(
    lines: &mut Vec<PluginLine>,
    direction: &str,
    addr: u8,
    data: &[u8],
    timestamp_ns: u64,
    color: Color,
) {
    lines.push(PluginLine::colored(
        format!("  [{}] {} dev={addr}  {} bytes", fmt_ts(timestamp_ns), direction, data.len()),
        color,
    ));
    let text = bytes_as_text(data);
    for chunk in text.as_bytes().chunks(64) {
        let s = std::str::from_utf8(chunk).unwrap_or("?");
        lines.push(PluginLine::colored(format!("    │{s}│"), color));
    }
    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;
        let mut hex = String::with_capacity(16 * 3 + 1);
        for (j, b) in chunk.iter().enumerate() {
            if j == 8 { hex.push(' '); }
            hex.push_str(&format!("{b:02x} "));
        }
        while hex.len() < 16 * 3 + 1 { hex.push(' '); }
        let ascii: String = chunk.iter().map(|&b| {
            if b >= 0x20 && b < 0x7f { b as char } else { '.' }
        }).collect();
        lines.push(PluginLine::colored(
            format!("    {offset:04x}  {hex} {ascii}"),
            Color::DarkGray,
        ));
    }
}

// ---------------------------------------------------------------------------
// UsbPlugin impl
// ---------------------------------------------------------------------------

impl UsbPlugin for CdcPlugin {
    fn name(&self) -> &str { "USB CDC Serial Monitor" }
    fn description(&self) -> &str { "Decodes CDC ACM control requests and serial TX/RX data" }

    fn on_transaction(&mut self, txn: &TransactionInfo, devices: &[UsbDeviceInfo]) {
        self.refresh_from_devices(devices);
        match txn.kind {
            TransactionKind::Control => self.handle_control(txn),
            TransactionKind::BulkIn | TransactionKind::BulkOut => self.handle_bulk(txn),
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.events.clear();
        self.cdc_data_eps.clear();
        self.cdc_dev_addrs.clear();
        self.announced.clear();
    }

    fn is_active(&self) -> bool { !self.events.is_empty() }

    fn render_lines(&self) -> Vec<PluginLine> {
        let mut lines = Vec::new();
        lines.push(PluginLine::header("  USB CDC Serial Monitor"));
        lines.push(PluginLine::colored(
            "  Decodes SET_LINE_CODING, SET_CONTROL_LINE_STATE, SEND_BREAK, and bulk serial data",
            Color::DarkGray,
        ));
        lines.push(PluginLine::separator());

        if self.events.is_empty() {
            lines.push(PluginLine::plain(""));
            lines.push(PluginLine::colored(
                "  No CDC activity detected.",
                Color::DarkGray,
            ));
            lines.push(PluginLine::colored(
                "  Connect a CDC/ACM device (Arduino, CH340, CP2102, FTDI, etc.) and capture.",
                Color::DarkGray,
            ));
            return lines;
        }

        for event in &self.events {
            match event {
                CdcEvent::DeviceDetected { label, .. } => {
                    lines.push(PluginLine::separator());
                    lines.push(PluginLine::colored(format!("  ○ CDC Device: {label}"), Color::Green));
                }
                CdcEvent::LineCoding { addr, baud, data_bits, parity, stop_bits, timestamp_ns } => {
                    lines.push(PluginLine::colored(
                        format!(
                            "  [{}] dev={addr}  LINE_CODING  {} baud  {}{}{}",
                            fmt_ts(*timestamp_ns), baud, data_bits,
                            fmt_parity(*parity), fmt_stop_bits(*stop_bits),
                        ),
                        Color::Yellow,
                    ));
                }
                CdcEvent::ControlLineState { addr, dtr, rts, timestamp_ns } => {
                    lines.push(PluginLine::colored(
                        format!(
                            "  [{}] dev={addr}  CTRL_LINE    DTR={}  RTS={}",
                            fmt_ts(*timestamp_ns),
                            if *dtr { "ON " } else { "OFF" },
                            if *rts { "ON " } else { "OFF" },
                        ),
                        Color::Magenta,
                    ));
                }
                CdcEvent::SendBreak { addr, duration_ms, timestamp_ns } => {
                    lines.push(PluginLine::colored(
                        format!("  [{}] dev={addr}  SEND_BREAK   {}ms", fmt_ts(*timestamp_ns), duration_ms),
                        Color::Red,
                    ));
                }
                CdcEvent::TxData { addr, data, timestamp_ns } => {
                    render_data_lines(&mut lines, "TX→", *addr, data, *timestamp_ns, Color::Blue);
                }
                CdcEvent::RxData { addr, data, timestamp_ns } => {
                    render_data_lines(&mut lines, "RX←", *addr, data, *timestamp_ns, Color::Green);
                }
            }
        }
        lines
    }
}
