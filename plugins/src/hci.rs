//! Bluetooth HCI over USB decoder plugin.
//!
//! Detects Bluetooth USB dongles (USB class 0xE0 / subclass 0x01 / protocol 0x01)
//! and decodes the three HCI transport channels carried over USB:
//!
//! | USB transfer   | HCI channel   |
//! |----------------|---------------|
//! | Control OUT    | HCI Commands  |
//! | Interrupt IN   | HCI Events    |
//! | Bulk OUT       | ACL / ISO data H→C  |
//! | Bulk IN        | ACL / ISO data C→H  |
//!
//! LE Audio (BT 5.2+) adds ISO transport:
//! - CIS (Connected Isochronous Streams) and BIS (Broadcast Isochronous Streams)
//! - ISO handles are learned from LE CIS Established / LE Create BIG Complete events
//! - ISO data packets are decoded with SDU sequence numbers and optional timestamps
//!
//! Each captured HCI packet is decoded to a human-readable summary line plus
//! optional expanded detail lines (parameter names / values).

use crate::{PluginLine, PluginNavRequest, UsbPlugin};
use crate::models::{PacketType, TransactionInfo, TransactionKind, UsbDeviceInfo};
use std::cell::Cell;
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

// ── USB class codes ───────────────────────────────────────────────────────────
const CLASS_WIRELESS:    u8 = 0xE0;
const SUBCLASS_RF:       u8 = 0x01;
const PROTOCOL_BT:       u8 = 0x01;

// bmRequestType for HCI command (Class | Interface | Host→Device)
const BMRT_HCI_CMD: u8 = 0x20;

// ── HCI packet direction ──────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir { HostToCtrl, CtrlToHost }

// ── HCI packet type ───────────────────────────────────────────────────────────
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HciPktKind { Command, Event, AclOut, AclIn, IsoOut, IsoIn }

// ── Recorded HCI packet ───────────────────────────────────────────────────────
#[derive(Debug, Clone)]
struct HciPacket {
    timestamp_ns: u64,
    dev_addr:     u8,
    ep:           u8,          // endpoint address with direction bit
    dir:          Dir,
    kind:         HciPktKind,
    /// One-line summary (shown in the list).
    summary:      String,
    /// Expanded detail lines (shown when selected / below summary).
    details:      Vec<String>,
}

// ── Device endpoint map ───────────────────────────────────────────────────────
#[derive(Debug, Clone)]
struct BtDevice {
    addr:          u8,
    label:         String,
    ep_intr_in:    Option<u8>,   // HCI events
    ep_bulk_in:    Option<u8>,   // ACL device→host
    ep_bulk_out:   Option<u8>,   // ACL host→device
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin state
// ─────────────────────────────────────────────────────────────────────────────

pub struct HciPlugin {
    devices:     Vec<BtDevice>,
    announced:   Vec<u8>,
    packets:     Vec<HciPacket>,
    /// Handles learned from LE CIS Established / BIG Complete events.
    /// Bulk packets with these handles are decoded as ISO rather than ACL.
    iso_handles: Vec<u16>,
    /// Index of the currently selected packet (for keyboard navigation).
    selected_idx: usize,
    /// Vertical scroll offset — managed internally via Cell so render can clamp it.
    scroll:       Cell<usize>,
    /// Last rendered list height — stored during render for page-step calculations.
    visible_h:    Cell<usize>,
    /// Pending navigation request (set when user presses Enter on a packet).
    pending_nav:  Option<PluginNavRequest>,
}

impl HciPlugin {
    pub fn new() -> Self {
        Self {
            devices:      Vec::new(),
            announced:    Vec::new(),
            packets:      Vec::new(),
            iso_handles:  Vec::new(),
            selected_idx: 0,
            scroll:       Cell::new(0),
            visible_h:    Cell::new(20),
            pending_nav:  None,
        }
    }

    // ── Device discovery ─────────────────────────────────────────────────────

    fn refresh_from_devices(&mut self, devices: &[UsbDeviceInfo]) {
        self.devices.clear();
        for dev in devices {
            for cfg in &dev.configurations {
                for iface in &cfg.interfaces {
                    if iface.class    == CLASS_WIRELESS
                    && iface.subclass == SUBCLASS_RF
                    && iface.protocol == PROTOCOL_BT
                    {
                        let mut ep_intr_in  = None;
                        let mut ep_bulk_in  = None;
                        let mut ep_bulk_out = None;
                        for ep in &iface.endpoints {
                            let dir_in = ep.address & 0x80 != 0;
                            match ep.attributes & 0x03 {
                                3 if dir_in  => ep_intr_in  = Some(ep.address),
                                2 if dir_in  => ep_bulk_in  = Some(ep.address),
                                2 if !dir_in => ep_bulk_out = Some(ep.address),
                                _ => {}
                            }
                        }
                        let name = dev.product.as_deref()
                            .or(dev.manufacturer.as_deref())
                            .unwrap_or("Bluetooth Adapter");
                        let label = format!(
                            "addr={:03}  {:04X}:{:04X}  \"{}\"",
                            dev.address, dev.vendor_id, dev.product_id, name
                        );
                        self.devices.push(BtDevice {
                            addr: dev.address, label,
                            ep_intr_in, ep_bulk_in, ep_bulk_out,
                        });
                        if !self.announced.contains(&dev.address) {
                            self.announced.push(dev.address);
                        }
                    }
                }
            }
        }
    }

    fn bt_device(&self, addr: u8) -> Option<&BtDevice> {
        self.devices.iter().find(|d| d.addr == addr)
    }

    // ── Helpers to pull dev / ep from transaction label ───────────────────────

    fn parse_dev(label: &str) -> Option<u8> {
        label.split("dev=").nth(1)?.split_whitespace().next()?.parse().ok()
    }
    fn parse_ep(label: &str) -> Option<u8> {
        label.split("ep=").nth(1)?.split_whitespace().next()?.parse().ok()
    }

    /// Returns `true` when a `BulkIn` transaction is actually on the Bluetooth
    /// adapter's interrupt IN endpoint (the backend emits all IN transactions as
    /// `BulkIn` regardless of the USB endpoint type).
    fn is_interrupt_in_txn(&self, txn: &TransactionInfo) -> bool {
        let dev_addr = match Self::parse_dev(&txn.label) { Some(a) => a, None => return false };
        let ep_num   = match Self::parse_ep(&txn.label)  { Some(e) => e, None => return false };
        let ep_addr  = ep_num | 0x80;
        self.bt_device(dev_addr)
            .and_then(|d| d.ep_intr_in)
            .map(|intr| intr == ep_addr)
            .unwrap_or(false)
    }

    // ── Transaction handlers ──────────────────────────────────────────────────

    fn handle_control(&mut self, txn: &TransactionInfo) {
        // Collect DATA packets.
        let data: Vec<&[u8]> = txn.packets.iter()
            .filter(|p| p.packet_type == PacketType::Data && !p.raw_bytes.is_empty())
            .map(|p| p.raw_bytes.as_slice())
            .collect();

        let setup = match data.first() {
            Some(d) if d.len() >= 8 => *d,
            _ => return,
        };
        if setup[0] != BMRT_HCI_CMD { return; }

        let dev_addr = Self::parse_dev(&txn.label).unwrap_or(0);
        if self.bt_device(dev_addr).is_none() { return; }

        // HCI command payload follows in the next DATA packet (data stage).
        let payload = match data.get(1) {
            Some(d) => *d,
            None    => return,
        };
        if payload.len() < 3 { return; }

        let (summary, details) = decode_hci_command(payload);
        self.packets.push(HciPacket {
            timestamp_ns: txn.timestamp_ns,
            dev_addr,
            ep:    0x00,
            dir:   Dir::HostToCtrl,
            kind:  HciPktKind::Command,
            summary,
            details,
        });
    }

    fn handle_interrupt_in(&mut self, txn: &TransactionInfo) {
        let dev_addr = match Self::parse_dev(&txn.label) { Some(a) => a, None => return };
        let ep_num   = match Self::parse_ep(&txn.label)  { Some(e) => e, None => return };
        let ep_addr  = ep_num | 0x80;

        let dev = match self.bt_device(dev_addr) {
            Some(d) => d.clone(),
            None    => return,
        };
        // Accept if it's the known interrupt IN or if we haven't mapped endpoints yet.
        let accept = dev.ep_intr_in.map(|e| e == ep_addr).unwrap_or(true);
        if !accept { return; }

        for pkt in &txn.packets {
            if pkt.packet_type != PacketType::Data || pkt.raw_bytes.is_empty() { continue; }
            if pkt.raw_bytes.len() < 2 { continue; }
            // Learn ISO handles before decoding for display.
            extract_iso_handles(&pkt.raw_bytes, &mut self.iso_handles);
            let (summary, details) = decode_hci_event(&pkt.raw_bytes);
            self.packets.push(HciPacket {
                timestamp_ns: pkt.timestamp_ns,
                dev_addr,
                ep:   ep_addr,
                dir:  Dir::CtrlToHost,
                kind: HciPktKind::Event,
                summary,
                details,
            });
        }
    }

    fn handle_bulk(&mut self, txn: &TransactionInfo, dir: Dir) {
        let dev_addr = match Self::parse_dev(&txn.label) { Some(a) => a, None => return };
        let ep_num   = match Self::parse_ep(&txn.label)  { Some(e) => e, None => return };
        let ep_addr  = if dir == Dir::CtrlToHost { ep_num | 0x80 } else { ep_num & 0x7F };

        if self.bt_device(dev_addr).is_none() { return; }

        for pkt in &txn.packets {
            if pkt.packet_type != PacketType::Data || pkt.raw_bytes.is_empty() { continue; }
            if pkt.raw_bytes.len() < 4 { continue; }

            // Peek at the handle field to decide ACL vs ISO.
            let hdr    = u16::from_le_bytes([pkt.raw_bytes[0], pkt.raw_bytes[1]]);
            let handle = hdr & 0x0FFF;
            let is_iso = self.iso_handles.contains(&handle);

            let (kind, summary, details) = if is_iso {
                let k = if dir == Dir::CtrlToHost { HciPktKind::IsoIn } else { HciPktKind::IsoOut };
                let (s, d) = decode_iso(&pkt.raw_bytes, dir);
                (k, s, d)
            } else {
                let k = if dir == Dir::CtrlToHost { HciPktKind::AclIn } else { HciPktKind::AclOut };
                let (s, d) = decode_acl(&pkt.raw_bytes, dir);
                (k, s, d)
            };

            self.packets.push(HciPacket {
                timestamp_ns: pkt.timestamp_ns,
                dev_addr,
                ep:   ep_addr,
                dir,
                kind,
                summary,
                details,
            });
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HCI decoding
// ─────────────────────────────────────────────────────────────────────────────

fn decode_hci_command(d: &[u8]) -> (String, Vec<String>) {
    if d.len() < 3 {
        return (format!("CMD  {:?}", hex_bytes(d)), vec![]);
    }
    let opcode = u16::from_le_bytes([d[0], d[1]]);
    let plen   = d[2] as usize;
    let params = if d.len() >= 3 + plen { &d[3..3 + plen] } else { &d[3..] };
    let ogf    = (opcode >> 10) as u8;
    let ocf    = opcode & 0x03FF;
    let name   = hci_command_name(ogf, ocf);

    let summary = format!("CMD  {name}  ogf=0x{ogf:02X} ocf=0x{ocf:03X}  plen={plen}");
    let mut details = vec![
        format!("Opcode: 0x{opcode:04X}  OGF=0x{ogf:02X} ({})  OCF=0x{ocf:03X}", ogf_name(ogf)),
        format!("Param len: {plen}"),
    ];
    details.extend(decode_command_params(ogf, ocf, params));
    if !params.is_empty() {
        details.push(format!("Raw params: {}", hex_bytes(params)));
    }
    (summary, details)
}

fn decode_hci_event(d: &[u8]) -> (String, Vec<String>) {
    if d.len() < 2 {
        return (format!("EVT  {:?}", hex_bytes(d)), vec![]);
    }
    let code = d[0];
    let plen = d[1] as usize;
    let params = if d.len() >= 2 + plen { &d[2..2 + plen] } else { &d[2..] };
    let name = hci_event_name(code);

    let summary = format!("EVT  {name}  code=0x{code:02X}  plen={plen}");
    let mut details = vec![
        format!("Event code: 0x{code:02X}  {name}"),
        format!("Param len: {plen}"),
    ];
    details.extend(decode_event_params(code, params));
    if !params.is_empty() {
        details.push(format!("Raw params: {}", hex_bytes(params)));
    }
    (summary, details)
}

fn decode_acl(d: &[u8], dir: Dir) -> (String, Vec<String>) {
    if d.len() < 4 {
        return (format!("ACL  {}", hex_bytes(d)), vec![]);
    }
    let hdr    = u16::from_le_bytes([d[0], d[1]]);
    let handle = hdr & 0x0FFF;
    let pb     = (hdr >> 12) & 0x03;
    let bc     = (hdr >> 14) & 0x03;
    let length = u16::from_le_bytes([d[2], d[3]]) as usize;
    let data   = if d.len() >= 4 + length { &d[4..4 + length] } else { &d[4..] };

    let pb_str = match pb { 0 => "start (no flush)", 1 => "continuing", 2 => "start", _ => "complete" };
    let bc_str = match bc { 0 => "point-to-point", 1 => "active broadcast", 2 => "piconet broadcast", _ => "?" };
    let dir_str = if dir == Dir::HostToCtrl { "H→C" } else { "C→H" };

    let mut details = vec![
        format!("Handle: 0x{handle:03X}  PB: {pb_str}  BC: {bc_str}"),
        format!("Total length: {length}  Direction: {dir_str}"),
    ];

    // Attempt L2CAP decode on first segment (PB=2 or PB=0)
    let l2cap_info = if (pb == 2 || pb == 0) && data.len() >= 4 {
        let l2len = u16::from_le_bytes([data[0], data[1]]) as usize;
        let cid   = u16::from_le_bytes([data[2], data[3]]);
        let l2data = if data.len() >= 4 + l2len { &data[4..4 + l2len] } else { &data[4..] };
        details.push(format!("L2CAP  len={l2len}  cid=0x{cid:04X}  ({})", l2cap_cid_name(cid)));
        details.extend(decode_l2cap_payload(cid, l2data));
        Some(format!("cid=0x{cid:04X} {}", l2cap_cid_name(cid)))
    } else {
        None
    };

    if !data.is_empty() {
        details.push(format!("Raw data: {}", hex_bytes(&data[..data.len().min(32)])));
    }

    let summary = if let Some(l2) = l2cap_info {
        format!("ACL  handle=0x{handle:03X}  {l2}  len={length}  [{dir_str}]")
    } else {
        format!("ACL  handle=0x{handle:03X}  pb={pb}  len={length}  [{dir_str}]")
    };

    (summary, details)
}

// ── ISO data decoder ──────────────────────────────────────────────────────────
// HCI ISO Data packet (BT 5.2+):
//   bits[11:0]  = connection handle
//   bit[12]     = TS flag (timestamp present)
//   bits[14:13] = PB flag  (00=first frag/no ts, 10=first frag, 01=continuing, 11=complete SDU)
//   bit[15]     = RFU
//   data_total_length (2)
//   if TS: timestamp(4) + packet_seq(2) + iso_sdu_length(2) + sdu_data
//   else:  packet_seq(2) + iso_sdu_length(2) + sdu_data

fn decode_iso(d: &[u8], dir: Dir) -> (String, Vec<String>) {
    if d.len() < 4 {
        return (format!("ISO  {}", hex_bytes(d)), vec![]);
    }
    let hdr    = u16::from_le_bytes([d[0], d[1]]);
    let handle = hdr & 0x0FFF;
    let ts     = (hdr >> 12) & 0x01 != 0;
    let pb     = (hdr >> 13) & 0x03;
    let length = u16::from_le_bytes([d[2], d[3]]) as usize;
    let dir_str = if dir == Dir::HostToCtrl { "H→C" } else { "C→H" };

    let pb_str = match pb {
        0 => "1st fragment (no TS)", 1 => "continuing",
        2 => "1st fragment", 3 => "complete SDU", _ => "?",
    };

    let mut details = vec![
        format!("Handle: 0x{handle:03X}  PB: {pb_str}  TS: {}  len: {length}  [{dir_str}]", ts),
    ];

    // Only decode SDU header on first/complete fragments.
    if pb == 0 || pb == 2 || pb == 3 {
        let payload = if d.len() > 4 { &d[4..] } else { &[] as &[u8] };
        let (timestamp, seq, sdu_len, sdu_data) = if ts && payload.len() >= 8 {
            let ts_val  = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            let seq     = u16::from_le_bytes([payload[4], payload[5]]);
            let sdu_len = u16::from_le_bytes([payload[6], payload[7]]) as usize;
            let data    = if payload.len() >= 8 + sdu_len { &payload[8..8+sdu_len] } else { &payload[8..] };
            (Some(ts_val), seq, sdu_len, data)
        } else if !ts && payload.len() >= 4 {
            let seq     = u16::from_le_bytes([payload[0], payload[1]]);
            let sdu_len = u16::from_le_bytes([payload[2], payload[3]]) as usize;
            let data    = if payload.len() >= 4 + sdu_len { &payload[4..4+sdu_len] } else { &payload[4..] };
            (None, seq, sdu_len, data)
        } else {
            return (format!("ISO  handle=0x{handle:03X}  len={length}  [{dir_str}]"), details);
        };

        if let Some(ts_val) = timestamp {
            details.push(format!("Timestamp: {ts_val} µs"));
        }
        details.push(format!("Seq: {seq}  SDU len: {sdu_len}"));
        if !sdu_data.is_empty() {
            details.push(format!("SDU data: {}", hex_bytes(&sdu_data[..sdu_data.len().min(32)])));
        }

        let ts_str = if let Some(t) = timestamp { format!("  ts={t}µs") } else { String::new() };
        let summary = format!("ISO  handle=0x{handle:03X}  seq={seq}  sdu={sdu_len}{ts_str}  [{dir_str}]");
        return (summary, details);
    }

    (format!("ISO  handle=0x{handle:03X}  frag  len={length}  [{dir_str}]"), details)
}

// ── ISO handle extraction ─────────────────────────────────────────────────────
// Parses LE Meta events for CIS Established and BIG Complete to learn handles.

fn extract_iso_handles(d: &[u8], handles: &mut Vec<u16>) {
    if d.len() < 3 { return; }
    if d[0] != 0x3E { return; }   // must be LE Meta Event
    let params = if d.len() >= 2 + d[1] as usize { &d[2..2 + d[1] as usize] } else { &d[2..] };
    if params.is_empty() { return; }
    match params[0] {
        // LE CIS Established (0x19): subevent(1) status(1) cis_handle(2) ...
        0x19 if params.len() >= 4 => {
            let h = u16::from_le_bytes([params[2], params[3]]) & 0x0FFF;
            if params[1] == 0x00 && !handles.contains(&h) { handles.push(h); }
        }
        // LE Create BIG Complete (0x1B): subevent(1) status(1) big_handle(1) num_bis(1) [bis_handles(2)*n]
        0x1B if params.len() >= 4 => {
            let num_bis = params[3] as usize;
            for i in 0..num_bis {
                let off = 4 + i * 2;
                if off + 2 <= params.len() {
                    let h = u16::from_le_bytes([params[off], params[off+1]]) & 0x0FFF;
                    if !handles.contains(&h) { handles.push(h); }
                }
            }
        }
        // LE BIG Sync Established (0x1D): subevent(1) status(1) big_handle(1) ... num_bis(1) [handles(2)*n]
        0x1D if params.len() >= 8 => {
            // num_bis is at a variable offset; offset 7 after: sub(1)+status(1)+big(1)+latency(3)+nse(1)+bn(1) ... actually variable
            // Conservative: scan for valid-looking 12-bit handles after offset 7
            // The spec layout: sub(1) status(1) big_handle(1) transport_latency(3) nse(1) bn(1) pto(1) irc(1) max_pdu(2) iso_interval(2) num_bis(1) [bis_conn_handle(2)*n]
            if params.len() >= 14 {
                let num_bis = params[13] as usize;
                for i in 0..num_bis {
                    let off = 14 + i * 2;
                    if off + 2 <= params.len() {
                        let h = u16::from_le_bytes([params[off], params[off+1]]) & 0x0FFF;
                        if !handles.contains(&h) { handles.push(h); }
                    }
                }
            }
        }
        _ => {}
    }
}

// ── HCI command parameter decoders ────────────────────────────────────────────

fn decode_command_params(ogf: u8, ocf: u16, p: &[u8]) -> Vec<String> {
    match (ogf, ocf) {
        // Reset
        (0x03, 0x003) => vec!["(no parameters)".into()],

        // Disconnect  [handle(2), reason(1)]
        (0x01, 0x006) if p.len() >= 3 => {
            let handle = u16::from_le_bytes([p[0], p[1]]) & 0x0FFF;
            vec![
                format!("Handle: 0x{handle:03X}"),
                format!("Reason: 0x{:02X}  {}", p[2], hci_error_name(p[2])),
            ]
        }

        // Create Connection  [bd_addr(6), pkt_type(2), page_scan_rpt(1), rsvd(1), clk_off(2), allow_role_sw(1)]
        (0x01, 0x005) if p.len() >= 13 => {
            vec![
                format!("BD_ADDR: {}", fmt_bd_addr(&p[0..6])),
                format!("Packet type: 0x{:04X}", u16::from_le_bytes([p[6], p[7]])),
                format!("Allow role switch: {}", p[12]),
            ]
        }

        // Inquiry  [lap(3), inquiry_length(1), num_responses(1)]
        (0x01, 0x001) if p.len() >= 5 => {
            let lap = u32::from_le_bytes([p[0], p[1], p[2], 0]);
            let dur_125ms = p[3];
            vec![
                format!("LAP: 0x{lap:06X}"),
                format!("Duration: {}s  ({}×1.28s)", dur_125ms as f32 * 1.28, dur_125ms),
                format!("Max responses: {}", p[4]),
            ]
        }

        // Write Scan Enable  [scan_enable(1)]
        (0x03, 0x01A) if !p.is_empty() => {
            let s = match p[0] {
                0 => "No scans enabled",
                1 => "Inquiry scan only",
                2 => "Page scan only",
                3 => "Inquiry + page scan",
                v => return vec![format!("Scan enable: 0x{v:02X}")],
            };
            vec![format!("Scan enable: {s}")]
        }

        // Set Event Mask  [event_mask(8)]
        (0x03, 0x001) if p.len() >= 8 => {
            let mask = u64::from_le_bytes(p[..8].try_into().unwrap_or([0u8;8]));
            vec![format!("Event mask: 0x{mask:016X}")]
        }

        // Read BD_ADDR (no params)
        (0x04, 0x009) => vec!["(no parameters)".into()],

        // Read Local Version (no params)
        (0x04, 0x001) => vec!["(no parameters)".into()],

        // Read Local Supported Features (no params)
        (0x04, 0x003) => vec!["(no parameters)".into()],

        // Read Buffer Size (no params)
        (0x04, 0x005) => vec!["(no parameters)".into()],

        // LE Set Scan Parameters  [type(1), interval(2), window(2), own_addr_type(1), filter_policy(1)]
        (0x08, 0x00B) if p.len() >= 7 => {
            let interval_us = u16::from_le_bytes([p[1], p[2]]) as f32 * 0.625;
            let window_us   = u16::from_le_bytes([p[3], p[4]]) as f32 * 0.625;
            vec![
                format!("Type: {}",
                    if p[0] == 0 { "Passive" } else { "Active" }),
                format!("Interval: {:.2}ms", interval_us / 1000.0),
                format!("Window:   {:.2}ms", window_us / 1000.0),
                format!("Own addr type: {}", le_addr_type(p[5])),
                format!("Filter policy: {}", match p[6] {
                    0 => "Accept all",
                    1 => "Whitelist only",
                    _ => "?",
                }),
            ]
        }

        // LE Set Scan Enable  [enable(1), filter_duplicates(1)]
        (0x08, 0x00C) if p.len() >= 2 => {
            vec![
                format!("Scan: {}", if p[0] == 1 { "Enable" } else { "Disable" }),
                format!("Filter duplicates: {}", if p[1] == 1 { "Yes" } else { "No" }),
            ]
        }

        // LE Set Advertising Parameters
        (0x08, 0x006) if p.len() >= 15 => {
            let min_ms = u16::from_le_bytes([p[0], p[1]]) as f32 * 0.625;
            let max_ms = u16::from_le_bytes([p[2], p[3]]) as f32 * 0.625;
            vec![
                format!("Adv type: {}", match p[4] {
                    0 => "ADV_IND (connectable undirected)",
                    1 => "ADV_DIRECT_IND (high duty)",
                    2 => "ADV_SCAN_IND (scannable undirected)",
                    3 => "ADV_NONCONN_IND (non-connectable)",
                    4 => "ADV_DIRECT_IND (low duty)",
                    v => return vec![format!("Adv type: 0x{v:02X}")],
                }),
                format!("Interval: {:.2}ms – {:.2}ms", min_ms, max_ms),
                format!("Own addr type: {}", le_addr_type(p[5])),
                format!("Channel map: 0x{:02X}", p[14]),
            ]
        }

        // LE Set Advertise Enable  [enable(1)]
        (0x08, 0x00A) if !p.is_empty() => {
            vec![format!("Advertising: {}", if p[0] == 1 { "Enable" } else { "Disable" })]
        }

        // LE Create Connection  [scan_interval(2), scan_window(2), filter(1),
        //   peer_addr_type(1), peer_addr(6), own_addr_type(1),
        //   min_ce_len(2), max_ce_len(2), conn_interval_min(2), conn_interval_max(2),
        //   max_latency(2), supervision_timeout(2), ...]
        (0x08, 0x00D) if p.len() >= 25 => {
            let interval_min = u16::from_le_bytes([p[12], p[13]]) as f32 * 1.25;
            let interval_max = u16::from_le_bytes([p[14], p[15]]) as f32 * 1.25;
            let timeout_ms   = u16::from_le_bytes([p[20], p[21]]) as u32 * 10;
            vec![
                format!("Peer addr type: {}", le_addr_type(p[5])),
                format!("Peer addr: {}", fmt_bd_addr(&p[6..12])),
                format!("Conn interval: {:.2}ms – {:.2}ms", interval_min, interval_max),
                format!("Supervision timeout: {}ms", timeout_ms),
            ]
        }

        // ── LE Audio (BT 5.2+) ─────────────────────────────────────────────

        // LE Set CIG Parameters  [cig_id(1), sdu_interval_c_to_p(3), sdu_interval_p_to_c(3),
        //   worst_case_sca(1), packing(1), framing(1), max_transport_latency_c_to_p(2),
        //   max_transport_latency_p_to_c(2), num_cis(1), [cis_id(1),max_sdu_c_to_p(2),
        //   max_sdu_p_to_c(2), phy_c_to_p(1),phy_p_to_c(1),rtn_c_to_p(1),rtn_p_to_c(1)]*]
        (0x08, 0x062) if p.len() >= 15 => {
            let cig_id     = p[0];
            let sdu_int_cp = u32::from_le_bytes([p[1], p[2], p[3], 0]);
            let sdu_int_pc = u32::from_le_bytes([p[4], p[5], p[6], 0]);
            let packing    = if p[8] == 0 { "Sequential" } else { "Interleaved" };
            let framing    = if p[9] == 0 { "Unframed" } else { "Framed" };
            let lat_cp     = u16::from_le_bytes([p[10], p[11]]);
            let lat_pc     = u16::from_le_bytes([p[12], p[13]]);
            let num_cis    = p[14] as usize;
            let mut out = vec![
                format!("CIG ID: 0x{cig_id:02X}"),
                format!("SDU interval C→P: {sdu_int_cp}µs  P→C: {sdu_int_pc}µs"),
                format!("Packing: {packing}  Framing: {framing}"),
                format!("Max transport latency C→P: {lat_cp}ms  P→C: {lat_pc}ms"),
                format!("Num CIS: {num_cis}"),
            ];
            for i in 0..num_cis.min(8) {
                let off = 15 + i * 9;
                if off + 9 <= p.len() {
                    let cis_id     = p[off];
                    let sdu_cp     = u16::from_le_bytes([p[off+1], p[off+2]]);
                    let sdu_pc     = u16::from_le_bytes([p[off+3], p[off+4]]);
                    let phy_cp     = phy_name(p[off+5]);
                    let phy_pc     = phy_name(p[off+6]);
                    out.push(format!("  CIS[{i}] id=0x{cis_id:02X}  SDU C→P={sdu_cp}  P→C={sdu_pc}  PHY C→P={phy_cp}  P→C={phy_pc}"));
                }
            }
            out
        }

        // LE Create CIS  [num_cis(1), (cis_handle(2), acl_handle(2))*]
        (0x08, 0x064) if !p.is_empty() => {
            let n = p[0] as usize;
            let mut out = vec![format!("Num CIS: {n}")];
            for i in 0..n.min(8) {
                let off = 1 + i * 4;
                if off + 4 <= p.len() {
                    let cis_h = u16::from_le_bytes([p[off],   p[off+1]]) & 0x0FFF;
                    let acl_h = u16::from_le_bytes([p[off+2], p[off+3]]) & 0x0FFF;
                    out.push(format!("  [{i}] CIS handle=0x{cis_h:03X}  ACL handle=0x{acl_h:03X}"));
                }
            }
            out
        }

        // LE Remove CIG  [cig_id(1)]
        (0x08, 0x065) if !p.is_empty() => {
            vec![format!("CIG ID: 0x{:02X}", p[0])]
        }

        // LE Accept CIS Request  [cis_handle(2)]
        (0x08, 0x066) if p.len() >= 2 => {
            let h = u16::from_le_bytes([p[0], p[1]]) & 0x0FFF;
            vec![format!("CIS Handle: 0x{h:03X}")]
        }

        // LE Reject CIS Request  [cis_handle(2), reason(1)]
        (0x08, 0x067) if p.len() >= 3 => {
            let h = u16::from_le_bytes([p[0], p[1]]) & 0x0FFF;
            vec![
                format!("CIS Handle: 0x{h:03X}"),
                format!("Reason: 0x{:02X}  {}", p[2], hci_error_name(p[2])),
            ]
        }

        // LE Create BIG  [big_handle(1), adv_handle(1), num_bis(1), sdu_interval(3),
        //   max_sdu(2), max_transport_latency(2), rtn(1), phy(1), packing(1), framing(1),
        //   encryption(1), broadcast_code(16)]
        (0x08, 0x068) if p.len() >= 31 => {
            let big_h      = p[0];
            let num_bis    = p[2];
            let sdu_int    = u32::from_le_bytes([p[3], p[4], p[5], 0]);
            let max_sdu    = u16::from_le_bytes([p[6], p[7]]);
            let latency    = u16::from_le_bytes([p[8], p[9]]);
            let encryption = p[12] != 0;
            vec![
                format!("BIG Handle: 0x{big_h:02X}  Num BIS: {num_bis}"),
                format!("SDU interval: {sdu_int}µs  Max SDU: {max_sdu}  Max latency: {latency}ms"),
                format!("PHY: {}  Packing: {}  Framing: {}  Encrypted: {}",
                    phy_name(p[11]),
                    if p[11] == 0 { "Sequential" } else { "Interleaved" },
                    if p[12] == 0 { "Unframed" } else { "Framed" },
                    encryption,
                ),
            ]
        }

        // LE Terminate BIG  [big_handle(1), reason(1)]
        (0x08, 0x06A) if p.len() >= 2 => {
            vec![
                format!("BIG Handle: 0x{:02X}", p[0]),
                format!("Reason: 0x{:02X}  {}", p[1], hci_error_name(p[1])),
            ]
        }

        // LE BIG Create Sync  [big_handle(1), sync_handle(2), encryption(1),
        //   broadcast_code(16), mse(1), big_sync_timeout(2), num_bis(1), bis(1)*]
        (0x08, 0x06B) if p.len() >= 24 => {
            let big_h    = p[0];
            let sync_h   = u16::from_le_bytes([p[1], p[2]]);
            let timeout  = u16::from_le_bytes([p[20], p[21]]) as u32 * 10;
            let num_bis  = p[22] as usize;
            let mut out  = vec![
                format!("BIG Handle: 0x{big_h:02X}  Sync Handle: 0x{sync_h:04X}"),
                format!("Encrypted: {}  Sync timeout: {timeout}ms", p[3] != 0),
            ];
            let bis_list: Vec<String> = (0..num_bis.min(8))
                .filter_map(|i| p.get(23 + i).map(|b| format!("0x{b:02X}")))
                .collect();
            if !bis_list.is_empty() {
                out.push(format!("BIS indices: {}", bis_list.join(", ")));
            }
            out
        }

        // LE BIG Terminate Sync  [big_handle(1)]
        (0x08, 0x06C) if !p.is_empty() => {
            vec![format!("BIG Handle: 0x{:02X}", p[0])]
        }

        // LE Setup ISO Data Path  [handle(2), data_path_dir(1), data_path_id(1),
        //   codec_id(5), controller_delay(3), codec_config_len(1), codec_config(n)]
        (0x08, 0x06E) if p.len() >= 13 => {
            let handle  = u16::from_le_bytes([p[0], p[1]]) & 0x0FFF;
            let dir     = if p[2] == 0 { "Input (H→C)" } else { "Output (C→H)" };
            let path_id = p[3];
            let codec   = &p[4..9];
            let delay   = u32::from_le_bytes([p[9], p[10], p[11], 0]);
            vec![
                format!("Handle: 0x{handle:03X}  Direction: {dir}"),
                format!("Data path ID: 0x{path_id:02X}  {}", if path_id == 0 { "(HCI)" } else { "(logical transport)" }),
                format!("Codec: company=0x{:04X} vendor=0x{:04X}  controller_delay={delay}µs",
                    u16::from_le_bytes([codec[3], codec[4]]),
                    u16::from_le_bytes([codec[1], codec[2]]),
                ),
            ]
        }

        // LE Remove ISO Data Path  [handle(2), data_path_dir(1)]
        (0x08, 0x06F) if p.len() >= 3 => {
            let handle = u16::from_le_bytes([p[0], p[1]]) & 0x0FFF;
            let dirs   = match p[2] & 0x03 {
                0x01 => "Input only",
                0x02 => "Output only",
                0x03 => "Both directions",
                _    => "?",
            };
            vec![
                format!("Handle: 0x{handle:03X}"),
                format!("Data path direction: {dirs}"),
            ]
        }

        // LE Set Host Feature  [bit_number(1), bit_value(1)]
        (0x08, 0x074) if p.len() >= 2 => {
            let feature = match p[0] {
                32 => "Connected Isochronous Stream (Central)",
                33 => "Connected Isochronous Stream (Peripheral)",
                34 => "Isochronous Broadcaster",
                35 => "Synchronized Receiver",
                _  => "?",
            };
            vec![
                format!("Feature bit {}: {}", p[0], feature),
                format!("Value: {}", if p[1] == 1 { "Enabled" } else { "Disabled" }),
            ]
        }

        _ => vec![],
    }
}

// ── HCI event parameter decoders ──────────────────────────────────────────────

fn decode_event_params(code: u8, p: &[u8]) -> Vec<String> {
    match code {
        // Command Complete  [num_hci_cmds(1), opcode(2), return_params...]
        0x0E if p.len() >= 3 => {
            let opcode = u16::from_le_bytes([p[1], p[2]]);
            let ogf    = (opcode >> 10) as u8;
            let ocf    = opcode & 0x03FF;
            let status_str = if p.len() >= 4 {
                format!("  status=0x{:02X} ({})", p[3], hci_error_name(p[3]))
            } else { String::new() };
            let mut out = vec![
                format!("Num HCI cmds: {}", p[0]),
                format!("Opcode: 0x{opcode:04X}  {}  (OGF={} OCF=0x{ocf:03X}){status_str}",
                    hci_command_name(ogf, ocf), ogf_name(ogf)),
            ];
            // Decode return params for known commands
            if p.len() >= 4 {
                out.extend(decode_cmd_complete_return(ogf, ocf, &p[3..]));
            }
            out
        }

        // Command Status  [status(1), num_hci_cmds(1), opcode(2)]
        0x0F if p.len() >= 4 => {
            let opcode = u16::from_le_bytes([p[2], p[3]]);
            let ogf    = (opcode >> 10) as u8;
            let ocf    = opcode & 0x03FF;
            vec![
                format!("Status: 0x{:02X}  {}", p[0], hci_error_name(p[0])),
                format!("Num HCI cmds: {}", p[1]),
                format!("Opcode: 0x{opcode:04X}  {}  (OGF={} OCF=0x{ocf:03X})",
                    hci_command_name(ogf, ocf), ogf_name(ogf)),
            ]
        }

        // Connection Complete  [status(1), handle(2), bd_addr(6), link_type(1), encryption(1)]
        0x04 if p.len() >= 11 => {
            let handle = u16::from_le_bytes([p[1], p[2]]) & 0x0FFF;
            vec![
                format!("Status: 0x{:02X}  {}", p[0], hci_error_name(p[0])),
                format!("Handle: 0x{handle:03X}"),
                format!("BD_ADDR: {}", fmt_bd_addr(&p[3..9])),
                format!("Link type: {}", if p[9] == 1 { "ACL" } else { "SCO" }),
                format!("Encryption: {}", if p[10] == 0 { "Disabled" } else { "Enabled" }),
            ]
        }

        // Disconnection Complete  [status(1), handle(2), reason(1)]
        0x06 if p.len() >= 4 => {
            let handle = u16::from_le_bytes([p[1], p[2]]) & 0x0FFF;
            vec![
                format!("Status: 0x{:02X}  {}", p[0], hci_error_name(p[0])),
                format!("Handle: 0x{handle:03X}"),
                format!("Reason: 0x{:02X}  {}", p[3], hci_error_name(p[3])),
            ]
        }

        // Remote Name Request Complete  [status(1), bd_addr(6), name(248)]
        0x07 if p.len() >= 7 => {
            let name_bytes = &p[7..p.len().min(7 + 248)];
            let nul = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
            let name = String::from_utf8_lossy(&name_bytes[..nul]).to_string();
            vec![
                format!("Status: 0x{:02X}  {}", p[0], hci_error_name(p[0])),
                format!("BD_ADDR: {}", fmt_bd_addr(&p[1..7])),
                format!("Name: \"{}\"", name),
            ]
        }

        // Inquiry Complete  [status(1)]
        0x01 if !p.is_empty() => {
            vec![format!("Status: 0x{:02X}  {}", p[0], hci_error_name(p[0]))]
        }

        // Inquiry Result  [num_responses(1), bd_addr(6*n), ...]
        0x02 if !p.is_empty() => {
            let n = p[0] as usize;
            let mut out = vec![format!("Num responses: {n}")];
            for i in 0..n.min(4) {
                let off = 1 + i * 6;
                if off + 6 <= p.len() {
                    out.push(format!("  [{i}] BD_ADDR: {}", fmt_bd_addr(&p[off..off+6])));
                }
            }
            out
        }

        // Number of Completed Packets  [num_handles(1), (handle(2), count(2)) * n]
        0x13 if !p.is_empty() => {
            let n = p[0] as usize;
            let mut out = vec![format!("Num handles: {n}")];
            for i in 0..n.min(8) {
                let off = 1 + i * 4;
                if off + 4 <= p.len() {
                    let handle = u16::from_le_bytes([p[off], p[off+1]]) & 0x0FFF;
                    let count  = u16::from_le_bytes([p[off+2], p[off+3]]);
                    out.push(format!("  handle=0x{handle:03X}  completed={count}"));
                }
            }
            out
        }

        // Hardware Error  [hardware_code(1)]
        0x10 if !p.is_empty() => {
            vec![format!("Hardware code: 0x{:02X}", p[0])]
        }

        // Extended Inquiry Result  [num(1), bd_addr(6), page_scan_rpt(1), rsvd(2), cod(3), clk_off(2), rssi(1), ext(240)]
        0x2F if p.len() >= 15 => {
            let rssi_off = 14;
            let rssi = p[rssi_off] as i8;
            let cod  = u32::from_le_bytes([p[8], p[9], p[10], 0]);
            vec![
                format!("BD_ADDR: {}", fmt_bd_addr(&p[1..7])),
                format!("CoD: 0x{cod:06X}  {}", class_of_device(cod)),
                format!("RSSI: {rssi} dBm"),
            ]
        }

        // LE Meta Event  [subevent(1), ...]
        0x3E if !p.is_empty() => decode_le_meta(p),

        _ => vec![],
    }
}

fn decode_cmd_complete_return(ogf: u8, ocf: u16, ret: &[u8]) -> Vec<String> {
    match (ogf, ocf) {
        // Read BD_ADDR  [status(1), bd_addr(6)]
        (0x04, 0x009) if ret.len() >= 7 => {
            vec![format!("BD_ADDR: {}", fmt_bd_addr(&ret[1..7]))]
        }
        // Read Local Version  [status(1), hci_version(1), hci_rev(2), lmp_version(1), mfr(2), lmp_subversion(2)]
        (0x04, 0x001) if ret.len() >= 9 => {
            vec![
                format!("HCI version: {} (0x{:02X})", bt_hci_version(ret[1]), ret[1]),
                format!("LMP version: 0x{:02X}", ret[4]),
                format!("Manufacturer: 0x{:04X}", u16::from_le_bytes([ret[5], ret[6]])),
            ]
        }
        // Read Buffer Size  [status(1), acl_data_pkt_len(2), sync_data_pkt_len(1), total_acl(2), total_sync(2)]
        (0x04, 0x005) if ret.len() >= 8 => {
            let acl_len   = u16::from_le_bytes([ret[1], ret[2]]);
            let total_acl = u16::from_le_bytes([ret[4], ret[5]]);
            vec![
                format!("ACL packet len: {acl_len}  total buffers: {total_acl}"),
            ]
        }
        _ => vec![],
    }
}

fn decode_le_meta(p: &[u8]) -> Vec<String> {
    if p.is_empty() { return vec![]; }
    let subevent = p[0];
    let sub_name = match subevent {
        0x01 => "LE Connection Complete",
        0x02 => "LE Advertising Report",
        0x03 => "LE Connection Update Complete",
        0x04 => "LE Read Remote Features Complete",
        0x05 => "LE Long Term Key Request",
        0x0A => "LE Enhanced Connection Complete",
        0x12 => "LE Extended Advertising Report",
        0x13 => "LE Periodic Advertising Sync Established",
        0x14 => "LE Periodic Advertising Report",
        0x15 => "LE Periodic Advertising Sync Lost",
        0x16 => "LE Scan Timeout",
        0x17 => "LE Advertising Set Terminated",
        // LE Audio (BT 5.2+)
        0x19 => "LE CIS Established",
        0x1A => "LE CIS Request",
        0x1B => "LE Create BIG Complete",
        0x1C => "LE Terminate BIG Complete",
        0x1D => "LE BIG Sync Established",
        0x1E => "LE BIG Sync Lost",
        0x1F => "LE Request Peer SCA Complete",
        0x20 => "LE Path Loss Threshold",
        0x21 => "LE Transmit Power Reporting",
        0x22 => "LE BIGInfo Advertising Report",
        _    => "LE Meta (unknown subevent)",
    };
    let mut out = vec![format!("Subevent: 0x{subevent:02X}  {sub_name}")];
    match subevent {
        // LE Connection Complete  [subevent(1), status(1), handle(2), role(1), peer_addr_type(1), peer_addr(6), interval(2), latency(2), timeout(2), accuracy(1)]
        0x01 if p.len() >= 19 => {
            let handle   = u16::from_le_bytes([p[2], p[3]]) & 0x0FFF;
            let interval = u16::from_le_bytes([p[8], p[9]]) as f32 * 1.25;
            let timeout  = u16::from_le_bytes([p[12], p[13]]) as u32 * 10;
            out.push(format!("Status: 0x{:02X}  {}", p[1], hci_error_name(p[1])));
            out.push(format!("Handle: 0x{handle:03X}  Role: {}",
                if p[4] == 0 { "Central" } else { "Peripheral" }));
            out.push(format!("Peer: {} {}", le_addr_type(p[5]), fmt_bd_addr(&p[6..12])));
            out.push(format!("Interval: {interval:.2}ms  Timeout: {timeout}ms"));
        }
        // LE Advertising Report  [subevent(1), num(1), (evt_type(1), addr_type(1), addr(6), data_len(1), data(n), rssi(1))*]
        0x02 if p.len() >= 3 => {
            let n = p[1] as usize;
            out.push(format!("Num reports: {n}"));
            let mut off = 2;
            for i in 0..n.min(3) {
                if off + 9 > p.len() { break; }
                let evt_type  = p[off];
                let addr_type = p[off+1];
                let addr = fmt_bd_addr(&p[off+2..off+8]);
                let data_len = p[off+8] as usize;
                let rssi_off = off + 9 + data_len;
                let rssi = if rssi_off < p.len() { p[rssi_off] as i8 } else { 0 };
                let evt_str = match evt_type {
                    0 => "ADV_IND", 1 => "ADV_DIRECT_IND", 2 => "ADV_SCAN_IND",
                    3 => "ADV_NONCONN_IND", 4 => "SCAN_RSP", _ => "?",
                };
                out.push(format!("  [{i}] {evt_str}  {} {}  rssi={rssi}dBm", le_addr_type(addr_type), addr));
                off += 9 + data_len + 1;
            }
        }

        // ── LE Audio events ──────────────────────────────────────────────────

        // LE CIS Established  [sub(1), status(1), cis_handle(2), cig_sync_delay(3),
        //   cis_sync_delay(3), transport_latency_c_to_p(3), transport_latency_p_to_c(3),
        //   phy_c_to_p(1), phy_p_to_c(1), nse(1), bn_c_to_p(1), bn_p_to_c(1),
        //   ft_c_to_p(1), ft_p_to_c(1), max_pdu_c_to_p(2), max_pdu_p_to_c(2),
        //   iso_interval(2)]
        0x19 if p.len() >= 29 => {
            let handle       = u16::from_le_bytes([p[2], p[3]]) & 0x0FFF;
            let lat_cp       = u32::from_le_bytes([p[10], p[11], p[12], 0]);
            let lat_pc       = u32::from_le_bytes([p[13], p[14], p[15], 0]);
            let phy_cp       = phy_name(p[16]);
            let phy_pc       = phy_name(p[17]);
            let iso_interval = u16::from_le_bytes([p[27], p[28]]) as f32 * 1.25;
            out.push(format!("Status: 0x{:02X}  {}", p[1], hci_error_name(p[1])));
            out.push(format!("CIS Handle: 0x{handle:03X}"));
            out.push(format!("Transport latency C→P: {lat_cp}µs  P→C: {lat_pc}µs"));
            out.push(format!("PHY C→P: {phy_cp}  P→C: {phy_pc}"));
            out.push(format!("ISO interval: {iso_interval:.2}ms"));
        }

        // LE CIS Request  [sub(1), acl_handle(2), cis_handle(2), cig_id(1), cis_id(1)]
        0x1A if p.len() >= 7 => {
            let acl_h = u16::from_le_bytes([p[1], p[2]]) & 0x0FFF;
            let cis_h = u16::from_le_bytes([p[3], p[4]]) & 0x0FFF;
            out.push(format!("ACL Handle: 0x{acl_h:03X}  CIS Handle: 0x{cis_h:03X}"));
            out.push(format!("CIG ID: 0x{:02X}  CIS ID: 0x{:02X}", p[5], p[6]));
        }

        // LE Create BIG Complete  [sub(1), status(1), big_handle(1), big_sync_delay(3),
        //   transport_latency_big(3), phy(1), nse(1), bn(1), pto(1), irc(1),
        //   max_pdu(2), iso_interval(2), num_bis(1), (bis_handle(2))*]
        0x1B if p.len() >= 18 => {
            let status      = p[1];
            let big_h       = p[2];
            let sync_delay  = u32::from_le_bytes([p[3], p[4], p[5], 0]);
            let transport   = u32::from_le_bytes([p[6], p[7], p[8], 0]);
            let phy         = phy_name(p[9]);
            let iso_int     = u16::from_le_bytes([p[15], p[16]]) as f32 * 1.25;
            let num_bis     = p[17] as usize;
            out.push(format!("Status: 0x{status:02X}  {}", hci_error_name(status)));
            out.push(format!("BIG Handle: 0x{big_h:02X}  PHY: {phy}"));
            out.push(format!("BIG sync delay: {sync_delay}µs  Transport latency: {transport}µs"));
            out.push(format!("ISO interval: {iso_int:.2}ms  Num BIS: {num_bis}"));
            let bis: Vec<String> = (0..num_bis.min(8)).filter_map(|i| {
                let off = 18 + i * 2;
                if off + 2 <= p.len() {
                    let h = u16::from_le_bytes([p[off], p[off+1]]) & 0x0FFF;
                    Some(format!("0x{h:03X}"))
                } else { None }
            }).collect();
            if !bis.is_empty() {
                out.push(format!("BIS handles: {}", bis.join(", ")));
            }
        }

        // LE Terminate BIG Complete  [sub(1), big_handle(1), reason(1)]
        0x1C if p.len() >= 3 => {
            out.push(format!("BIG Handle: 0x{:02X}", p[1]));
            out.push(format!("Reason: 0x{:02X}  {}", p[2], hci_error_name(p[2])));
        }

        // LE BIG Sync Established  [sub(1), status(1), big_handle(1), transport_latency(3),
        //   nse(1), bn(1), pto(1), irc(1), max_pdu(2), iso_interval(2), num_bis(1), (bis_handle(2))*]
        0x1D if p.len() >= 14 => {
            let status    = p[1];
            let big_h     = p[2];
            let transport = u32::from_le_bytes([p[3], p[4], p[5], 0]);
            let iso_int   = u16::from_le_bytes([p[11], p[12]]) as f32 * 1.25;
            let num_bis   = p[13] as usize;
            out.push(format!("Status: 0x{status:02X}  {}", hci_error_name(status)));
            out.push(format!("BIG Handle: 0x{big_h:02X}  Transport latency: {transport}µs"));
            out.push(format!("ISO interval: {iso_int:.2}ms  Num BIS: {num_bis}"));
            let bis: Vec<String> = (0..num_bis.min(8)).filter_map(|i| {
                let off = 14 + i * 2;
                if off + 2 <= p.len() {
                    let h = u16::from_le_bytes([p[off], p[off+1]]) & 0x0FFF;
                    Some(format!("0x{h:03X}"))
                } else { None }
            }).collect();
            if !bis.is_empty() {
                out.push(format!("BIS handles: {}", bis.join(", ")));
            }
        }

        // LE BIG Sync Lost  [sub(1), big_handle(1), reason(1)]
        0x1E if p.len() >= 3 => {
            out.push(format!("BIG Handle: 0x{:02X}", p[1]));
            out.push(format!("Reason: 0x{:02X}  {}", p[2], hci_error_name(p[2])));
        }

        // LE BIGInfo Advertising Report  [sub(1), sync_handle(2), num_bis(1), nse(1),
        //   iso_interval(2), bn(1), pto(1), irc(1), max_pdu(2), sdu_interval(3),
        //   max_sdu(2), phy(1), framing(1), encryption(1)]
        0x22 if p.len() >= 19 => {
            let sync_h    = u16::from_le_bytes([p[1], p[2]]);
            let num_bis   = p[3];
            let iso_int   = u16::from_le_bytes([p[5], p[6]]) as f32 * 1.25;
            let sdu_int   = u32::from_le_bytes([p[11], p[12], p[13], 0]);
            let max_sdu   = u16::from_le_bytes([p[14], p[15]]);
            let phy       = phy_name(p[16]);
            let encrypted = p[18] != 0;
            out.push(format!("Sync Handle: 0x{sync_h:04X}  Num BIS: {num_bis}  PHY: {phy}"));
            out.push(format!("ISO interval: {iso_int:.2}ms  SDU interval: {sdu_int}µs  Max SDU: {max_sdu}"));
            out.push(format!("Framing: {}  Encrypted: {}", if p[17] == 0 { "Unframed" } else { "Framed" }, encrypted));
        }

        _ => {}
    }
    out
}

// ── L2CAP decoder ─────────────────────────────────────────────────────────────

fn decode_l2cap_payload(cid: u16, d: &[u8]) -> Vec<String> {
    match cid {
        // ATT (Attribute Protocol)
        0x0004 if !d.is_empty() => decode_att(d),
        // LE L2CAP Signaling
        0x0005 if d.len() >= 4 => {
            let code   = d[0];
            let id     = d[1];
            let length = u16::from_le_bytes([d[2], d[3]]);
            let name   = match code {
                0x01 => "Command Reject",    0x06 => "Disconnect Request",
                0x07 => "Disconnect Response",
                0x12 => "Connection Parameter Update Request",
                0x13 => "Connection Parameter Update Response",
                0x14 => "LE Credit Based Connection Request",
                0x15 => "LE Credit Based Connection Response",
                0x16 => "LE Flow Control Credit",
                _ => "?",
            };
            vec![format!("  L2CAP Signal code=0x{code:02X} ({name}) id={id} len={length}")]
        }
        // SMP (Security Manager)
        0x0006 if !d.is_empty() => {
            let cmd = d[0];
            let name = match cmd {
                0x01 => "Pairing Request",  0x02 => "Pairing Response",
                0x03 => "Pairing Confirm",  0x04 => "Pairing Random",
                0x05 => "Pairing Failed",   0x06 => "Encryption Information",
                0x07 => "Central ID",       0x08 => "Identity Information",
                0x09 => "Identity Address", 0x0A => "Signing Information",
                0x0B => "Security Request", 0x0C => "Pairing Public Key",
                0x0D => "Pairing DH Key Check", 0x0E => "Pairing Keypress",
                _ => "?",
            };
            vec![format!("  SMP  cmd=0x{cmd:02X}  {name}")]
        }
        _ => vec![],
    }
}

fn decode_att(d: &[u8]) -> Vec<String> {
    if d.is_empty() { return vec![]; }
    let opcode = d[0];
    let name = match opcode {
        0x01 => "Error Response",
        0x02 => "Exchange MTU Request",  0x03 => "Exchange MTU Response",
        0x04 => "Find Information Request",   0x05 => "Find Information Response",
        0x06 => "Find By Type Value Request", 0x07 => "Find By Type Value Response",
        0x08 => "Read By Type Request",       0x09 => "Read By Type Response",
        0x0A => "Read Request",               0x0B => "Read Response",
        0x0C => "Read Blob Request",          0x0D => "Read Blob Response",
        0x0E => "Read Multiple Request",      0x0F => "Read Multiple Response",
        0x10 => "Read By Group Type Request", 0x11 => "Read By Group Type Response",
        0x12 => "Write Request",              0x13 => "Write Response",
        0x16 => "Prepare Write Request",      0x17 => "Prepare Write Response",
        0x18 => "Execute Write Request",      0x19 => "Execute Write Response",
        0x1B => "Handle Value Notification",
        0x1D => "Handle Value Indication",    0x1E => "Handle Value Confirmation",
        0x52 => "Write Command",
        _ => "?",
    };
    let mut out = vec![format!("  ATT  opcode=0x{opcode:02X}  {name}")];
    match opcode {
        // Error Response  [req_opcode(1), handle(2), error(1)]
        0x01 if d.len() >= 5 => {
            let handle = u16::from_le_bytes([d[2], d[3]]);
            out.push(format!("  req=0x{:02X}  handle=0x{handle:04X}  error=0x{:02X}", d[1], d[4]));
        }
        // Exchange MTU  [mtu(2)]
        0x02 | 0x03 if d.len() >= 3 => {
            out.push(format!("  MTU: {}", u16::from_le_bytes([d[1], d[2]])));
        }
        // Read By Type / Group Type Request  [start(2), end(2), uuid(2 or 16)]
        0x08 | 0x10 if d.len() >= 7 => {
            let start = u16::from_le_bytes([d[1], d[2]]);
            let end   = u16::from_le_bytes([d[3], d[4]]);
            let uuid  = u16::from_le_bytes([d[5], d[6]]);
            let name  = gatt_uuid_name(uuid);
            let uuid_str = if name.is_empty() {
                format!("0x{uuid:04X}")
            } else {
                format!("0x{uuid:04X} ({name})")
            };
            out.push(format!("  handle 0x{start:04X}–0x{end:04X}  uuid={uuid_str}"));
        }
        // Read By Type / Group Type Response  [len(1), (handle(2), value(len-2))*]
        0x09 | 0x11 if d.len() >= 4 => {
            let item_len = d[1] as usize;
            if item_len >= 2 {
                let n = (d.len() - 2) / item_len;
                out.push(format!("  {n} attribute(s), item_len={item_len}"));
                for i in 0..n.min(4) {
                    let off = 2 + i * item_len;
                    if off + 2 <= d.len() {
                        let h = u16::from_le_bytes([d[off], d[off+1]]);
                        out.push(format!("  [{i}] handle=0x{h:04X}"));
                    }
                }
            }
        }
        // Read / Write Request  [handle(2)]
        0x0A | 0x12 | 0x52 if d.len() >= 3 => {
            let handle = u16::from_le_bytes([d[1], d[2]]);
            out.push(format!("  handle=0x{handle:04X}"));
        }
        // Handle Value Notification / Indication  [handle(2), value...]
        0x1B | 0x1D if d.len() >= 3 => {
            let handle = u16::from_le_bytes([d[1], d[2]]);
            let val = &d[3..d.len().min(19)];
            out.push(format!("  handle=0x{handle:04X}  value={}", hex_bytes(val)));
        }
        _ => {}
    }
    out
}

// ── Lookup tables ─────────────────────────────────────────────────────────────

fn hci_command_name(ogf: u8, ocf: u16) -> &'static str {
    match (ogf, ocf) {
        // ── OGF 0x01  Link Control ────────────────────────────────────────────
        (0x01, 0x001) => "Inquiry",
        (0x01, 0x002) => "Inquiry Cancel",
        (0x01, 0x003) => "Periodic Inquiry Mode",
        (0x01, 0x004) => "Exit Periodic Inquiry Mode",
        (0x01, 0x005) => "Create Connection",
        (0x01, 0x006) => "Disconnect",
        (0x01, 0x008) => "Create Connection Cancel",
        (0x01, 0x009) => "Accept Connection Request",
        (0x01, 0x00A) => "Reject Connection Request",
        (0x01, 0x00B) => "Link Key Request Reply",
        (0x01, 0x00C) => "Link Key Request Negative Reply",
        (0x01, 0x00D) => "PIN Code Request Reply",
        (0x01, 0x00E) => "PIN Code Request Negative Reply",
        (0x01, 0x00F) => "Change Connection Packet Type",
        (0x01, 0x011) => "Authentication Requested",
        (0x01, 0x013) => "Set Connection Encryption",
        (0x01, 0x015) => "Change Connection Link Key",
        (0x01, 0x019) => "Remote Name Request",
        (0x01, 0x01A) => "Remote Name Request Cancel",
        (0x01, 0x01B) => "Read Remote Supported Features",
        (0x01, 0x01C) => "Read Remote Extended Features",
        (0x01, 0x01D) => "Read Remote Version Information",
        (0x01, 0x01F) => "Read Clock Offset",
        (0x01, 0x028) => "Setup Synchronous Connection",
        (0x01, 0x029) => "Accept Synchronous Connection Request",
        (0x01, 0x02A) => "Reject Synchronous Connection Request",
        (0x01, 0x02B) => "IO Capability Request Reply",
        (0x01, 0x02C) => "User Confirmation Request Reply",
        (0x01, 0x02D) => "User Confirmation Request Negative Reply",
        (0x01, 0x02E) => "User Passkey Request Reply",
        (0x01, 0x02F) => "User Passkey Request Negative Reply",
        (0x01, 0x030) => "Remote OOB Data Request Reply",
        (0x01, 0x033) => "Remote OOB Data Request Negative Reply",
        (0x01, 0x034) => "IO Capability Request Negative Reply",
        (0x01, 0x03D) => "Enhanced Setup Synchronous Connection",
        (0x01, 0x03E) => "Enhanced Accept Synchronous Connection Request",
        // ── OGF 0x02  Link Policy ─────────────────────────────────────────────
        (0x02, 0x001) => "Hold Mode",
        (0x02, 0x003) => "Sniff Mode",
        (0x02, 0x004) => "Exit Sniff Mode",
        (0x02, 0x007) => "QoS Setup",
        (0x02, 0x009) => "Role Discovery",
        (0x02, 0x00B) => "Switch Role",
        (0x02, 0x00C) => "Read Link Policy Settings",
        (0x02, 0x00D) => "Write Link Policy Settings",
        (0x02, 0x00E) => "Read Default Link Policy Settings",
        (0x02, 0x00F) => "Write Default Link Policy Settings",
        (0x02, 0x010) => "Flow Specification",
        (0x02, 0x011) => "Sniff Subrating",
        // ── OGF 0x03  Controller & Baseband ──────────────────────────────────
        (0x03, 0x001) => "Set Event Mask",
        (0x03, 0x003) => "Reset",
        (0x03, 0x005) => "Set Event Filter",
        (0x03, 0x008) => "Flush",
        (0x03, 0x009) => "Read PIN Type",
        (0x03, 0x00A) => "Write PIN Type",
        (0x03, 0x00D) => "Read Stored Link Key",
        (0x03, 0x011) => "Write Stored Link Key",
        (0x03, 0x012) => "Delete Stored Link Key",
        (0x03, 0x013) => "Write Local Name",
        (0x03, 0x014) => "Read Local Name",
        (0x03, 0x015) => "Read Connection Accept Timeout",
        (0x03, 0x016) => "Write Connection Accept Timeout",
        (0x03, 0x017) => "Read Page Timeout",
        (0x03, 0x018) => "Write Page Timeout",
        (0x03, 0x019) => "Read Scan Enable",
        (0x03, 0x01A) => "Write Scan Enable",
        (0x03, 0x01B) => "Read Page Scan Activity",
        (0x03, 0x01C) => "Write Page Scan Activity",
        (0x03, 0x01D) => "Read Inquiry Scan Activity",
        (0x03, 0x01E) => "Write Inquiry Scan Activity",
        (0x03, 0x01F) => "Read Authentication Enable",
        (0x03, 0x020) => "Write Authentication Enable",
        (0x03, 0x023) => "Read Class of Device",
        (0x03, 0x024) => "Write Class of Device",
        (0x03, 0x025) => "Read Voice Setting",
        (0x03, 0x026) => "Write Voice Setting",
        (0x03, 0x02D) => "Read Transmit Power Level",
        (0x03, 0x031) => "Set Controller To Host Flow Control",
        (0x03, 0x033) => "Host Buffer Size",
        (0x03, 0x035) => "Host Number of Completed Packets",
        (0x03, 0x036) => "Read Link Supervision Timeout",
        (0x03, 0x037) => "Write Link Supervision Timeout",
        (0x03, 0x03F) => "Set AFH Host Channel Classification",
        (0x03, 0x042) => "Read Inquiry Scan Type",
        (0x03, 0x043) => "Write Inquiry Scan Type",
        (0x03, 0x044) => "Read Inquiry Mode",
        (0x03, 0x045) => "Write Inquiry Mode",
        (0x03, 0x046) => "Read Page Scan Type",
        (0x03, 0x047) => "Write Page Scan Type",
        (0x03, 0x051) => "Read Extended Inquiry Response",
        (0x03, 0x052) => "Write Extended Inquiry Response",
        (0x03, 0x053) => "Refresh Encryption Key",
        (0x03, 0x055) => "Read Simple Pairing Mode",
        (0x03, 0x056) => "Write Simple Pairing Mode",
        (0x03, 0x057) => "Read Local OOB Data",
        (0x03, 0x058) => "Read Inquiry Response Transmit Power Level",
        (0x03, 0x059) => "Write Inquiry Transmit Power Level",
        (0x03, 0x05F) => "Enhanced Flush",
        (0x03, 0x060) => "Send Keypress Notification",
        (0x03, 0x066) => "Read Flow Control Mode",
        (0x03, 0x067) => "Write Flow Control Mode",
        (0x03, 0x06C) => "Read LE Host Support",
        (0x03, 0x06D) => "Write LE Host Support",
        (0x03, 0x079) => "Read Secure Connections Host Support",
        (0x03, 0x07A) => "Write Secure Connections Host Support",
        (0x03, 0x07B) => "Read Authenticated Payload Timeout",
        (0x03, 0x07C) => "Write Authenticated Payload Timeout",
        (0x03, 0x082) => "Set Ecosystem Base Interval",
        (0x03, 0x083) => "Configure Data Path",
        (0x03, 0x084) => "Set Min Encryption Key Size",
        // ── OGF 0x04  Informational ───────────────────────────────────────────
        (0x04, 0x001) => "Read Local Version Information",
        (0x04, 0x002) => "Read Local Supported Commands",
        (0x04, 0x003) => "Read Local Supported Features",
        (0x04, 0x004) => "Read Local Extended Features",
        (0x04, 0x005) => "Read Buffer Size",
        (0x04, 0x009) => "Read BD_ADDR",
        (0x04, 0x00A) => "Read Data Block Size",
        (0x04, 0x00B) => "Read Local Supported Codecs",
        (0x04, 0x00C) => "Read Local Simple Pairing Options",
        (0x04, 0x00E) => "Read Local Supported Codec Capabilities",
        (0x04, 0x00F) => "Read Local Supported Controller Delay",
        // ── OGF 0x05  Status ──────────────────────────────────────────────────
        (0x05, 0x001) => "Read Failed Contact Counter",
        (0x05, 0x002) => "Reset Failed Contact Counter",
        (0x05, 0x003) => "Read Link Quality",
        (0x05, 0x005) => "Read RSSI",
        (0x05, 0x006) => "Read AFH Channel Map",
        (0x05, 0x007) => "Read Clock",
        (0x05, 0x008) => "Read Encryption Key Size",
        (0x05, 0x00D) => "Set Triggered Clock Capture",
        // ── OGF 0x06  Testing ─────────────────────────────────────────────────
        (0x06, 0x001) => "Read Loopback Mode",
        (0x06, 0x002) => "Write Loopback Mode",
        (0x06, 0x003) => "Enable Device Under Test Mode",
        (0x06, 0x004) => "Write Simple Pairing Debug Mode",
        (0x06, 0x00A) => "Write Secure Connections Test Mode",
        // ── OGF 0x08  LE Controller ───────────────────────────────────────────
        (0x08, 0x001) => "LE Set Event Mask",
        (0x08, 0x002) => "LE Read Buffer Size",
        (0x08, 0x003) => "LE Read Local Supported Features",
        (0x08, 0x005) => "LE Set Random Address",
        (0x08, 0x006) => "LE Set Advertising Parameters",
        (0x08, 0x007) => "LE Read Advertising Physical Channel TX Power",
        (0x08, 0x008) => "LE Set Advertising Data",
        (0x08, 0x009) => "LE Set Scan Response Data",
        (0x08, 0x00A) => "LE Set Advertising Enable",
        (0x08, 0x00B) => "LE Set Scan Parameters",
        (0x08, 0x00C) => "LE Set Scan Enable",
        (0x08, 0x00D) => "LE Create Connection",
        (0x08, 0x00E) => "LE Create Connection Cancel",
        (0x08, 0x00F) => "LE Read Filter Accept List Size",
        (0x08, 0x010) => "LE Clear Filter Accept List",
        (0x08, 0x011) => "LE Add Device To Filter Accept List",
        (0x08, 0x012) => "LE Remove Device From Filter Accept List",
        (0x08, 0x013) => "LE Connection Update",
        (0x08, 0x014) => "LE Set Host Channel Classification",
        (0x08, 0x015) => "LE Read Channel Map",
        (0x08, 0x016) => "LE Read Remote Features",
        (0x08, 0x017) => "LE Encrypt",
        (0x08, 0x018) => "LE Rand",
        (0x08, 0x019) => "LE Enable Encryption",
        (0x08, 0x01A) => "LE Long Term Key Request Reply",
        (0x08, 0x01B) => "LE Long Term Key Request Negative Reply",
        (0x08, 0x01C) => "LE Read Supported States",
        (0x08, 0x01D) => "LE Receiver Test",
        (0x08, 0x01E) => "LE Transmitter Test",
        (0x08, 0x01F) => "LE Test End",
        (0x08, 0x020) => "LE Remote Connection Parameter Request Reply",
        (0x08, 0x021) => "LE Remote Connection Parameter Request Negative Reply",
        (0x08, 0x022) => "LE Set Data Length",
        (0x08, 0x023) => "LE Read Suggested Default Data Length",
        (0x08, 0x024) => "LE Write Suggested Default Data Length",
        (0x08, 0x026) => "LE Generate DHKey",
        (0x08, 0x027) => "LE Add Device To Resolving List",
        (0x08, 0x028) => "LE Remove Device From Resolving List",
        (0x08, 0x029) => "LE Clear Resolving List",
        (0x08, 0x02A) => "LE Read Resolving List Size",
        (0x08, 0x02B) => "LE Read Peer Resolvable Address",
        (0x08, 0x02C) => "LE Read Local Resolvable Address",
        (0x08, 0x02D) => "LE Set Address Resolution Enable",
        (0x08, 0x02E) => "LE Set Resolvable Private Address Timeout",
        (0x08, 0x02F) => "LE Read Maximum Data Length",
        (0x08, 0x030) => "LE Read PHY",
        (0x08, 0x031) => "LE Set Default PHY",
        (0x08, 0x032) => "LE Set PHY",
        (0x08, 0x035) => "LE Set Advertising Set Random Address",
        (0x08, 0x036) => "LE Set Extended Advertising Parameters",
        (0x08, 0x037) => "LE Set Extended Advertising Data",
        (0x08, 0x038) => "LE Set Extended Scan Response Data",
        (0x08, 0x039) => "LE Set Extended Advertising Enable",
        (0x08, 0x03A) => "LE Read Maximum Advertising Data Length",
        (0x08, 0x03B) => "LE Read Number Of Supported Advertising Sets",
        (0x08, 0x03C) => "LE Remove Advertising Set",
        (0x08, 0x03D) => "LE Clear Advertising Sets",
        (0x08, 0x03E) => "LE Set Periodic Advertising Parameters",
        (0x08, 0x03F) => "LE Set Periodic Advertising Data",
        (0x08, 0x040) => "LE Set Periodic Advertising Enable",
        (0x08, 0x041) => "LE Set Extended Scan Parameters",
        (0x08, 0x042) => "LE Set Extended Scan Enable",
        (0x08, 0x043) => "LE Extended Create Connection",
        (0x08, 0x044) => "LE Periodic Advertising Create Sync",
        (0x08, 0x045) => "LE Periodic Advertising Create Sync Cancel",
        (0x08, 0x046) => "LE Periodic Advertising Terminate Sync",
        (0x08, 0x047) => "LE Add Device To Periodic Advertiser List",
        (0x08, 0x048) => "LE Remove Device From Periodic Advertiser List",
        (0x08, 0x049) => "LE Clear Periodic Advertiser List",
        (0x08, 0x04A) => "LE Read Periodic Advertiser List Size",
        (0x08, 0x04B) => "LE Read Transmit Power",
        (0x08, 0x04C) => "LE Read RF Path Compensation",
        (0x08, 0x04D) => "LE Write RF Path Compensation",
        (0x08, 0x04E) => "LE Set Privacy Mode",
        (0x08, 0x051) => "LE Set Connectionless CTE Transmit Parameters",
        (0x08, 0x052) => "LE Set Connectionless CTE Transmit Enable",
        (0x08, 0x053) => "LE Set Connectionless IQ Sampling Enable",
        (0x08, 0x054) => "LE Set Connection CTE Receive Parameters",
        (0x08, 0x055) => "LE Set Connection CTE Transmit Parameters",
        (0x08, 0x056) => "LE Connection CTE Request Enable",
        (0x08, 0x057) => "LE Connection CTE Response Enable",
        (0x08, 0x058) => "LE Read Antenna Information",
        (0x08, 0x059) => "LE Set Periodic Advertising Receive Enable",
        (0x08, 0x05A) => "LE Periodic Advertising Sync Transfer",
        (0x08, 0x05B) => "LE Periodic Advertising Set Info Transfer",
        (0x08, 0x05C) => "LE Set Periodic Advertising Sync Transfer Parameters",
        (0x08, 0x05D) => "LE Set Default Periodic Advertising Sync Transfer Parameters",
        (0x08, 0x05F) => "LE Modify Sleep Clock Accuracy",
        // ── OGF 0x08  LE Audio (BT 5.2+) ─────────────────────────────────────
        (0x08, 0x061) => "LE Read ISO TX Sync",
        (0x08, 0x062) => "LE Set CIG Parameters",
        (0x08, 0x063) => "LE Set CIG Parameters Test",
        (0x08, 0x064) => "LE Create CIS",
        (0x08, 0x065) => "LE Remove CIG",
        (0x08, 0x066) => "LE Accept CIS Request",
        (0x08, 0x067) => "LE Reject CIS Request",
        (0x08, 0x068) => "LE Create BIG",
        (0x08, 0x069) => "LE Create BIG Test",
        (0x08, 0x06A) => "LE Terminate BIG",
        (0x08, 0x06B) => "LE BIG Create Sync",
        (0x08, 0x06C) => "LE BIG Terminate Sync",
        (0x08, 0x06D) => "LE Request Peer SCA",
        (0x08, 0x06E) => "LE Setup ISO Data Path",
        (0x08, 0x06F) => "LE Remove ISO Data Path",
        (0x08, 0x070) => "LE ISO Transmit Test",
        (0x08, 0x071) => "LE ISO Receive Test",
        (0x08, 0x072) => "LE ISO Read Test Counters",
        (0x08, 0x073) => "LE ISO Test End",
        (0x08, 0x074) => "LE Set Host Feature",
        (0x08, 0x075) => "LE Read ISO Link Quality",
        (0x08, 0x076) => "LE Enhanced Read Transmit Power Level",
        (0x08, 0x077) => "LE Read Remote Transmit Power Level",
        (0x08, 0x078) => "LE Set Path Loss Reporting Parameters",
        (0x08, 0x079) => "LE Set Path Loss Reporting Enable",
        (0x08, 0x07A) => "LE Set Transmit Power Reporting Enable",
        (0x08, 0x07C) => "LE Set Data Related Address Changes",
        (0x08, 0x07D) => "LE Set Default Subrate",
        (0x08, 0x07E) => "LE Subrate Request",
        (0x08, 0x082) => "LE Set Periodic Advertising Subevent Data",
        (0x08, 0x083) => "LE Set Periodic Advertising Response Data",
        (0x08, 0x084) => "LE Set Periodic Sync Subevent",
        (0x08, 0x087) => "LE Read All Local Supported Features",
        (0x08, 0x088) => "LE Read All Remote Features",
        (0x08, 0x089) => "LE CS Read Local Supported Capabilities",
        (0x08, 0x08A) => "LE CS Read Remote Supported Capabilities",
        (0x08, 0x08B) => "LE CS Write Cached Remote Supported Capabilities",
        (0x08, 0x08C) => "LE CS Security Enable",
        (0x08, 0x08D) => "LE CS Set Default Settings",
        (0x08, 0x08E) => "LE CS Read Remote FAE Table",
        (0x08, 0x08F) => "LE CS Write Cached Remote FAE Table",
        (0x08, 0x090) => "LE CS Create Config",
        (0x08, 0x091) => "LE CS Remove Config",
        (0x08, 0x092) => "LE CS Set Channel Classification",
        (0x08, 0x093) => "LE CS Set Procedure Parameters",
        (0x08, 0x094) => "LE CS Procedure Enable",
        (0x08, 0x095) => "LE CS Test",
        (0x08, 0x096) => "LE CS Test End",
        (0x08, 0x098) => "LE Add Device To Monitored Advertisers List",
        (0x08, 0x099) => "LE Remove Device From Monitored Advertisers List",
        (0x08, 0x09A) => "LE Clear Monitored Advertisers List",
        (0x08, 0x09B) => "LE Read Monitored Advertisers List Size",
        (0x08, 0x09C) => "LE Enable Monitoring Advertisers",
        (0x08, 0x09D) => "LE Frame Space Update",
        (0x08, 0x09F) => "LE Enable UTP OTA Mode",
        (0x08, 0x0A0) => "LE UTP Send",
        (0x08, 0x0A1) => "LE Connection Rate Request",
        (0x08, 0x0A2) => "LE Set Default Rate Parameters",
        (0x08, 0x0A3) => "LE Read Minimum Supported Connection Interval",
        _             => "Unknown Command",
    }
}

fn hci_event_name(code: u8) -> &'static str {
    match code {
        0x01 => "Inquiry Complete",
        0x02 => "Inquiry Result",
        0x03 => "Connection Complete",
        0x04 => "Connection Complete (ACL)",
        0x05 => "Connection Request",
        0x06 => "Disconnection Complete",
        0x07 => "Authentication Complete",
        0x08 => "Remote Name Request Complete",
        0x09 => "Encryption Change",
        0x0C => "Read Remote Supported Features Complete",
        0x0D => "Read Remote Version Information Complete",
        0x0E => "Command Complete",
        0x0F => "Command Status",
        0x10 => "Hardware Error",
        0x11 => "Flush Occurred",
        0x12 => "Role Change",
        0x13 => "Number of Completed Packets",
        0x14 => "Mode Change",
        0x17 => "Return Link Keys",
        0x18 => "PIN Code Request",
        0x19 => "Link Key Request",
        0x1A => "Link Key Notification",
        0x1B => "Loopback Command",
        0x1C => "Data Buffer Overflow",
        0x1D => "Max Slots Change",
        0x1E => "Read Clock Offset Complete",
        0x1F => "Connection Packet Type Changed",
        0x20 => "QoS Violation",
        0x22 => "Page Scan Repetition Mode Change",
        0x23 => "Flow Specification Complete",
        0x2F => "Extended Inquiry Result",
        0x30 => "Encryption Key Refresh Complete",
        0x31 => "IO Capability Request",
        0x32 => "IO Capability Response",
        0x33 => "User Confirmation Request",
        0x34 => "User Passkey Request",
        0x35 => "Remote OOB Data Request",
        0x36 => "Simple Pairing Complete",
        0x38 => "Link Supervision Timeout Changed",
        0x39 => "Enhanced Flush Complete",
        0x3B => "User Passkey Notification",
        0x3C => "Keypress Notification",
        0x3D => "Remote Host Supported Features Notification",
        0x3E => "LE Meta Event",
        0xFF => "Vendor Specific",
        _    => "Unknown Event",
    }
}

fn hci_error_name(code: u8) -> &'static str {
    match code {
        0x00 => "Success",
        0x01 => "Unknown Command",
        0x02 => "No Connection",
        0x03 => "Hardware Failure",
        0x04 => "Page Timeout",
        0x05 => "Authentication Failure",
        0x06 => "Key Missing",
        0x07 => "Memory Full",
        0x08 => "Connection Timeout",
        0x09 => "Max Connections",
        0x0C => "Command Disallowed",
        0x0D => "Rejected – Limited Resources",
        0x11 => "Unsupported Feature",
        0x12 => "Invalid Parameter",
        0x13 => "Remote User Terminated",
        0x14 => "Remote – Low Resources",
        0x15 => "Remote – Power Off",
        0x16 => "Connection Terminated (local)",
        0x1A => "Pairing Not Allowed",
        0x22 => "LMP/LL Response Timeout",
        0x26 => "Instant Passed",
        0x29 => "Pairing with Unit Key Not Supported",
        0x2A => "Different Transaction Collision",
        0x3A => "Controller Busy",
        0x3B => "Unacceptable Connection Parameters",
        0x3C => "Directed Advertising Timeout",
        0x3D => "Connection Terminated – MIC Failure",
        0x3E => "Connection Failed – Establishment",
        _    => "?",
    }
}

fn ogf_name(ogf: u8) -> &'static str {
    match ogf {
        0x01 => "Link Control",
        0x02 => "Link Policy",
        0x03 => "Controller/BB",
        0x04 => "Informational",
        0x05 => "Status",
        0x06 => "Testing",
        0x08 => "LE Controller",
        0x3F => "Vendor Specific",
        _    => "?",
    }
}

fn l2cap_cid_name(cid: u16) -> &'static str {
    match cid {
        0x0001 => "L2CAP Signaling",
        0x0002 => "Connectionless",
        0x0003 => "AMP Manager",
        0x0004 => "ATT",
        0x0005 => "LE Signaling",
        0x0006 => "SMP",
        0x0007 => "BR/EDR SMP",
        0x0040..=0x007F => "EATT / LE CoC",  // Enhanced ATT or LE credit-based CoC channels
        _      => if cid >= 0x0080 { "Dynamically allocated" } else { "?" },
    }
}

fn le_addr_type(t: u8) -> &'static str {
    match t { 0 => "Public", 1 => "Random", 2 => "Public ID", 3 => "Random ID", _ => "?" }
}

fn phy_name(phy: u8) -> &'static str {
    match phy { 0x01 => "LE 1M", 0x02 => "LE 2M", 0x03 => "LE Coded", _ => "?" }
}

/// Map a 16-bit GATT UUID to a service or characteristic name.
/// Covers standard GATT services/characteristics and LE Audio profiles.
fn gatt_uuid_name(uuid: u16) -> &'static str {
    match uuid {
        // ── Standard GATT Services ────────────────────────────────────────────
        0x1800 => "Generic Access",
        0x1801 => "Generic Attribute",
        0x1802 => "Immediate Alert",
        0x1803 => "Link Loss",
        0x1804 => "Tx Power",
        0x180A => "Device Information",
        0x180F => "Battery Service",
        // ── LE Audio Services (BT 5.2+) ──────────────────────────────────────
        0x1844 => "VCS – Volume Control Service",
        0x1845 => "VOCS – Volume Offset Control Service",
        0x1846 => "AICS – Audio Input Control Service",
        0x1848 => "MCS – Media Control Service",
        0x1849 => "TBS – Telephone Bearer Service",
        0x184C => "GTBS – Generic Telephone Bearer Service",
        0x184D => "GMCS – Generic Media Control Service",
        0x184E => "ASCS – Audio Stream Control Service",
        0x184F => "BASS – Broadcast Audio Scan Service",
        0x1850 => "PACS – Published Audio Capabilities Service",
        0x1853 => "CSIS – Coordinated Set Identification Service",
        0x1854 => "HAS – Hearing Access Service",
        // ── Standard GATT Characteristics ────────────────────────────────────
        0x2A00 => "Device Name",
        0x2A01 => "Appearance",
        0x2A04 => "Peripheral Preferred Connection Parameters",
        0x2A05 => "Service Changed",
        0x2A19 => "Battery Level",
        0x2A24 => "Model Number String",
        0x2A25 => "Serial Number String",
        0x2A26 => "Firmware Revision String",
        0x2A27 => "Hardware Revision String",
        0x2A28 => "Software Revision String",
        0x2A29 => "Manufacturer Name String",
        // ── LE Audio Characteristics (BT 5.2+) ───────────────────────────────
        0x2B77 => "Sink PAC",
        0x2B78 => "Sink Audio Locations",
        0x2B79 => "Source PAC",
        0x2B7A => "Source Audio Locations",
        0x2B7B => "Available Audio Contexts",
        0x2B7C => "Supported Audio Contexts",
        0x2B7D => "ASE Sink Endpoint",
        0x2B7E => "ASE Source Endpoint",
        0x2B7F => "ASE Control Point",
        0x2B80 => "Broadcast Audio Scan Control Point",
        0x2B81 => "Broadcast Receive State",
        0x2B84 => "Volume State",
        0x2B85 => "Volume Control Point",
        0x2B86 => "Volume Flags",
        0x2B87 => "Media Player Name",
        0x2B88 => "Media Player Icon Object ID",
        0x2B89 => "Media Player Icon URL",
        0x2B8D => "Track Title",
        0x2B8E => "Track Duration",
        0x2B8F => "Track Position",
        0x2B90 => "Playback Speed",
        0x2B91 => "Seeking Speed",
        0x2B93 => "Current Track Segments Object ID",
        0x2B94 => "Current Track Object ID",
        0x2B95 => "Next Track Object ID",
        0x2B96 => "Parent Group Object ID",
        0x2B97 => "Current Group Object ID",
        0x2B9A => "Playing Order",
        0x2B9B => "Playing Orders Supported",
        0x2B9C => "Media State",
        0x2B9D => "Media Control Point",
        0x2B9E => "Media Control Point Opcodes Supported",
        0x2BA0 => "Content Control ID (CCID)",
        0x2BA1 => "Correlated Missed Calls",
        0x2BA2 => "Bearer Provider Name",
        0x2BA3 => "Bearer UCI",
        0x2BA4 => "Bearer Technology",
        0x2BA5 => "Bearer URI Schemes Supported List",
        0x2BA6 => "Bearer Signal Strength",
        0x2BA7 => "Bearer Signal Strength Reporting Interval",
        0x2BA8 => "Bearer List Current Calls",
        0x2BA9 => "Content Control ID",
        0x2BAA => "Status Flags",
        0x2BAB => "Incoming Call Target Bearer URI",
        0x2BAC => "Call State",
        0x2BAD => "Call Control Point",
        0x2BAE => "Call Control Point Optional Opcodes",
        0x2BAF => "Termination Reason",
        0x2BB0 => "Incoming Call",
        0x2BB1 => "Call Friendly Name",
        0x2BBB => "Set Identity Resolving Key",
        0x2BBC => "Coordinated Set Size",
        0x2BBD => "Set Member Lock",
        0x2BBE => "Set Member Rank",
        0x2BBF => "Encrypted Data Key Material",
        0x2BC0 => "Apparent Energy 32",
        0x2BBA => "Hearing Aid Features",
        0x2BC3 => "Preset Record",
        _ => "",
    }
}

fn bt_hci_version(v: u8) -> &'static str {
    match v {
        0 => "BT 1.0b", 1 => "BT 1.1", 2 => "BT 1.2", 3 => "BT 2.0",
        4 => "BT 2.1", 5 => "BT 3.0", 6 => "BT 4.0", 7 => "BT 4.1",
        8 => "BT 4.2", 9 => "BT 5.0", 10 => "BT 5.1", 11 => "BT 5.2",
        12 => "BT 5.3", 13 => "BT 5.4", _ => "?",
    }
}

fn class_of_device(cod: u32) -> String {
    let major = (cod >> 8) & 0x1F;
    let s = match major {
        0x00 => "Miscellaneous",
        0x01 => "Computer",
        0x02 => "Phone",
        0x03 => "LAN/Network",
        0x04 => "Audio/Video",
        0x05 => "Peripheral",
        0x06 => "Imaging",
        0x07 => "Wearable",
        0x08 => "Toy",
        0x09 => "Health",
        0x1F => "Uncategorized",
        _    => "?",
    };
    s.to_string()
}

fn fmt_bd_addr(b: &[u8]) -> String {
    if b.len() < 6 { return "??:??:??:??:??:??".into(); }
    format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        b[5], b[4], b[3], b[2], b[1], b[0])
}

fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ")
}

fn fmt_ts(ns: u64) -> String {
    let s    = ns / 1_000_000_000;
    let frac = ns % 1_000_000_000;
    format!("{s}.{frac:09}")
}

// ─────────────────────────────────────────────────────────────────────────────
// UsbPlugin impl
// ─────────────────────────────────────────────────────────────────────────────

impl UsbPlugin for HciPlugin {
    fn name(&self)        -> &str { "Bluetooth HCI" }
    fn description(&self) -> &str { "Decodes HCI over USB: commands, events, and ACL data" }

    fn on_transaction(&mut self, txn: &TransactionInfo, devices: &[UsbDeviceInfo]) {
        self.refresh_from_devices(devices);
        if self.devices.is_empty() { return; }

        // Remember whether selection was already at the tail before new packets arrive.
        let was_at_tail = self.packets.is_empty()
            || self.selected_idx == self.packets.len().saturating_sub(1);

        match txn.kind {
            TransactionKind::Control => self.handle_control(txn),
            // The backend classifies all IN transactions as BulkIn regardless of
            // the USB endpoint type.  Route to the interrupt handler when the
            // endpoint matches the adapter's known interrupt IN endpoint.
            TransactionKind::Interrupt => self.handle_interrupt_in(txn),
            TransactionKind::BulkIn => {
                if self.is_interrupt_in_txn(txn) {
                    self.handle_interrupt_in(txn);
                } else {
                    self.handle_bulk(txn, Dir::CtrlToHost);
                }
            }
            TransactionKind::BulkOut => self.handle_bulk(txn, Dir::HostToCtrl),
            _ => {}
        }

        // Auto-follow tail: keep selection on the newest packet when the user
        // hasn't manually scrolled up.
        if was_at_tail && !self.packets.is_empty() {
            self.selected_idx = self.packets.len() - 1;
        }
    }

    fn reset(&mut self) {
        self.devices.clear();
        self.announced.clear();
        self.packets.clear();
        self.iso_handles.clear();
        self.selected_idx = 0;
        self.scroll.set(0);
        self.visible_h.set(20);
        self.pending_nav = None;
    }

    fn is_active(&self) -> bool { !self.packets.is_empty() }

    fn captures_navigation(&self) -> bool { true }

    fn on_focus(&mut self) {
        self.selected_idx = 0;
        self.scroll.set(0);
    }

    fn on_key(&mut self, key: char) {
        if self.packets.is_empty() { return; }
        let last = self.packets.len() - 1;
        match key {
            'j'  => { if self.selected_idx < last { self.selected_idx += 1; } }
            'k'  => { if self.selected_idx > 0    { self.selected_idx -= 1; } }
            'g'  => { self.selected_idx = 0; }
            'G'  => { self.selected_idx = last; }
            '\r' => {
                let ts = self.packets[self.selected_idx].timestamp_ns;
                self.pending_nav = Some(PluginNavRequest::GotoTimestamp(ts));
            }
            _ => {}
        }
    }

    fn take_nav_request(&mut self) -> Option<PluginNavRequest> {
        self.pending_nav.take()
    }

    fn on_key_code(&mut self, key: crossterm::event::KeyCode) {
        if self.packets.is_empty() { return; }
        let last = self.packets.len() - 1;
        let step = (self.visible_h.get() / 2).max(1);
        match key {
            crossterm::event::KeyCode::PageDown => {
                self.selected_idx = (self.selected_idx + step).min(last);
            }
            crossterm::event::KeyCode::PageUp => {
                self.selected_idx = self.selected_idx.saturating_sub(step);
            }
            _ => {}
        }
    }

    fn render_lines(&self) -> Vec<PluginLine> {
        let mut lines = vec![
            PluginLine::header("  Bluetooth HCI Monitor"),
            PluginLine::colored(
                "  Decodes HCI commands, events, and ACL data over USB",
                Color::DarkGray,
            ),
            PluginLine::separator(),
        ];
        if self.packets.is_empty() {
            lines.push(PluginLine::colored(
                "  No Bluetooth adapter detected (class 0xE0 / sub 0x01 / proto 0x01).",
                Color::DarkGray,
            ));
        } else {
            for pkt in &self.packets {
                lines.push(PluginLine::plain(format!(
                    "  [{}]  {}",
                    fmt_ts(pkt.timestamp_ns), pkt.summary,
                )));
            }
        }
        lines
    }

    fn render_custom(&self, f: &mut Frame<'_>, area: Rect, _scroll: usize) -> bool {
        // Split: device info header at top, packet list fills the rest.
        let dev_h  = (self.devices.len() as u16 + 3).min(area.height / 4).max(3);
        let list_h = area.height.saturating_sub(dev_h);

        let [dev_area, list_area] = Layout::vertical([
            Constraint::Length(dev_h),
            Constraint::Min(0),
        ]).areas(area);

        // ── Device info pane ─────────────────────────────────────────────────
        {
            let mut lines: Vec<Line> = vec![
                Line::from(Span::styled(
                    "  Bluetooth HCI Monitor",
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    "─".repeat(80),
                    Style::default().fg(Color::DarkGray),
                )),
            ];
            if self.devices.is_empty() {
                lines.push(Line::from(Span::styled(
                    "  No Bluetooth adapter detected (class 0xE0 / sub 0x01 / proto 0x01).",
                    Style::default().fg(Color::DarkGray),
                )));
            } else {
                for dev in &self.devices {
                    let ep_str = format!(
                        "intr={} bulk_in={} bulk_out={}",
                        dev.ep_intr_in .map(|e| format!("0x{e:02X}")).unwrap_or("?".into()),
                        dev.ep_bulk_in .map(|e| format!("0x{e:02X}")).unwrap_or("?".into()),
                        dev.ep_bulk_out.map(|e| format!("0x{e:02X}")).unwrap_or("?".into()),
                    );
                    lines.push(Line::from(Span::styled(
                        format!("  ◉ {}   [{}]", dev.label, ep_str),
                        Style::default().fg(Color::Green),
                    )));
                }
            }
            f.render_widget(Paragraph::new(lines), dev_area);
        }

        // ── Split lower area: packet list (left) + detail pane (right) ──────
        if list_h == 0 { return true; }

        let [left_area, right_area] = Layout::horizontal([
            Constraint::Percentage(55),
            Constraint::Percentage(45),
        ]).areas(list_area);

        if self.packets.is_empty() {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "  Waiting for HCI traffic…",
                    Style::default().fg(Color::DarkGray),
                ))),
                left_area,
            );
            return true;
        }

        // ── Left: packet list (one line per packet) ───────────────────────────
        {
            let mut lines: Vec<Line> = Vec::new();

            for (pkt_idx, pkt) in self.packets.iter().enumerate() {
                let is_selected = pkt_idx == self.selected_idx;

                let (dir_icon, dir_color) = match pkt.dir {
                    Dir::HostToCtrl => ("→", Color::Yellow),
                    Dir::CtrlToHost => ("←", Color::Cyan),
                };
                let (kind_str, kind_color) = match pkt.kind {
                    HciPktKind::Command => ("CMD", Color::Yellow),
                    HciPktKind::Event   => ("EVT", Color::Cyan),
                    HciPktKind::AclOut  => ("ACL", Color::Magenta),
                    HciPktKind::AclIn   => ("ACL", Color::Blue),
                    HciPktKind::IsoOut  => ("ISO", Color::LightMagenta),
                    HciPktKind::IsoIn   => ("ISO", Color::LightBlue),
                };
                let ep_str = if pkt.ep == 0 { "ep=ctrl".to_string() }
                             else           { format!("ep=0x{:02X}", pkt.ep) };

                if is_selected {
                    let row_text = format!(
                        " [{:>12}] {} {:<3}  {:<10}  {}",
                        fmt_ts(pkt.timestamp_ns), dir_icon, kind_str, ep_str, pkt.summary,
                    );
                    lines.push(Line::from(Span::styled(
                        row_text,
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )));
                } else {
                    lines.push(Line::from(vec![
                        Span::styled(
                            format!(" [{:>12}] ", fmt_ts(pkt.timestamp_ns)),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(
                            format!("{dir_icon} "),
                            Style::default().fg(dir_color).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("{kind_str}  "),
                            Style::default().fg(kind_color).add_modifier(Modifier::BOLD),
                        ),
                        Span::styled(
                            format!("{:<10}  ", ep_str),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(
                            pkt.summary.clone(),
                            Style::default().fg(Color::White),
                        ),
                    ]));
                }
            }

            // Clamp scroll so selected row stays visible (one line per packet now).
            let visible_h = left_area.height as usize;
            self.visible_h.set(visible_h);
            let max_scroll = lines.len().saturating_sub(visible_h);
            let mut scroll = self.scroll.get();
            if self.selected_idx < scroll {
                scroll = self.selected_idx;
            } else if self.selected_idx >= scroll + visible_h {
                scroll = self.selected_idx + 1 - visible_h;
            }
            scroll = scroll.min(max_scroll);
            self.scroll.set(scroll);

            let visible: Vec<Line> = lines.into_iter()
                .skip(scroll)
                .take(visible_h)
                .collect();

            f.render_widget(Paragraph::new(visible), left_area);
        }

        // ── Right: selected packet detail pane ────────────────────────────────
        {
            let detail_block = Block::default()
                .borders(Borders::LEFT)
                .border_style(Style::default().fg(Color::DarkGray));
            let inner = detail_block.inner(right_area);
            f.render_widget(detail_block, right_area);

            let pkt = &self.packets[self.selected_idx.min(self.packets.len() - 1)];

            let (dir_label, dir_color) = match pkt.dir {
                Dir::HostToCtrl => ("Host → Controller", Color::Yellow),
                Dir::CtrlToHost => ("Controller ← Host", Color::Cyan),
            };
            let (kind_str, kind_color) = match pkt.kind {
                HciPktKind::Command => ("HCI Command",  Color::Yellow),
                HciPktKind::Event   => ("HCI Event",    Color::Cyan),
                HciPktKind::AclOut  => ("ACL Data OUT", Color::Magenta),
                HciPktKind::AclIn   => ("ACL Data IN",  Color::Blue),
                HciPktKind::IsoOut  => ("ISO Data OUT", Color::LightMagenta),
                HciPktKind::IsoIn   => ("ISO Data IN",  Color::LightBlue),
            };
            let ep_str = if pkt.ep == 0 { "Control (ep0)".to_string() }
                         else           { format!("0x{:02X}", pkt.ep) };

            let mut detail_lines: Vec<Line> = vec![
                // Summary as header
                Line::from(Span::styled(
                    format!(" {}", pkt.summary),
                    Style::default().fg(kind_color).add_modifier(Modifier::BOLD),
                )),
                Line::from(Span::styled(
                    " ─".repeat(inner.width as usize / 2),
                    Style::default().fg(Color::DarkGray),
                )),
                // Metadata fields
                Line::from(vec![
                    Span::styled(" Type  ", Style::default().fg(Color::DarkGray)),
                    Span::styled(kind_str, Style::default().fg(kind_color)),
                ]),
                Line::from(vec![
                    Span::styled(" Dir   ", Style::default().fg(Color::DarkGray)),
                    Span::styled(dir_label, Style::default().fg(dir_color)),
                ]),
                Line::from(vec![
                    Span::styled(" EP    ", Style::default().fg(Color::DarkGray)),
                    Span::styled(ep_str, Style::default().fg(Color::White)),
                ]),
                Line::from(vec![
                    Span::styled(" Time  ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        fmt_ts(pkt.timestamp_ns),
                        Style::default().fg(Color::White),
                    ),
                ]),
            ];

            if !pkt.details.is_empty() {
                detail_lines.push(Line::from(Span::styled(
                    " ─".repeat(inner.width as usize / 2),
                    Style::default().fg(Color::DarkGray),
                )));
                for d in &pkt.details {
                    // Split "Key: value" into styled key + value spans.
                    let line = if let Some(colon) = d.find(": ") {
                        let (key, val) = d.split_at(colon + 2);
                        Line::from(vec![
                            Span::styled(
                                format!(" {key}"),
                                Style::default().fg(Color::DarkGray),
                            ),
                            Span::styled(val.to_string(), Style::default().fg(Color::White)),
                        ])
                    } else {
                        Line::from(Span::styled(
                            format!(" {d}"),
                            Style::default().fg(Color::White),
                        ))
                    };
                    detail_lines.push(line);
                }
            }

            f.render_widget(Paragraph::new(detail_lines).wrap(Wrap { trim: false }), inner);
        }

        true
    }
}
