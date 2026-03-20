//! Real USB capture backend for Cynthion (replaces simulation).

use anyhow::{Context, Result};
use crate::dbg_log;
use crate::app::Speed;
use crate::models::{PacketItem, PacketType, TransactionInfo, TransactionKind,
                    UsbDeviceInfo, UsbConfigInfo, UsbInterfaceInfo, UsbEndpointInfo};
use crate::pcap;
use nusb::{
    Interface,
    transfer::{Bulk, In, ControlOut, ControlType, Recipient},
};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::BufWriter;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc;

// ── Cynthion device constants ──────────────────────────────────────────────
const VID: u16 = 0x1d50;
const PID: u16 = 0x615b;
const CLASS: u8 = 0xff;
const SUBCLASS: u8 = 0x10;
const PROTOCOL: u8 = 0x01;
/// Bulk IN endpoint carrying the captured packet stream.
const ENDPOINT_BULK_IN: u8 = 0x81;
/// Bytes requested per bulk transfer (16 KiB, matching the GTK app).
const READ_LEN: usize = 0x4000;
/// Number of simultaneously queued transfers.
const NUM_TRANSFERS: usize = 4;

// ── USB 2.0 PID values ─────────────────────────────────────────────────────
const PID_SOF:   u8 = 0xA5;
const PID_SETUP: u8 = 0x2D;
const PID_IN:    u8 = 0x69;
const PID_OUT:   u8 = 0xE1;
const PID_DATA0: u8 = 0xC3;
const PID_DATA1: u8 = 0x4B;
const PID_DATA2: u8 = 0x87;
const PID_MDATA: u8 = 0x0F;
const PID_ACK:   u8 = 0xD2;
const PID_NAK:   u8 = 0x5A;
const PID_STALL: u8 = 0x1E;
const PID_NYET:  u8 = 0x96;
const PID_PING:  u8 = 0xB4;
const PID_SPLIT: u8 = 0x78;
const PID_PRE:   u8 = 0x3C; // also ERR in HS

// ── Cynthion State byte ────────────────────────────────────────────────────
// Bit 0   : enable capture
// Bits 2:1: speed  (High=0, Full=1, Low=2, Auto=3 — matches our Speed enum)
// Bit 3   : target_c_vbus_en
// Bit 4   : control_vbus_en
// Bit 5   : aux_vbus_en
// Bit 6   : target_a_discharge  (active-low VBUS; set when VBUS is OFF)
// Bit 7   : power_control_enable (must be set for bits 3-6 to take effect)
fn state_byte(speed: Speed, enable: bool) -> u8 {
    ((speed as u8) << 1) | (enable as u8)
}

fn apply_vbus(state: u8, vbus_on: bool) -> u8 {
    // Clear existing VBUS/power bits, then re-apply.
    let base = state & 0x07; // keep only enable + speed
    let power_bits: u8 = if vbus_on {
        (1 << 7) | (1 << 3) // power_control_enable + target_c_vbus_en
    } else {
        (1 << 7) | (1 << 6) // power_control_enable + target_a_discharge
    };
    base | power_bits
}

// ── DeviceInfo ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct DeviceInfo {
    pub name: String,
    pub vendor_id: u16,
    pub product_id: u16,
}

// ── CynthionManager ────────────────────────────────────────────────────────

pub struct CynthionManager {
    found_device: Option<(DeviceInfo, nusb::DeviceInfo)>,
    /// Channel receiving completed transactions from the capture task.
    txn_rx: Option<mpsc::Receiver<TransactionInfo>>,
    /// Handle to the capture background task.
    capture_handle: Option<tokio::task::JoinHandle<()>>,
    /// Tracks USB devices discovered from captured enumeration traffic.
    device_tracker: DeviceTracker,

    // ── VBUS control ─────────────────────────────────────────────────────────
    /// Current VBUS state (TARGET-C).
    pub vbus_enabled: bool,
    /// Channel to send updated state bytes to the running capture task.
    state_tx: Option<mpsc::UnboundedSender<u8>>,
    /// Speed saved from open_device so we can rebuild the state byte on toggle.
    capture_speed: Option<Speed>,

    // ── PCAP save ────────────────────────────────────────────────────────────
    /// Channel receiving raw (bytes, timestamp_ns) from the capture task.
    raw_rx: Option<mpsc::UnboundedReceiver<(Vec<u8>, u64)>>,
    /// Active PCAP writer (Some while recording).
    pcap_writer: Option<pcap::PcapWriter<BufWriter<File>>>,
    /// Path of the file currently being written.
    pub save_path: Option<PathBuf>,
}

impl CynthionManager {
    pub async fn new() -> Result<Self> {
        Ok(CynthionManager {
            found_device: None,
            txn_rx: None,
            capture_handle: None,
            device_tracker: DeviceTracker::new(),
            vbus_enabled: false,
            state_tx: None,
            capture_speed: None,
            raw_rx: None,
            pcap_writer: None,
            save_path: None,
        })
    }

    pub fn has_found_device(&self) -> bool {
        self.found_device.is_some()
    }

    pub async fn find_device(&mut self) -> Result<Option<DeviceInfo>> {
        dbg_log!("find_device: calling nusb::list_devices()");
        let devices = nusb::list_devices().await?;
        dbg_log!("find_device: list_devices() returned");
        for d in devices {
            if d.vendor_id() == VID && d.product_id() == PID {
                dbg_log!("find_device: Cynthion found ({:04x}:{:04x})", d.vendor_id(), d.product_id());
                let info = DeviceInfo {
                    name: format!("Cynthion ({:04x}:{:04x})", d.vendor_id(), d.product_id()),
                    vendor_id: d.vendor_id(),
                    product_id: d.product_id(),
                };
                self.found_device = Some((info.clone(), d));
                return Ok(Some(info));
            }
        }
        dbg_log!("find_device: no device found");
        self.found_device = None;
        Ok(None)
    }

    /// Open the device, start USB capture at the requested speed, and spawn the
    /// background capture task that feeds transactions via an mpsc channel.
    pub async fn open_device(&mut self, speed: Speed) -> Result<()> {
        dbg_log!("open_device: start (speed={speed})");
        let (_, nusb_info) = self.found_device.as_ref().context("No device found")?;

        let device = nusb_info.open().await.context("Failed to open device")?;
        let config = device.active_configuration()
            .context("Failed to get active configuration")?;

        let mut iface_num = None;
        'outer: for iface in config.interfaces() {
            for alt in iface.alt_settings() {
                dbg_log!("open_device: iface {} alt: class={} sub={} proto={}",
                    iface.interface_number(), alt.class(), alt.subclass(), alt.protocol());
                if alt.class() == CLASS && alt.subclass() == SUBCLASS && alt.protocol() == PROTOCOL {
                    iface_num = Some(iface.interface_number());
                    break 'outer;
                }
            }
        }
        let iface_num = iface_num.context("Could not find Cynthion analyzer interface")?;
        dbg_log!("open_device: claiming interface {iface_num}");
        let interface = device.detach_and_claim_interface(iface_num).await
            .context("Failed to claim interface")?;
        dbg_log!("open_device: interface claimed successfully");

        // Abort any previous capture task and reset device tracking.
        if let Some(h) = self.capture_handle.take() {
            h.abort();
        }
        self.device_tracker = DeviceTracker::new();

        let (tx, rx) = mpsc::channel::<TransactionInfo>(4096);
        self.txn_rx = Some(rx);

        let (raw_tx, raw_rx) = mpsc::unbounded_channel::<(Vec<u8>, u64)>();
        self.raw_rx = Some(raw_rx);

        let state = state_byte(speed, true);
        self.capture_speed = Some(speed);
        self.vbus_enabled = false;

        let (state_tx, state_rx) = mpsc::unbounded_channel::<u8>();
        self.state_tx = Some(state_tx);

        let handle = tokio::task::spawn(run_capture(interface, state, tx, raw_tx, state_rx));
        self.capture_handle = Some(handle);

        dbg_log!("open_device: capture task spawned");
        Ok(())
    }

    /// Toggle VBUS (TARGET-C) on or off and send the updated state to the
    /// running capture task.  Returns `Ok(new_state)` or `Err` if not capturing.
    pub fn toggle_vbus(&mut self) -> Result<bool> {
        let speed = self.capture_speed.context("Not capturing")?;
        let state_tx = self.state_tx.as_ref().context("No capture task")?;
        self.vbus_enabled = !self.vbus_enabled;
        let new_state = apply_vbus(state_byte(speed, true), self.vbus_enabled);
        state_tx.send(new_state).ok();
        dbg_log!("toggle_vbus: vbus={} state=0x{new_state:02X}", self.vbus_enabled);
        Ok(self.vbus_enabled)
    }

    /// Returns any transactions the capture task has produced since the last call,
    /// and updates the device tracker with any control-transfer data found.
    /// If a PCAP save is active, also writes raw packets to disk.
    pub async fn get_new_transactions(&mut self) -> Result<Option<Vec<TransactionInfo>>> {
        // Drain raw packets first so they're written even if txn channel is empty.
        if let Some(ref mut raw_rx) = self.raw_rx {
            while let Ok((bytes, ts_ns)) = raw_rx.try_recv() {
                if let Some(ref mut w) = self.pcap_writer {
                    let _ = w.write_packet(ts_ns, &bytes);
                }
            }
        }

        let Some(rx) = self.txn_rx.as_mut() else {
            return Ok(None);
        };
        let mut result = Vec::new();
        while let Ok(txn) = rx.try_recv() {
            self.device_tracker.observe(&txn);
            result.push(txn);
        }
        Ok(if result.is_empty() { None } else { Some(result) })
    }

    pub fn discovered_devices(&self) -> Vec<UsbDeviceInfo> {
        self.device_tracker.devices()
    }

    pub fn is_saving(&self) -> bool {
        self.pcap_writer.is_some()
    }

    /// Open a new PCAP file and start recording every raw USB packet into it.
    /// Returns the path that was opened.
    pub fn start_save(&mut self, path: PathBuf) -> Result<PathBuf> {
        // Close any existing save first.
        self.stop_save()?;
        let file = File::create(&path)
            .with_context(|| format!("creating pcap file {}", path.display()))?;
        let mut writer = pcap::PcapWriter::new(BufWriter::new(file))?;
        writer.flush()?; // write global header immediately
        self.pcap_writer = Some(writer);
        self.save_path = Some(path.clone());
        dbg_log!("pcap save started: {}", path.display());
        Ok(path)
    }

    /// Flush and close the current PCAP save file.
    pub fn stop_save(&mut self) -> Result<()> {
        if let Some(mut w) = self.pcap_writer.take() {
            w.flush()?;
            dbg_log!("pcap save closed: {:?}", self.save_path);
        }
        Ok(())
    }

    /// Load a PCAP file and replay its packets as transactions through the
    /// existing transaction channel. The app should be in Capturing state.
    pub async fn load_pcap_file(&mut self, path: PathBuf) -> Result<()> {
        // Abort any live capture task.
        if let Some(h) = self.capture_handle.take() {
            h.abort();
        }
        self.device_tracker = DeviceTracker::new();
        self.raw_rx = None;
        self.state_tx = None;
        self.capture_speed = None;
        self.vbus_enabled = false;

        let (tx, rx) = mpsc::channel::<TransactionInfo>(4096);
        self.txn_rx = Some(rx);

        let handle = tokio::task::spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                load_pcap_blocking(path, tx)
            }).await;
            if let Err(e) = result {
                dbg_log!("pcap load task panicked: {e:?}");
            }
        });
        self.capture_handle = Some(handle);
        Ok(())
    }
}

// ── PCAP file loader (blocking) ────────────────────────────────────────────

/// Read a pcap file and send completed transactions via `tx`.
/// Runs inside `spawn_blocking`.
fn load_pcap_blocking(path: PathBuf, tx: mpsc::Sender<TransactionInfo>) {
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => { dbg_log!("pcap load: cannot open {}: {e}", path.display()); return; }
    };
    let mut reader = match pcap::PcapReader::new(std::io::BufReader::new(file)) {
        Ok(r) => r,
        Err(e) => { dbg_log!("pcap load: bad header: {e}"); return; }
    };

    let mut builder = TransactionBuilder::new();

    loop {
        match reader.next_packet() {
            Err(e) => { dbg_log!("pcap load: read error: {e}"); break; }
            Ok(None) => break,
            Ok(Some((timestamp_ns, bytes))) => {
                if bytes.is_empty() { continue; }
                let pid = bytes[0];
                let raw = RawPacket { pid, bytes, timestamp_ns };
                for txn in builder.push_packet(raw) {
                    if tx.blocking_send(txn).is_err() { return; }
                }
            }
        }
    }
    // Flush all pending state at end-of-stream.
    for txn in builder.flush_all() {
        let _ = tx.blocking_send(txn);
    }
    dbg_log!("pcap load: finished");
}

// ── Device tracker ─────────────────────────────────────────────────────────
//
// Watches the stream of transactions for USB enumeration traffic and builds a
// map of connected devices from the descriptor exchanges it observes.

struct DeviceTracker {
    /// Partial and complete device info keyed by USB device address.
    devices: HashMap<u8, UsbDeviceInfo>,
    /// SET_ADDRESS: maps old address to new address.
    address_remap: HashMap<u8, u8>,
}

impl DeviceTracker {
    fn new() -> Self {
        DeviceTracker {
            devices: HashMap::new(),
            address_remap: HashMap::new(),
        }
    }

    /// Observe a completed transfer and update device state.
    /// With the new grouper, a `Control` TransactionInfo contains ALL packets
    /// from SETUP + DATA stage + STATUS in one flat `packets` list.
    fn observe(&mut self, txn: &TransactionInfo) {
        if txn.kind != TransactionKind::Control { return; }

        // Extract addr from label.  Control transfers are always ep=0.
        let addr = txn.label.split("dev=").nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(0);

        // Find Data packets in order.  The first is always the SETUP DATA0
        // (8 raw bytes); subsequent ones carry the descriptor response.
        let data_pkts: Vec<&PacketItem> = txn.packets.iter()
            .filter(|p| p.packet_type == PacketType::Data)
            .collect();

        let Some(setup_pkt) = data_pkts.first() else { return };
        let sf = &setup_pkt.raw_bytes;
        if sf.len() < 8 { return; }

        let bm_request_type = sf[0];
        let b_request       = sf[1];
        let w_value_lo      = sf[2];
        let w_value_hi      = sf[3];

        match (bm_request_type, b_request) {
            // GET_DESCRIPTOR
            (0x80, 0x06) => {
                let desc_type  = w_value_hi;
                let desc_index = w_value_lo;

                // Response data may be split across multiple IN transactions
                // (e.g. device descriptor fetched 8 bytes at a time during
                // early enumeration before wMaxPacketSize0 is known).
                // Concatenate all data packets after the SETUP packet.
                let resp_data: Vec<u8> = data_pkts[1..].iter()
                    .flat_map(|p| p.raw_bytes.iter().copied())
                    .collect();
                let data: &[u8] = &resp_data;
                if data.is_empty() { return; }

                let dev = self.devices.entry(addr).or_insert_with(|| UsbDeviceInfo {
                    address: addr,
                    bcd_usb: 0, bcd_device: 0,
                    vendor_id: 0, product_id: 0,
                    class: 0, subclass: 0, protocol: 0,
                    max_packet_size0: 0, num_configurations: 0,
                    manufacturer: None, product: None, serial: None,
                    configurations: Vec::new(),
                });

                match desc_type {
                    0x01 => { // Device descriptor (18 bytes)
                        if data.len() >= 18 {
                            dev.bcd_usb          = u16::from_le_bytes([data[2],  data[3]]);
                            dev.class            = data[4];
                            dev.subclass         = data[5];
                            dev.protocol         = data[6];
                            dev.max_packet_size0 = data[7];
                            dev.vendor_id        = u16::from_le_bytes([data[8],  data[9]]);
                            dev.product_id       = u16::from_le_bytes([data[10], data[11]]);
                            dev.bcd_device       = u16::from_le_bytes([data[12], data[13]]);
                            dev.num_configurations = data[17];
                            dbg_log!("device_tracker: device {addr} VID={:04X} PID={:04X}",
                                dev.vendor_id, dev.product_id);
                        }
                    }
                    0x02 => { // Configuration descriptor
                        if let Some(cfg) = parse_config_descriptor(data) {
                            // Replace existing config with the same value, or append.
                            let cv = cfg.configuration_value;
                            if let Some(existing) = dev.configurations.iter_mut().find(|c| c.configuration_value == cv) {
                                *existing = cfg;
                            } else {
                                dev.configurations.push(cfg);
                                dev.configurations.sort_by_key(|c| c.configuration_value);
                            }
                        }
                    }
                    0x03 => { // String descriptor [bLength, bDescriptorType, UTF-16LE...]
                        if data.len() >= 2 {
                            let chars: Vec<u16> = data[2..].chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect();
                            let s = String::from_utf16_lossy(&chars).trim().to_string();
                            if !s.is_empty() {
                                match desc_index {
                                    1 => { dev.manufacturer = Some(s); }
                                    2 => { dev.product      = Some(s); }
                                    3 => { dev.serial       = Some(s); }
                                    _ => {}
                                }
                                dbg_log!("device_tracker: device {addr} string[{desc_index}]");
                            }
                        }
                    }
                    _ => {}
                }
            }

            // SET_ADDRESS
            (0x00, 0x05) => {
                let new_addr = w_value_lo;
                let old_info = self.devices.remove(&addr).unwrap_or_else(|| UsbDeviceInfo {
                    address: new_addr,
                    bcd_usb: 0, bcd_device: 0,
                    vendor_id: 0, product_id: 0,
                    class: 0, subclass: 0, protocol: 0,
                    max_packet_size0: 0, num_configurations: 0,
                    manufacturer: None, product: None, serial: None,
                    configurations: Vec::new(),
                });
                let mut info = old_info;
                info.address = new_addr;
                self.devices.insert(new_addr, info);
                self.address_remap.insert(addr, new_addr);
                dbg_log!("device_tracker: SET_ADDRESS {addr} → {new_addr}");
            }

            _ => {}
        }
    }

    fn devices(&self) -> Vec<UsbDeviceInfo> {
        let mut v: Vec<UsbDeviceInfo> = self.devices.values()
            .filter(|d| d.vendor_id != 0 || !d.configurations.is_empty())
            .cloned()
            .collect();
        v.sort_by_key(|d| d.address);
        v
    }
}

/// Parse a configuration descriptor blob and return a `UsbConfigInfo` tree.
/// Returns `None` if the data is too short to contain a valid config descriptor header.
fn parse_config_descriptor(data: &[u8]) -> Option<UsbConfigInfo> {
    // Configuration descriptor is at least 9 bytes.
    if data.len() < 9 || data[1] != 0x02 { return None; }

    let num_interfaces = data[4];
    let configuration_value = data[5];
    let attributes = data[7];
    let max_power = data[8];

    let mut config = UsbConfigInfo {
        configuration_value,
        num_interfaces,
        attributes,
        max_power,
        interfaces: Vec::new(),
    };

    let mut i = data[0] as usize; // skip the configuration descriptor itself
    let mut current_iface: Option<UsbInterfaceInfo> = None;

    while i + 1 < data.len() {
        let len = data[i] as usize;
        if len < 2 || i + len > data.len() { break; }
        let desc_type = data[i + 1];

        match desc_type {
            0x04 if len >= 9 => { // Interface descriptor
                // Flush previous interface.
                if let Some(iface) = current_iface.take() {
                    config.interfaces.push(iface);
                }
                current_iface = Some(UsbInterfaceInfo {
                    interface_number: data[i + 2],
                    alternate_setting: data[i + 3],
                    num_endpoints: data[i + 4],
                    class: data[i + 5],
                    subclass: data[i + 6],
                    protocol: data[i + 7],
                    endpoints: Vec::new(),
                });
            }
            0x05 if len >= 7 => { // Endpoint descriptor
                let ep = UsbEndpointInfo {
                    address: data[i + 2],
                    attributes: data[i + 3],
                    max_packet_size: u16::from_le_bytes([data[i + 4], data[i + 5]]),
                    interval: data[i + 6],
                };
                if let Some(ref mut iface) = current_iface {
                    iface.endpoints.push(ep);
                }
            }
            _ => {}
        }
        i += len;
    }

    // Flush last interface.
    if let Some(iface) = current_iface {
        config.interfaces.push(iface);
    }

    Some(config)
}



// ── Capture background task ────────────────────────────────────────────────

async fn send_state(interface: &Interface, state: u8) {
    let ctrl = ControlOut {
        control_type: ControlType::Vendor,
        recipient: Recipient::Interface,
        request: 1,
        value: state as u16,
        index: interface.interface_number() as u16,
        data: &[],
    };
    if let Err(e) = interface.control_out(ctrl, Duration::from_secs(1)).await {
        dbg_log!("capture: state control transfer failed: {e}");
    }
}

async fn run_capture(
    interface: Interface,
    state: u8,
    tx: mpsc::Sender<TransactionInfo>,
    raw_tx: mpsc::UnboundedSender<(Vec<u8>, u64)>,
    mut state_rx: mpsc::UnboundedReceiver<u8>,
) {
    // Tell the Cynthion to start capturing at the requested speed.
    send_state(&interface, state).await;
    dbg_log!("capture: started (state=0x{state:02X})");

    // Obtain the bulk IN endpoint.
    let mut endpoint = match interface.endpoint::<Bulk, In>(ENDPOINT_BULK_IN) {
        Ok(ep) => ep,
        Err(e) => { dbg_log!("capture: endpoint error: {e}"); return; }
    };

    // Prime the transfer queue.
    for _ in 0..NUM_TRANSFERS {
        let mut buf = endpoint.allocate(READ_LEN);
        buf.set_requested_len(READ_LEN);
        endpoint.submit(buf);
    }

    let mut parser  = StreamParser::new();
    let mut builder = TransactionBuilder::new();

    loop {
        tokio::select! {
            // ── New state byte from main thread (VBUS toggle, etc.) ──────
            Some(new_state) = state_rx.recv() => {
                send_state(&interface, new_state).await;
            }

            // ── Next bulk IN completion ───────────────────────────────────
            completion = endpoint.next_complete() => {
                let ok = completion.status.is_ok();
                if ok {
                    parser.push(&completion.buffer);
                    while let Some(pkt) = parser.next_packet() {
                        let _ = raw_tx.send((pkt.bytes.clone(), pkt.timestamp_ns));
                        for txn in builder.push_packet(pkt) {
                            if tx.send(txn).await.is_err() {
                                dbg_log!("capture: receiver dropped, stopping");
                                return;
                            }
                        }
                    }
                } else {
                    dbg_log!("capture: transfer error: {:?}", completion.status);
                }
                // Resubmit the buffer for the next transfer.
                let mut buf = completion.buffer;
                buf.set_requested_len(READ_LEN);
                endpoint.submit(buf);
            }
        }
    }
}

// ── Wire-format stream parser ──────────────────────────────────────────────
//
// Cynthion streams 4-byte records:
//   Event record : [0xFF, event_code, delta_cycles_hi, delta_cycles_lo]
//   Packet record: [pkt_len_hi, pkt_len_lo, delta_cycles_hi, delta_cycles_lo]
//                  followed by `pkt_len` bytes of USB packet data, plus one
//                  padding byte if `pkt_len` is odd.

struct StreamParser {
    buf: VecDeque<u8>,
    padding_due: bool,
    /// Accumulated 60 MHz clock cycles from the Cynthion wire format.
    cumulative_cycles: u64,
}

struct RawPacket {
    pid: u8,
    bytes: Vec<u8>,
    /// Nanoseconds from start of capture (derived from cumulative_cycles).
    timestamp_ns: u64,
}

impl StreamParser {
    fn new() -> Self {
        StreamParser { buf: VecDeque::new(), padding_due: false, cumulative_cycles: 0 }
    }

    fn push(&mut self, data: &[u8]) {
        self.buf.extend(data);
    }

    /// Returns the next complete USB packet from the stream, or `None` if more
    /// data is needed.
    fn next_packet(&mut self) -> Option<RawPacket> {
        loop {
            // Consume any outstanding padding byte.
            if self.padding_due {
                if self.buf.is_empty() { return None; }
                self.buf.pop_front();
                self.padding_due = false;
            }

            // Need at least the 4-byte header.
            if self.buf.len() < 4 { return None; }

            if self.buf[0] == 0xFF {
                // Event record — accumulate delta cycles but skip otherwise.
                let delta = u16::from_be_bytes([self.buf[2], self.buf[3]]) as u64;
                self.cumulative_cycles += delta;
                self.buf.drain(0..4);
                continue;
            }

            // Packet record.
            let pkt_len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            let delta   = u16::from_be_bytes([self.buf[2], self.buf[3]]) as u64;
            self.cumulative_cycles += delta;
            // 60 MHz clock → nanoseconds: cycles * 1_000_000_000 / 60_000_000 = cycles * 50 / 3
            let timestamp_ns = self.cumulative_cycles * 50 / 3;

            // Need header (4) + packet data.
            if self.buf.len() < 4 + pkt_len { return None; }

            // Consume header.
            self.buf.drain(0..4);

            if pkt_len % 2 == 1 {
                self.padding_due = true;
            }

            if pkt_len == 0 { continue; }

            let bytes: Vec<u8> = self.buf.drain(0..pkt_len).collect();
            let pid = bytes[0];
            return Some(RawPacket { pid, bytes, timestamp_ns });
        }
    }
}

// ── Transfer builder state machine ────────────────────────────────────────
//
// Two-layer pipeline:
//   Layer 1 (inner): raw packets → single token+data+handshake transaction
//   Layer 2 (outer): completed transactions → USB transfers
//
// Control transfers: SETUP + optional DATA stage + STATUS → one node.
// Bulk/Interrupt:    consecutive same-endpoint transactions, terminated by
//                    short packet or direction change → one node.
// NAK retries:       folded into the in-progress transfer's packet list.
// SOF:               burst-grouped independently.

// ── Inner state: building a single token+data+handshake triplet ────────────

enum InnerState {
    Idle,
    HaveToken { pid: u8, addr: u8, ep: u8, pkt: PacketItem, timestamp_ns: u64 },
    HaveData  {
        pid: u8, addr: u8, ep: u8,
        token: PacketItem, data: PacketItem,
        /// Raw DATA payload (no PID/CRC), used for setup parsing.
        payload: Vec<u8>,
        timestamp_ns: u64,
    },
}

/// A completed token+data+handshake triplet fed to the outer layer.
struct CompletedTxn {
    tok_pid: u8,
    hs_pid:  u8,
    addr:    u8,
    ep:      u8,
    /// All raw packets (token, optional data, handshake) in order.
    packets: Vec<PacketItem>,
    /// If this was a SETUP transaction, the raw 8-byte setup data.
    setup_bytes: Option<[u8; 8]>,
    /// Length of the DATA payload (0 if no data phase).
    data_len: usize,
    timestamp_ns: u64,
}

// ── Outer state: grouping transactions into complete transfers ─────────────

#[derive(Debug, Clone, Copy, PartialEq)]
enum CtrlStage { Data, Status }

enum XferState {
    Idle,
    /// A USB control transfer being assembled.
    Control {
        addr: u8,
        ep: u8,
        stage: CtrlStage,
        /// Direction of the DATA stage: true = device→host (IN).
        data_is_in: bool,
        /// Expected DATA bytes (wLength from SETUP).
        w_length: u16,
        /// DATA bytes received so far.
        bytes_xfrd: u32,
        /// Summary label built from the SETUP descriptor.
        setup_label: String,
        /// All packets from all stages accumulated here.
        all_packets: Vec<PacketItem>,
        nak_count:   u32,
        stalled:     bool,
        ts: u64,
    },
    /// A bulk or interrupt transfer being assembled.
    Bulk {
        is_in: bool,
        addr: u8,
        ep: u8,
        all_packets: Vec<PacketItem>,
        ts: u64,
        total_bytes: usize,
        /// First non-zero payload size — used as a heuristic max-packet-size
        /// to detect short packets without knowing the descriptor.
        first_data_len: usize,
        nak_count: u32,
    },
}

// ── The builder ────────────────────────────────────────────────────────────

struct TransactionBuilder {
    inner: InnerState,
    xfer:  XferState,
    /// SOF packets that arrived with no transfer in progress; flushed as a
    /// standalone SofGroup node before the next real transaction starts.
    pending_sof: Vec<PacketItem>,
    sof_first_ts: u64,
    /// SOF packets that arrived while a Control/Bulk transfer was in progress;
    /// flushed as a single grouped child PacketItem just before the next
    /// non-SOF packet is added to that transfer.
    mid_xfer_sof: Vec<PacketItem>,
}

impl TransactionBuilder {
    fn new() -> Self {
        TransactionBuilder {
            inner: InnerState::Idle,
            xfer:  XferState::Idle,
            pending_sof: Vec::new(),
            sof_first_ts: 0,
            mid_xfer_sof: Vec::new(),
        }
    }

    // ── Public entry point ─────────────────────────────────────────────────

    fn push_packet(&mut self, raw: RawPacket) -> Vec<TransactionInfo> {
        let mut out = Vec::new();

        match raw.pid {
            // ── Start-of-Frame ───────────────────────────────────────────
            PID_SOF => {
                let frame = if raw.bytes.len() >= 3 {
                    u16::from_le_bytes([raw.bytes[1], raw.bytes[2]]) & 0x7FF
                } else { 0 };
                let (crc5_sof_valid, crc5_sof) = if raw.bytes.len() >= 3 {
                    let valid = check_crc5(&raw.bytes);
                    let received = (raw.bytes[2] >> 3) & 0x1F;
                    (Some(valid), format!("\nCRC5: 0x{:02X}{}", received, crc_annotation(valid)))
                } else {
                    (None, String::new())
                };
                let sof_label = if crc5_sof_valid == Some(false) {
                    format!("SOF   frame={frame:04}  [CRC ERR]")
                } else {
                    format!("SOF   frame={frame:04}")
                };
                let sof_pkt = PacketItem {
                    packet_type: PacketType::Sof,
                    label: sof_label,
                    details: format!("PID: SOF (0xA5)\nFrame number: {frame}{crc5_sof}"),
                    raw_bytes: Vec::new(),
                    timestamp_ns: raw.timestamp_ns,
                    crc_valid: crc5_sof_valid,
                };
                // If a transfer is already in progress, buffer the SOF so
                // consecutive SOFs can be collapsed into a single child node.
                // Otherwise, accumulate for a standalone SOF-group node.
                match &self.xfer {
                    XferState::Idle => {
                        if self.pending_sof.is_empty() {
                            self.sof_first_ts = raw.timestamp_ns;
                        }
                        self.pending_sof.push(sof_pkt);
                    }
                    _ => { self.mid_xfer_sof.push(sof_pkt); }
                }
            }

            // ── Token packets ────────────────────────────────────────────
            PID_SETUP | PID_IN | PID_OUT | PID_PING => {
                // Flush any incomplete inner transaction first.
                if let Some(t) = self.flush_inner() {
                    self.feed_xfer(t, &mut out);
                }
                // Flush SOF group before the first real packet.
                if let Some(sof) = self.flush_sof_group() {
                    out.push(sof);
                }

                let (addr, ep) = decode_token(&raw.bytes);
                let pname = pid_name(raw.pid);
                let (crc5_tok_valid, crc5_tok) = if raw.bytes.len() >= 3 {
                    let valid = check_crc5(&raw.bytes);
                    let received = (raw.bytes[2] >> 3) & 0x1F;
                    (Some(valid), format!("\nCRC5: 0x{:02X}{}", received, crc_annotation(valid)))
                } else {
                    (None, String::new())
                };
                let tok_label = if crc5_tok_valid == Some(false) {
                    format!("{pname}   dev={addr}  ep={ep}  [CRC ERR]")
                } else {
                    format!("{pname}   dev={addr}  ep={ep}")
                };
                let pkt = PacketItem {
                    packet_type: PacketType::Other,
                    label: tok_label,
                    details: format!(
                        "PID: {pname} (0x{:02X})\nAddr: {addr}  EP: {ep}\nData: {}{crc5_tok}",
                        raw.pid, hex_str(&raw.bytes)
                    ),
                    raw_bytes: Vec::new(),
                    timestamp_ns: raw.timestamp_ns,
                    crc_valid: crc5_tok_valid,
                };
                self.inner = InnerState::HaveToken {
                    pid: raw.pid, addr, ep, pkt, timestamp_ns: raw.timestamp_ns,
                };
            }

            // ── Data packets ─────────────────────────────────────────────
            PID_DATA0 | PID_DATA1 | PID_DATA2 | PID_MDATA => {
                let payload_len = raw.bytes.len().saturating_sub(3);
                let payload = if raw.bytes.len() >= 3 {
                    raw.bytes[1..raw.bytes.len() - 2].to_vec()
                } else {
                    Vec::new()
                };
                let pname = pid_name(raw.pid);
                let (crc16_valid, crc16_str) = if raw.bytes.len() >= 3 {
                    let valid = check_crc16(&raw.bytes);
                    let lo = raw.bytes[raw.bytes.len() - 2];
                    let hi = raw.bytes[raw.bytes.len() - 1];
                    let val = u16::from_le_bytes([lo, hi]);
                    (Some(valid), format!("\nCRC16: 0x{:04X}{}", val, crc_annotation(valid)))
                } else {
                    (None, String::new())
                };
                let data_label = if crc16_valid == Some(false) {
                    format!("{pname}   {payload_len} bytes  [CRC ERR]")
                } else {
                    format!("{pname}   {payload_len} bytes")
                };
                let data_pkt = PacketItem {
                    packet_type: PacketType::Data,
                    label: data_label,
                    details: format!(
                        "PID: {pname} (0x{:02X})\nLength: {payload_len} bytes\nPayload: {}{crc16_str}",
                        raw.pid, hex_str(&payload)
                    ),
                    raw_bytes: payload.clone(),
                    timestamp_ns: raw.timestamp_ns,
                    crc_valid: crc16_valid,
                };
                let old = std::mem::replace(&mut self.inner, InnerState::Idle);
                self.inner = match old {
                    InnerState::HaveToken { pid, addr, ep, pkt, timestamp_ns } => {
                        InnerState::HaveData {
                            pid, addr, ep, token: pkt, data: data_pkt,
                            payload, timestamp_ns,
                        }
                    }
                    other => {
                        self.inner = other;
                        out.push(standalone_data_txn(data_pkt, raw.timestamp_ns));
                        return out;
                    }
                };
            }

            // ── Handshake packets ────────────────────────────────────────
            PID_ACK | PID_NAK | PID_STALL | PID_NYET | PID_PRE => {
                let hs_name = pid_name(raw.pid);
                let hs_pkt = PacketItem {
                    packet_type: match raw.pid {
                        PID_ACK   => PacketType::Ack,
                        PID_NAK   => PacketType::Nak,
                        PID_STALL => PacketType::Stall,
                        _         => PacketType::Other,
                    },
                    label: hs_name.to_string(),
                    details: format!("PID: {hs_name} (0x{:02X})\n(no CRC — handshake packet)", raw.pid),
                    raw_bytes: Vec::new(),
                    timestamp_ns: raw.timestamp_ns,
                    crc_valid: None,
                };

                let old = std::mem::replace(&mut self.inner, InnerState::Idle);
                let completed = match old {
                    InnerState::HaveToken { pid: tok_pid, addr, ep, pkt: tok, timestamp_ns } => {
                        Some(CompletedTxn {
                            tok_pid, hs_pid: raw.pid, addr, ep,
                            packets: vec![tok, hs_pkt],
                            setup_bytes: None, data_len: 0, timestamp_ns,
                        })
                    }
                    InnerState::HaveData { pid: tok_pid, addr, ep, token, data, payload, timestamp_ns } => {
                        let data_len = payload.len();
                        let setup_bytes = if tok_pid == PID_SETUP && payload.len() == 8 {
                            let mut b = [0u8; 8];
                            b.copy_from_slice(&payload);
                            Some(b)
                        } else {
                            None
                        };
                        Some(CompletedTxn {
                            tok_pid, hs_pid: raw.pid, addr, ep,
                            packets: vec![token, data, hs_pkt],
                            setup_bytes, data_len, timestamp_ns,
                        })
                    }
                    InnerState::Idle => None,
                };
                if let Some(t) = completed {
                    self.feed_xfer(t, &mut out);
                }
            }

            // ── Unknown / reset ──────────────────────────────────────────
            _ => {
                if let Some(t) = self.flush_inner() {
                    self.feed_xfer(t, &mut out);
                }
            }
        }

        out
    }

    // ── Layer 2: feed a completed inner transaction to the transfer machine ─

    fn feed_xfer(&mut self, txn: CompletedTxn, out: &mut Vec<TransactionInfo>) {
        // Flush any mid-transfer SOF packets accumulated since the last triplet.
        self.drain_mid_xfer_sof();

        // ── Isochronous detection ──────────────────────────────────────────
        // Isochronous transfers carry no ACK/NAK handshake.  When flush_inner
        // fires because a new token arrived before any handshake (hs_pid == 0),
        // and there is a non-empty data phase, treat it as isochronous.
        // Emit immediately without disturbing any in-progress Bulk/Control state
        // (iso and bulk can coexist on different endpoints of the same device).
        if txn.hs_pid == 0
            && (txn.tok_pid == PID_IN || txn.tok_pid == PID_OUT)
            && txn.data_len > 0
        {
            out.push(build_iso_txn(
                txn.tok_pid == PID_IN,
                txn.addr, txn.ep,
                &txn.packets,
                txn.data_len,
                txn.timestamp_ns,
            ));
            return;
        }

        // SETUP always begins a new control transfer.
        if txn.tok_pid == PID_SETUP {
            if let Some(t) = self.flush_xfer() { out.push(t); }
            self.start_control(txn);
            return;
        }

        let xfer = std::mem::replace(&mut self.xfer, XferState::Idle);
        match xfer {
            // ── Continuing a control transfer ────────────────────────────
            XferState::Control {
                addr, ep, mut stage, data_is_in, w_length, mut bytes_xfrd,
                setup_label, mut all_packets, mut nak_count, mut stalled, ts,
            } => {
                if txn.addr != addr || txn.ep != ep {
                    // Different endpoint → emit the control transfer, handle new txn fresh.
                    let item = build_control_txn(
                        addr, ep, &setup_label, &all_packets, nak_count, stalled, ts,
                    );
                    out.push(item);
                    self.xfer = XferState::Idle;
                    self.feed_xfer(txn, out);
                    return;
                }

                all_packets.extend(txn.packets.clone());

                if txn.hs_pid == PID_STALL {
                    stalled = true;
                    out.push(build_control_txn(
                        addr, ep, &setup_label, &all_packets, nak_count, stalled, ts,
                    ));
                    // xfer stays Idle (already replaced above)
                    return;
                }

                if txn.hs_pid == PID_NAK || txn.hs_pid == PID_NYET {
                    nak_count += 1;
                    self.xfer = XferState::Control {
                        addr, ep, stage, data_is_in, w_length, bytes_xfrd,
                        setup_label, all_packets, nak_count, stalled, ts,
                    };
                    return;
                }

                // ACK (or NYET treated as provisional ACK)
                match stage {
                    CtrlStage::Data => {
                        bytes_xfrd += txn.data_len as u32;
                        // Is this actually the STATUS stage sneaking in?
                        let is_status_dir = (txn.tok_pid == PID_OUT) == data_is_in;
                        let is_zlp = txn.data_len == 0;
                        if is_status_dir && is_zlp {
                            // Zero-length packet in opposite direction = STATUS.
                            out.push(build_control_txn(
                                addr, ep, &setup_label, &all_packets, nak_count, stalled, ts,
                            ));
                            return; // xfer stays Idle
                        }
                        if bytes_xfrd >= w_length as u32 {
                            stage = CtrlStage::Status;
                        }
                        self.xfer = XferState::Control {
                            addr, ep, stage, data_is_in, w_length, bytes_xfrd,
                            setup_label, all_packets, nak_count, stalled, ts,
                        };
                    }
                    CtrlStage::Status => {
                        // STATUS ACK → transfer complete.
                        out.push(build_control_txn(
                            addr, ep, &setup_label, &all_packets, nak_count, stalled, ts,
                        ));
                        // xfer stays Idle
                    }
                }
            }

            // ── Continuing a bulk / interrupt transfer ───────────────────
            XferState::Bulk {
                is_in, addr, ep, mut all_packets, ts,
                mut total_bytes, mut first_data_len, mut nak_count,
            } => {
                let same = txn.addr == addr
                    && txn.ep == ep
                    && (txn.tok_pid == PID_IN) == is_in;

                if !same {
                    out.push(build_bulk_txn(
                        is_in, addr, ep, &all_packets, total_bytes, nak_count, ts,
                    ));
                    self.xfer = XferState::Idle;
                    self.feed_xfer(txn, out);
                    return;
                }

                all_packets.extend(txn.packets.clone());

                if txn.hs_pid == PID_NAK || txn.hs_pid == PID_NYET {
                    nak_count += 1;
                    self.xfer = XferState::Bulk {
                        is_in, addr, ep, all_packets, ts,
                        total_bytes, first_data_len, nak_count,
                    };
                    return;
                }
                if txn.hs_pid == PID_STALL {
                    out.push(build_bulk_txn(
                        is_in, addr, ep, &all_packets, total_bytes, nak_count, ts,
                    ));
                    return;
                }

                // ACK
                let len = txn.data_len;
                if first_data_len == 0 && len > 0 { first_data_len = len; }
                total_bytes += len;

                // Short packet (or ZLP) terminates the bulk transfer.
                let is_short = len == 0 || (first_data_len > 0 && len < first_data_len);
                if is_short {
                    out.push(build_bulk_txn(
                        is_in, addr, ep, &all_packets, total_bytes, nak_count, ts,
                    ));
                } else {
                    self.xfer = XferState::Bulk {
                        is_in, addr, ep, all_packets, ts,
                        total_bytes, first_data_len, nak_count,
                    };
                }
            }

            // ── No transfer in progress → start one ──────────────────────
            XferState::Idle => {
                let is_in = txn.tok_pid == PID_IN;
                if txn.tok_pid == PID_IN || txn.tok_pid == PID_OUT {
                    if txn.hs_pid == PID_STALL {
                        // Immediate STALL → emit single transaction.
                        out.push(build_bulk_txn(
                            is_in, txn.addr, txn.ep, &txn.packets, 0, 0, txn.timestamp_ns,
                        ));
                        return;
                    }
                    let len = txn.data_len;
                    let first_data_len = if txn.hs_pid == PID_ACK { len } else { 0 };
                    let nak_count = if txn.hs_pid == PID_NAK { 1 } else { 0 };
                    let total_bytes = if txn.hs_pid == PID_ACK { len } else { 0 };
                    self.xfer = XferState::Bulk {
                        is_in, addr: txn.addr, ep: txn.ep,
                        all_packets: txn.packets,
                        ts: txn.timestamp_ns,
                        total_bytes, first_data_len, nak_count,
                    };
                    // ZLP immediately closes the transfer.
                    if txn.hs_pid == PID_ACK && len == 0 {
                        if let Some(t) = self.flush_xfer() { out.push(t); }
                    }
                } else {
                    let has_crc_error = pkts_have_crc_error(&txn.packets);
                    let crc_tag = if has_crc_error { "  [CRC ERR]" } else { "" };
                    out.push(TransactionInfo {
                        kind: TransactionKind::Other,
                        label: format!(
                            "{}  dev={}  ep={}{}",
                            pid_name(txn.tok_pid), txn.addr, txn.ep, crc_tag
                        ),
                        details: build_details(txn.addr, txn.ep, &txn.packets),
                        packets: txn.packets,
                        timestamp_ns: txn.timestamp_ns,
                        has_crc_error,
                    });
                }
            }
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────

    /// Start a control transfer from a completed SETUP transaction.
    fn start_control(&mut self, txn: CompletedTxn) {
        let (setup_label, data_is_in, w_length, first_stage) =
            if let Some(sb) = txn.setup_bytes {
                let bm_request_type = sb[0];
                let b_request       = sb[1];
                let w_value         = u16::from_le_bytes([sb[2], sb[3]]);
                let w_len           = u16::from_le_bytes([sb[6], sb[7]]);
                let din             = (bm_request_type >> 7) & 1 == 1;
                let stage = if w_len == 0 { CtrlStage::Status } else { CtrlStage::Data };
                (decode_setup_label(bm_request_type, b_request, w_value), din, w_len, stage)
            } else {
                ("SETUP".to_string(), false, 0, CtrlStage::Status)
            };

        self.xfer = XferState::Control {
            addr: txn.addr,
            ep: txn.ep,
            stage: first_stage,
            data_is_in,
            w_length,
            bytes_xfrd: 0,
            setup_label,
            all_packets: txn.packets,
            nak_count: 0,
            stalled: false,
            ts: txn.timestamp_ns,
        };
    }

    /// Drain any buffered mid-transfer SOF packets into the current transfer's
    /// packet list, collapsing consecutive SOFs into a single grouped child item.
    fn drain_mid_xfer_sof(&mut self) {
        if self.mid_xfer_sof.is_empty() { return; }
        let pkts = std::mem::take(&mut self.mid_xfer_sof);
        let n = pkts.len();
        let first = frame_from_sof(&pkts[0]);
        let last  = frame_from_sof(&pkts[n - 1]);
        let ts    = pkts[0].timestamp_ns;
        let has_crc_error = pkts.iter().any(|p| p.crc_valid == Some(false));
        let crc_tag = if has_crc_error { "  [CRC ERR]" } else { "" };
        let grouped = if n == 1 {
            pkts.into_iter().next().unwrap()
        } else {
            PacketItem {
                packet_type: PacketType::Sof,
                label:   format!("SOF   frames {first:04}–{last:04}  ({n} packets){crc_tag}"),
                details: format!("PID: SOF (0xA5)\nFrame numbers: {first}–{last}\nCount: {n}{crc_tag}"),
                raw_bytes: Vec::new(),
                timestamp_ns: ts,
                crc_valid: if has_crc_error { Some(false) } else { None },
            }
        };
        match &mut self.xfer {
            XferState::Control { all_packets, .. } => all_packets.push(grouped),
            XferState::Bulk    { all_packets, .. } => all_packets.push(grouped),
            XferState::Idle => {} // discard — xfer finished before we could drain
        }
    }

    fn flush_sof_group(&mut self) -> Option<TransactionInfo> {
        if self.pending_sof.is_empty() { return None; }
        let pkts = std::mem::take(&mut self.pending_sof);
        let n = pkts.len();
        let first = frame_from_sof(&pkts[0]);
        let last  = frame_from_sof(&pkts[n - 1]);
        let ts = self.sof_first_ts;
        self.sof_first_ts = 0;
        let has_crc_error = pkts_have_crc_error(&pkts);
        let crc_tag = if has_crc_error { "  [CRC ERR]" } else { "" };
        Some(TransactionInfo {
            kind: TransactionKind::SofGroup,
            label: format!("SOF   frames {first:04}–{last:04}  ({n} packet{}){crc_tag}", if n==1{""} else{"s"}),
            details: format!("Start-of-Frame group\nFrames: {first}–{last}\nCount: {n}"),
            packets: pkts,
            timestamp_ns: ts,
            has_crc_error,
        })
    }

    /// Flush the in-progress outer transfer.
    fn flush_xfer(&mut self) -> Option<TransactionInfo> {
        // Flush any trailing mid-transfer SOFs before closing the transfer.
        self.drain_mid_xfer_sof();
        let xfer = std::mem::replace(&mut self.xfer, XferState::Idle);
        match xfer {
            XferState::Idle => None,
            XferState::Control { addr, ep, setup_label, all_packets, nak_count, stalled, ts, .. } => {
                Some(build_control_txn(addr, ep, &setup_label, &all_packets, nak_count, stalled, ts))
            }
            XferState::Bulk { is_in, addr, ep, all_packets, ts, total_bytes, nak_count, .. } => {
                Some(build_bulk_txn(is_in, addr, ep, &all_packets, total_bytes, nak_count, ts))
            }
        }
    }

    /// Flush an incomplete inner transaction as a degenerate completed one.
    fn flush_inner(&mut self) -> Option<CompletedTxn> {
        let old = std::mem::replace(&mut self.inner, InnerState::Idle);
        match old {
            InnerState::Idle => None,
            InnerState::HaveToken { pid, addr, ep, pkt, timestamp_ns } => {
                Some(CompletedTxn {
                    tok_pid: pid, hs_pid: 0, addr, ep,
                    packets: vec![pkt],
                    setup_bytes: None, data_len: 0, timestamp_ns,
                })
            }
            InnerState::HaveData { pid, addr, ep, token, data, payload, timestamp_ns } => {
                let data_len = payload.len();
                let setup_bytes = if pid == PID_SETUP && payload.len() == 8 {
                    let mut b = [0u8; 8]; b.copy_from_slice(&payload); Some(b)
                } else { None };
                Some(CompletedTxn {
                    tok_pid: pid, hs_pid: 0, addr, ep,
                    packets: vec![token, data],
                    setup_bytes, data_len, timestamp_ns,
                })
            }
        }
    }

    /// Flush everything: inner transaction → outer transfer, then SOF group.
    fn flush_all(&mut self) -> Vec<TransactionInfo> {
        let mut out = Vec::new();
        if let Some(t) = self.flush_inner() {
            self.feed_xfer(t, &mut out);
        }
        if let Some(t) = self.flush_xfer() { out.push(t); }
        if let Some(s) = self.flush_sof_group() { out.push(s); }
        out
    }
}


// ── Helper functions ───────────────────────────────────────────────────────

// ── USB CRC validation ─────────────────────────────────────────────────────

/// Validate CRC5 for token and SOF packets.
///
/// Processes all 16 bits of the two post-PID bytes (11 data bits + 5 CRC bits)
/// through the USB CRC5 engine using the reflected (LSB-first) algorithm:
///   polynomial: G(X) = X^5 + X^2 + 1, reflected = 0x14
///   initial value: 0x1F (all ones)
///
/// The USB spec states the residual as 01100b in wire (LSB-first) order.
/// In the reflected register that equals 0x06 (bit-reverse of 0x0C over 5 bits).
fn check_crc5(bytes: &[u8]) -> bool {
    if bytes.len() < 3 { return false; }
    // bytes[1..2] hold the 11 data bits (ADDR+ENDP for token, frame# for SOF)
    // followed by the 5 transmitted CRC bits, all packed LSB-first across 16 bits.
    let combined = u16::from_le_bytes([bytes[1], bytes[2]]);
    let mut crc: u8 = 0x1F;
    for i in 0..16 {
        let feedback = (((combined >> i) as u8) ^ crc) & 1;
        crc >>= 1;
        if feedback != 0 {
            crc ^= 0x14; // reflected G(X) = X^5 + X^2 + 1
        }
    }
    // USB CRC5 residual in the reflected domain: 0x06
    // (the spec's "01100b" in LSB-first wire order = 0x06 as a register value)
    crc == 0x06
}

/// Validate CRC16 for data packets (DATA0/DATA1/DATA2/MDATA).
///
/// Processes bytes[1..] (payload + the two transmitted CRC bytes) through the
/// reflected (LSB-first) CRC-16/USB algorithm:
///   polynomial: G(X) = X^16 + X^15 + X^2 + 1 (0x8005), reflected = 0xA001
///   initial value: 0xFFFF
///
/// The USB spec states the residual as 1000000000001101b (0x800D) in MSB-first
/// notation.  In the reflected register that equals 0xB001
/// (bit-reverse of 0x800D over 16 bits).
fn check_crc16(bytes: &[u8]) -> bool {
    if bytes.len() < 3 { return false; }
    let mut crc: u16 = 0xFFFF;
    for &byte in &bytes[1..] { // skip PID, include both CRC bytes
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA001; // reflected 0x8005
            } else {
                crc >>= 1;
            }
        }
    }
    // USB CRC16 residual in the reflected domain: 0xB001
    // (the spec's 0x800D written MSB-first bit-reverses to 0xB001 in the register)
    crc == 0xB001
}

/// Format a CRC value with a validity indicator for the details pane.
fn crc_annotation(valid: bool) -> &'static str {
    if valid { "  ✓" } else { "  ✗ INVALID" }
}

/// Decode ADDR and ENDP from a USB token packet (bytes after PID).
fn decode_token(bytes: &[u8]) -> (u8, u8) {
    if bytes.len() < 3 {
        return (0, 0);
    }
    let addr = bytes[1] & 0x7F;
    let ep   = ((bytes[1] >> 7) & 1) | ((bytes[2] & 0x07) << 1);
    (addr, ep)
}

/// Extract frame number from a SOF PacketItem label (best-effort).
fn frame_from_sof(pkt: &PacketItem) -> u16 {
    pkt.label.split("frame=").nth(1)
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn pid_name(pid: u8) -> &'static str {
    match pid {
        PID_SOF   => "SOF",
        PID_SETUP => "SETUP",
        PID_IN    => "IN",
        PID_OUT   => "OUT",
        PID_PING  => "PING",
        PID_SPLIT => "SPLIT",
        PID_DATA0 => "DATA0",
        PID_DATA1 => "DATA1",
        PID_DATA2 => "DATA2",
        PID_MDATA => "MDATA",
        PID_ACK   => "ACK",
        PID_NAK   => "NAK",
        PID_STALL => "STALL",
        PID_NYET  => "NYET",
        PID_PRE   => "PRE/ERR",
        _         => "?",
    }
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

/// Returns `true` if any packet in the slice has an invalid CRC.
fn pkts_have_crc_error(pkts: &[PacketItem]) -> bool {
    pkts.iter().any(|p| p.crc_valid == Some(false))
}

fn standalone_data_txn(pkt: PacketItem, timestamp_ns: u64) -> TransactionInfo {
    let has_crc_error = pkt.crc_valid == Some(false);
    TransactionInfo {
        kind: TransactionKind::Other,
        label: pkt.label.clone(),
        details: pkt.details.clone(),
        packets: vec![pkt],
        timestamp_ns,
        has_crc_error,
    }
}

/// Emit a completed control transfer as a `TransactionInfo`.
fn build_control_txn(
    addr: u8, ep: u8,
    setup_label: &str,
    packets: &[PacketItem],
    nak_count: u32,
    stalled: bool,
    ts: u64,
) -> TransactionInfo {
    let has_crc_error = pkts_have_crc_error(packets);
    let status = if stalled { "[STALL]" } else { "[ACK]" };
    let retry  = if nak_count > 0 { format!("  ({nak_count} retries)") } else { String::new() };
    let crc_tag = if has_crc_error { "  [CRC ERR]" } else { "" };
    let label  = format!("Control  {setup_label}  dev={addr}{retry}  {status}{crc_tag}");
    let details = build_details(addr, ep, packets);
    TransactionInfo {
        kind: TransactionKind::Control,
        label,
        details,
        packets: packets.to_vec(),
        timestamp_ns: ts,
        has_crc_error,
    }
}

/// Emit a completed bulk/interrupt transfer as a `TransactionInfo`.
fn build_bulk_txn(
    is_in: bool,
    addr: u8, ep: u8,
    packets: &[PacketItem],
    total_bytes: usize,
    nak_count: u32,
    ts: u64,
) -> TransactionInfo {
    let has_crc_error = pkts_have_crc_error(packets);
    let dir     = if is_in { "IN " } else { "OUT" };
    let retry   = if nak_count > 0 { format!("  ({nak_count} retries)") } else { String::new() };
    let crc_tag = if has_crc_error { "  [CRC ERR]" } else { "" };
    let label   = format!("Bulk {dir}  dev={addr}  ep={ep}  {total_bytes} bytes{retry}{crc_tag}");
    let kind    = if is_in { TransactionKind::BulkIn } else { TransactionKind::BulkOut };
    TransactionInfo {
        kind,
        label,
        details: build_details(addr, ep, packets),
        packets: packets.to_vec(),
        timestamp_ns: ts,
        has_crc_error,
    }
}

/// Emit a completed isochronous transfer as a `TransactionInfo`.
fn build_iso_txn(
    is_in: bool,
    addr: u8, ep: u8,
    packets: &[PacketItem],
    data_len: usize,
    ts: u64,
) -> TransactionInfo {
    let has_crc_error = pkts_have_crc_error(packets);
    let dir     = if is_in { "IN " } else { "OUT" };
    let crc_tag = if has_crc_error { "  [CRC ERR]" } else { "" };
    TransactionInfo {
        kind: TransactionKind::Isochronous,
        label: format!("Isoch {dir}  dev={addr}  ep={ep}  {data_len} bytes{crc_tag}"),
        details: build_details(addr, ep, packets),
        packets: packets.to_vec(),
        timestamp_ns: ts,
        has_crc_error,
    }
}

fn build_details(addr: u8, ep: u8, packets: &[PacketItem]) -> String {
    let mut s = format!("Device: {addr}  Endpoint: {ep}\n\nPackets:\n");
    for p in packets {
        s.push_str(&format!("  {}\n", p.label));
    }
    s
}

/// Human-readable label derived from the SETUP packet fields.
fn decode_setup_label(bm_request_type: u8, b_request: u8, w_value: u16) -> String {
    let dir      = if (bm_request_type >> 7) & 1 == 1 { "IN" } else { "OUT" };
    let req_type = match (bm_request_type >> 5) & 0x3 {
        0 => "Standard",
        1 => "Class",
        2 => "Vendor",
        _ => "Reserved",
    };

    match (bm_request_type & 0x60, b_request) {
        // Standard requests
        (0x00, 0x00) => "GET_STATUS".to_string(),
        (0x00, 0x01) => "CLEAR_FEATURE".to_string(),
        (0x00, 0x03) => "SET_FEATURE".to_string(),
        (0x00, 0x05) => format!("SET_ADDRESS  addr={}", w_value & 0x7F),
        (0x00, 0x06) => {
            let desc_type = (w_value >> 8) as u8;
            let idx       = (w_value & 0xFF) as u8;
            let name = match desc_type {
                1 => "Device",
                2 => "Configuration",
                3 => "String",
                4 => "Interface",
                5 => "Endpoint",
                6 => "DeviceQualifier",
                7 => "OtherSpeedConfig",
                _ => "Unknown",
            };
            format!("GET_DESCRIPTOR  {name}[{idx}]")
        }
        (0x00, 0x07) => "SET_DESCRIPTOR".to_string(),
        (0x00, 0x08) => "GET_CONFIGURATION".to_string(),
        (0x00, 0x09) => format!("SET_CONFIGURATION  cfg={}", w_value & 0xFF),
        (0x00, 0x0A) => "GET_INTERFACE".to_string(),
        (0x00, 0x0B) => "SET_INTERFACE".to_string(),
        (0x00, 0x0C) => "SYNCH_FRAME".to_string(),
        // Class / Vendor fallback
        _ => format!("{req_type} 0x{b_request:02X} {dir}"),
    }
}
