use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// Hex + ASCII dump
// ---------------------------------------------------------------------------

/// Produce a classic hex+ASCII dump string, 16 bytes per line.
/// Non-printable bytes are shown as `.` in the ASCII column.
///
/// Example line:
///   `0000  2d 00 02 c3 4b 00 02 d2  00 00 00 00 00 00 00 00  -...K...........`
pub fn hex_ascii_dump(bytes: &[u8]) -> String {
    if bytes.is_empty() { return String::new(); }
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let offset = i * 16;
        // Hex part — two groups of 8, padded to fixed width.
        let mut hex = String::new();
        for (j, b) in chunk.iter().enumerate() {
            if j == 8 { hex.push(' '); }
            hex.push_str(&format!("{b:02x} "));
        }
        // Pad to align the ASCII column when the last row is short.
        let hex_width = 16 * 3 + 1; // 16 bytes × "xx " + mid-space
        while hex.len() < hex_width { hex.push(' '); }
        // ASCII part.
        let ascii: String = chunk.iter().map(|&b| {
            if b >= 0x20 && b < 0x7f { b as char } else { '.' }
        }).collect();
        out.push_str(&format!("{offset:04x}  {hex} {ascii}\n"));
    }
    // Remove trailing newline.
    if out.ends_with('\n') { out.pop(); }
    out
}

/// Produce additional searchable text hints from raw bytes:
/// - UTF-16LE decode (covers USB string descriptors like `4f 00 6e 00 65 00` → "One")
/// - Null-stripped ASCII (same bytes → "One" even without proper pairing)
///
/// The result is concatenated so callers can do a single `.contains()` check.
pub fn bytes_to_text_hints(bytes: &[u8]) -> String {
    let mut out = String::new();

    // UTF-16LE: pair up bytes and decode.
    if bytes.len() >= 2 {
        let units: Vec<u16> = bytes.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let decoded = String::from_utf16_lossy(&units);
        if decoded.chars().any(|c| c.is_alphanumeric()) {
            out.push_str(&decoded);
            out.push('\n');
        }
    }

    // Null-stripped: keep printable ASCII, skip nulls.
    let stripped: String = bytes.iter()
        .filter(|&&b| b != 0x00 && b >= 0x20 && b < 0x7f)
        .map(|&b| b as char)
        .collect();
    if !stripped.is_empty() {
        out.push_str(&stripped);
    }

    out
}

// ---------------------------------------------------------------------------
// Packet-level types
// ---------------------------------------------------------------------------

/// The PID type of a single USB packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Sof,
    Setup,
    In,
    Out,
    Data,
    Ack,
    Nak,
    Stall,
    Other,
}

impl PacketType {
    pub fn short_name(self) -> &'static str {
        match self {
            PacketType::Sof   => "SOF  ",
            PacketType::Setup => "SETUP",
            PacketType::In    => "IN   ",
            PacketType::Out   => "OUT  ",
            PacketType::Data  => "DATA ",
            PacketType::Ack   => "ACK  ",
            PacketType::Nak   => "NAK  ",
            PacketType::Stall => "STALL",
            PacketType::Other => "?    ",
        }
    }
}

/// One packet that lives inside a transaction node.
#[derive(Debug, Clone)]
pub struct PacketItem {
    pub packet_type: PacketType,
    /// Short summary shown in the tree when the node is expanded.
    pub label: String,
    /// Full decoded fields shown in the detail pane.
    pub details: String,
    /// Raw USB packet bytes (PID + payload, no CRC).  Used for descriptor
    /// parsing; empty for token/handshake packets where we don't need them.
    pub raw_bytes: Vec<u8>,
    /// Nanoseconds from start of capture for this individual packet.
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// Transaction-level types
// ---------------------------------------------------------------------------

/// The logical kind of a USB transaction; drives colour coding in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionKind {
    Control,
    BulkIn,
    BulkOut,
    Interrupt,
    SofGroup,
    Nak,
    Stall,
    Other,
}

/// A complete, atomic USB transaction – one top-level tree node.
///
/// A transaction is the smallest unit a human cares about: a token + data +
/// handshake triplet, or a burst of SOF packets, or an isochronous transfer.
#[derive(Debug, Clone)]
pub struct TransactionInfo {
    pub kind: TransactionKind,
    /// Summary label shown collapsed, e.g. "Control  dev=0  GET_DESCRIPTOR".
    pub label: String,
    /// Details shown in the right-hand pane when the node itself is selected.
    pub details: String,
    /// Constituent packets; shown as children when the node is expanded.
    pub packets: Vec<PacketItem>,
    /// Nanoseconds from the start of capture (first packet of this transaction).
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// Tree display types
// ---------------------------------------------------------------------------

/// Flat displayable row produced by `TreeItem::flat_rows`.
#[derive(Debug, Clone)]
pub struct FlatRow {
    /// Index into `App::tree_items`.
    pub top_idx: usize,
    /// `Some(i)` when this row is the i-th child packet of the parent node.
    pub child_idx: Option<usize>,
    pub label: String,
    pub has_children: bool,
    pub is_expanded: bool,
    /// 0 = top-level, 1 = child packet.
    pub depth: u8,
    pub kind: TransactionKind,
    /// Nanoseconds from start of capture (inherited from parent for child rows).
    pub timestamp_ns: u64,
}

/// A top-level entry in the captured-traffic tree.
#[derive(Debug, Clone)]
pub struct TreeItem {
    pub kind: TransactionKind,
    pub label: String,
    pub details: String,
    pub expanded: bool,
    pub children: Vec<PacketItem>,
    /// Nanoseconds from start of capture.
    pub timestamp_ns: u64,
}

impl TreeItem {
    pub fn from_transaction(t: TransactionInfo) -> Self {
        TreeItem {
            kind: t.kind,
            label: t.label,
            details: t.details,
            expanded: false,
            children: t.packets,
            timestamp_ns: t.timestamp_ns,
        }
    }

    /// How many flat rows this item contributes (1 + children when expanded).
    #[inline]
    pub fn row_height(&self) -> usize {
        1 + if self.expanded { self.children.len() } else { 0 }
    }

    #[inline]
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Efficient flat-row helpers (no full-list allocation)
// ---------------------------------------------------------------------------

fn child_kind(pt: PacketType) -> TransactionKind {
    match pt {
        PacketType::Setup => TransactionKind::Control,
        PacketType::In    => TransactionKind::BulkIn,
        PacketType::Out   => TransactionKind::BulkOut,
        PacketType::Nak   => TransactionKind::Nak,
        PacketType::Stall => TransactionKind::Stall,
        PacketType::Sof   => TransactionKind::SofGroup,
        _                 => TransactionKind::Other,
    }
}

/// Total number of visible flat rows (O(n), no allocation).
pub fn flat_row_count(items: &VecDeque<TreeItem>) -> usize {
    items.iter().map(|i| i.row_height()).sum()
}

/// Resolve a flat-row index to `(top_idx, child_idx)`.  O(n).
pub fn flat_index_resolve(
    items: &VecDeque<TreeItem>,
    flat_idx: usize,
) -> Option<(usize, Option<usize>)> {
    let mut gi = 0usize;
    for (ti, item) in items.iter().enumerate() {
        if gi == flat_idx {
            return Some((ti, None));
        }
        gi += 1;
        if item.expanded {
            for ci in 0..item.children.len() {
                if gi == flat_idx {
                    return Some((ti, Some(ci)));
                }
                gi += 1;
            }
        }
    }
    None
}

/// Flat row index of the top-level row for `top_idx`.  O(top_idx).
pub fn flat_top_row_index(items: &VecDeque<TreeItem>, top_idx: usize) -> Option<usize> {
    let mut gi = 0usize;
    for (ti, item) in items.iter().enumerate() {
        if ti == top_idx {
            return Some(gi);
        }
        gi += item.row_height();
    }
    None
}

/// Yield only the rows in `[offset, offset + max_rows)`, as
/// `(global_flat_index, FlatRow)` pairs.  Never allocates the full list.
pub fn flat_rows_window(
    items: &VecDeque<TreeItem>,
    offset: usize,
    max_rows: usize,
) -> Vec<(usize, FlatRow)> {
    let mut result = Vec::with_capacity(max_rows);
    let end = offset.saturating_add(max_rows);
    let mut gi = 0usize;

    'outer: for (ti, item) in items.iter().enumerate() {
        if gi >= end {
            break;
        }
        // Top-level row.
        if gi >= offset {
            result.push((gi, FlatRow {
                top_idx: ti,
                child_idx: None,
                label: item.label.clone(),
                has_children: !item.children.is_empty(),
                is_expanded: item.expanded,
                depth: 0,
                kind: item.kind,
                timestamp_ns: item.timestamp_ns,
            }));
        }
        gi += 1;

        if item.expanded {
            for (ci, pkt) in item.children.iter().enumerate() {
                if gi >= end {
                    break 'outer;
                }
                if gi >= offset {
                    result.push((gi, FlatRow {
                        top_idx: ti,
                        child_idx: Some(ci),
                        label: pkt.label.clone(),
                        has_children: false,
                        is_expanded: false,
                        depth: 1,
                        kind: child_kind(pkt.packet_type),
                        timestamp_ns: pkt.timestamp_ns,
                    }));
                }
                gi += 1;
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Device information
// ---------------------------------------------------------------------------

/// Descriptor information about a USB device observed on the bus.
#[derive(Debug, Clone)]
pub struct UsbDeviceInfo {
    pub address: u8,
    // Device descriptor fields
    pub bcd_usb: u16,
    pub bcd_device: u16,
    pub vendor_id: u16,
    pub product_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub max_packet_size0: u8,
    pub num_configurations: u8,
    pub manufacturer: Option<String>,
    pub product: Option<String>,
    pub serial: Option<String>,
    /// Parsed configuration descriptors (populated as GET_DESCRIPTOR responses arrive).
    pub configurations: Vec<UsbConfigInfo>,
}

impl UsbDeviceInfo {
    pub fn class_name(&self) -> &'static str {
        usb_class_name(self.class)
    }
}

pub fn usb_class_name(class: u8) -> &'static str {
    match class {
        0x00 => "Defined per interface",
        0x01 => "Audio",
        0x02 => "Communications (CDC)",
        0x03 => "Human Interface Device (HID)",
        0x05 => "Physical",
        0x06 => "Image",
        0x07 => "Printer",
        0x08 => "Mass Storage",
        0x09 => "Hub",
        0x0A => "CDC-Data",
        0x0B => "Smart Card",
        0x0D => "Content Security",
        0x0E => "Video",
        0x0F => "Personal Healthcare",
        0x10 => "Audio/Video",
        0xDC => "Diagnostic",
        0xE0 => "Wireless Controller",
        0xEF => "Miscellaneous",
        0xFE => "Application Specific",
        0xFF => "Vendor Specific",
        _ => "Unknown",
    }
}

/// A single USB configuration (from a Configuration Descriptor).
#[derive(Debug, Clone)]
pub struct UsbConfigInfo {
    pub configuration_value: u8,
    pub num_interfaces: u8,
    pub attributes: u8,
    /// Max bus power in units of 2 mA (multiply by 2 for mA).
    pub max_power: u8,
    pub interfaces: Vec<UsbInterfaceInfo>,
}

impl UsbConfigInfo {
    pub fn self_powered(&self) -> bool { self.attributes & 0x40 != 0 }
    pub fn remote_wakeup(&self) -> bool { self.attributes & 0x20 != 0 }
    pub fn max_power_ma(&self) -> u16 { self.max_power as u16 * 2 }
}

/// A single USB interface (from an Interface Descriptor).
#[derive(Debug, Clone)]
pub struct UsbInterfaceInfo {
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub num_endpoints: u8,
    pub class: u8,
    pub subclass: u8,
    pub protocol: u8,
    pub endpoints: Vec<UsbEndpointInfo>,
}

impl UsbInterfaceInfo {
    pub fn class_name(&self) -> &'static str { usb_class_name(self.class) }
}

/// Endpoint descriptor.
#[derive(Debug, Clone)]
pub struct UsbEndpointInfo {
    pub address: u8,
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

impl UsbEndpointInfo {
    pub fn direction(&self) -> &'static str {
        if self.address & 0x80 != 0 { "IN" } else { "OUT" }
    }
    pub fn transfer_type(&self) -> &'static str {
        match self.attributes & 0x03 {
            0 => "Control",
            1 => "Isochronous",
            2 => "Bulk",
            _ => "Interrupt",
        }
    }
    pub fn ep_number(&self) -> u8 { self.address & 0x0F }
}

