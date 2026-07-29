//! Shared USB capture data types used by all plugins.

// ---------------------------------------------------------------------------
// Hex + ASCII dump utilities
// ---------------------------------------------------------------------------

/// Produce a classic hex+ASCII dump string, 16 bytes per line.
pub fn hex_ascii_dump(bytes: &[u8]) -> String {
    if bytes.is_empty() { return String::new(); }
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let offset = i * 16;
        let mut hex = String::new();
        for (j, b) in chunk.iter().enumerate() {
            if j == 8 { hex.push(' '); }
            hex.push_str(&format!("{b:02x} "));
        }
        let hex_width = 16 * 3 + 1;
        while hex.len() < hex_width { hex.push(' '); }
        let ascii: String = chunk.iter().map(|&b| {
            if b >= 0x20 && b < 0x7f { b as char } else { '.' }
        }).collect();
        out.push_str(&format!("{offset:04x}  {hex} {ascii}\n"));
    }
    if out.ends_with('\n') { out.pop(); }
    out
}

/// Produce additional searchable text hints from raw bytes (UTF-16LE + null-stripped ASCII).
pub fn bytes_to_text_hints(bytes: &[u8]) -> String {
    let mut out = String::new();
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
    let stripped: String = bytes.iter()
        .filter(|&&b| b != 0x00 && b >= 0x20 && b < 0x7f)
        .map(|&b| b as char)
        .collect();
    if !stripped.is_empty() { out.push_str(&stripped); }
    out
}

// ---------------------------------------------------------------------------
// Packet-level types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Sof, Setup, In, Out, Data, Ack, Nak, Stall, Other,
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

#[derive(Debug, Clone)]
pub struct PacketItem {
    pub packet_type: PacketType,
    pub label: String,
    pub details: String,
    pub raw_bytes: Vec<u8>,
    pub timestamp_ns: u64,
    pub crc_valid: Option<bool>,
}

// ---------------------------------------------------------------------------
// Transaction-level types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionKind {
    Control,
    BulkIn,
    BulkOut,
    Interrupt,
    Isochronous,
    SofGroup,
    Nak,
    Stall,
    Other,
}

#[derive(Debug, Clone)]
pub struct TransactionInfo {
    pub kind: TransactionKind,
    pub label: String,
    pub details: String,
    pub packets: Vec<PacketItem>,
    pub timestamp_ns: u64,
    pub has_crc_error: bool,
}

// ---------------------------------------------------------------------------
// Device descriptor types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct UsbDeviceInfo {
    pub address: u8,
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
    pub configurations: Vec<UsbConfigInfo>,
}

impl UsbDeviceInfo {
    pub fn class_name(&self) -> &'static str { usb_class_name(self.class) }
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
        _    => "Unknown",
    }
}

#[derive(Debug, Clone)]
pub struct UsbConfigInfo {
    pub configuration_value: u8,
    pub num_interfaces: u8,
    pub attributes: u8,
    pub max_power: u8,
    pub interfaces: Vec<UsbInterfaceInfo>,
}

impl UsbConfigInfo {
    pub fn self_powered(&self) -> bool   { self.attributes & 0x40 != 0 }
    pub fn remote_wakeup(&self) -> bool  { self.attributes & 0x20 != 0 }
    pub fn max_power_ma(&self) -> u16    { self.max_power as u16 * 2 }
}

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
