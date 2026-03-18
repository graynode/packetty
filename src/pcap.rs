//! Minimal PCAP (classic libpcap) file reader and writer for USB 2.0 captures.
//!
//! Format details:
//!   - Magic      0xA1B2_3C4D  (nanosecond-resolution variant)
//!   - Link type  288          (DLT_USB_2_0, same as packetry / Wireshark)
//!   - All multi-byte fields are little-endian.

use std::io::{self, Read, Write};
use anyhow::{bail, Context, Result};

pub const LINK_TYPE_USB_2_0: u32 = 288;

const MAGIC_NS: u32 = 0xa1b2_3c4d; // nanosecond timestamps
const MAGIC_US: u32 = 0xa1b2_c3d4; // microsecond timestamps (read-only support)
const VERSION_MAJOR: u16 = 2;
const VERSION_MINOR: u16 = 4;
const SNAPLEN: u32 = 65_535;

// ── Writer ─────────────────────────────────────────────────────────────────

/// Writes a pcap file containing raw USB 2.0 packets.
pub struct PcapWriter<W: Write> {
    inner: W,
}

impl<W: Write> PcapWriter<W> {
    /// Create a new writer and emit the 24-byte global header.
    pub fn new(mut w: W) -> Result<Self> {
        w.write_all(&MAGIC_NS.to_le_bytes())?;
        w.write_all(&VERSION_MAJOR.to_le_bytes())?;
        w.write_all(&VERSION_MINOR.to_le_bytes())?;
        w.write_all(&0i32.to_le_bytes())?; // thiszone
        w.write_all(&0u32.to_le_bytes())?; // sigfigs
        w.write_all(&SNAPLEN.to_le_bytes())?;
        w.write_all(&LINK_TYPE_USB_2_0.to_le_bytes())?;
        Ok(PcapWriter { inner: w })
    }

    /// Write one USB packet with a nanosecond timestamp.
    pub fn write_packet(&mut self, timestamp_ns: u64, data: &[u8]) -> Result<()> {
        let ts_sec  = (timestamp_ns / 1_000_000_000) as u32;
        let ts_frac = (timestamp_ns % 1_000_000_000) as u32;
        let len     = data.len() as u32;
        self.inner.write_all(&ts_sec.to_le_bytes())?;
        self.inner.write_all(&ts_frac.to_le_bytes())?;
        self.inner.write_all(&len.to_le_bytes())?; // incl_len
        self.inner.write_all(&len.to_le_bytes())?; // orig_len
        self.inner.write_all(data)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.inner.flush().context("flushing pcap writer")
    }
}

// ── Reader ─────────────────────────────────────────────────────────────────

/// Reads a pcap file and yields `(timestamp_ns, packet_bytes)` pairs.
pub struct PcapReader<R: Read> {
    inner: R,
    /// Nanoseconds per fractional timestamp unit (1 for ns files, 1000 for µs).
    ns_per_frac: u64,
    /// Origin timestamp of first packet (subtracted so stream starts at t=0).
    origin_ns: Option<u64>,
    pub link_type: u32,
}

impl<R: Read> PcapReader<R> {
    pub fn new(mut r: R) -> Result<Self> {
        let magic = read_u32_le(&mut r).context("reading pcap magic")?;
        let ns_per_frac = match magic {
            MAGIC_NS => 1,
            MAGIC_US => 1_000,
            _ => bail!("Not a valid pcap file (magic 0x{magic:08X})"),
        };
        let _major = read_u16_le(&mut r)?;
        let _minor = read_u16_le(&mut r)?;
        let _thiszone = read_u32_le(&mut r)?;
        let _sigfigs  = read_u32_le(&mut r)?;
        let _snaplen  = read_u32_le(&mut r)?;
        let link_type = read_u32_le(&mut r)?;
        Ok(PcapReader { inner: r, ns_per_frac, origin_ns: None, link_type })
    }

    /// Return the next `(timestamp_ns, bytes)` or `None` at EOF.
    pub fn next_packet(&mut self) -> Result<Option<(u64, Vec<u8>)>> {
        let ts_sec = match try_read_u32_le(&mut self.inner)? {
            Some(v) => v as u64,
            None    => return Ok(None),
        };
        let ts_frac  = read_u32_le(&mut self.inner)? as u64;
        let incl_len = read_u32_le(&mut self.inner)? as usize;
        let _orig_len = read_u32_le(&mut self.inner)?;

        let mut data = vec![0u8; incl_len];
        self.inner.read_exact(&mut data)?;

        let raw_ns = ts_sec * 1_000_000_000 + ts_frac * self.ns_per_frac;
        let origin = *self.origin_ns.get_or_insert(raw_ns);
        let timestamp_ns = raw_ns.saturating_sub(origin);

        Ok(Some((timestamp_ns, data)))
    }
}

// ── I/O helpers ────────────────────────────────────────────────────────────

fn read_u16_le(r: &mut impl Read) -> io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_le_bytes(b))
}

fn read_u32_le(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

/// Like `read_u32_le` but returns `None` at clean EOF instead of an error.
fn try_read_u32_le(r: &mut impl Read) -> io::Result<Option<u32>> {
    let mut b = [0u8; 4];
    let mut filled = 0;
    while filled < 4 {
        match r.read(&mut b[filled..])? {
            0 if filled == 0 => return Ok(None), // clean EOF
            0 => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated pcap packet header")),
            n => filled += n,
        }
    }
    Ok(Some(u32::from_le_bytes(b)))
}

// ── Auto-generate a save filename ──────────────────────────────────────────

/// Generate a capture filename like `capture-20240317-143022.pcap`.
pub fn default_capture_filename() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Simple timestamp decomposition (no chrono dep needed here).
    let s = secs % 86400;
    let d = secs / 86400;
    // Days since epoch → rough YYYYMMDD (good enough for a filename).
    let ymd = epoch_days_to_ymd(d as u32);
    let hh = s / 3600;
    let mm = (s % 3600) / 60;
    let ss = s % 60;
    format!("capture-{}-{:02}{:02}{:02}.pcap", ymd, hh, mm, ss)
}

fn epoch_days_to_ymd(days: u32) -> String {
    // Gregorian calendar approximation.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{}{:02}{:02}", y, m, d)
}
