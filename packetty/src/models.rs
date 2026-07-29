//! Flat, windowed view of the capture tree for the ratatui traffic pane,
//! backed by `packetry_core`/`packetry_db` via [`crate::item`] instead of an
//! in-memory `Vec<TreeItem>`.
//!
//! packetty renders a two-level tree (transfer row + flattened packet rows),
//! simpler than packetry-gui's three-level Hierarchical view (transfer /
//! transaction / packet) — see [`crate::item::flatten_packets`].

use std::collections::BTreeMap;

use anyhow::{Context, Result};

use packetry_core::capture::{
    CaptureReader, CaptureReaderOps, EndpointType as CapEndpointType, GroupContent, PacketId,
};
use packetry_core::usb::{Direction, EndpointType as UsbEndpointType, PID};

use crate::item::{self, ItemSource, TrafficItem, TrafficViewMode};

pub use plugins::models::{
    bytes_to_text_hints, hex_ascii_dump, UsbConfigInfo, UsbDeviceInfo, UsbEndpointInfo, UsbInterfaceInfo,
};

// ---------------------------------------------------------------------------
// Row coloring
// ---------------------------------------------------------------------------

/// Coarse classification of a row, used only to pick a display color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowKind {
    Control,
    BulkIn,
    BulkOut,
    Interrupt,
    Isochronous,
    Framing,
    Polling,
    Ambiguous,
    Event,
    Other,
}

pub fn row_kind_for_item(reader: &mut CaptureReader, item: &TrafficItem) -> Result<RowKind> {
    use TrafficItem::*;
    match item {
        EventGroup(..) | EventSubgroup(..) | Event(..) => Ok(RowKind::Event),
        TransactionGroup(_, endpoint_id, ep_group_id) | TransactionGroupEnd(_, endpoint_id, ep_group_id) => {
            let group = reader.group(*endpoint_id, *ep_group_id)?;
            Ok(match group.content {
                GroupContent::Request(_) | GroupContent::IncompleteRequest => RowKind::Control,
                GroupContent::Framing => RowKind::Framing,
                GroupContent::Polling(_) => RowKind::Polling,
                GroupContent::Ambiguous(..) => RowKind::Ambiguous,
                GroupContent::Invalid => RowKind::Other,
                GroupContent::Data(_) => match group.endpoint_type {
                    CapEndpointType::Normal(UsbEndpointType::Bulk) => match group.endpoint.direction() {
                        Direction::In => RowKind::BulkIn,
                        Direction::Out => RowKind::BulkOut,
                    },
                    CapEndpointType::Normal(UsbEndpointType::Interrupt) => RowKind::Interrupt,
                    CapEndpointType::Normal(UsbEndpointType::Isochronous) => RowKind::Isochronous,
                    _ => RowKind::Other,
                },
            })
        }
        _ => Ok(RowKind::Other),
    }
}

fn packet_row_kind(reader: &mut CaptureReader, packet_id: PacketId) -> Result<RowKind> {
    let bytes = reader.packet(packet_id)?;
    Ok(match bytes.first().map(|&b| PID::from(b)) {
        Some(PID::SOF) => RowKind::Framing,
        Some(PID::SETUP) => RowKind::Control,
        Some(PID::IN) => RowKind::BulkIn,
        Some(PID::OUT) => RowKind::BulkOut,
        Some(PID::NAK) => RowKind::Polling,
        Some(PID::STALL) => RowKind::Ambiguous,
        _ => RowKind::Other,
    })
}

// ---------------------------------------------------------------------------
// FlatRow — one displayable row
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FlatRow {
    /// Top-level `TrafficItemId`, as a plain index.
    pub top_idx: u64,
    /// `Some(i)` when this row is the i-th flattened packet of the parent.
    pub child_idx: Option<u64>,
    pub label: String,
    pub has_children: bool,
    pub is_expanded: bool,
    /// 0 = top-level (transfer/group), 1 = child packet.
    pub depth: u8,
    pub kind: RowKind,
    pub timestamp_ns: u64,
    pub crc_error: bool,
}

// ---------------------------------------------------------------------------
// ItemStore — windowed queries against a live CaptureReader
// ---------------------------------------------------------------------------

/// Cap on how many children get materialized when a row is expanded — bounds
/// the one-time cost of expanding a pathologically large group (e.g. a
/// multi-minute SOF/Framing run covering hundreds of thousands of packets).
/// Collapsing and re-expanding refreshes the cache from scratch.
const EXPAND_CHILD_CAP: u64 = 20_000;

/// Cap on how many of a row's children get scanned for a CRC error when
/// building its collapsed summary — this runs once per *visible* row on
/// every redraw, so it must stay cheap regardless of the row's real child
/// count.
const CRC_SCAN_CAP: u64 = 256;

/// Cap on how many packets get concatenated into the "raw data" hex-dump
/// preview for a selected but *unexpanded* top-level row. Same reasoning as
/// [`CRC_SCAN_CAP`]: runs every redraw for whatever's selected.
const RAW_BYTES_PACKET_CAP: u64 = 512;

/// Hard cap on the total bytes in that hex-dump preview, in case even a
/// bounded number of packets (e.g. large isochronous frames) add up to more
/// than is useful to render.
const RAW_BYTES_TOTAL_CAP: usize = 65_536;

/// Holds the capture reader plus which top-level rows are expanded, and
/// answers the same windowed-row questions `app.rs`/`ui.rs` used to ask of
/// an in-memory `VecDeque<TreeItem>`.
///
/// Unlike that old `VecDeque`, `item_count()` here can be in the hundreds of
/// thousands, and every query against it does real (mmap-backed) I/O — so
/// unlike the old O(n)-but-in-memory-only scans, an O(n) scan here is
/// genuinely slow, and even a single expanded row can itself cover a huge
/// number of packets (one giant SOF/Framing group, say). Two things keep
/// navigation fast regardless of capture size:
///  - `expanded` caches each expanded row's (capped) child list up front, so
///    resolving flat indices and rendering never re-walks a row's children
///    more than once per expand/collapse — not once per redraw.
///  - collapsed rows never expand their children at all: `has_children` is
///    an O(1) range-length check, and the CRC-error indicator only scans a
///    bounded prefix of children (see [`CRC_SCAN_CAP`]).
pub struct ItemStore {
    pub reader: CaptureReader,
    /// top_idx -> (capped child packet ids, whether that list was truncated).
    expanded: BTreeMap<u64, (Vec<PacketId>, bool)>,
}

impl ItemStore {
    pub fn new(reader: CaptureReader) -> Self {
        ItemStore { reader, expanded: BTreeMap::new() }
    }

    pub fn replace_reader(&mut self, reader: CaptureReader) {
        self.reader = reader;
        self.expanded.clear();
    }

    pub fn item_count(&self) -> u64 {
        self.reader.item_count()
    }

    pub fn top_item(&mut self, top_idx: u64) -> Result<TrafficItem> {
        ItemSource::<TrafficItem, TrafficViewMode>::item(
            &mut self.reader,
            None,
            TrafficViewMode::Hierarchical,
            top_idx,
        )
    }

    pub fn is_expanded(&self, top_idx: u64) -> bool {
        self.expanded.contains_key(&top_idx)
    }

    pub fn set_expanded(&mut self, top_idx: u64, expanded: bool) -> Result<()> {
        if expanded {
            let item = self.top_item(top_idx)?;
            let (children, truncated) = item::flatten_packets_capped(&mut self.reader, &item, EXPAND_CHILD_CAP)?;
            if !children.is_empty() {
                self.expanded.insert(top_idx, (children, truncated));
            }
        } else {
            self.expanded.remove(&top_idx);
        }
        Ok(())
    }

    pub fn collapse(&mut self, top_idx: u64) {
        self.expanded.remove(&top_idx);
    }

    /// Full (uncapped) child list — only used off the hot redraw path (a
    /// selected row's details, or the plugin bridge), so correctness beats
    /// speed here.
    pub fn child_ids(&mut self, top_idx: u64) -> Result<Vec<PacketId>> {
        let item = self.top_item(top_idx)?;
        item::flatten_packets(&mut self.reader, &item)
    }

    /// O(1): whether this row has any children, without expanding them.
    pub fn has_children(&mut self, top_idx: u64) -> Result<bool> {
        let item = self.top_item(top_idx)?;
        item::group_has_children(&mut self.reader, &item)
    }

    /// O(1) cached child-row count of an expanded item.
    fn expanded_len(&self, top_idx: u64) -> u64 {
        self.expanded.get(&top_idx).map(|(v, _)| v.len() as u64).unwrap_or(0)
    }

    /// Sum of cached child-row counts for every expanded item with `top_idx`
    /// less than `before`. O(k), k = number of expanded rows.
    fn extra_rows_before(&self, before: u64) -> u64 {
        self.expanded.range(..before).map(|(_, (v, _))| v.len() as u64).sum()
    }

    /// Total number of visible flat rows. O(k).
    pub fn flat_row_count(&mut self) -> Result<u64> {
        let n = self.item_count();
        Ok(n + self.extra_rows_before(n))
    }

    /// Resolve a flat-row index to `(top_idx, child_idx)`. O(k).
    pub fn flat_index_resolve(&mut self, flat_idx: u64) -> Result<Option<(u64, Option<u64>)>> {
        let n = self.item_count();
        let expanded: Vec<u64> = self.expanded.keys().copied().collect();
        let mut gi = 0u64; // flat index of the start of the current segment
        let mut prev_top = 0u64; // first not-yet-accounted-for top_idx

        for exp_top in expanded {
            // Unexpanded run [prev_top, exp_top): 1 row each, 1:1 with flat index.
            let run_len = exp_top - prev_top;
            if flat_idx < gi + run_len {
                return Ok(Some((prev_top + (flat_idx - gi), None)));
            }
            gi += run_len;

            // exp_top's own row.
            if flat_idx == gi {
                return Ok(Some((exp_top, None)));
            }
            gi += 1;

            // exp_top's children.
            let count = self.expanded_len(exp_top);
            if flat_idx < gi + count {
                return Ok(Some((exp_top, Some(flat_idx - gi))));
            }
            gi += count;

            prev_top = exp_top + 1;
        }

        // Trailing unexpanded run [prev_top, n).
        if flat_idx < gi + (n - prev_top) {
            return Ok(Some((prev_top + (flat_idx - gi), None)));
        }
        Ok(None)
    }

    /// Flat row index of the top-level row for `top_idx`. O(k).
    pub fn flat_top_row_index(&mut self, top_idx: u64) -> Result<Option<u64>> {
        if top_idx >= self.item_count() {
            return Ok(None);
        }
        Ok(Some(top_idx + self.extra_rows_before(top_idx)))
    }

    fn build_top_row(&mut self, top_idx: u64, item: &TrafficItem) -> Result<FlatRow> {
        let label = ItemSource::<TrafficItem, TrafficViewMode>::description(&mut self.reader, item, false)?;
        let timestamp_ns = ItemSource::<TrafficItem, TrafficViewMode>::timestamp(&mut self.reader, item)?;
        let has_children = item::group_has_children(&mut self.reader, item)?;

        // Bounded CRC scan: reuse the expand cache if we have one, otherwise
        // pull just enough packets to check without expanding the whole row.
        let cached_prefix: Option<Vec<PacketId>> = self
            .expanded
            .get(&top_idx)
            .map(|(v, _)| v.iter().take(CRC_SCAN_CAP as usize).copied().collect());
        let scan_packets = match cached_prefix {
            Some(v) => v,
            None => item::flatten_packets_capped(&mut self.reader, item, CRC_SCAN_CAP)?.0,
        };
        let mut crc_error = false;
        for pid in scan_packets {
            if item::packet_has_crc_error(&mut self.reader, pid)? {
                crc_error = true;
                break;
            }
        }

        Ok(FlatRow {
            top_idx,
            child_idx: None,
            label,
            has_children,
            is_expanded: self.is_expanded(top_idx),
            depth: 0,
            kind: row_kind_for_item(&mut self.reader, item)?,
            timestamp_ns,
            crc_error,
        })
    }

    fn build_packet_row(&mut self, top_idx: u64, child_idx: u64, packet_id: PacketId) -> Result<FlatRow> {
        let pkt_item = TrafficItem::Packet(None, None, packet_id);
        let label = ItemSource::<TrafficItem, TrafficViewMode>::description(&mut self.reader, &pkt_item, false)?;
        let timestamp_ns = ItemSource::<TrafficItem, TrafficViewMode>::timestamp(&mut self.reader, &pkt_item)?;
        let crc_error = item::packet_has_crc_error(&mut self.reader, packet_id)?;
        Ok(FlatRow {
            top_idx,
            child_idx: Some(child_idx),
            label,
            has_children: false,
            is_expanded: false,
            depth: 1,
            kind: packet_row_kind(&mut self.reader, packet_id)?,
            timestamp_ns,
            crc_error,
        })
    }

    /// Yield only the rows in `[offset, offset + max_rows)`, as
    /// `(global_flat_index, FlatRow)` pairs. Jumps straight to `offset` in
    /// O(k) via [`Self::flat_index_resolve`] instead of scanning every row
    /// before it, then walks forward for at most `max_rows` rows using only
    /// cached/bounded child lookups.
    pub fn flat_rows_window(&mut self, offset: u64, max_rows: u64) -> Result<Vec<(u64, FlatRow)>> {
        let mut result = Vec::with_capacity(max_rows as usize);
        let end = offset.saturating_add(max_rows);
        let n = self.item_count();

        let Some((mut ti, start_child)) = self.flat_index_resolve(offset)? else {
            return Ok(result);
        };

        let mut gi = offset;

        // If `offset` lands inside `ti`'s children, finish emitting the rest
        // of them before moving on to the next top-level item.
        if let Some(start_c) = start_child {
            let packets = self.expanded.get(&ti).map(|(v, _)| v.clone()).unwrap_or_default();
            for (ci, &packet_id) in packets.iter().enumerate().skip(start_c as usize) {
                if gi >= end {
                    return Ok(result);
                }
                result.push((gi, self.build_packet_row(ti, ci as u64, packet_id)?));
                gi += 1;
            }
            ti += 1;
        }

        while ti < n && gi < end {
            let item = self.top_item(ti)?;
            result.push((gi, self.build_top_row(ti, &item)?));
            gi += 1;

            if gi < end && self.is_expanded(ti) {
                let packets = self.expanded.get(&ti).map(|(v, _)| v.clone()).unwrap_or_default();
                for (ci, &packet_id) in packets.iter().enumerate() {
                    if gi >= end {
                        break;
                    }
                    result.push((gi, self.build_packet_row(ti, ci as u64, packet_id)?));
                    gi += 1;
                }
            }
            ti += 1;
        }
        Ok(result)
    }

    /// Packet id for the `ci`-th child of `top_idx`, using the expand cache
    /// (populated when the row was expanded — which it must be, for a child
    /// row to be selectable at all) instead of re-flattening the whole
    /// group. Falls back to a bounded fetch if for some reason it isn't
    /// cached (e.g. called right after a collapse).
    fn cached_child(&mut self, top_idx: u64, ci: u64) -> Result<Option<PacketId>> {
        if let Some((cached, _)) = self.expanded.get(&top_idx) {
            return Ok(cached.get(ci as usize).copied());
        }
        let item = self.top_item(top_idx)?;
        let (packets, _truncated) = item::flatten_packets_capped(&mut self.reader, &item, ci + 1)?;
        Ok(packets.get(ci as usize).copied())
    }

    /// `(label, details)` for a specific row.
    pub fn row_details(&mut self, top_idx: u64, child_idx: Option<u64>) -> Result<(String, String)> {
        let item = match child_idx {
            None => self.top_item(top_idx)?,
            Some(ci) => {
                let packet_id = self.cached_child(top_idx, ci)?.context("packet index out of range")?;
                TrafficItem::Packet(None, None, packet_id)
            }
        };
        let label = ItemSource::<TrafficItem, TrafficViewMode>::description(&mut self.reader, &item, false)?;
        let details = ItemSource::<TrafficItem, TrafficViewMode>::description(&mut self.reader, &item, true)?;
        Ok((label, details))
    }

    /// Raw bytes for a specific row: a single packet's payload, or (for a
    /// top-level row) up to [`RAW_BYTES_PACKET_CAP`] packets' worth,
    /// concatenated, capped at [`RAW_BYTES_TOTAL_CAP`] total bytes. This runs
    /// on every redraw for whatever's selected, so a transfer with a huge
    /// number of packets (a long isochronous stream, say) can't turn
    /// "navigate onto this row" into a multi-second stall just to build a
    /// hex-dump preview of it.
    pub fn row_raw_bytes(&mut self, top_idx: u64, child_idx: Option<u64>) -> Result<Option<Vec<u8>>> {
        match child_idx {
            Some(ci) => {
                let packet_id = self.cached_child(top_idx, ci)?.context("packet index out of range")?;
                let bytes = self.reader.packet(packet_id)?;
                Ok(if bytes.is_empty() { None } else { Some(bytes) })
            }
            None => {
                let item = self.top_item(top_idx)?;
                let packets: Vec<PacketId> = match self.expanded.get(&top_idx) {
                    Some((cached, _)) => cached.iter().take(RAW_BYTES_PACKET_CAP as usize).copied().collect(),
                    None => item::flatten_packets_capped(&mut self.reader, &item, RAW_BYTES_PACKET_CAP)?.0,
                };
                let mut all = Vec::new();
                for pid in packets {
                    if all.len() >= RAW_BYTES_TOTAL_CAP {
                        break;
                    }
                    all.extend(self.reader.packet(pid)?);
                }
                all.truncate(RAW_BYTES_TOTAL_CAP);
                Ok(if all.is_empty() { None } else { Some(all) })
            }
        }
    }

    /// Every top-level row whose label/details/packet contents match `query`
    /// (case-insensitive), as `(top_idx, child_idx)` pairs in capture order.
    pub fn search(&mut self, query: &str) -> Result<Vec<(u64, Option<u64>)>> {
        let query = query.to_lowercase();
        let mut matches = Vec::new();
        if query.is_empty() {
            return Ok(matches);
        }
        let n = self.item_count();
        for ti in 0..n {
            let item = self.top_item(ti)?;
            let label = ItemSource::<TrafficItem, TrafficViewMode>::description(&mut self.reader, &item, false)?;
            let details = ItemSource::<TrafficItem, TrafficViewMode>::description(&mut self.reader, &item, true)?;
            if label.to_lowercase().contains(&query) || details.to_lowercase().contains(&query) {
                matches.push((ti, None));
            }
            let packets = item::flatten_packets(&mut self.reader, &item)?;
            for (ci, &packet_id) in packets.iter().enumerate() {
                let pkt_item = TrafficItem::Packet(None, None, packet_id);
                let label =
                    ItemSource::<TrafficItem, TrafficViewMode>::description(&mut self.reader, &pkt_item, false)?;
                let details =
                    ItemSource::<TrafficItem, TrafficViewMode>::description(&mut self.reader, &pkt_item, true)?;
                let raw = self.reader.packet(packet_id).unwrap_or_default();
                let dump = hex_ascii_dump(&raw);
                let hints = bytes_to_text_hints(&raw);
                if label.to_lowercase().contains(&query)
                    || details.to_lowercase().contains(&query)
                    || dump.to_lowercase().contains(&query)
                    || hints.to_lowercase().contains(&query)
                {
                    matches.push((ti, Some(ci as u64)));
                }
            }
        }
        Ok(matches)
    }

    /// Total number of top-level transfer/group rows captured so far.
    pub fn transaction_count(&self) -> u64 {
        self.item_count()
    }

    /// Total individual packets captured so far.
    pub fn packet_count(&self) -> u64 {
        self.reader.packet_count()
    }

    /// Find the top-level row index of the first item at or after `ts`
    /// (nanoseconds from start of capture), used by plugin "goto timestamp"
    /// navigation requests.
    pub fn top_index_at_or_after(&mut self, ts: u64) -> Result<Option<u64>> {
        let n = self.item_count();
        for ti in 0..n {
            let item = self.top_item(ti)?;
            let item_ts = ItemSource::<TrafficItem, TrafficViewMode>::timestamp(&mut self.reader, &item)?;
            if item_ts >= ts {
                return Ok(Some(ti));
            }
        }
        Ok(if n == 0 { None } else { Some(n - 1) })
    }

    /// Whether the underlying capture is fully decoded (finished loading /
    /// capture stopped).
    pub fn complete(&self) -> bool {
        self.reader.complete()
    }
}
