//! GTK-free reimplementation of packetry-gui's `ItemSource` pattern.
//!
//! `TrafficItem`/`ItemSource` below are a near-verbatim port of
//! `packetry-gui/src/item.rs`'s Hierarchical view (the only GTK-free part of
//! that file) — same enum, same query semantics against `CaptureReaderOps` +
//! `EndpointLookup`. packetty's own two-level tree (transfer row + flattened
//! packet rows) is built on top via [`flatten_packets`] instead of exposing
//! packetry-gui's intermediate `Transaction` row.

use std::cmp::min;
use std::fmt::Write;

use anyhow::{Error, bail};

use packetry_core::capture::prelude::*;
use packetry_core::event::EventType;
use packetry_core::usb::{self, prelude::*, validate_packet};
use packetry_core::util::{Bytes, RangeLength, titlecase};
use packetry_db::util::{fmt_count, fmt_size};

pub trait ItemSource<Item, ViewMode> {
    fn item(&mut self, parent: Option<&Item>, view_mode: ViewMode, index: u64)
        -> Result<Item, Error>;
    fn item_children(&mut self, parent: Option<&Item>, view_mode: ViewMode)
        -> Result<(CompletionStatus, u64), Error>;
    fn child_item(&mut self, parent: &Item, index: u64) -> Result<Item, Error>;
    fn description(&mut self, item: &Item, detail: bool) -> Result<String, Error>;
    fn timestamp(&mut self, item: &Item) -> Result<Timestamp, Error>;
}

#[derive(Copy, Clone)]
pub enum CompletionStatus {
    Complete,
    Ongoing,
}

impl CompletionStatus {
    pub fn is_complete(&self) -> bool {
        matches!(self, CompletionStatus::Complete)
    }
}

#[derive(Clone, Debug)]
pub enum TrafficItem {
    EventGroup(GroupId, EndpointGroupId),
    EventSubgroup(Option<GroupId>, TransactionId),
    Event(Option<GroupId>, Option<TransactionId>, PacketId, EventId),
    TransactionGroup(GroupId, EndpointId, EndpointGroupId),
    TransactionGroupEnd(GroupId, EndpointId, EndpointGroupId),
    Transaction(Option<GroupId>, TransactionId),
    Packet(Option<GroupId>, Option<TransactionId>, PacketId),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum TrafficViewMode {
    Hierarchical,
    Transactions,
    Packets,
}

impl<T: CaptureReaderOps + EndpointLookup> ItemSource<TrafficItem, TrafficViewMode> for T {
    fn item(
        &mut self,
        parent: Option<&TrafficItem>,
        view_mode: TrafficViewMode,
        index: u64,
    ) -> Result<TrafficItem, Error> {
        use TrafficItem::*;
        use TrafficViewMode::*;
        match parent {
            None => Ok(match view_mode {
                Hierarchical => {
                    let item_id = TrafficItemId::from(index);
                    let group_id = self.item_group(item_id)?;
                    let entry = self.group_entry(group_id)?;
                    let endpoint_id = entry.endpoint_id();
                    let ep_group_id = entry.group_id();
                    match (endpoint_id == EVENT_EP_ID, entry.is_start()) {
                        (true, true) => EventGroup(group_id, ep_group_id),
                        (true, false) => {
                            let ep_traf = self.endpoint_traffic(endpoint_id)?;
                            let ep_transaction_id = ep_traf.group_start(ep_group_id)?;
                            let transaction_id = ep_traf.transaction_id(ep_transaction_id)?;
                            let packet_id = self.transaction_start(transaction_id)?;
                            let event_id = self.event_id(packet_id)?;
                            Event(None, None, packet_id, event_id)
                        }
                        (false, true) => TransactionGroup(group_id, endpoint_id, ep_group_id),
                        (false, false) => TransactionGroupEnd(group_id, endpoint_id, ep_group_id),
                    }
                }
                Transactions => {
                    let transaction_id = TransactionId::from(index);
                    Transaction(None, transaction_id)
                }
                Packets => {
                    let packet_id = PacketId::from(index);
                    Packet(None, None, packet_id)
                }
            }),
            Some(item) => self.child_item(item, index),
        }
    }

    fn child_item(&mut self, parent: &TrafficItem, index: u64) -> Result<TrafficItem, Error> {
        use TrafficItem::*;
        Ok(match parent {
            EventGroup(group_id, ep_group_id) => EventSubgroup(Some(*group_id), {
                let ep_traf = self.endpoint_traffic(EVENT_EP_ID)?;
                let offset = ep_traf.group_start(*ep_group_id)?;
                ep_traf.transaction_id(offset + index)?
            }),
            EventSubgroup(group_id_opt, transaction_id) => {
                let packet_id = self.transaction_start(*transaction_id)? + index;
                let event_id = self.event_id(packet_id)?;
                Event(*group_id_opt, Some(*transaction_id), packet_id, event_id)
            }
            TransactionGroup(group_id, endpoint_id, ep_group_id) => Transaction(Some(*group_id), {
                let ep_traf = self.endpoint_traffic(*endpoint_id)?;
                let offset = ep_traf.group_start(*ep_group_id)?;
                ep_traf.transaction_id(offset + index)?
            }),
            Transaction(group_id_opt, transaction_id) => Packet(
                *group_id_opt,
                Some(*transaction_id),
                self.transaction_start(*transaction_id)? + index,
            ),
            _ => bail!("Item {parent:?} has no children"),
        })
    }

    fn item_children(
        &mut self,
        parent: Option<&TrafficItem>,
        view_mode: TrafficViewMode,
    ) -> Result<(CompletionStatus, u64), Error> {
        use CompletionStatus::*;
        use TrafficItem::*;
        use TrafficViewMode::*;
        Ok(match parent {
            None => {
                let completion = if self.complete() { Complete } else { Ongoing };
                (
                    completion,
                    match view_mode {
                        Hierarchical => self.item_count(),
                        Transactions => self.transaction_count(),
                        Packets => self.packet_count(),
                    },
                )
            }
            Some(EventGroup(_, ep_group_id)) => {
                let transaction_count = self.group_range(EVENT_EP_ID, *ep_group_id)?.len();
                let ep_traf = self.endpoint_traffic(EVENT_EP_ID)?;
                if ep_group_id.value >= ep_traf.end_count() {
                    (Ongoing, transaction_count)
                } else {
                    (Complete, transaction_count)
                }
            }
            Some(Event(..)) => (Complete, 0),
            Some(TransactionGroup(_, endpoint_id, ep_group_id)) => {
                let transaction_count = self.group_range(*endpoint_id, *ep_group_id)?.len();
                let ep_traf = self.endpoint_traffic(*endpoint_id)?;
                if ep_group_id.value >= ep_traf.end_count() {
                    (Ongoing, transaction_count)
                } else {
                    (Complete, transaction_count)
                }
            }
            Some(TransactionGroupEnd(..)) => (Complete, 0),
            Some(Transaction(_, transaction_id) | EventSubgroup(_, transaction_id)) => {
                let packet_count = self.transaction_packet_range(*transaction_id)?.len();
                if transaction_id.value < self.transaction_count() - 1 {
                    (Complete, packet_count)
                } else {
                    (Ongoing, packet_count)
                }
            }
            Some(Packet(..)) => (Complete, 0),
        })
    }

    fn description(&mut self, item: &TrafficItem, detail: bool) -> Result<String, Error> {
        use usb::StartComplete::*;
        use TrafficItem::*;
        use PID::*;
        let mut s = String::new();
        Ok(match item {
            Packet(.., packet_id) => {
                let packet = self.packet(*packet_id)?;
                let len = packet.len();
                let too_long = len > 1027;
                if detail {
                    writeln!(s, "Packet #{} with {len} bytes", packet_id.value + 1)?;
                    writeln!(
                        s,
                        "Timestamp: {} ns from capture start",
                        fmt_count(self.packet_time(*packet_id)?)
                    )?;
                }
                match validate_packet(&packet) {
                    Err(None) => {
                        write!(s, "Malformed 0-byte packet")?;
                    }
                    Err(Some(pid)) => {
                        write!(s, "Malformed packet")?;
                        match pid {
                            RSVD if too_long => write!(s, " (reserved PID, and too long)"),
                            Malformed if too_long => write!(s, " (invalid PID, and too long)"),
                            RSVD => write!(s, " (reserved PID)"),
                            Malformed => write!(s, " (invalid PID)"),
                            pid if too_long => write!(s, " (possibly {pid}, but too long)"),
                            pid => write!(
                                s,
                                " (possibly {pid}, but {})",
                                match pid {
                                    SOF | SETUP | IN | OUT | PING => {
                                        if len != 3 { "wrong length" } else { "bad CRC" }
                                    }
                                    SPLIT => {
                                        if len != 4 { "wrong length" } else { "bad CRC" }
                                    }
                                    DATA0 | DATA1 | DATA2 | MDATA => {
                                        if len < 3 { "too short" } else { "bad CRC" }
                                    }
                                    ACK | NAK | NYET | STALL | ERR => "too long",
                                    RSVD | Malformed => unreachable!(),
                                }
                            ),
                        }?;
                        if len == 1 {
                            write!(s, " of 1 byte")
                        } else {
                            write!(s, " of {len} bytes")
                        }?;
                        if detail {
                            write!(s, "\nHex bytes: {}", Bytes::first(1024, &packet))
                        } else {
                            write!(s, ": {}", Bytes::first(100, &packet))
                        }?;
                    }
                    Ok(pid) => {
                        write!(s, "{pid} packet")?;
                        let fields = PacketFields::from_packet(&packet);
                        match &fields {
                            PacketFields::SOF(sof) => write!(
                                s,
                                " with frame number {}, CRC {:02X}",
                                sof.frame_number(),
                                sof.crc()
                            ),
                            PacketFields::Token(token) => write!(
                                s,
                                " on {}.{}, CRC {:02X}",
                                token.device_address(),
                                token.endpoint_number(),
                                token.crc()
                            ),
                            PacketFields::Data(data) if len <= 3 => {
                                write!(s, " with CRC {:04X} and no data", data.crc)
                            }
                            PacketFields::Data(data) => write!(
                                s,
                                " with CRC {:04X} and {} data bytes",
                                data.crc,
                                len - 3
                            ),
                            PacketFields::Split(split) => write!(
                                s,
                                " {} {} speed {} transaction on hub {} port {}",
                                match split.sc() {
                                    Start => "starting",
                                    Complete => "completing",
                                },
                                format!("{:?}", split.speed()).to_lowercase(),
                                format!("{:?}", split.endpoint_type()).to_lowercase(),
                                split.hub_address(),
                                split.port()
                            ),
                            PacketFields::None => Ok(()),
                        }?;
                        if matches!(fields, PacketFields::Data(_)) && len > 3 {
                            let data = &packet[1..len - 2];
                            if detail {
                                write!(
                                    s,
                                    concat!(
                                        "\nHex bytes: [{:02X}, <payload>, {:02X}, {:02X}]",
                                        "\nPayload: {}"
                                    ),
                                    packet[0],
                                    packet[len - 2],
                                    packet[len - 1],
                                    Bytes::first(1024, data)
                                )
                            } else {
                                write!(s, ": {}", Bytes::first(100, data))
                            }?;
                        } else if detail {
                            write!(s, "\nHex bytes: {packet:02X?}")?;
                        }
                    }
                }
                s
            }
            Transaction(group_id_opt, transaction_id) => {
                let packet_id_range = self.transaction_packet_range(*transaction_id)?;
                let start_packet_id = packet_id_range.start;
                let start_packet = self.packet(start_packet_id)?;
                let packet_count = packet_id_range.len();
                if detail {
                    writeln!(
                        s,
                        "Transaction #{} with {} {}",
                        transaction_id.value + 1,
                        packet_count,
                        if packet_count == 1 { "packet" } else { "packets" }
                    )?;
                    writeln!(
                        s,
                        "Timestamp: {} ns from capture start",
                        fmt_count(self.packet_time(start_packet_id)?)
                    )?;
                    write!(s, "Packets: #{}", packet_id_range.start + 1)?;
                    if packet_count > 1 {
                        write!(s, " to #{}", packet_id_range.end)?;
                    }
                    writeln!(s)?;
                }
                if let Ok(pid) = validate_packet(&start_packet) {
                    let num_packets = self.packet_count();
                    if pid == SPLIT && start_packet_id.value + 1 == num_packets {
                        let split = SplitFields::from_packet(&start_packet);
                        return Ok(format!(
                            "{} {} speed {} transaction on hub {} port {}",
                            match split.sc() {
                                Start => "Starting",
                                Complete => "Completing",
                            },
                            format!("{:?}", split.speed()).to_lowercase(),
                            format!("{:?}", split.endpoint_type()).to_lowercase(),
                            split.hub_address(),
                            split.port()
                        ));
                    }
                    let endpoint_id = match group_id_opt {
                        Some(group_id) => self.group_entry(*group_id)?.endpoint_id(),
                        None => match self.packet_endpoint(pid, &start_packet) {
                            Ok(endpoint_id) => endpoint_id,
                            Err(_) => INVALID_EP_ID,
                        },
                    };
                    let endpoint = self.endpoint(endpoint_id)?;
                    let transaction = self.transaction(*transaction_id)?;
                    s += &transaction.description(self, &endpoint, detail)?
                } else {
                    let packet_count = packet_id_range.len();
                    write!(
                        s,
                        "{} malformed {}",
                        packet_count,
                        if packet_count == 1 { "packet" } else { "packets" }
                    )?;
                }
                s
            }
            TransactionGroup(_, endpoint_id, ep_group_id) => {
                use GroupContent::*;
                let group = self.group(*endpoint_id, *ep_group_id)?;
                if detail {
                    let ep_traf = self.endpoint_traffic(*endpoint_id)?;
                    let start_ep_transaction_id = group.range.start;
                    let start_transaction_id = ep_traf.transaction_id(start_ep_transaction_id)?;
                    let start_packet_id = self.transaction_start(start_transaction_id)?;
                    if group.count == 1 {
                        writeln!(s, "Transaction group with 1 transaction")?;
                    } else {
                        writeln!(s, "Transaction group with {} transactions", group.count)?;
                    }
                    writeln!(
                        s,
                        "Timestamp: {} ns from start of capture",
                        fmt_count(self.packet_time(start_packet_id)?)
                    )?;
                    writeln!(
                        s,
                        "First transaction #{}, first packet #{}",
                        start_transaction_id.value + 1,
                        start_packet_id.value + 1
                    )?;
                }
                let endpoint = &group.endpoint;
                let endpoint_type = group.endpoint_type;
                let addr = group.endpoint.device_address();
                let count = group.count;
                match group.content {
                    Invalid => write!(s, "{count} invalid groups"),
                    Framing => write!(s, "{count} SOF groups"),
                    Request(transfer) if detail => {
                        write!(s, "Control transfer on device {addr}\n{}", transfer.summary(true))
                    }
                    Request(transfer) => write!(s, "{}", transfer.summary(false)),
                    IncompleteRequest => write!(s, "Incomplete control transfer on device {addr}"),
                    Data(data_range) => {
                        let ep_traf = self.endpoint_traffic(group.endpoint_id)?;
                        let length = ep_traf.transfer_data_length(&data_range)?;
                        let length_string = fmt_size(length);
                        let max = if detail { 1024 } else { 100 };
                        let display_length = min(length, max) as usize;
                        let transfer_bytes =
                            self.transfer_bytes(group.endpoint_id, &data_range, display_length)?;
                        let display_bytes = Bytes {
                            partial: length > display_length as u64,
                            bytes: &transfer_bytes,
                        };
                        let ep_type_string = titlecase(&format!("{endpoint_type}"));
                        write!(s, "{ep_type_string} transfer ")?;
                        write!(s, "of {length_string} ")?;
                        write!(s, "on endpoint {endpoint}")?;
                        if detail {
                            write!(s, "\nPayload: {display_bytes}")
                        } else {
                            write!(s, ": {display_bytes}")
                        }
                    }
                    Polling(count) => write!(
                        s,
                        "Polling {count} times for {endpoint_type} transfer on endpoint {endpoint}"
                    ),
                    Ambiguous(_data_range, count) => {
                        write!(s, "{count} ambiguous transactions on endpoint {endpoint}")?;
                        if detail {
                            write!(
                                s,
                                "\nThe result of these transactions is ambiguous because the endpoint type is not known."
                            )?;
                            write!(
                                s,
                                "\nTry starting the capture before this device is enumerated, so that its descriptors are captured."
                            )?;
                        }
                        Ok(())
                    }
                }?;
                s
            }
            TransactionGroupEnd(_, endpoint_id, ep_group_id) => {
                use GroupContent::*;
                let group = self.group(*endpoint_id, *ep_group_id)?;
                let endpoint = &group.endpoint;
                let endpoint_type = group.endpoint_type;
                let addr = group.endpoint.device_address();
                match group.content {
                    Invalid => write!(s, "End of invalid groups"),
                    Framing => write!(s, "End of SOF groups"),
                    Data(..) => write!(s, "End of {endpoint_type} transfer on endpoint {endpoint}"),
                    Request(_) | IncompleteRequest => write!(s, "End of control transfer on device {addr}"),
                    Polling(_) => write!(
                        s,
                        "End polling for {endpoint_type} transfer on endpoint {endpoint}"
                    ),
                    Ambiguous(..) => write!(s, "End of ambiguous transactions."),
                }?;
                s
            }
            EventGroup(_, ep_group_id) => {
                let range = self.group_range(EVENT_EP_ID, *ep_group_id)?;
                let ep_traf = self.endpoint_traffic(EVENT_EP_ID)?;
                let transaction_id = ep_traf.transaction_id(range.start)?;
                let packet_id = self.transaction_start(transaction_id)?;
                let event_id = self.event_id(packet_id)?;
                match self.event_type(event_id)? {
                    EventType::LsKeepalive => write!(s, "{} Low Speed keepalive groups", range.len()),
                    _ => write!(s, "High Speed negotiation"),
                }?;
                s
            }
            EventSubgroup(_, transaction_id) => {
                let packet_id = self.transaction_start(*transaction_id)?;
                let event_id = self.event_id(packet_id)?;
                match self.event_type(event_id)? {
                    EventType::LsKeepalive => {
                        let event_count = self.transaction_packet_range(*transaction_id)?.len();
                        write!(s, "{event_count} Low Speed keepalives")
                    }
                    _ => match self.event_type(event_id - 1)? {
                        EventType::BusReset => write!(s, "Device HS chirp"),
                        _ => write!(s, "Host HS chirp"),
                    },
                }?;
                s
            }
            Event(.., event_id) => {
                write!(s, "{}", self.event_type(*event_id)?)?;
                s
            }
        })
    }

    fn timestamp(&mut self, item: &TrafficItem) -> Result<Timestamp, Error> {
        use TrafficItem::*;
        let packet_id = match item {
            EventGroup(_, ep_group_id) => {
                let ep_traf = self.endpoint_traffic(EVENT_EP_ID)?;
                let ep_transaction_id = ep_traf.group_start(*ep_group_id)?;
                let transaction_id = ep_traf.transaction_id(ep_transaction_id)?;
                self.transaction_start(transaction_id)?
            }
            EventSubgroup(.., transaction_id) => self.transaction_start(*transaction_id)?,
            Event(.., packet_id, _) => *packet_id,
            TransactionGroup(_, endpoint_id, ep_group_id)
            | TransactionGroupEnd(_, endpoint_id, ep_group_id) => {
                let ep_traf = self.endpoint_traffic(*endpoint_id)?;
                let ep_transaction_id = ep_traf.group_start(*ep_group_id)?;
                let transaction_id = ep_traf.transaction_id(ep_transaction_id)?;
                self.transaction_start(transaction_id)?
            }
            Transaction(.., transaction_id) => self.transaction_start(*transaction_id)?,
            Packet(.., packet_id) => *packet_id,
        };
        self.packet_time(packet_id)
    }
}

// ---------------------------------------------------------------------------
// packetty's own flattening layer: turn a top-level TrafficItem into the flat
// list of packet ids it covers, skipping the intermediate `Transaction` node
// that packetry-gui's Hierarchical view exposes as a separate row. This keeps
// packetty's original two-level (transfer / packet) tree UX.
// ---------------------------------------------------------------------------

/// The (endpoint_id, ep_group_id) a top-level `TrafficItem` covers, if any
/// (only `TransactionGroup`/`EventGroup` have children in packetty's
/// flattened two-level tree — `TransactionGroupEnd` etc. never do).
fn group_endpoint(item: &TrafficItem) -> Option<(EndpointId, EndpointGroupId)> {
    use TrafficItem::*;
    match item {
        TransactionGroup(_, endpoint_id, ep_group_id) => Some((*endpoint_id, *ep_group_id)),
        EventGroup(_, ep_group_id) => Some((EVENT_EP_ID, *ep_group_id)),
        _ => None,
    }
}

/// Cheap (O(1)) check for whether `item` has any children at all — just the
/// endpoint-transaction range length, no packet-level expansion. Use this
/// instead of `!flatten_packets(..)?.is_empty()` on a hot path (e.g. once per
/// visible row per redraw), since a single group can cover a huge number of
/// transactions (a multi-second SOF/Framing run, for instance).
pub fn group_has_children<C: CaptureReaderOps + EndpointLookup>(
    cap: &mut C,
    item: &TrafficItem,
) -> Result<bool, Error> {
    let Some((endpoint_id, ep_group_id)) = group_endpoint(item) else {
        return Ok(false);
    };
    Ok(!cap.group_range(endpoint_id, ep_group_id)?.is_empty())
}

/// Enumerate up to `limit` packets belonging to `item`, starting from the
/// `skip_transactions`-th transaction of its group (not the packet index).
/// Unlike [`flatten_packets`]/[`flatten_packets_capped`], this never touches
/// transactions before `skip_transactions` — so resuming a group with many
/// thousands of transactions (a long SOF/Framing run, a big isochronous
/// transfer) costs only O(transactions actually consumed this call), not
/// O(transactions skipped so far). Returns the packet ids, how many
/// transactions were consumed, and whether that was the group's last one.
pub fn flatten_packets_window<C: CaptureReaderOps + EndpointLookup>(
    cap: &mut C,
    item: &TrafficItem,
    skip_transactions: u64,
    limit: u64,
) -> Result<(Vec<PacketId>, u64, bool), Error> {
    let Some((endpoint_id, ep_group_id)) = group_endpoint(item) else {
        return Ok((Vec::new(), 0, true));
    };
    let range = cap.group_range(endpoint_id, ep_group_id)?;
    let total = range.len();
    if skip_transactions >= total {
        return Ok((Vec::new(), 0, true));
    }

    let mut out = Vec::new();
    let mut consumed = 0u64;
    let mut ep_transaction_id = range.start + skip_transactions;
    while consumed < total - skip_transactions {
        let transaction_id = {
            let ep_traf = cap.endpoint_traffic(endpoint_id)?;
            ep_traf.transaction_id(ep_transaction_id)?
        };
        let prange = cap.transaction_packet_range(transaction_id)?;
        let mut v = prange.start.value;
        while v < prange.end.value {
            out.push(PacketId::from(v));
            v += 1;
        }
        consumed += 1;
        ep_transaction_id += 1;
        if out.len() as u64 >= limit {
            break;
        }
    }
    let is_final = skip_transactions + consumed >= total;
    Ok((out, consumed, is_final))
}

/// Packet ids belonging to a top-level `TrafficItem`, in capture order.
pub fn flatten_packets<C: CaptureReaderOps + EndpointLookup>(
    cap: &mut C,
    item: &TrafficItem,
) -> Result<Vec<PacketId>, Error> {
    flatten_packets_capped(cap, item, u64::MAX).map(|(ids, _truncated)| ids)
}

/// Like [`flatten_packets`], but stops (returning `truncated = true`) after
/// collecting `limit` packet ids, so callers that only need a bounded prefix
/// (a CRC-error scan, a capped "expand" cache) never pay for enumerating an
/// enormous group in full.
pub fn flatten_packets_capped<C: CaptureReaderOps + EndpointLookup>(
    cap: &mut C,
    item: &TrafficItem,
    limit: u64,
) -> Result<(Vec<PacketId>, bool), Error> {
    let Some((endpoint_id, ep_group_id)) = group_endpoint(item) else {
        return Ok((Vec::new(), false));
    };
    let transaction_ids = {
        let range = cap.group_range(endpoint_id, ep_group_id)?;
        let ep_traf = cap.endpoint_traffic(endpoint_id)?;
        ep_traf.transaction_id_range(&range)?
    };
    let mut out = Vec::new();
    for transaction_id in transaction_ids {
        let range = cap.transaction_packet_range(transaction_id)?;
        let mut v = range.start.value;
        while v < range.end.value {
            if out.len() as u64 >= limit {
                return Ok((out, true));
            }
            out.push(PacketId::from(v));
            v += 1;
        }
    }
    Ok((out, false))
}

/// Whether any packet belonging to `item` failed CRC/PID validation.
pub fn group_has_crc_error<C: CaptureReaderOps + EndpointLookup>(
    cap: &mut C,
    item: &TrafficItem,
) -> Result<bool, Error> {
    for packet_id in flatten_packets(cap, item)? {
        if packet_has_crc_error(cap, packet_id)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a single packet failed CRC/PID validation.
pub fn packet_has_crc_error<C: CaptureReaderOps>(
    cap: &mut C,
    packet_id: PacketId,
) -> Result<bool, Error> {
    let packet = cap.packet(packet_id)?;
    Ok(validate_packet(&packet).is_err())
}
