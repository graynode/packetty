//! Adapter that reconstructs `plugins::models::{TransactionInfo, UsbDeviceInfo}`
//! from the `packetry_core`/`packetry_db`-backed capture, since
//! `packetry_core`'s `Decoder`/`Capture` has no per-transaction callback the
//! way the old hand-rolled backend did — it's a pull-based query API. Called
//! once per tick from `App::update()`.

use anyhow::Result;

use packetry_core::capture::{CaptureReaderOps, DeviceId};
use packetry_core::usb::{validate_packet, PID};

use plugins::models::{
    PacketItem, PacketType, TransactionInfo, TransactionKind, UsbConfigInfo, UsbDeviceInfo, UsbEndpointInfo,
    UsbInterfaceInfo,
};
use plugins::PluginManager;

use crate::item::TrafficItem;
use crate::models::{ItemStore, RowKind};

/// Cap on how many newly-completed top-level items are looked at per call.
const MAX_PER_SYNC: u64 = 500;

/// Cap on how many packets get built into `PacketItem`s (each a handful of
/// real DB queries) per call, *across every item touched* — not just per
/// item. A single top-level item can itself cover tens of thousands of
/// packets (e.g. one continuous isochronous audio transfer, or a long
/// SOF/Framing run); without this, syncing even one such item in a single
/// call could block the main loop — and hence the whole UI — for seconds.
/// When the budget runs out mid-item, [`sync`] remembers how many
/// *transactions* of it it already consumed (`pending_offset`) and resumes
/// from exactly there next call — via [`item::flatten_packets_window`],
/// which costs only O(transactions consumed this call), not O(transactions
/// skipped so far) — instead of skipping the rest of the item, or re-walking
/// everything already sent on every call.
const MAX_PACKETS_PER_SYNC: u64 = 4000;

/// Same idea as [`MAX_PER_SYNC`]/[`MAX_PACKETS_PER_SYNC`], but for replaying
/// an already-loaded file rather than a live capture (`sync`'s `fast`
/// parameter). Measured against a real ~690k-packet capture: fully lifting
/// the caps (no bound at all) just moves the *same total* per-packet DB-query
/// work into one call instead of spreading it out — about 20 seconds of
/// solid UI freeze in one shot, worse than the throttled trickle it was
/// meant to replace, and long enough that the "Syncing plugins…" status
/// text would never even get a chance to redraw. These are ~12x the live
/// caps: generous enough to replace ~150 throttled ticks with ~12-15, while
/// keeping each individual tick's blocking work down to a few hundred ms so
/// the UI keeps redrawing (and the sync percentage keeps visibly moving)
/// throughout the catch-up instead of locking up once for the whole thing.
const FAST_MAX_PER_SYNC: u64 = 6_000;
const FAST_MAX_PACKETS_PER_SYNC: u64 = 50_000;

/// Feed newly-completed top-level items to `plugin_manager`, bounded so a
/// single call never blocks the main loop for long even when a huge item
/// becomes available all at once, and return a freshly rebuilt device list
/// (also used to populate the Devices pane).
///
/// `pending_offset` carries, for `*last_synced`, how many of its
/// transactions have already been fed to plugins across calls, for when an
/// item is too big to finish in one call's packet budget.
///
/// `fast`, when true, switches to the much larger [`FAST_MAX_PER_SYNC`]/
/// [`FAST_MAX_PACKETS_PER_SYNC`] caps instead of the default (tight) ones.
/// The tight caps exist to keep the UI responsive during a *live*,
/// open-ended capture, where new items keep arriving indefinitely and a
/// slow trickle-in is actually fine. Replaying an already-loaded file is
/// different: the data is finite and already fully decoded (or decoding as
/// fast as disk I/O allows), so there's no reason to throttle the plugin
/// pane's catch-up to it nearly as hard — callers pass `fast: true`
/// whenever the session isn't a live capture.
pub fn sync(
    store: &mut ItemStore,
    plugin_manager: &mut PluginManager,
    last_synced: &mut u64,
    pending_offset: &mut u64,
    fast: bool,
) -> Result<Vec<UsbDeviceInfo>> {
    let devices = build_usb_devices(store)?;

    let (max_per_sync, max_packets_per_sync) = if fast {
        (FAST_MAX_PER_SYNC, FAST_MAX_PACKETS_PER_SYNC)
    } else {
        (MAX_PER_SYNC, MAX_PACKETS_PER_SYNC)
    };
    let item_limit = store.item_count().min(last_synced.saturating_add(max_per_sync));
    let mut packet_budget = max_packets_per_sync;

    while *last_synced < item_limit {
        if packet_budget == 0 {
            break;
        }
        let ti = *last_synced;
        let item = store.top_item(ti)?;
        // "End" markers carry no new content of their own; skip them.
        if matches!(item, TrafficItem::TransactionGroupEnd(..)) {
            *last_synced += 1;
            *pending_offset = 0;
            continue;
        }

        let (batch, consumed, is_final) =
            crate::item::flatten_packets_window(&mut store.reader, &item, *pending_offset, packet_budget)?;

        if consumed == 0 {
            // Empty group (e.g. zero transactions) — nothing to send.
            *last_synced += 1;
            *pending_offset = 0;
            continue;
        }

        if let Some(txn) = build_transaction_info(store, &item, &batch)? {
            plugin_manager.on_transaction(&txn, &devices);
        }
        packet_budget = packet_budget.saturating_sub(batch.len() as u64);

        if is_final {
            *last_synced += 1;
            *pending_offset = 0;
        } else {
            *pending_offset += consumed;
            break;
        }
    }

    Ok(devices)
}

fn row_kind_to_plugin_kind(kind: RowKind) -> TransactionKind {
    match kind {
        RowKind::Control => TransactionKind::Control,
        RowKind::BulkIn => TransactionKind::BulkIn,
        RowKind::BulkOut => TransactionKind::BulkOut,
        RowKind::Interrupt => TransactionKind::Interrupt,
        RowKind::Isochronous => TransactionKind::Isochronous,
        RowKind::Framing => TransactionKind::SofGroup,
        RowKind::Polling => TransactionKind::Nak,
        RowKind::Ambiguous => TransactionKind::Stall,
        RowKind::Event | RowKind::Other => TransactionKind::Other,
    }
}

/// The `(device_address, endpoint_number)` a top-level item's transfer ran
/// on, if it has one (only `TransactionGroup`/`TransactionGroupEnd` do).
fn group_endpoint_addr(
    reader: &mut packetry_core::capture::CaptureReader,
    item: &TrafficItem,
) -> Result<Option<(u8, u8)>> {
    use TrafficItem::*;
    match item {
        TransactionGroup(_, endpoint_id, ep_group_id) | TransactionGroupEnd(_, endpoint_id, ep_group_id) => {
            let group = reader.group(*endpoint_id, *ep_group_id)?;
            Ok(Some((group.endpoint.device_address().0, group.endpoint.number().0)))
        }
        _ => Ok(None),
    }
}

fn packet_type_for_pid(pid: PID) -> PacketType {
    match pid {
        PID::SOF => PacketType::Sof,
        PID::SETUP => PacketType::Setup,
        PID::IN => PacketType::In,
        PID::OUT => PacketType::Out,
        PID::DATA0 | PID::DATA1 | PID::DATA2 | PID::MDATA => PacketType::Data,
        PID::ACK => PacketType::Ack,
        PID::NAK => PacketType::Nak,
        PID::STALL => PacketType::Stall,
        _ => PacketType::Other,
    }
}

fn build_transaction_info(
    store: &mut ItemStore,
    item: &TrafficItem,
    packet_ids: &[packetry_core::capture::PacketId],
) -> Result<Option<TransactionInfo>> {
    use crate::item::ItemSource;
    use crate::item::TrafficViewMode;

    let kind = crate::models::row_kind_for_item(&mut store.reader, item)?;
    let mut label = ItemSource::<TrafficItem, TrafficViewMode>::description(&mut store.reader, item, false)?;
    let details = ItemSource::<TrafficItem, TrafficViewMode>::description(&mut store.reader, item, true)?;
    let timestamp_ns = ItemSource::<TrafficItem, TrafficViewMode>::timestamp(&mut store.reader, item)?;

    // Every plugin (CDC/HID/HCI/Audio) parses `dev=<addr>` / `ep=<num>` back
    // out of `TransactionInfo.label` — a convention from the old hand-rolled
    // backend's own label format. packetry-core's `description()` text
    // doesn't contain those tags, so append them in the same format the
    // plugins already expect, on top of the human-readable description.
    if let Some((dev, ep)) = group_endpoint_addr(&mut store.reader, item)? {
        label = format!("{label}  dev={dev}  ep={ep}");
    }

    let mut packets = Vec::with_capacity(packet_ids.len());
    let mut has_crc_error = false;
    for &packet_id in packet_ids {
        // `reader.packet()` returns the full wire bytes: [PID][payload][CRC].
        // The old hand-rolled backend's `PacketItem::raw_bytes` — what every
        // plugin parses — only ever held the bare payload for Data packets
        // (PID and CRC stripped) and was empty for everything else (tokens,
        // handshakes). Reproduce that here, or e.g. the audio/CDC/HID
        // plugins read `bmRequestType` etc. one byte off from where they
        // should be (into the PID byte instead of the payload).
        let wire_bytes = store.reader.packet(packet_id)?;
        let valid = validate_packet(&wire_bytes).is_ok();
        if !valid {
            has_crc_error = true;
        }
        let pid = wire_bytes.first().map(|&b| PID::from(b)).unwrap_or(PID::Malformed);
        let packet_type = packet_type_for_pid(pid);
        let raw_bytes = if packet_type == PacketType::Data && wire_bytes.len() >= 3 {
            wire_bytes[1..wire_bytes.len() - 2].to_vec()
        } else {
            Vec::new()
        };
        // No plugin (CDC/HID/HCI/Audio) reads a per-packet `label`/`details`
        // — they only look at `packet_type`/`raw_bytes`/`timestamp_ns` — so
        // skip building the (expensive: byte fetch + PID/field parsing +
        // string formatting) human-readable text per packet. This was the
        // dominant per-packet cost; a capture with hundreds of thousands of
        // packets was taking over a minute to fully sync otherwise.
        let pkt_timestamp_ns = store.reader.packet_time(packet_id)?;
        packets.push(PacketItem {
            packet_type,
            label: String::new(),
            details: String::new(),
            raw_bytes,
            timestamp_ns: pkt_timestamp_ns,
            crc_valid: Some(valid),
        });
    }

    Ok(Some(TransactionInfo {
        kind: row_kind_to_plugin_kind(kind),
        label,
        details,
        packets,
        timestamp_ns,
        has_crc_error,
    }))
}

fn bcd(major: u8, minor: u8) -> u16 {
    ((major as u16) << 8) | minor as u16
}

/// Rebuild the device list from the capture's live descriptor tracking,
/// which is strictly more complete than the old hand-rolled `DeviceTracker`
/// (packetry-core already parses full config/interface/endpoint/string
/// descriptors as they're captured).
fn build_usb_devices(store: &mut ItemStore) -> Result<Vec<UsbDeviceInfo>> {
    let mut out = Vec::new();
    let count = store.reader.device_count();
    for i in 0..count {
        let device_id = DeviceId::from(i);
        let device = store.reader.device(device_id)?;
        let data = store.reader.device_data(device_id)?;
        let strings = data.strings.load();
        let string = |id: packetry_core::usb::StringId| -> Option<String> {
            let bytes = strings.get(id)?;
            let chars = bytes.chars();
            String::from_utf16(&chars).ok()
        };

        let desc = data.device_descriptor.load();
        let configurations = data.configurations.load();
        let mut config_infos = Vec::new();
        for (_num, config) in configurations.iter_pairs() {
            let mut interfaces = Vec::new();
            for (_key, iface) in config.interfaces.iter() {
                let mut endpoints = Vec::new();
                for ep in &iface.endpoints {
                    endpoints.push(UsbEndpointInfo {
                        address: ep.descriptor.endpoint_address.0,
                        attributes: ep.descriptor.attributes.0,
                        max_packet_size: ep.descriptor.max_packet_size,
                        interval: ep.descriptor.interval,
                    });
                }
                interfaces.push(UsbInterfaceInfo {
                    interface_number: iface.descriptor.interface_number.0,
                    alternate_setting: iface.descriptor.alternate_setting.0,
                    num_endpoints: iface.descriptor.num_endpoints,
                    class: iface.descriptor.interface_class.0,
                    subclass: iface.descriptor.interface_subclass.0,
                    protocol: iface.descriptor.interface_protocol.0,
                    endpoints,
                });
            }
            config_infos.push(UsbConfigInfo {
                configuration_value: config.descriptor.config_value,
                num_interfaces: config.descriptor.num_interfaces,
                attributes: config.descriptor.attributes,
                max_power: config.descriptor.max_power,
                interfaces,
            });
        }

        let has_content = desc.is_some() || !config_infos.is_empty();
        if !has_content {
            continue;
        }

        let (bcd_usb, bcd_device, vendor_id, product_id, class, subclass, protocol, max_packet_size0, num_configurations, manufacturer, product, serial) =
            match desc.as_ref() {
                Some(d) => (
                    bcd(d.usb_version.major, d.usb_version.minor),
                    bcd(d.device_version.major, d.device_version.minor),
                    d.vendor_id,
                    d.product_id,
                    d.device_class.0,
                    d.device_subclass.0,
                    d.device_protocol.0,
                    d.max_packet_size_0,
                    d.num_configurations,
                    string(d.manufacturer_str_id),
                    string(d.product_str_id),
                    string(d.serial_str_id),
                ),
                None => (0, 0, 0, 0, 0, 0, 0, 0, config_infos.len() as u8, None, None, None),
            };

        out.push(UsbDeviceInfo {
            address: device.address.0,
            bcd_usb,
            bcd_device,
            vendor_id,
            product_id,
            class,
            subclass,
            protocol,
            max_packet_size0,
            num_configurations,
            manufacturer,
            product,
            serial,
            configurations: config_infos,
        });
    }
    Ok(out)
}
