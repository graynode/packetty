//! Capture session lifecycle: open a device (or a saved file) and decode its
//! USB traffic into a `packetry_core`/`packetry_db`-backed `Capture`,
//! mirroring packetry-gui's `start_capture`/`start_file` — minus GTK.
//!
//! A background `std::thread` owns the `Decoder`/`CaptureWriter` (the
//! `EventIterator` a backend hands back is a blocking `Iterator`, not async,
//! so it can't run on a tokio task); the async side (this app's main loop)
//! only ever touches a cloned, lock-free `CaptureReader` plus a channel of
//! periodic `CaptureSnapshot`s.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::mpsc as std_mpsc;
use std::thread::JoinHandle;

use anyhow::{Context, Result};

use packetry_core::backend::{BackendHandle, BackendStop, EventIterator, PowerConfig, TimestampedEvent};
pub use packetry_core::backend::Speed;
use packetry_core::capture::{create_capture, CaptureReader, CaptureReaderOps, CaptureSnapshot, CaptureWriter, PacketOrEvent};
use packetry_core::decoder::Decoder;
use packetry_core::event::EventType;
use packetry_core::file::{GenericLoader, GenericPacket, GenericSaver, LoaderItem, PcapLoader, PcapNgLoader, PcapSaver, PcapNgSaver};

use crate::dbg_log;
use crate::device::ActiveDevice;

/// Send every this-many packets/events, so the UI thread never waits long
/// for a fresh view of a large, fast-moving capture.
const SNAPSHOT_EVERY: u64 = 32;

/// A capture-format-agnostic saver (`GenericSaver::close` takes `self` by
/// value, so it can't be boxed as `dyn GenericSaver`).
enum FileSaver {
    Pcap(PcapSaver<File>),
    PcapNg(PcapNgSaver<File>),
}

impl FileSaver {
    fn open(path: &Path, meta: std::sync::Arc<packetry_core::capture::CaptureMetadata>) -> Result<Self> {
        let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
        if is_pcap_extension(path) {
            Ok(FileSaver::Pcap(PcapSaver::new(file, meta)?))
        } else {
            Ok(FileSaver::PcapNg(PcapNgSaver::new(file, meta)?))
        }
    }

    fn add_packet(&mut self, bytes: &[u8], timestamp_ns: u64) -> Result<()> {
        match self {
            FileSaver::Pcap(s) => s.add_packet(bytes, timestamp_ns),
            FileSaver::PcapNg(s) => s.add_packet(bytes, timestamp_ns),
        }
    }

    fn add_event(&mut self, event_type: EventType, timestamp_ns: u64) -> Result<()> {
        match self {
            FileSaver::Pcap(s) => s.add_event(event_type, timestamp_ns),
            FileSaver::PcapNg(s) => s.add_event(event_type, timestamp_ns),
        }
    }

    fn close(self) -> Result<()> {
        match self {
            FileSaver::Pcap(s) => s.close(),
            FileSaver::PcapNg(s) => s.close(),
        }
    }
}

fn is_pcap_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("pcap"))
        .unwrap_or(false)
}

/// Format-agnostic view of a `LoaderItem`, fully owned (no borrowed/opaque
/// `impl GenericPacket` data), so both the pcap and pcap-ng loaders can share
/// one decode loop.
enum FileEvent {
    Packet(Vec<u8>, u64),
    Event(EventType, u64),
    Metadata(Box<packetry_core::capture::CaptureMetadata>),
    Ignore,
    Error(anyhow::Error),
    End,
}

fn convert_loader_item(item: LoaderItem<impl GenericPacket>) -> FileEvent {
    match item {
        LoaderItem::Packet(p) => FileEvent::Packet(p.bytes().to_vec(), p.timestamp_ns()),
        LoaderItem::Event(e) => FileEvent::Event(e.event_type, e.timestamp_ns),
        LoaderItem::Metadata(m) => FileEvent::Metadata(m),
        LoaderItem::LoadError(e) => FileEvent::Error(e),
        LoaderItem::Ignore => FileEvent::Ignore,
        LoaderItem::End => FileEvent::End,
    }
}

enum FileLoader {
    Pcap(PcapLoader<File>),
    PcapNg(PcapNgLoader<File>),
}

impl FileLoader {
    fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        if is_pcap_extension(path) {
            Ok(FileLoader::Pcap(PcapLoader::new(file)?))
        } else {
            Ok(FileLoader::PcapNg(PcapNgLoader::new(file)?))
        }
    }

    fn next(&mut self) -> FileEvent {
        match self {
            FileLoader::Pcap(l) => convert_loader_item(l.next()),
            FileLoader::PcapNg(l) => convert_loader_item(l.next()),
        }
    }
}

// ---------------------------------------------------------------------------
// CaptureSession
// ---------------------------------------------------------------------------

/// An in-progress or finished capture: either live from a device, or replayed
/// from a saved file. Owns the background decode thread and a reader handle
/// onto the `packetry_db`-backed capture database it's decoding into.
pub struct CaptureSession {
    pub reader: CaptureReader,
    pub device_name: Option<String>,
    snapshot_rx: std_mpsc::Receiver<CaptureSnapshot>,
    save_rx: Option<std_mpsc::Receiver<Result<PathBuf, String>>>,
    save_label: Option<String>,
    backend_handle: Option<Box<dyn BackendHandle>>,
    backend_stop: Option<BackendStop>,
    decoder_thread: Option<JoinHandle<()>>,
}

impl CaptureSession {
    /// Open `device`, start capturing at `speed`, and spawn the background
    /// decode thread. Mirrors packetry-gui's `start_capture`.
    pub async fn start_capture(device: &ActiveDevice, speed: Speed) -> Result<Self> {
        let mut backend_handle = crate::device::DeviceManager::open_backend_device(device).await?;

        let (writer, reader) = create_capture()?;
        writer.shared.metadata.store(std::sync::Arc::new(backend_handle.metadata().clone()));

        let (events, stop) = backend_handle
            .start(speed, Box::new(|result| {
                if let Err(e) = result {
                    dbg_log!("capture: backend worker thread ended with error: {e}");
                }
            }))
            .context("Failed to start capture")?;

        // Power the target on *after* capture has been enabled, so the
        // device's attach/enumeration sequence — the most useful traffic to
        // see right after plugging something in — actually gets captured
        // instead of racing it. `power_config()` reflects whatever the
        // hardware's power state was left in by a previous session (Cynthion
        // remembers `power_control_enable` *and* which source was selected
        // across reconnects, but not across power cycles) — without this, a
        // target last left powered off, or powered from a different source
        // than TARGET-C, silently stays that way.
        dbg_log!("capture: power_sources={:?}", backend_handle.power_sources());
        if let Some(mut power) = backend_handle.power_config().await {
            dbg_log!(
                "capture: power_config before enabling: source_index={} on_now={} start_on={} stop_off={}",
                power.source_index, power.on_now, power.start_on, power.stop_off
            );
            power.source_index = 0; // TARGET-C
            power.on_now = true;
            power.start_on = true;
            if let Err(e) = backend_handle.set_power_config(power).await {
                dbg_log!("capture: failed to enable target power: {e}");
            }
        } else {
            dbg_log!("capture: device reports no power configuration (no power control support?)");
        }

        let (snapshot_tx, snapshot_rx) = std_mpsc::channel();

        let decoder_thread = std::thread::spawn(move || {
            run_capture_thread(writer, events, snapshot_tx);
        });

        Ok(CaptureSession {
            reader,
            device_name: Some(device.name.to_string()),
            snapshot_rx,
            save_rx: None,
            save_label: None,
            backend_handle: Some(backend_handle),
            backend_stop: Some(stop),
            decoder_thread: Some(decoder_thread),
        })
    }

    /// Replay a saved `.pcap`/`.pcapng` file. Mirrors packetry-gui's
    /// `start_file(FileAction::Load, ...)`.
    pub fn start_load(path: PathBuf) -> Result<Self> {
        let (writer, reader) = create_capture()?;
        let (snapshot_tx, snapshot_rx) = std_mpsc::channel();

        let decoder_thread = std::thread::spawn(move || {
            run_load_thread(writer, path, snapshot_tx);
        });

        Ok(CaptureSession {
            reader,
            device_name: None,
            snapshot_rx,
            save_rx: None,
            save_label: None,
            backend_handle: None,
            backend_stop: None,
            decoder_thread: Some(decoder_thread),
        })
    }

    /// Drain any pending snapshots (keeping only the most recent) so the
    /// reader's next query reflects the latest decoded state.
    pub fn poll(&mut self) {
        while self.snapshot_rx.try_recv().is_ok() {
            // The reader itself is always live (lock-free RCU reads); we
            // only drain the channel here to avoid it backing up. Callers
            // read straight from `self.reader`, which already observes the
            // latest writer state without needing the snapshot value itself.
        }
    }

    pub fn complete(&self) -> bool {
        self.reader.complete()
    }

    pub fn is_live(&self) -> bool {
        self.backend_handle.is_some()
    }

    pub fn is_saving(&self) -> bool {
        self.save_rx.is_some()
    }

    pub fn save_label(&self) -> Option<&str> {
        self.save_label.as_deref()
    }

    /// Save everything decoded so far — live capture or a loaded file alike
    /// — into a `.pcap`/`.pcapng` file, as a one-shot snapshot. Mirrors
    /// packetry-gui's Save (`save()` in `ui/mod.rs`), which always replays
    /// the *whole* existing capture from packet 0 via
    /// `CaptureReader::timestamped_packets_and_events`, rather than tee-ing
    /// only packets arriving after the save starts — so there's no need to
    /// have started saving before the capture began to not lose anything.
    ///
    /// Runs on a background thread (a big capture can have hundreds of
    /// thousands of packets, and this app's main loop is a single-threaded
    /// async task that must keep rendering); poll for completion with
    /// [`Self::poll_save`].
    pub fn save_now(&mut self, path: PathBuf) -> Result<()> {
        if self.save_rx.is_some() {
            anyhow::bail!("A save is already in progress");
        }
        let label = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        let mut reader = self.reader.clone();
        let (tx, rx) = std_mpsc::channel();
        self.save_rx = Some(rx);
        self.save_label = Some(label);

        std::thread::spawn(move || {
            let result = (|| -> Result<()> {
                let meta = reader.shared.metadata.load_full();
                let mut saver = FileSaver::open(&path, meta)?;
                let packet_count = reader.packet_count();
                if packet_count > 0 {
                    for item in reader.timestamped_packets_and_events()? {
                        let (timestamp, packet_or_event) = item?;
                        match packet_or_event {
                            PacketOrEvent::Packet(bytes) => saver.add_packet(&bytes, timestamp)?,
                            PacketOrEvent::Event(event_type) => saver.add_event(event_type, timestamp)?,
                        }
                    }
                }
                saver.close()
            })();
            let _ = tx.send(result.map(|()| path).map_err(|e| format!("{e:#}")));
        });
        Ok(())
    }

    /// Poll for completion of a background [`Self::save_now`] save. Returns
    /// `Some` exactly once per save, then clears the saving state.
    pub fn poll_save(&mut self) -> Option<Result<PathBuf, String>> {
        let rx = self.save_rx.as_ref()?;
        let result = match rx.try_recv() {
            Ok(result) => result,
            Err(std_mpsc::TryRecvError::Empty) => return None,
            Err(std_mpsc::TryRecvError::Disconnected) => Err("save thread ended unexpectedly".to_string()),
        };
        self.save_rx = None;
        self.save_label = None;
        Some(result)
    }

    /// Which power sources this device supports, if any.
    pub fn power_sources(&self) -> Option<Vec<&str>> {
        self.backend_handle.as_ref()?.power_sources().map(|s| s.to_vec())
    }

    /// Toggle `on_now` for the current power source. Returns the new state.
    pub async fn toggle_power(&mut self) -> Result<bool> {
        let handle = self.backend_handle.as_mut().context("No device power control available")?;
        let mut config = handle
            .power_config()
            .await
            .context("Device has no known power configuration")?;
        config.on_now = !config.on_now;
        let new_state = config.on_now;
        handle.set_power_config(config).await?;
        Ok(new_state)
    }

    #[allow(dead_code)]
    pub async fn power_config(&self) -> Option<PowerConfig> {
        match self.backend_handle.as_ref() {
            Some(h) => h.power_config().await,
            None => None,
        }
    }

    /// Stop a live capture (no-op for a replayed file) and join the decode
    /// thread.
    pub fn stop(&mut self) -> Result<()> {
        if let Some(stop) = self.backend_stop.take() {
            stop.stop()?;
        }
        if let Some(handle) = self.decoder_thread.take() {
            let _ = handle.join();
        }
        Ok(())
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

// ---------------------------------------------------------------------------
// Background threads
// ---------------------------------------------------------------------------

fn run_capture_thread(
    writer: CaptureWriter,
    events: Box<dyn EventIterator>,
    snapshot_tx: std_mpsc::Sender<CaptureSnapshot>,
) {
    let mut decoder = match Decoder::new(writer) {
        Ok(d) => d,
        Err(e) => {
            dbg_log!("capture thread: Decoder::new failed: {e}");
            return;
        }
    };

    let mut count: u64 = 0;
    let mut ended_with_error = false;

    dbg_log!("capture: decoder thread started, waiting for events");

    for event in events {
        match event {
            Ok(TimestampedEvent::Packet { timestamp_ns, bytes }) => {
                if count < 20 {
                    dbg_log!(
                        "capture: packet #{count} ts={timestamp_ns} len={} bytes={:02x?}",
                        bytes.len(),
                        &bytes[..bytes.len().min(16)]
                    );
                }
                if let Err(e) = decoder.handle_raw_packet(&bytes, timestamp_ns) {
                    dbg_log!("capture: handle_raw_packet error: {e}");
                }
            }
            Ok(TimestampedEvent::Event { timestamp_ns, event_type }) => {
                if count < 20 {
                    dbg_log!("capture: event #{count} ts={timestamp_ns} type={event_type:?}");
                }
                if let Err(e) = decoder.handle_event(event_type, timestamp_ns) {
                    dbg_log!("capture: handle_event error: {e}");
                }
            }
            Err(e) => {
                dbg_log!("capture: stream error after {count} events: {e:?}");
                ended_with_error = true;
                break;
            }
        }

        count += 1;
        if count % SNAPSHOT_EVERY == 0 {
            let _ = snapshot_tx.send(decoder.capture.snapshot());
        }
    }

    if !ended_with_error {
        dbg_log!("capture: event stream ended after {count} events (device stopped or disconnected)");
    }

    match decoder.finish() {
        Ok(mut writer) => {
            let _ = snapshot_tx.send(writer.snapshot());
        }
        Err(e) => dbg_log!("capture: decoder finish error: {e}"),
    }
}

fn run_load_thread(writer: CaptureWriter, path: PathBuf, snapshot_tx: std_mpsc::Sender<CaptureSnapshot>) {
    let mut decoder = match Decoder::new(writer) {
        Ok(d) => d,
        Err(e) => {
            dbg_log!("load thread: Decoder::new failed: {e}");
            return;
        }
    };

    let result: Result<()> = (|| {
        let mut loader = FileLoader::open(&path)?;
        let mut count: u64 = 0;
        loop {
            match loader.next() {
                FileEvent::Packet(bytes, timestamp_ns) => {
                    decoder.handle_raw_packet(&bytes, timestamp_ns)?;
                }
                FileEvent::Event(event_type, timestamp_ns) => {
                    decoder.handle_event(event_type, timestamp_ns)?;
                }
                FileEvent::Metadata(meta) => decoder.handle_metadata(meta),
                FileEvent::Ignore => {}
                FileEvent::Error(e) => dbg_log!("load: packet error: {e}"),
                FileEvent::End => break,
            }
            count += 1;
            if count % SNAPSHOT_EVERY == 0 {
                let _ = snapshot_tx.send(decoder.capture.snapshot());
            }
        }
        Ok(())
    })();

    if let Err(e) = result {
        // `{e}` on an anyhow::Error only shows the outermost `.context(...)`
        // (e.g. "opening <path>") and swallows the actual underlying cause
        // (e.g. "No such file or directory"); `{:#}` prints the full chain.
        dbg_log!("load: {e:#}");
    }

    match decoder.finish() {
        Ok(mut writer) => {
            let _ = snapshot_tx.send(writer.snapshot());
        }
        Err(e) => dbg_log!("load: decoder finish error: {e}"),
    }
}

/// Generate a capture filename like `capture-20240317-143022.pcapng`.
pub fn default_capture_filename() -> String {
    use chrono::Local;
    format!("capture-{}.pcapng", Local::now().format("%Y%m%d-%H%M%S"))
}
