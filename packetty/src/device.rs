//! USB device discovery via nusb hotplug detection, backed by
//! `packetry_core::backend::{scan, probe}` — recognizes any backend
//! packetry-core supports (Cynthion, iCE40-usbtrace, ...), not just Cynthion.
//!
//! The hotplug watcher runs on a `tokio::spawn`ed background task, which
//! requires everything it stores to be `Send`. `packetry_core::backend::
//! BackendDevice` trait objects are not guaranteed `Send`, so the shared list
//! only keeps the lightweight, `Send`-safe identifying info (name +
//! `nusb::DeviceInfo`); [`DeviceManager::open_backend_device`] re-probes the
//! chosen device on demand, in the caller's own async context, to obtain a
//! fresh `Box<dyn BackendDevice>` to open.

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use futures_lite::StreamExt;
use nusb::{
    hotplug::{HotplugEvent, HotplugWatch},
    DeviceId,
};
use packetry_core::backend::{probe, scan, BackendDevice, BackendHandle};

use crate::dbg_log;

// ---------------------------------------------------------------------------
// ActiveDevice
// ---------------------------------------------------------------------------

/// A capture-capable USB device detected on the bus and recognized by one of
/// packetry-core's backends.
#[derive(Clone)]
pub struct ActiveDevice {
    /// Stable device identifier used to match [`HotplugEvent::Disconnected`]
    /// events.
    pub id: DeviceId,

    /// Human-readable backend name as reported by the probe function
    /// (e.g. `"Cynthion"` or `"iCE40-usbtrace"`).
    pub name: &'static str,

    /// Raw nusb [`nusb::DeviceInfo`] carrying VID/PID, bus address, string
    /// descriptors, and everything else needed to (re-)probe and open the
    /// device.
    pub info: nusb::DeviceInfo,
}

// ---------------------------------------------------------------------------
// DeviceManager
// ---------------------------------------------------------------------------

/// Maintains a live, thread-safe list of validated capture-capable USB
/// devices that are currently connected to the host.
pub struct DeviceManager {
    /// Shared, mutex-protected list of currently connected devices.
    devices: Arc<Mutex<Vec<ActiveDevice>>>,

    /// Background hotplug-watcher task.  Kept alive for the full lifetime of
    /// the `DeviceManager` so that the watch never stops prematurely.
    _watcher: tokio::task::JoinHandle<()>,
}

impl DeviceManager {
    /// Create a `DeviceManager` and start watching for USB hotplug events.
    pub async fn new() -> Result<Self> {
        let devices: Arc<Mutex<Vec<ActiveDevice>>> = Arc::new(Mutex::new(Vec::new()));

        // Register the hotplug watcher BEFORE scanning, to avoid missing any
        // connect events in the gap between the two steps.
        let mut watcher: HotplugWatch = nusb::watch_devices()
            .map_err(|e| anyhow!("Failed to register USB hotplug watch: {e}"))?;

        match scan().await {
            Ok(results) => {
                let mut lock = devices.lock().unwrap();
                for pr in results {
                    lock.push(ActiveDevice {
                        id: pr.info.id(),
                        name: pr.name,
                        info: pr.info,
                    });
                }
                let count = lock.len();
                if count > 0 {
                    dbg_log!("[DeviceManager] initial scan: {count} supported device(s) found");
                } else {
                    dbg_log!("[DeviceManager] initial scan: no supported devices found");
                }
            }
            Err(e) => {
                dbg_log!("[DeviceManager] initial scan error: {e}");
            }
        }

        let shared = Arc::clone(&devices);
        let watcher_task = tokio::spawn(async move {
            while let Some(event) = watcher.next().await {
                match event {
                    HotplugEvent::Connected(info) => {
                        let detected = probe(info.clone()).await.map(|pr| (pr.info.id(), pr.name, pr.info));
                        if let Some((id, name, dev_info)) = detected {
                            let mut lock = shared.lock().unwrap();
                            if !lock.iter().any(|d| d.id == id) {
                                dbg_log!(
                                    "[DeviceManager] connected: {name} ({:04x}:{:04x})",
                                    dev_info.vendor_id(),
                                    dev_info.product_id(),
                                );
                                lock.push(ActiveDevice { id, name, info: dev_info });
                            }
                        }
                    }
                    HotplugEvent::Disconnected(id) => {
                        let mut lock = shared.lock().unwrap();
                        let before = lock.len();
                        lock.retain(|d| d.id != id);
                        if lock.len() < before {
                            dbg_log!("[DeviceManager] disconnected: device removed from list");
                        }
                    }
                }
            }
            dbg_log!("[DeviceManager] hotplug watch stream ended");
        });

        Ok(DeviceManager {
            devices,
            _watcher: watcher_task,
        })
    }

    // ── Accessors ─────────────────────────────────────────────────────────

    pub fn has_devices(&self) -> bool {
        !self.devices.lock().unwrap().is_empty()
    }

    pub fn device_count(&self) -> usize {
        self.devices.lock().unwrap().len()
    }

    /// Snapshot of every currently connected recognized device.
    pub fn devices(&self) -> Vec<ActiveDevice> {
        self.devices.lock().unwrap().clone()
    }

    /// The first currently connected recognized device, if any.
    pub fn first_device(&self) -> Option<ActiveDevice> {
        self.devices.lock().unwrap().first().cloned()
    }

    // ── Opening a device for capture ────────────────────────────────────────

    /// Re-probe `device` (fresh, in the caller's own async context) and open
    /// it for capture, returning a live handle.
    pub async fn open_backend_device(device: &ActiveDevice) -> Result<Box<dyn BackendHandle>> {
        let result = probe(device.info.clone())
            .await
            .with_context(|| format!("{} is no longer a recognized capture device", device.name))?;
        let backend_device: Box<dyn BackendDevice> = result
            .result
            .map_err(|e| anyhow!("Failed to probe {}: {e}", device.name))?;
        backend_device
            .open_as_generic()
            .await
            .with_context(|| format!("Failed to open {}", device.name))
    }
}
