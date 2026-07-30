use crate::capture::{CaptureSession, Speed};
use crate::dbg_log;
use crate::device::{ActiveDevice, DeviceManager};
use crate::models::{FlatRow, ItemStore, RowKind, UsbDeviceInfo};
use crate::plugin_bridge;
use plugins::{PluginManager, PluginNavRequest};

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::collections::HashMap;
use tui_file_explorer::{ExplorerOutcome, FileExplorer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppState {
    WaitingForDevice,
    SpeedSelection,
    Connecting,
    Capturing,
    Error,
    /// User is typing a file path to open a saved pcap.
    LoadFile,
}

/// Which tab is visible while capturing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveView {
    Traffic,
    Devices,
    Plugins,
}

pub struct App {
    pub state: AppState,
    pub active_view: ActiveView,
    pub device_manager: DeviceManager,
    pub selected_device: Option<ActiveDevice>,
    pub selected_speed: Speed,
    pub speed_options: Vec<Speed>,
    pub selected_speed_idx: usize,
    pub status_message: String,
    pub error_message: Option<String>,

    // Traffic view / capture session
    pub capture: Option<CaptureSession>,
    pub items: Option<ItemStore>,
    last_synced_top: u64,
    /// How many packets of `last_synced_top`'s item have already been fed to
    /// plugins, when that item was too large to finish in one `sync()` call.
    plugin_sync_offset: u64,
    /// Set by the `v` key; consumed (and the actual async VBUS toggle
    /// performed) on the next `update()` tick.
    pending_power_toggle: bool,
    /// Selected row index into the *flattened* view (across expanded children).
    pub selected_row: Option<usize>,
    /// First visible row index (for scrolling).
    pub scroll_offset: usize,
    /// Number of visible rows (updated each draw; used for page nav).
    pub page_size: usize,

    // Device view
    pub usb_devices: Vec<UsbDeviceInfo>,
    /// Expansion state for device tree nodes. Key: "d:{addr}", "d:{addr}:c:{cv}",
    /// "d:{addr}:c:{cv}:i:{ifn}:{alt}", "d:{addr}:c:{cv}:i:{ifn}:{alt}:e:{ep}".
    pub device_expanded: HashMap<String, bool>,
    /// Selected row in the device tree (flat index).
    pub device_selected: usize,
    /// Scroll offset for the device tree.
    pub device_scroll: usize,

    // Plugin view
    pub plugin_manager: PluginManager,
    /// Index of the selected plugin in the plugin list.
    pub plugin_selected: usize,
    /// Scroll offset into the selected plugin's rendered lines.
    pub plugin_scroll: usize,
    /// `true` when the content pane has keyboard focus (Enter to enter, Esc to leave).
    pub plugin_pane_focus: bool,

    device_check_counter: usize,
    /// `true` when the user has pressed `g` once; a second `g` goes to top.
    g_pending: bool,

    // PCAP save/load
    /// Display name of the loaded file (shown in status bar).
    pub load_label: Option<String>,
    /// File-browser widget shown when AppState::LoadFile is active.
    pub file_explorer: Option<FileExplorer>,
    /// Pcap path queued for loading (set by LoadFile dialog, consumed by update()).
    pub pending_load: Option<std::path::PathBuf>,
    /// State to restore if the file dialog is cancelled.
    pub file_dialog_return: AppState,

    /// `true` while the help popup is open.
    pub show_help: bool,

    // Search
    /// `true` while the user is typing a `/` search query.
    pub search_mode: bool,
    /// Characters typed so far (shown in search bar).
    pub search_input: String,
    /// Last committed search query.
    pub search_query: String,
    /// Ordered list of matches as `(top_idx, child_idx)`.
    pub search_matches: Vec<(usize, Option<usize>)>,
    /// Which match is currently highlighted.
    pub search_match_idx: Option<usize>,
}

impl App {
    pub async fn new() -> Result<Self> {
        let device_manager = DeviceManager::new().await?;

        let mut plugin_manager = PluginManager::new();
        plugin_manager.register(Box::new(plugins::cdc::CdcPlugin::new()));
        plugin_manager.register(Box::new(plugins::hid_mouse::HidMousePlugin::new()));
        plugin_manager.register(Box::new(plugins::hid_keyboard::HidKeyboardPlugin::new()));
        plugin_manager.register(Box::new(plugins::audio::AudioPlugin::new()));
        plugin_manager.register(Box::new(plugins::hci::HciPlugin::new()));

        Ok(App {
            state: AppState::WaitingForDevice,
            active_view: ActiveView::Traffic,
            device_manager,
            selected_device: None,
            selected_speed: Speed::High,
            speed_options: vec![Speed::High, Speed::Full, Speed::Low, Speed::Auto],
            selected_speed_idx: 0,
            status_message: "Waiting for a USB analyzer device…".to_string(),
            error_message: None,
            capture: None,
            items: None,
            last_synced_top: 0,
            plugin_sync_offset: 0,
            pending_power_toggle: false,
            selected_row: None,
            scroll_offset: 0,
            page_size: 30,
            usb_devices: Vec::new(),
            device_expanded: HashMap::new(),
            device_selected: 0,
            device_scroll: 0,
            plugin_manager,
            plugin_selected: 0,
            plugin_scroll: 0,
            plugin_pane_focus: false,
            device_check_counter: 0,
            g_pending: false,
            load_label: None,
            file_explorer: None,
            pending_load: None,
            file_dialog_return: AppState::WaitingForDevice,
            show_help: false,
            search_mode: false,
            search_input: String::new(),
            search_query: String::new(),
            search_matches: Vec::new(),
            search_match_idx: None,
        })
    }

    /// Jump directly to Capturing state by replaying a pcap/pcapng file.
    pub async fn start_load(&mut self, path: std::path::PathBuf) -> Result<()> {
        let label = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        let session = CaptureSession::start_load(path)?;
        let reader = session.reader.clone();
        self.clear_capture_state();
        self.capture = Some(session);
        self.items = Some(ItemStore::new(reader));
        self.state = AppState::Capturing;
        self.load_label = Some(label.clone());
        self.status_message = format!("Loaded: {label}");
        Ok(())
    }

    /// Clear all per-capture UI state so a new capture/file can start cleanly.
    fn clear_capture_state(&mut self) {
        self.last_synced_top = 0;
        self.plugin_sync_offset = 0;
        self.usb_devices.clear();
        self.device_expanded.clear();
        self.selected_row = None;
        self.scroll_offset = 0;
        self.device_selected = 0;
        self.device_scroll = 0;
        self.search_mode = false;
        self.search_input.clear();
        self.search_query.clear();
        self.search_matches.clear();
        self.search_match_idx = None;
        self.plugin_manager.reset();
        self.plugin_scroll = 0;
        self.plugin_pane_focus = false;
    }

    // -----------------------------------------------------------------------
    // Flat-row helpers (wrap the fallible ItemStore queries for input handling)
    // -----------------------------------------------------------------------

    fn flat_len(&mut self) -> usize {
        match self.items.as_mut() {
            Some(store) => store.flat_row_count().unwrap_or_else(|e| {
                dbg_log!("flat_row_count error: {e}");
                0
            }) as usize,
            None => 0,
        }
    }

    fn resolve(&mut self, flat_idx: usize) -> Option<(usize, Option<usize>)> {
        let store = self.items.as_mut()?;
        match store.flat_index_resolve(flat_idx as u64) {
            Ok(Some((ti, ci))) => Some((ti as usize, ci.map(|c| c as usize))),
            Ok(None) => None,
            Err(e) => {
                dbg_log!("flat_index_resolve error: {e}");
                None
            }
        }
    }

    fn top_row_index(&mut self, top_idx: usize) -> Option<usize> {
        let store = self.items.as_mut()?;
        match store.flat_top_row_index(top_idx as u64) {
            Ok(Some(v)) => Some(v as usize),
            Ok(None) => None,
            Err(e) => {
                dbg_log!("flat_top_row_index error: {e}");
                None
            }
        }
    }

    // -----------------------------------------------------------------------
    // Input handling
    // -----------------------------------------------------------------------

    /// Returns `true` when the application should quit.
    pub fn handle_input(&mut self, key: KeyEvent) -> bool {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return true;
        }
        if key.code == KeyCode::Char('?') && key.modifiers.is_empty() && !self.search_mode {
            self.show_help = !self.show_help;
            return false;
        }
        if self.show_help {
            if key.code == KeyCode::Esc {
                self.show_help = false;
            }
            return false;
        }
        if key.code == KeyCode::Esc {
            if self.state == AppState::LoadFile {
                self.file_explorer = None;
                self.state = self.file_dialog_return;
                return false;
            }
            if self.active_view == ActiveView::Plugins && self.plugin_pane_focus {
                self.plugin_pane_focus = false;
                return false;
            }
            return true;
        }
        if key.code == KeyCode::Char('q') && self.state != AppState::SpeedSelection && self.state != AppState::LoadFile {
            return true;
        }
        match self.state {
            AppState::WaitingForDevice | AppState::Connecting => {
                if key.code == KeyCode::Char('o') && key.modifiers.is_empty() {
                    self.open_file_dialog(AppState::WaitingForDevice);
                }
            }
            AppState::SpeedSelection => self.handle_speed_input(key),
            AppState::Capturing => self.handle_capture_input(key),
            AppState::Error => {
                if key.code == KeyCode::Enter {
                    self.state = AppState::WaitingForDevice;
                    self.error_message = None;
                }
            }
            AppState::LoadFile => self.handle_load_file_input(key),
        }
        false
    }

    fn handle_load_file_input(&mut self, key: KeyEvent) {
        let return_state = self.file_dialog_return;
        let explorer = match self.file_explorer.as_mut() {
            Some(e) => e,
            None => {
                self.state = return_state;
                return;
            }
        };
        match explorer.handle_key(key) {
            ExplorerOutcome::Selected(path) => {
                self.file_explorer = None;
                self.pending_load = Some(path);
                self.state = AppState::Connecting;
                self.status_message = "Loading capture file…".to_string();
            }
            ExplorerOutcome::Dismissed => {
                self.file_explorer = None;
                self.state = return_state;
            }
            _ => {}
        }
    }

    fn open_file_dialog(&mut self, return_to: AppState) {
        let start = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        self.file_explorer = Some(
            FileExplorer::builder(start)
                .allow_extension("pcap")
                .allow_extension("pcapng")
                .build(),
        );
        self.file_dialog_return = return_to;
        self.state = AppState::LoadFile;
    }

    fn handle_speed_input(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up if self.selected_speed_idx > 0 => {
                self.selected_speed_idx -= 1;
                self.selected_speed = self.speed_options[self.selected_speed_idx];
            }
            KeyCode::Down if self.selected_speed_idx < self.speed_options.len() - 1 => {
                self.selected_speed_idx += 1;
                self.selected_speed = self.speed_options[self.selected_speed_idx];
            }
            KeyCode::Enter => {
                self.state = AppState::Connecting;
                self.status_message = format!("Connecting at {}…", self.selected_speed.description());
            }
            KeyCode::Char('o') if key.modifiers.is_empty() => {
                self.open_file_dialog(AppState::SpeedSelection);
            }
            _ => {}
        }
    }

    fn handle_capture_input(&mut self, key: KeyEvent) {
        if self.search_mode {
            self.handle_search_input(key);
            return;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            self.save_capture();
            return;
        }
        match key.code {
            KeyCode::Tab => {
                self.active_view = match self.active_view {
                    ActiveView::Traffic => ActiveView::Devices,
                    ActiveView::Devices => ActiveView::Plugins,
                    ActiveView::Plugins => ActiveView::Traffic,
                };
            }
            KeyCode::Char('o') if key.modifiers.is_empty() => {
                self.open_file_dialog(AppState::Capturing);
            }
            KeyCode::Char('/') if self.load_label.is_some() && key.modifiers.is_empty() => {
                self.search_mode = true;
                self.search_input.clear();
            }
            KeyCode::Char('n') if key.modifiers.is_empty() && !self.search_matches.is_empty() => {
                let next = self.search_match_idx.map(|i| i + 1).unwrap_or(0);
                self.jump_to_match(next);
            }
            KeyCode::Char('p') if key.modifiers.is_empty() && !self.search_matches.is_empty() => {
                let prev = self
                    .search_match_idx
                    .map(|i| if i == 0 { self.search_matches.len() - 1 } else { i - 1 })
                    .unwrap_or(0);
                self.jump_to_match(prev);
            }
            KeyCode::Char('s') if key.modifiers.is_empty() => {
                self.state = AppState::SpeedSelection;
            }
            KeyCode::Char('v') if key.modifiers.is_empty() && self.load_label.is_none() => {
                // VBUS toggle is async (BackendHandle::set_power_config); the
                // actual call happens in `update()` via a pending-request flag
                // isn't needed here since we can just spawn nothing — toggling
                // is handled synchronously enough by queuing it for the next
                // `update()` tick via `pending_power_toggle`.
                self.pending_power_toggle = true;
            }
            _ => match self.active_view {
                ActiveView::Traffic => self.handle_traffic_nav(key),
                ActiveView::Devices => self.handle_device_nav(key),
                ActiveView::Plugins => self.handle_plugin_nav(key),
            },
        }
    }

    fn handle_search_input(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char(c) if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT => {
                self.search_input.push(c);
            }
            KeyCode::Backspace => {
                self.search_input.pop();
            }
            KeyCode::Esc => {
                self.search_mode = false;
                self.search_input.clear();
            }
            KeyCode::Enter => {
                self.search_query = std::mem::take(&mut self.search_input);
                self.search_mode = false;
                self.run_search();
                if !self.search_matches.is_empty() {
                    self.jump_to_match(0);
                }
            }
            _ => {}
        }
    }

    fn run_search(&mut self) {
        self.search_matches.clear();
        self.search_match_idx = None;
        if self.search_query.is_empty() {
            return;
        }
        if let Some(store) = self.items.as_mut() {
            match store.search(&self.search_query) {
                Ok(matches) => {
                    self.search_matches =
                        matches.into_iter().map(|(ti, ci)| (ti as usize, ci.map(|c| c as usize))).collect();
                }
                Err(e) => dbg_log!("search error: {e}"),
            }
        }
    }

    fn jump_to_match(&mut self, idx: usize) {
        if self.search_matches.is_empty() {
            return;
        }
        let idx = idx % self.search_matches.len();
        self.search_match_idx = Some(idx);
        let (ti, ci) = self.search_matches[idx];

        if ci.is_some() {
            if let Some(store) = self.items.as_mut() {
                let _ = store.set_expanded(ti as u64, true);
            }
        }

        let top = self.top_row_index(ti);
        let flat_idx = top.map(|t| t + ci.map(|c| 1 + c).unwrap_or(0));

        if let Some(flat) = flat_idx {
            self.selected_row = Some(flat);
            let len = self.flat_len();
            self.clamp_scroll(len);
        }
    }

    /// Save everything decoded so far (live capture or a loaded file alike)
    /// to a `.pcapng` file, as a one-shot snapshot — see
    /// `CaptureSession::save_now` for why this doesn't require having
    /// started saving before the capture began.
    fn save_capture(&mut self) {
        let Some(capture) = self.capture.as_mut() else { return };
        if capture.is_saving() {
            self.status_message = "Already saving…".to_string();
            return;
        }
        let filename = crate::capture::default_capture_filename();
        let path = std::path::PathBuf::from(&filename);
        match capture.save_now(path) {
            Ok(()) => self.status_message = format!("Saving → {filename}…"),
            Err(e) => self.status_message = format!("Cannot save: {e}"),
        }
    }

    fn handle_traffic_nav(&mut self, key: KeyEvent) {
        let len = self.flat_len();

        let is_g = key.code == KeyCode::Char('g') && key.modifiers.is_empty();
        if !is_g {
            self.g_pending = false;
        }

        if len == 0 {
            if is_g {
                self.g_pending = false;
            }
            return;
        }

        let page = self.page_size.max(1);

        match key.code {
            KeyCode::Up | KeyCode::Char('k') if key.modifiers.is_empty() || key.code == KeyCode::Up => {
                let cur = self.selected_row.unwrap_or(0);
                self.selected_row = Some(cur.saturating_sub(1));
                self.clamp_scroll(len);
            }
            KeyCode::Down | KeyCode::Char('j') if key.modifiers.is_empty() || key.code == KeyCode::Down => {
                let cur = self.selected_row.unwrap_or(0);
                self.selected_row = Some((cur + 1).min(len - 1));
                self.clamp_scroll(len);
            }
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let half = (page / 2).max(1);
                let cur = self.selected_row.unwrap_or(0);
                self.selected_row = Some((cur + half).min(len - 1));
                self.clamp_scroll(len);
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let half = (page / 2).max(1);
                let cur = self.selected_row.unwrap_or(0);
                self.selected_row = Some(cur.saturating_sub(half));
                self.clamp_scroll(len);
            }
            KeyCode::PageDown | KeyCode::Char('f')
                if key.modifiers.contains(KeyModifiers::CONTROL) || key.code == KeyCode::PageDown =>
            {
                let cur = self.selected_row.unwrap_or(0);
                self.selected_row = Some((cur + page).min(len - 1));
                self.clamp_scroll(len);
            }
            KeyCode::PageUp | KeyCode::Char('b')
                if key.modifiers.contains(KeyModifiers::CONTROL) || key.code == KeyCode::PageUp =>
            {
                let cur = self.selected_row.unwrap_or(0);
                self.selected_row = Some(cur.saturating_sub(page));
                self.clamp_scroll(len);
            }
            KeyCode::Char('G') => {
                self.selected_row = Some(len - 1);
                self.scroll_offset = len.saturating_sub(page);
            }
            KeyCode::Char('g') if key.modifiers.is_empty() => {
                if self.g_pending {
                    self.selected_row = Some(0);
                    self.scroll_offset = 0;
                    self.g_pending = false;
                } else {
                    self.g_pending = true;
                }
                return;
            }
            KeyCode::Right | KeyCode::Char('l') => {
                if let Some(idx) = self.selected_row {
                    if let Some((ti, None)) = self.resolve(idx) {
                        let has_children =
                            self.items.as_mut().map(|s| s.has_children(ti as u64).unwrap_or(false)).unwrap_or(false);
                        if has_children {
                            if let Some(store) = self.items.as_mut() {
                                let _ = store.set_expanded(ti as u64, true);
                            }
                        }
                    }
                }
            }
            KeyCode::Enter => {
                if let Some(idx) = self.selected_row {
                    if let Some((ti, None)) = self.resolve(idx) {
                        let has_children =
                            self.items.as_mut().map(|s| s.has_children(ti as u64).unwrap_or(false)).unwrap_or(false);
                        if has_children {
                            let was_expanded = self.items.as_ref().map(|s| s.is_expanded(ti as u64)).unwrap_or(false);
                            if let Some(store) = self.items.as_mut() {
                                let _ = store.set_expanded(ti as u64, !was_expanded);
                            }
                            if was_expanded {
                                let parent_row = self.top_row_index(ti).unwrap_or(idx);
                                self.selected_row = Some(parent_row);
                                let new_len = self.flat_len();
                                self.clamp_scroll(new_len);
                            }
                        }
                    }
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                if let Some(idx) = self.selected_row {
                    if let Some((ti, _)) = self.resolve(idx) {
                        if let Some(store) = self.items.as_mut() {
                            store.collapse(ti as u64);
                        }
                        let parent_row = self.top_row_index(ti).unwrap_or(idx);
                        self.selected_row = Some(parent_row);
                        let new_len = self.flat_len();
                        self.clamp_scroll(new_len);
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_device_nav(&mut self, key: KeyEvent) {
        let rows = crate::ui::device_tree_rows(&self.usb_devices, &self.device_expanded);
        let count = rows.len();
        if count == 0 {
            return;
        }

        if self.device_selected >= count {
            self.device_selected = count - 1;
        }

        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                if self.device_selected + 1 < count {
                    self.device_selected += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if self.device_selected > 0 {
                    self.device_selected -= 1;
                }
            }
            KeyCode::Char('G') => {
                self.device_selected = count - 1;
            }
            KeyCode::Char('g') if key.modifiers.is_empty() => {
                if self.g_pending {
                    self.device_selected = 0;
                    self.g_pending = false;
                } else {
                    self.g_pending = true;
                    return;
                }
            }
            KeyCode::Char('d') if key.modifiers == KeyModifiers::CONTROL => {
                let step = (self.page_size / 2).max(1);
                self.device_selected = (self.device_selected + step).min(count - 1);
            }
            KeyCode::Char('u') if key.modifiers == KeyModifiers::CONTROL => {
                let step = (self.page_size / 2).max(1);
                self.device_selected = self.device_selected.saturating_sub(step);
            }
            KeyCode::Char('l') | KeyCode::Right => {
                if let Some(row) = rows.get(self.device_selected) {
                    if let Some(key) = &row.expand_key {
                        self.device_expanded.insert(key.clone(), true);
                    }
                }
            }
            KeyCode::Enter => {
                if let Some(row) = rows.get(self.device_selected) {
                    if let Some(key) = &row.expand_key {
                        let currently = *self.device_expanded.get(key).unwrap_or(&false);
                        self.device_expanded.insert(key.clone(), !currently);
                    }
                }
            }
            KeyCode::Char('h') | KeyCode::Left => {
                if let Some(row) = rows.get(self.device_selected) {
                    if let Some(key) = &row.expand_key {
                        self.device_expanded.insert(key.clone(), false);
                    } else if self.device_selected > 0 {
                        let indent = row.indent;
                        for i in (0..self.device_selected).rev() {
                            if rows[i].indent < indent && rows[i].expand_key.is_some() {
                                self.device_selected = i;
                                break;
                            }
                        }
                    }
                }
            }
            _ => {
                self.g_pending = false;
            }
        }
        self.g_pending = false;

        let page = self.page_size.max(1);
        if self.device_selected < self.device_scroll {
            self.device_scroll = self.device_selected;
        } else if self.device_selected >= self.device_scroll + page {
            self.device_scroll = self.device_selected + 1 - page;
        }
    }

    fn handle_plugin_nav(&mut self, key: KeyEvent) {
        let n_plugins = self.plugin_manager.len();
        if n_plugins == 0 {
            return;
        }

        if !self.plugin_pane_focus {
            match key.code {
                KeyCode::Char('k') | KeyCode::Up if key.modifiers.is_empty() => {
                    if self.plugin_selected > 0 {
                        self.plugin_selected -= 1;
                        self.plugin_scroll = 0;
                    }
                }
                KeyCode::Char('j') | KeyCode::Down if key.modifiers.is_empty() => {
                    if self.plugin_selected + 1 < n_plugins {
                        self.plugin_selected += 1;
                        self.plugin_scroll = 0;
                    }
                }
                KeyCode::Enter => {
                    self.plugin_pane_focus = true;
                    self.plugin_scroll = 0;
                    self.g_pending = false;
                    self.plugin_manager.dispatch_focus(self.plugin_selected);
                }
                _ => {}
            }
            return;
        }

        let captures = self.plugin_manager.plugin_captures_nav(self.plugin_selected);

        let dispatched = match key.code {
            KeyCode::Char('j') | KeyCode::Down if captures && key.modifiers.is_empty() => {
                self.plugin_manager.dispatch_key(self.plugin_selected, 'j');
                true
            }
            KeyCode::Char('k') | KeyCode::Up if captures && key.modifiers.is_empty() => {
                self.plugin_manager.dispatch_key(self.plugin_selected, 'k');
                true
            }
            KeyCode::Enter if captures => {
                self.plugin_manager.dispatch_key(self.plugin_selected, '\r');
                true
            }
            KeyCode::Char('G') if captures => {
                self.plugin_manager.dispatch_key(self.plugin_selected, 'G');
                true
            }
            KeyCode::Char('d') if captures && key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.plugin_manager.dispatch_key_code(self.plugin_selected, KeyCode::PageDown);
                true
            }
            KeyCode::Char('u') if captures && key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.plugin_manager.dispatch_key_code(self.plugin_selected, KeyCode::PageUp);
                true
            }
            KeyCode::PageDown if captures => {
                self.plugin_manager.dispatch_key_code(self.plugin_selected, KeyCode::PageDown);
                true
            }
            KeyCode::PageUp if captures => {
                self.plugin_manager.dispatch_key_code(self.plugin_selected, KeyCode::PageUp);
                true
            }
            _ => false,
        };

        if dispatched {
            if let Some(nav) = self.plugin_manager.take_nav_request(self.plugin_selected) {
                self.handle_plugin_nav_request(nav);
            }
            self.g_pending = false;
            return;
        }

        match key.code {
            KeyCode::Char('j') | KeyCode::Down if key.modifiers.is_empty() => {
                self.plugin_scroll = self.plugin_scroll.saturating_add(1);
            }
            KeyCode::Char('k') | KeyCode::Up if key.modifiers.is_empty() => {
                self.plugin_scroll = self.plugin_scroll.saturating_sub(1);
            }
            KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let step = (self.page_size / 2).max(1);
                self.plugin_scroll = self.plugin_scroll.saturating_add(step);
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                let step = (self.page_size / 2).max(1);
                self.plugin_scroll = self.plugin_scroll.saturating_sub(step);
            }
            KeyCode::PageDown => {
                self.plugin_scroll = self.plugin_scroll.saturating_add(self.page_size);
            }
            KeyCode::PageUp => {
                self.plugin_scroll = self.plugin_scroll.saturating_sub(self.page_size);
            }
            KeyCode::Char('g') if key.modifiers.is_empty() => {
                if self.g_pending {
                    if captures {
                        self.plugin_manager.dispatch_key(self.plugin_selected, 'g');
                    } else {
                        self.plugin_scroll = 0;
                    }
                    self.g_pending = false;
                } else {
                    self.g_pending = true;
                    return;
                }
            }
            KeyCode::Char('G') => {
                if captures {
                    self.plugin_manager.dispatch_key(self.plugin_selected, 'G');
                } else {
                    self.plugin_scroll = usize::MAX / 2;
                }
            }
            KeyCode::Char(c @ (' ' | '[' | ']' | 'w' | 'e')) if key.modifiers.is_empty() => {
                self.plugin_manager.dispatch_key(self.plugin_selected, c);
                if let Some(nav) = self.plugin_manager.take_nav_request(self.plugin_selected) {
                    self.handle_plugin_nav_request(nav);
                }
            }
            KeyCode::Left | KeyCode::Right if key.modifiers.is_empty() => {
                self.plugin_manager.dispatch_key_code(self.plugin_selected, key.code);
            }
            _ => {
                self.g_pending = false;
            }
        }
        self.g_pending = false;
    }

    fn handle_plugin_nav_request(&mut self, nav: PluginNavRequest) {
        match nav {
            PluginNavRequest::GotoTimestamp(ts) => {
                let target = match self.items.as_mut() {
                    Some(store) => store.top_index_at_or_after(ts).ok().flatten(),
                    None => None,
                };
                if let Some(ti) = target {
                    if let Some(flat) = self.top_row_index(ti as usize) {
                        self.selected_row = Some(flat);
                        let len = self.flat_len();
                        self.clamp_scroll(len);
                        self.active_view = ActiveView::Traffic;
                    }
                }
            }
        }
    }

    fn clamp_scroll(&mut self, flat_len: usize) {
        let page = self.page_size.max(1);
        if let Some(sel) = self.selected_row {
            if sel < self.scroll_offset {
                self.scroll_offset = sel;
            } else if sel >= self.scroll_offset + page {
                self.scroll_offset = sel + 1 - page;
            }
            self.scroll_offset = self.scroll_offset.min(flat_len.saturating_sub(1));
        }
    }

    // -----------------------------------------------------------------------
    // Async updates
    // -----------------------------------------------------------------------

    pub async fn update(&mut self) -> Result<()> {
        match self.state {
            AppState::WaitingForDevice => {
                self.device_check_counter += 1;
                if self.device_check_counter >= 10 {
                    self.device_check_counter = 0;
                    if let Some(device) = self.device_manager.first_device() {
                        dbg_log!("update: device found ({}) → SpeedSelection", device.name);
                        self.selected_device = Some(device);
                        self.state = AppState::SpeedSelection;
                        self.status_message = "Device found!  Select USB speed:".to_string();
                        self.selected_speed_idx = 0;
                        self.selected_speed = Speed::High;
                    }
                }
            }
            AppState::Connecting => {
                if let Some(path) = self.pending_load.take() {
                    dbg_log!("update: Connecting → loading {}", path.display());
                    if let Err(e) = self.start_load(path).await {
                        dbg_log!("update: load error: {e}");
                        self.state = AppState::Error;
                        self.error_message = Some(format!("Failed to load capture: {e}"));
                    }
                    return Ok(());
                }

                let device = match self.selected_device.clone() {
                    Some(d) => d,
                    None => match self.device_manager.first_device() {
                        Some(d) => {
                            self.selected_device = Some(d.clone());
                            d
                        }
                        None => {
                            self.state = AppState::Error;
                            self.error_message = Some("No capture device found".to_string());
                            return Ok(());
                        }
                    },
                };

                dbg_log!("update: Connecting → starting capture on {}", device.name);
                match CaptureSession::start_capture(&device, self.selected_speed).await {
                    Ok(session) => {
                        dbg_log!("update: capture started → Capturing");
                        let reader = session.reader.clone();
                        self.clear_capture_state();
                        self.load_label = None;
                        self.capture = Some(session);
                        self.items = Some(ItemStore::new(reader));
                        self.state = AppState::Capturing;
                        self.status_message = format!(
                            "Capturing at {}  — Tab=views  s=speed  ↑↓=navigate  ←→=expand  q=quit",
                            self.selected_speed.description()
                        );
                    }
                    Err(e) => {
                        dbg_log!("update: start_capture error: {e}");
                        self.state = AppState::Error;
                        self.error_message = Some(format!("Failed to open device: {e}"));
                    }
                }
            }
            AppState::Capturing => {
                if self.pending_power_toggle {
                    self.pending_power_toggle = false;
                    if let Some(capture) = self.capture.as_mut() {
                        match capture.toggle_power().await {
                            Ok(on) => {
                                self.status_message =
                                    if on { "VBUS ON  (TARGET-C)".to_string() } else { "VBUS OFF (TARGET-C)".to_string() };
                            }
                            Err(e) => {
                                self.status_message = format!("VBUS toggle failed: {e}");
                            }
                        }
                    }
                }

                if let Some(capture) = self.capture.as_mut() {
                    capture.poll();
                    if let Some(result) = capture.poll_save() {
                        self.status_message = match result {
                            Ok(path) => {
                                let label = path
                                    .file_name()
                                    .map(|n| n.to_string_lossy().into_owned())
                                    .unwrap_or_else(|| path.display().to_string());
                                format!("Saved → {label}")
                            }
                            Err(e) => format!("Save error: {e}"),
                        };
                    }
                }

                if let Some(store) = self.items.as_mut() {
                    let before = self.last_synced_top;
                    let fast = self.capture.as_ref().map(|c| !c.is_live()).unwrap_or(false);
                    match plugin_bridge::sync(
                        store,
                        &mut self.plugin_manager,
                        &mut self.last_synced_top,
                        &mut self.plugin_sync_offset,
                        fast,
                    ) {
                        Ok(devices) => {
                            if self.last_synced_top != before {
                                dbg_log!(
                                    "update: synced {} new top-level items (total item_count={}, packet_count={}, devices={})",
                                    self.last_synced_top - before,
                                    store.transaction_count(),
                                    store.packet_count(),
                                    devices.len()
                                );
                            }
                            self.usb_devices = devices;
                        }
                        Err(e) => dbg_log!("update: plugin sync error: {e}"),
                    }
                }

                let auto_scroll = self.selected_row.is_none() && self.load_label.is_none();
                if auto_scroll {
                    let flat_len = self.flat_len();
                    if flat_len > 0 {
                        self.scroll_offset = flat_len.saturating_sub(self.page_size);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Helpers for the UI layer
    // -----------------------------------------------------------------------

    /// Flat rows visible in `[scroll_offset, scroll_offset + max_rows)`.
    /// Returns `(row, is_selected)` pairs.  Never allocates the full flat list.
    pub fn visible_rows(&mut self, max_rows: usize) -> Vec<(FlatRow, bool)> {
        let selected = self.selected_row;
        let Some(store) = self.items.as_mut() else { return Vec::new() };
        match store.flat_rows_window(self.scroll_offset as u64, max_rows as u64) {
            Ok(rows) => rows.into_iter().map(|(gi, row)| (row, Some(gi as usize) == selected)).collect(),
            Err(e) => {
                dbg_log!("visible_rows error: {e}");
                Vec::new()
            }
        }
    }

    /// Details text for the currently selected row.
    pub fn selected_details(&mut self) -> Option<(String, String)> {
        let flat_idx = self.selected_row?;
        let (ti, ci) = self.resolve(flat_idx)?;
        self.items.as_mut()?.row_details(ti as u64, ci.map(|c| c as u64)).ok()
    }

    /// Raw bytes for the currently selected row (for hex+ASCII dump in detail pane).
    pub fn selected_raw_bytes(&mut self) -> Option<Vec<u8>> {
        let flat_idx = self.selected_row?;
        let (ti, ci) = self.resolve(flat_idx)?;
        self.items.as_mut()?.row_raw_bytes(ti as u64, ci.map(|c| c as u64)).ok().flatten()
    }

    /// Current flat-row position (1-based) and total flat rows.
    pub fn selected_flat_position(&mut self) -> (usize, usize) {
        let total = self.flat_len();
        let pos = self.selected_row.map(|r| r + 1).unwrap_or(0);
        (pos, total)
    }

    /// Total number of top-level rows captured.
    pub fn transaction_count(&self) -> usize {
        self.items.as_ref().map(|s| s.transaction_count()).unwrap_or(0) as usize
    }

    /// Total individual packets captured.
    pub fn packet_count(&self) -> usize {
        self.items.as_ref().map(|s| s.packet_count()).unwrap_or(0) as usize
    }

    pub fn is_saving(&self) -> bool {
        self.capture.as_ref().map(|c| c.is_saving()).unwrap_or(false)
    }

    pub fn save_label(&self) -> Option<&str> {
        self.capture.as_ref().and_then(|c| c.save_label())
    }

    /// True while a file load is still in progress (background decode
    /// thread hasn't reached the end of the file yet).
    pub fn is_loading(&self) -> bool {
        self.load_label.is_some() && self.capture.as_ref().map(|c| !c.complete()).unwrap_or(false)
    }

    /// Fraction (0.0..=1.0) of the file read so far, if known. `None` while
    /// not loading, or if the file size couldn't be determined up front.
    pub fn load_progress(&self) -> Option<f32> {
        self.capture.as_ref().and_then(|c| c.load_progress())
    }

    /// True while a loaded file's decoded items are still being fed to the
    /// plugin decoders (CDC/HID/Audio/HCI) — this trails file loading itself
    /// since it's driven by a separate incremental sync (`plugin_bridge::
    /// sync`), so the Plugins pane can lag behind "Loaded" even once the
    /// underlying file is fully decoded.
    pub fn is_syncing_plugins(&self) -> bool {
        !self.is_loading()
            && self.load_label.is_some()
            && self.items.as_ref().map(|s| self.last_synced_top < s.item_count()).unwrap_or(false)
    }

    /// Fraction (0.0..=1.0) of top-level items synced to plugins so far.
    pub fn plugin_sync_progress(&self) -> Option<f32> {
        let store = self.items.as_ref()?;
        let total = store.item_count();
        if total == 0 {
            return None;
        }
        Some((self.last_synced_top as f32 / total as f32).min(1.0))
    }

    /// Color hint used by the UI when rendering a row's kind.
    pub fn kind_color(kind: RowKind) -> ratatui::style::Color {
        use ratatui::style::Color;
        match kind {
            RowKind::Control => Color::Cyan,
            RowKind::BulkIn => Color::Green,
            RowKind::BulkOut => Color::Blue,
            RowKind::Interrupt => Color::Magenta,
            RowKind::Isochronous => Color::LightYellow,
            RowKind::Framing => Color::DarkGray,
            RowKind::Polling => Color::Red,
            RowKind::Ambiguous => Color::LightRed,
            RowKind::Event => Color::Yellow,
            RowKind::Other => Color::White,
        }
    }
}
