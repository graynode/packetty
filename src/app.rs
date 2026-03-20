use crate::backend::{CynthionManager, DeviceInfo};
use crate::dbg_log;
use crate::models::{FlatRow, TreeItem, TransactionKind, UsbDeviceInfo,
                    flat_row_count, flat_index_resolve, flat_top_row_index,
                    flat_rows_window, hex_ascii_dump, bytes_to_text_hints};
use crate::plugins::{PluginManager, PluginNavRequest};
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::collections::{HashMap, VecDeque};
use tui_file_explorer::{FileExplorer, ExplorerOutcome};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speed {
    High = 0,
    Full = 1,
    Low  = 2,
    Auto = 3,
}

impl std::fmt::Display for Speed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Speed::High => write!(f, "High-Speed (480 Mbps)"),
            Speed::Full => write!(f, "Full-Speed (12 Mbps)"),
            Speed::Low  => write!(f, "Low-Speed (1.5 Mbps)"),
            Speed::Auto => write!(f, "Auto"),
        }
    }
}

pub struct App {
    pub state: AppState,
    pub active_view: ActiveView,
    pub device_manager: CynthionManager,
    pub selected_device: Option<DeviceInfo>,
    pub selected_speed: Speed,
    pub speed_options: Vec<Speed>,
    pub selected_speed_idx: usize,
    pub status_message: String,
    pub error_message: Option<String>,

    // Traffic view
    /// Top-level transaction nodes in capture order.
    pub tree_items: VecDeque<TreeItem>,
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

    device_check_counter: usize,
    /// `true` when the user has pressed `g` once; a second `g` goes to top.
    g_pending: bool,

    // PCAP save/load
    /// Display name of the save file (shown in status bar).
    pub save_label: Option<String>,
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
        let device_manager = CynthionManager::new().await?;

        let mut plugin_manager = PluginManager::new();
        plugin_manager.register(Box::new(crate::plugins::cdc::CdcPlugin::new()));
        plugin_manager.register(Box::new(crate::plugins::hid_mouse::HidMousePlugin::new()));
        plugin_manager.register(Box::new(crate::plugins::hid_keyboard::HidKeyboardPlugin::new()));
        plugin_manager.register(Box::new(crate::plugins::audio::AudioPlugin::new()));

        Ok(App {
            state: AppState::WaitingForDevice,
            active_view: ActiveView::Traffic,
            device_manager,
            selected_device: None,
            selected_speed: Speed::High,
            speed_options: vec![Speed::High, Speed::Full, Speed::Low, Speed::Auto],
            selected_speed_idx: 0,
            status_message: "Waiting for Cynthion device…".to_string(),
            error_message: None,
            tree_items: VecDeque::new(),
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
            device_check_counter: 0,
            g_pending: false,
            save_label: None,
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

    /// Jump directly to Capturing state by replaying a pcap file.
    pub async fn start_load(&mut self, path: std::path::PathBuf) -> Result<()> {
        let label = path.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        self.device_manager.load_pcap_file(path).await?;
        self.state = AppState::Capturing;
        self.load_label = Some(label.clone());
        self.save_label = None;
        self.status_message = format!("Loaded: {label}");
        self.clear_capture_state();
        Ok(())
    }

    /// Clear all per-capture UI state so a new file can be loaded cleanly.
    fn clear_capture_state(&mut self) {
        self.tree_items.clear();
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
    }

    // -----------------------------------------------------------------------
    // Input handling
    // -----------------------------------------------------------------------

    /// Returns `true` when the application should quit.
    pub fn handle_input(&mut self, key: KeyEvent) -> bool {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return true;
        }
        // `?` toggles the help popup (not while typing a search query).
        if key.code == KeyCode::Char('?') && key.modifiers.is_empty() && !self.search_mode {
            self.show_help = !self.show_help;
            return false;
        }
        // When the help popup is open, consume all keys except Esc/?  (already handled above).
        if self.show_help {
            if key.code == KeyCode::Esc { self.show_help = false; }
            return false;
        }
        // Allow Esc to cancel the file dialog without quitting.
        if key.code == KeyCode::Esc {
            if self.state == AppState::LoadFile {
                self.file_explorer = None;
                self.state = self.file_dialog_return;
                return false;
            }
            return true;
        }
        if key.code == KeyCode::Char('q') && self.state != AppState::SpeedSelection && self.state != AppState::LoadFile {
            return true;
        }
        match self.state {
            AppState::WaitingForDevice | AppState::Connecting => {
                // `o` opens the file-load dialog from the waiting screen.
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
            None => { self.state = return_state; return; }
        };
        match explorer.handle_key(key) {
            ExplorerOutcome::Selected(path) => {
                self.file_explorer = None;
                self.pending_load = Some(path);
                self.state = AppState::Connecting;
                self.status_message = "Loading pcap file…".to_string();
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
                self.status_message = format!("Connecting at {}…", self.selected_speed);
            }
            // `o` opens a pcap file without starting a live capture.
            KeyCode::Char('o') if key.modifiers.is_empty() => {
                self.open_file_dialog(AppState::SpeedSelection);
            }
            _ => {}
        }
    }

    fn handle_capture_input(&mut self, key: KeyEvent) {
        // While search input is active, funnel all keys there.
        if self.search_mode {
            self.handle_search_input(key);
            return;
        }

        // Ctrl+S: toggle PCAP save (only while live-capturing, not when loading a file).
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            if self.load_label.is_none() {
                self.toggle_save();
            }
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
            // `o` opens the file dialog to load a (new) pcap while capturing.
            KeyCode::Char('o') if key.modifiers.is_empty() => {
                self.open_file_dialog(AppState::Capturing);
            }
            // `/` opens search — only available when reviewing a loaded file (not live capture).
            KeyCode::Char('/') if self.load_label.is_some() && key.modifiers.is_empty() => {
                self.search_mode = true;
                self.search_input.clear();
            }
            // `n` → next match, `p` → previous match.
            KeyCode::Char('n') if key.modifiers.is_empty() && !self.search_matches.is_empty() => {
                let next = self.search_match_idx.map(|i| i + 1).unwrap_or(0);
                self.jump_to_match(next);
            }
            KeyCode::Char('p') if key.modifiers.is_empty() && !self.search_matches.is_empty() => {
                let prev = self.search_match_idx.map(|i| {
                    if i == 0 { self.search_matches.len() - 1 } else { i - 1 }
                }).unwrap_or(0);
                self.jump_to_match(prev);
            }
            KeyCode::Char('s') if key.modifiers.is_empty() => {
                self.state = AppState::SpeedSelection;
            }
            // `v` toggles VBUS (TARGET-C) — only meaningful during live capture.
            KeyCode::Char('v') if key.modifiers.is_empty() && self.load_label.is_none() => {
                match self.device_manager.toggle_vbus() {
                    Ok(on) => {
                        self.status_message = if on {
                            "VBUS ON  (TARGET-C)".to_string()
                        } else {
                            "VBUS OFF (TARGET-C)".to_string()
                        };
                    }
                    Err(e) => {
                        self.status_message = format!("VBUS toggle failed: {e}");
                    }
                }
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
            KeyCode::Backspace => { self.search_input.pop(); }
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
        let query = self.search_query.to_lowercase();
        self.search_matches.clear();
        self.search_match_idx = None;
        if query.is_empty() { return; }

        for (ti, item) in self.tree_items.iter().enumerate() {
            if item.label.to_lowercase().contains(&query)
                || item.details.to_lowercase().contains(&query)
            {
                self.search_matches.push((ti, None));
            }
            for (ci, pkt) in item.children.iter().enumerate() {
                let dump  = hex_ascii_dump(&pkt.raw_bytes);
                let hints = bytes_to_text_hints(&pkt.raw_bytes);
                if pkt.label.to_lowercase().contains(&query)
                    || pkt.details.to_lowercase().contains(&query)
                    || dump.to_lowercase().contains(&query)
                    || hints.to_lowercase().contains(&query)
                {
                    self.search_matches.push((ti, Some(ci)));
                }
            }
        }
    }

    fn jump_to_match(&mut self, idx: usize) {
        if self.search_matches.is_empty() { return; }
        let idx = idx % self.search_matches.len();
        self.search_match_idx = Some(idx);
        let (ti, ci) = self.search_matches[idx];

        // Expand parent when jumping to a child row.
        if ci.is_some() {
            if let Some(item) = self.tree_items.get_mut(ti) {
                item.expanded = true;
            }
        }

        let flat_idx = flat_top_row_index(&self.tree_items, ti)
            .map(|top| top + ci.map(|c| 1 + c).unwrap_or(0));

        if let Some(flat) = flat_idx {
            self.selected_row = Some(flat);
            let len = flat_row_count(&self.tree_items);
            self.clamp_scroll(len);
        }
    }

    fn toggle_save(&mut self) {
        if self.device_manager.is_saving() {
            if let Err(e) = self.device_manager.stop_save() {
                self.status_message = format!("Save error: {e}");
            } else {
                let name = self.save_label.take().unwrap_or_default();
                self.status_message = format!("Saved → {name}");
            }
        } else {
            let filename = crate::pcap::default_capture_filename();
            let path = std::path::PathBuf::from(&filename);
            match self.device_manager.start_save(path) {
                Ok(p) => {
                    let label = p.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or(filename);
                    self.save_label = Some(label.clone());
                    self.status_message = format!("Recording → {label}");
                }
                Err(e) => {
                    self.status_message = format!("Cannot save: {e}");
                }
            }
        }
    }

    fn handle_traffic_nav(&mut self, key: KeyEvent) {
        let len = flat_row_count(&self.tree_items);

        // Any key other than `g` clears the gg-pending state unless it is itself `g`.
        let is_g = key.code == KeyCode::Char('g') && key.modifiers.is_empty();
        if !is_g {
            self.g_pending = false;
        }

        if len == 0 {
            if is_g { self.g_pending = false; }
            return;
        }

        let page = self.page_size.max(1);

        match key.code {
            // ── Vertical movement ──────────────────────────────────────────
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

            // ── Page navigation ────────────────────────────────────────────
            // Ctrl+d / Ctrl+u  — half page
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
            // Ctrl+f / Ctrl+b or PageDown/PageUp — full page
            KeyCode::PageDown | KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::CONTROL) || key.code == KeyCode::PageDown => {
                let cur = self.selected_row.unwrap_or(0);
                self.selected_row = Some((cur + page).min(len - 1));
                self.clamp_scroll(len);
            }
            KeyCode::PageUp | KeyCode::Char('b') if key.modifiers.contains(KeyModifiers::CONTROL) || key.code == KeyCode::PageUp => {
                let cur = self.selected_row.unwrap_or(0);
                self.selected_row = Some(cur.saturating_sub(page));
                self.clamp_scroll(len);
            }

            // ── First / last ───────────────────────────────────────────────
            // G  → last row
            KeyCode::Char('G') => {
                self.selected_row = Some(len - 1);
                self.scroll_offset = len.saturating_sub(page);
            }
            // gg → first row  (g pressed twice)
            KeyCode::Char('g') if key.modifiers.is_empty() => {
                if self.g_pending {
                    self.selected_row = Some(0);
                    self.scroll_offset = 0;
                    self.g_pending = false;
                } else {
                    self.g_pending = true;
                }
                return; // don't fall through to the g_pending reset below
            }

            // ── Expand / collapse ──────────────────────────────────────────
            // Right / l: expand only
            KeyCode::Right | KeyCode::Char('l') => {
                if let Some(idx) = self.selected_row {
                    if let Some((ti, None)) = flat_index_resolve(&self.tree_items, idx) {
                        if let Some(item) = self.tree_items.get_mut(ti) {
                            if item.has_children() {
                                item.expanded = true;
                            }
                        }
                    }
                }
            }
            // Enter: toggle expand/collapse
            KeyCode::Enter => {
                if let Some(idx) = self.selected_row {
                    if let Some((ti, None)) = flat_index_resolve(&self.tree_items, idx) {
                        if let Some(item) = self.tree_items.get_mut(ti) {
                            if item.has_children() {
                                item.expanded = !item.expanded;
                                if !item.expanded {
                                    // Move cursor back to the parent row.
                                    let parent_row = flat_top_row_index(&self.tree_items, ti).unwrap_or(idx);
                                    self.selected_row = Some(parent_row);
                                    let new_len = flat_row_count(&self.tree_items);
                                    self.clamp_scroll(new_len);
                                }
                            }
                        }
                    }
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                if let Some(idx) = self.selected_row {
                    if let Some((ti, _)) = flat_index_resolve(&self.tree_items, idx) {
                        // Collapse the parent item.
                        if let Some(item) = self.tree_items.get_mut(ti) {
                            item.expanded = false;
                        }
                        // Move cursor to the parent's top-level row.
                        let parent_row = flat_top_row_index(&self.tree_items, ti).unwrap_or(idx);
                        self.selected_row = Some(parent_row);
                        let new_len = flat_row_count(&self.tree_items);
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
        if count == 0 { return; }

        // Clamp selection first.
        if self.device_selected >= count { self.device_selected = count - 1; }

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
            // l / Right — expand; Enter — toggle expand/collapse
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
            // h / Left — collapse
            KeyCode::Char('h') | KeyCode::Left => {
                if let Some(row) = rows.get(self.device_selected) {
                    if let Some(key) = &row.expand_key {
                        self.device_expanded.insert(key.clone(), false);
                    } else if self.device_selected > 0 {
                        // Jump to parent node.
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
            _ => { self.g_pending = false; }
        }
        self.g_pending = false;

        // Scroll to keep selection in view.
        let page = self.page_size.max(1);
        if self.device_selected < self.device_scroll {
            self.device_scroll = self.device_selected;
        } else if self.device_selected >= self.device_scroll + page {
            self.device_scroll = self.device_selected + 1 - page;
        }
    }

    fn handle_plugin_nav(&mut self, key: KeyEvent) {
        let n_plugins = self.plugin_manager.len();
        if n_plugins == 0 { return; }

        // When the active plugin has an internal list focused it wants j/k/Enter
        // for itself rather than for plugin selection.
        let captures = self.plugin_manager.plugin_captures_nav(self.plugin_selected);

        let dispatched = match key.code {
            KeyCode::Char('j') | KeyCode::Down if captures && key.modifiers.is_empty() => {
                self.plugin_manager.dispatch_key(self.plugin_selected, 'j'); true
            }
            KeyCode::Char('k') | KeyCode::Up if captures && key.modifiers.is_empty() => {
                self.plugin_manager.dispatch_key(self.plugin_selected, 'k'); true
            }
            KeyCode::Enter if captures => {
                self.plugin_manager.dispatch_key(self.plugin_selected, '\r'); true
            }
            _ => false,
        };

        // After any plugin key dispatch, check for a pending nav request.
        if dispatched {
            if let Some(nav) = self.plugin_manager.take_nav_request(self.plugin_selected) {
                self.handle_plugin_nav_request(nav);
            }
            self.g_pending = false;
            return;
        }

        match key.code {
            // Select previous / next plugin in the list
            KeyCode::Char('k') | KeyCode::Up => {
                if self.plugin_selected > 0 {
                    self.plugin_selected -= 1;
                    self.plugin_scroll = 0;
                }
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if self.plugin_selected + 1 < n_plugins {
                    self.plugin_selected += 1;
                    self.plugin_scroll = 0;
                }
            }
            // Scroll content pane
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
                    self.plugin_scroll = 0;
                    self.g_pending = false;
                } else {
                    self.g_pending = true;
                    return;
                }
            }
            KeyCode::Char('G') => {
                self.plugin_scroll = usize::MAX / 2;
            }
            // Forward Space, [, ], w, e to the active plugin.
            KeyCode::Char(c @ (' ' | '[' | ']' | 'w' | 'e')) if key.modifiers.is_empty() => {
                self.plugin_manager.dispatch_key(self.plugin_selected, c);
                if let Some(nav) = self.plugin_manager.take_nav_request(self.plugin_selected) {
                    self.handle_plugin_nav_request(nav);
                }
            }
            _ => { self.g_pending = false; }
        }
        self.g_pending = false;
    }

    fn handle_plugin_nav_request(&mut self, nav: PluginNavRequest) {
        match nav {
            PluginNavRequest::GotoTimestamp(ts) => {
                // Find the first tree item at or after the target timestamp.
                for (ti, item) in self.tree_items.iter().enumerate() {
                    if item.timestamp_ns >= ts {
                        if let Some(flat) = flat_top_row_index(&self.tree_items, ti) {
                            self.selected_row = Some(flat);
                            let len = flat_row_count(&self.tree_items);
                            self.clamp_scroll(len);
                            self.active_view = ActiveView::Traffic;
                        }
                        return;
                    }
                }
                // Timestamp past end — jump to last row.
                if !self.tree_items.is_empty() {
                    let last = flat_row_count(&self.tree_items) - 1;
                    self.selected_row = Some(last);
                    let len = last + 1;
                    self.clamp_scroll(len);
                    self.active_view = ActiveView::Traffic;
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
                    dbg_log!("update: polling for device");
                    if let Some(info) = self.device_manager.find_device().await? {
                        dbg_log!("update: device found → SpeedSelection");
                        self.selected_device = Some(info);
                        self.state = AppState::SpeedSelection;
                        self.status_message =
                            "Device found!  Select USB speed:".to_string();
                        self.selected_speed_idx = 0;
                        self.selected_speed = Speed::High;
                    }
                }
            }
            AppState::Connecting => {
                // If the user opened a pcap file via the dialog, load it instead of
                // opening the hardware device.
                if let Some(path) = self.pending_load.take() {
                    dbg_log!("update: Connecting → loading pcap {}", path.display());
                    match self.start_load(path).await {
                        Ok(()) => {}
                        Err(e) => {
                            dbg_log!("update: pcap load error: {e}");
                            self.state = AppState::Error;
                            self.error_message = Some(format!("Failed to load pcap: {e}"));
                        }
                    }
                    return Ok(());
                }
                // If we came from pcap viewing (s key) the device scan may not
                // have run yet — find it now before trying to open it.
                if !self.device_manager.has_found_device() {
                    dbg_log!("update: Connecting — no device cached, scanning first");
                    match self.device_manager.find_device().await? {
                        None => {
                            self.state = AppState::Error;
                            self.error_message = Some("No Cynthion device found".to_string());
                            return Ok(());
                        }
                        Some(info) => {
                            self.selected_device = Some(info);
                        }
                    }
                }
                dbg_log!("update: Connecting → calling open_device()");
                match self.device_manager.open_device(self.selected_speed).await {
                    Ok(()) => {
                        dbg_log!("update: open_device() OK → Capturing");
                        // Discard any previously loaded pcap and start fresh.
                        self.clear_capture_state();
                        self.load_label = None;
                        self.save_label = None;
                        self.usb_devices = self.device_manager.discovered_devices();
                        self.state = AppState::Capturing;
                        self.status_message = format!(
                            "Capturing at {}  — Tab=views  s=speed  ↑↓=navigate  ←→=expand  q=quit",
                            self.selected_speed
                        );
                    }
                    Err(e) => {
                        dbg_log!("update: open_device() error: {e}");
                        self.state = AppState::Error;
                        self.error_message = Some(format!("Failed to open device: {e}"));
                    }
                }
            }
            AppState::Capturing => {
                if let Some(txns) = self.device_manager.get_new_transactions().await? {
                    // Auto-scroll only during live capture; loaded files start at the top.
                    let auto_scroll = self.selected_row.is_none() && self.load_label.is_none();
                    // Refresh device list once per batch.
                    self.usb_devices = self.device_manager.discovered_devices();
                    for txn in txns {
                        // Feed transaction to plugins before consuming it.
                        self.plugin_manager.on_transaction(&txn, &self.usb_devices);
                        let item = TreeItem::from_transaction(txn);
                        self.tree_items.push_back(item);
                    }
                    // Auto-scroll to bottom when nothing is selected.
                    if auto_scroll {
                        let flat_len = flat_row_count(&self.tree_items);
                        if flat_len > 0 {
                            self.scroll_offset = flat_len.saturating_sub(self.page_size);
                        }
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
    pub fn visible_rows(&self, max_rows: usize) -> Vec<(FlatRow, bool)> {
        flat_rows_window(&self.tree_items, self.scroll_offset, max_rows)
            .into_iter()
            .map(|(gi, row)| (row, Some(gi) == self.selected_row))
            .collect()
    }

    /// Details text for the currently selected row.
    /// Returns `(label, details)` or `None`.
    pub fn selected_details(&self) -> Option<(String, String)> {
        let flat_idx = self.selected_row?;
        let (ti, ci) = flat_index_resolve(&self.tree_items, flat_idx)?;
        let item = self.tree_items.get(ti)?;
        if let Some(ci) = ci {
            let pkt = item.children.get(ci)?;
            Some((pkt.label.clone(), pkt.details.clone()))
        } else {
            Some((item.label.clone(), item.details.clone()))
        }
    }

    /// Raw bytes for the currently selected row (for hex+ASCII dump in detail pane).
    pub fn selected_raw_bytes(&self) -> Option<Vec<u8>> {
        let flat_idx = self.selected_row?;
        let (ti, ci) = flat_index_resolve(&self.tree_items, flat_idx)?;
        let item = self.tree_items.get(ti)?;
        if let Some(ci) = ci {
            let pkt = item.children.get(ci)?;
            if pkt.raw_bytes.is_empty() { None } else { Some(pkt.raw_bytes.clone()) }
        } else {
            // Top-level: collect all child raw bytes into one flat buffer.
            let all: Vec<u8> = item.children.iter()
                .flat_map(|p| p.raw_bytes.iter().copied())
                .collect();
            if all.is_empty() { None } else { Some(all) }
        }
    }

    /// Current flat-row position (1-based) and total flat rows.
    /// Returns `(0, total)` when nothing is selected.
    pub fn selected_flat_position(&self) -> (usize, usize) {
        let total = flat_row_count(&self.tree_items);
        let pos   = self.selected_row.map(|r| r + 1).unwrap_or(0);
        (pos, total)
    }

    /// Total number of top-level transaction nodes captured.
    pub fn transaction_count(&self) -> usize {
        self.tree_items.len()
    }

    /// Total individual packets (summing all children, or 1 for leaf nodes).
    pub fn packet_count(&self) -> usize {
        self.tree_items.iter().map(|i| {
            if i.children.is_empty() { 1 } else { i.children.len() }
        }).sum()
    }

    /// Color hint used by the UI when rendering a transaction kind.
    pub fn kind_color(kind: TransactionKind) -> ratatui::style::Color {
        use ratatui::style::Color;
        match kind {
            TransactionKind::Control      => Color::Cyan,
            TransactionKind::BulkIn       => Color::Green,
            TransactionKind::BulkOut      => Color::Blue,
            TransactionKind::Interrupt    => Color::Magenta,
            TransactionKind::Isochronous  => Color::LightYellow,
            TransactionKind::SofGroup     => Color::DarkGray,
            TransactionKind::Nak          => Color::Red,
            TransactionKind::Stall        => Color::LightRed,
            TransactionKind::Other        => Color::White,
        }
    }
}


