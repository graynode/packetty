pub mod cdc;
pub mod hid_mouse;
pub mod hid_keyboard;
pub mod audio;

use crate::models::{TransactionInfo, UsbDeviceInfo};
use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

// ---------------------------------------------------------------------------
// PluginLine — a single rendered line from a plugin's output
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PluginLine {
    pub text: String,
    pub color: Color,
    pub bold: bool,
    pub dim: bool,
}

impl PluginLine {
    pub fn plain(text: impl Into<String>) -> Self {
        Self { text: text.into(), color: Color::White, bold: false, dim: false }
    }

    pub fn colored(text: impl Into<String>, color: Color) -> Self {
        Self { text: text.into(), color, bold: false, dim: false }
    }

    pub fn header(text: impl Into<String>) -> Self {
        Self { text: text.into(), color: Color::Cyan, bold: true, dim: false }
    }

    pub fn separator() -> Self {
        Self {
            text: "─".repeat(80),
            color: Color::DarkGray,
            bold: false,
            dim: false,
        }
    }

    pub fn into_ratatui_line(self) -> Line<'static> {
        let mut style = Style::default().fg(self.color);
        if self.bold { style = style.add_modifier(Modifier::BOLD); }
        if self.dim  { style = style.add_modifier(Modifier::DIM); }
        Line::from(Span::styled(self.text, style))
    }
}

// ---------------------------------------------------------------------------
// UsbPlugin trait
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// PluginNavRequest — plugin-initiated navigation back to the main view
// ---------------------------------------------------------------------------

/// A navigation action a plugin can request after handling a key press.
#[derive(Debug, Clone)]
pub enum PluginNavRequest {
    /// Jump to the transaction in the Traffic view whose timestamp matches.
    GotoTimestamp(u64),
}

// ---------------------------------------------------------------------------
// UsbPlugin trait
// ---------------------------------------------------------------------------

/// Trait implemented by every USB higher-level decoder plugin.
///
/// Each plugin receives every completed transaction and the current device
/// list, then exposes rendered lines for display in the Plugins tab.
pub trait UsbPlugin: Send {
    /// Short name shown in the plugin list (≤ 30 chars recommended).
    fn name(&self) -> &str;

    /// One-line human description of what this plugin decodes.
    fn description(&self) -> &str;

    /// Called for every newly completed USB transaction while capturing or
    /// replaying a file.  `devices` is the current snapshot of all discovered
    /// USB devices on the bus.
    fn on_transaction(&mut self, txn: &TransactionInfo, devices: &[UsbDeviceInfo]);

    /// Called when the capture is cleared or a new file is loaded so plugins
    /// can discard stale state.
    fn reset(&mut self);

    /// Returns the lines to display in this plugin's content pane.
    /// Used as fallback when `render_custom` returns false.
    fn render_lines(&self) -> Vec<PluginLine>;

    /// Returns `true` when the plugin has seen relevant activity.
    /// Used to show an indicator on the Plugins tab.
    fn is_active(&self) -> bool;

    /// Optional fully-custom rendering into `area`.  Return `true` if the
    /// plugin handled the render itself; return `false` to fall back to the
    /// default `render_lines` paragraph renderer.
    ///
    /// `scroll` is the current vertical scroll offset (lines to skip).
    fn render_custom(&self, _f: &mut ratatui::Frame<'_>, _area: Rect, _scroll: usize) -> bool {
        false
    }

    /// Called when a key is pressed while this plugin's content pane is
    /// focused.  Plugins can use this for interactive controls (e.g. audio
    /// playback).
    fn on_key(&mut self, _key: char) {}

    /// Called for special keys (arrows, etc.) that cannot be represented as
    /// a single `char`.  Default implementation is a no-op.
    fn on_key_code(&mut self, _key: KeyCode) {}

    /// Returns plugin-specific key bindings shown in the help popup.
    /// Each entry is `(key_label, description)`.
    fn help_keys(&self) -> Vec<(&'static str, &'static str)> { vec![] }

    /// When `true`, the plugin wants to receive `j`/`k`/Enter navigation keys
    /// directly (e.g. while an internal list is focused) instead of having
    /// them used for plugin selection.
    fn captures_navigation(&self) -> bool { false }

    /// Consume and return a pending navigation request produced by `on_key`.
    fn take_nav_request(&mut self) -> Option<PluginNavRequest> { None }
}

// ---------------------------------------------------------------------------
// PluginManager — registry and event dispatcher
// ---------------------------------------------------------------------------

pub struct PluginManager {
    plugins: Vec<Box<dyn UsbPlugin>>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self { plugins: Vec::new() }
    }

    pub fn register(&mut self, plugin: Box<dyn UsbPlugin>) {
        self.plugins.push(plugin);
    }

    /// Dispatch a transaction to all registered plugins.
    pub fn on_transaction(&mut self, txn: &TransactionInfo, devices: &[UsbDeviceInfo]) {
        for p in &mut self.plugins {
            p.on_transaction(txn, devices);
        }
    }

    /// Reset all plugins (called on capture clear or new file load).
    pub fn reset(&mut self) {
        for p in &mut self.plugins { p.reset(); }
    }

    pub fn plugins(&self) -> &[Box<dyn UsbPlugin>] {
        &self.plugins
    }

    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Number of plugins that currently have active data.
    pub fn active_count(&self) -> usize {
        self.plugins.iter().filter(|p| p.is_active()).count()
    }

    /// Forward a keypress to the selected plugin's `on_key` handler.
    pub fn dispatch_key(&mut self, idx: usize, key: char) {
        if let Some(p) = self.plugins.get_mut(idx) {
            p.on_key(key);
        }
    }

    /// Forward a special key code to the selected plugin's `on_key_code` handler.
    pub fn dispatch_key_code(&mut self, idx: usize, key: KeyCode) {
        if let Some(p) = self.plugins.get_mut(idx) {
            p.on_key_code(key);
        }
    }

    /// Returns `true` if the selected plugin wants to handle navigation keys.
    pub fn plugin_captures_nav(&self, idx: usize) -> bool {
        self.plugins.get(idx).map(|p| p.captures_navigation()).unwrap_or(false)
    }

    /// Consume a pending navigation request from the selected plugin.
    pub fn take_nav_request(&mut self, idx: usize) -> Option<PluginNavRequest> {
        self.plugins.get_mut(idx)?.take_nav_request()
    }
}
