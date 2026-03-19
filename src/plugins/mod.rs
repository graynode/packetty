pub mod cdc;
pub mod hid_mouse;
pub mod hid_keyboard;

use crate::models::{TransactionInfo, UsbDeviceInfo};
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
    fn render_lines(&self) -> Vec<PluginLine>;

    /// Returns `true` when the plugin has seen relevant activity.
    /// Used to show an indicator on the Plugins tab.
    fn is_active(&self) -> bool;
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
}
