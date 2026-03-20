use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};
use crate::app::{App, AppState, ActiveView};
use crate::models::{TransactionKind, UsbDeviceInfo, UsbConfigInfo, UsbInterfaceInfo, UsbEndpointInfo, hex_ascii_dump};
use std::collections::HashMap;

const PLUGIN_LIST_WIDTH: u16 = 28;

// ---------------------------------------------------------------------------
// Top-level dispatcher
// ---------------------------------------------------------------------------

pub fn draw(f: &mut Frame, app: &mut App) {
    let [main, status] = Layout::vertical([
        Constraint::Min(5),
        Constraint::Length(2),
    ]).areas(f.area());

    match app.state {
        AppState::WaitingForDevice => draw_waiting(f, main, status, app),
        AppState::SpeedSelection   => draw_speed_selection(f, main, status, app),
        AppState::Connecting       => draw_connecting(f, main, status, app),
        AppState::Capturing        => draw_capture(f, main, status, app),
        AppState::Error            => draw_error(f, main, status, app),
        AppState::LoadFile         => draw_load_file(f, main, status, app),
    }

    if app.show_help {
        draw_help_popup(f, app);
    }
}

// ---------------------------------------------------------------------------
// Waiting screen
// ---------------------------------------------------------------------------

fn draw_waiting(f: &mut Frame, main: Rect, status: Rect, app: &App) {
    let block = Block::default()
        .title(" Packetry Terminal — Waiting for Device ")
        .borders(Borders::ALL);

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "⏳  Searching for Cynthion USB analyzer…",
            Style::default().fg(Color::Yellow),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "VID: 0x1d50   PID: 0x615b",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Connect the device to continue.",
            Style::default().fg(Color::Gray),
        )),
    ];

    f.render_widget(
        Paragraph::new(text).block(block).alignment(Alignment::Center),
        main,
    );
    render_status(f, status, &app.status_message, "o = open pcap  Ctrl+C / q = quit");
}

// ---------------------------------------------------------------------------
// Speed selection
// ---------------------------------------------------------------------------

fn draw_speed_selection(f: &mut Frame, main: Rect, status: Rect, app: &App) {
    let block = Block::default()
        .title(" Select USB Capture Speed ")
        .borders(Borders::ALL);

    let items: Vec<ListItem> = app.speed_options
        .iter()
        .enumerate()
        .map(|(i, speed)| {
            let selected = i == app.selected_speed_idx;
            let style = if selected {
                Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let prefix = if selected { "▶ " } else { "  " };
            ListItem::new(format!("{prefix}{speed}")).style(style)
        })
        .collect();

    f.render_widget(List::new(items).block(block), main);
    render_status(f, status, "↑↓ = select   Enter = connect   o = open pcap", "");
}

// ---------------------------------------------------------------------------
// Connecting
// ---------------------------------------------------------------------------

fn draw_connecting(f: &mut Frame, main: Rect, status: Rect, app: &App) {
    let block = Block::default()
        .title(" Connecting ")
        .borders(Borders::ALL);

    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "Opening device interface…",
            Style::default().fg(Color::Cyan),
        )),
    ];

    f.render_widget(
        Paragraph::new(text).block(block).alignment(Alignment::Center),
        main,
    );
    render_status(f, status, &app.status_message, "");
}

// ---------------------------------------------------------------------------
// Capture screen — tab strip + routed views
// ---------------------------------------------------------------------------

fn draw_capture(f: &mut Frame, main: Rect, status: Rect, app: &mut App) {
    // Split the main area: tab strip at top, content below.
    let [tabs_area, content_area] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
    ]).areas(main);

    draw_tabs(f, tabs_area, app);

    match app.active_view {
        ActiveView::Traffic => draw_traffic_view(f, content_area, app),
        ActiveView::Devices => draw_devices_view(f, content_area, app),
        ActiveView::Plugins => draw_plugins_view(f, content_area, app),
    }

    // If search mode is active, replace the status bar with a search input bar.
    if app.search_mode {
        render_search_bar(f, status, &app.search_input);
        return;
    }

    // Build status: left = capture state, right = key hints
    let state_str = if !app.search_query.is_empty() && !app.search_matches.is_empty() {
        let idx = app.search_match_idx.map(|i| i + 1).unwrap_or(0);
        let total = app.search_matches.len();
        format!("/{} [{}/{}]", app.search_query, idx, total)
    } else if !app.search_query.is_empty() && app.search_matches.is_empty() {
        format!("/{} [no matches]", app.search_query)
    } else if let Some(ref name) = app.load_label {
        format!("Loaded: {name}")
    } else if app.device_manager.is_saving() {
        let name = app.save_label.as_deref().unwrap_or("capture.pcap");
        format!("● REC {name}")
    } else {
        app.status_message.clone()
    };
    let hint = format!(
        "Tab=views  {}  o=open  j/k=↑↓  Ctrl+d/u=½pg  G/gg=last/first  {}  q=quit  txns={}  pkts={}",
        if app.load_label.is_some() { "/=search  n/p=next/prev" } else { "s=speed  Ctrl+S=save" },
        if app.load_label.is_none() { "h/l=←→" } else { "" },
        app.transaction_count(),
        app.packet_count(),
    );
    render_status(f, status, &state_str, &hint);
}

fn draw_tabs(f: &mut Frame, area: Rect, app: &App) {
    let active_style = Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD);
    let inactive_style = Style::default().fg(Color::DarkGray);

    let traffic_style = if app.active_view == ActiveView::Traffic { active_style } else { inactive_style };
    let devices_style = if app.active_view == ActiveView::Devices { active_style } else { inactive_style };
    let plugins_active = app.plugin_manager.active_count() > 0;
    let plugins_style = if app.active_view == ActiveView::Plugins {
        active_style
    } else if plugins_active {
        inactive_style.fg(Color::Yellow)
    } else {
        inactive_style
    };
    let plugins_label = if plugins_active {
        format!(" Plugins ({}) ", app.plugin_manager.active_count())
    } else {
        " Plugins ".to_string()
    };

    let tabs = Line::from(vec![
        Span::raw(" "),
        Span::styled(" Traffic ", traffic_style),
        Span::raw("  "),
        Span::styled(" Devices ", devices_style),
        Span::raw("  "),
        Span::styled(plugins_label, plugins_style),
        Span::raw("  "),
        Span::styled("Tab to switch", Style::default().fg(Color::DarkGray)),
    ]);

    f.render_widget(Paragraph::new(tabs), area);
}

// ---------------------------------------------------------------------------
// Traffic view  (left: tree,  right: details)
// ---------------------------------------------------------------------------

fn draw_traffic_view(f: &mut Frame, area: Rect, app: &mut App) {
    let [tree_area, detail_area] = Layout::horizontal([
        Constraint::Percentage(55),
        Constraint::Percentage(45),
    ]).areas(area);

    draw_packet_tree(f, tree_area, app);
    draw_packet_details(f, detail_area, app);
}

fn draw_packet_tree(f: &mut Frame, area: Rect, app: &mut App) {
    let block = Block::default()
        .title(" Transactions ")
        .borders(Borders::ALL);

    // Reserve 2 rows for border.
    let inner_height = area.height.saturating_sub(2) as usize;
    // Keep page_size in sync so keyboard nav uses the real visible height.
    app.page_size = inner_height;
    let rows = app.visible_rows(inner_height);

    let items: Vec<ListItem> = rows.iter().map(|(row, selected)| {
        // ── Timestamp prefix ──────────────────────────────────────────────
        // "3.066331633  " = 13 chars; shown for every row using that row's
        // own timestamp (child packets carry their individual arrival time).
        let secs  = row.timestamp_ns / 1_000_000_000;
        let frac  = row.timestamp_ns % 1_000_000_000;
        let ts_prefix = format!("{secs}.{frac:09}  ");

        // ── Tree connector ────────────────────────────────────────────────
        // Depth-0: "○──── ▶ " (collapsed) / "○──── ▼ " (expanded) / "○────   "
        // Depth-1: "  │○── "
        let connector = if row.depth == 0 {
            let arrow = if row.has_children {
                if row.is_expanded { "▼" } else { "▶" }
            } else { " " };
            format!("○──── {arrow} ")
        } else {
            "  │○── ".to_string()
        };

        let label = format!("{ts_prefix}{connector}{}", row.label);

        let base_color = if row.crc_error {
            Color::Red
        } else {
            App::kind_color(row.kind)
        };
        let style = if *selected {
            Style::default()
                .fg(Color::Black)
                .bg(base_color)
                .add_modifier(Modifier::BOLD)
        } else if row.depth == 0 {
            Style::default().fg(base_color)
        } else {
            Style::default().fg(base_color).add_modifier(Modifier::DIM)
        };

        ListItem::new(label).style(style)
    }).collect();

    f.render_widget(List::new(items).block(block), area);
}

fn draw_packet_details(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" Details ")
        .borders(Borders::ALL);

    let text: Vec<Line> = if let Some((label, details)) = app.selected_details() {
        let mut lines = vec![
            Line::from(Span::styled(label, Style::default().add_modifier(Modifier::BOLD))),
            Line::from(""),
        ];
        for part in details.split('\n') {
            lines.push(Line::from(part.to_owned()));
        }
        // Hex + ASCII dump of raw bytes.
        if let Some(bytes) = app.selected_raw_bytes() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("── Raw data ({} bytes) ──────────────────────", bytes.len()),
                Style::default().fg(Color::DarkGray),
            )));
            for dump_line in hex_ascii_dump(&bytes).split('\n') {
                let parts: Vec<&str> = dump_line.splitn(3, "  ").collect();
                match parts.as_slice() {
                    [offset, hex, ascii] => {
                        lines.push(Line::from(vec![
                            Span::styled(format!("{offset}  "), Style::default().fg(Color::DarkGray)),
                            Span::styled(format!("{hex}  "), Style::default().fg(Color::Cyan)),
                            Span::styled(ascii.to_string(), Style::default().fg(Color::Yellow)),
                        ]));
                    }
                    _ => lines.push(Line::from(dump_line.to_owned())),
                }
            }
        }
        lines
    } else {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "Select a transaction to view details.",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "↑↓ navigate   → expand   ← collapse",
                Style::default().fg(Color::DarkGray),
            )),
        ]
    };

    f.render_widget(
        Paragraph::new(text).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

// ---------------------------------------------------------------------------
// Devices view  (left: device list,  right: descriptor details)
// ---------------------------------------------------------------------------

fn draw_devices_view(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .title(" Discovered Devices  (l/Enter=expand  h=collapse  j/k=navigate) ")
        .borders(Borders::ALL);
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.usb_devices.is_empty() {
        f.render_widget(
            Paragraph::new("No devices captured yet.")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    let rows = device_tree_rows(&app.usb_devices, &app.device_expanded);
    let offset = app.device_scroll;
    let height = inner.height as usize;

    let items: Vec<ListItem> = rows
        .iter()
        .skip(offset)
        .take(height)
        .enumerate()
        .map(|(screen_i, row)| {
            let abs_i = offset + screen_i;
            let selected = abs_i == app.device_selected;
            let style = if selected {
                row.style.bg(Color::DarkGray).add_modifier(Modifier::BOLD)
            } else {
                row.style
            };
            ListItem::new(Line::from(Span::styled(row.text.clone(), style)))
        })
        .collect();

    f.render_widget(List::new(items), inner);
}

// ---------------------------------------------------------------------------
// Plugins view  (left: plugin list,  right: selected plugin content)
// ---------------------------------------------------------------------------

fn draw_plugins_view(f: &mut Frame, area: Rect, app: &mut App) {
    let plugins = app.plugin_manager.plugins();

    if plugins.is_empty() {
        let block = Block::default().title(" Plugins ").borders(Borders::ALL);
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "No plugins registered.",
                Style::default().fg(Color::DarkGray),
            ))).block(block),
            area,
        );
        return;
    }

    // Split into plugin list (left) + content pane (right).
    let [list_area, content_area] = Layout::horizontal([
        Constraint::Length(PLUGIN_LIST_WIDTH),
        Constraint::Min(1),
    ]).areas(area);

    // ── Plugin list ──────────────────────────────────────────────────────────
    let list_block = Block::default()
        .title(" Plugins ")
        .borders(Borders::ALL);

    let list_items: Vec<ListItem> = plugins.iter().enumerate().map(|(i, p)| {
        let selected = i == app.plugin_selected;
        let active   = p.is_active();
        let indicator = if active { "●" } else { "○" };
        let indicator_color = if active { Color::Green } else { Color::DarkGray };
        let name_color = if selected { Color::Black } else if active { Color::White } else { Color::DarkGray };
        let bg = if selected { Color::Cyan } else { Color::Reset };

        // Truncate name to fit the pane.
        let max_name = PLUGIN_LIST_WIDTH as usize - 5;
        let name: String = p.name().chars().take(max_name).collect();

        let line = Line::from(vec![
            Span::styled(format!(" {indicator} "), Style::default().fg(indicator_color).bg(bg)),
            Span::styled(name, Style::default().fg(name_color).bg(bg)
                .add_modifier(if selected { Modifier::BOLD } else { Modifier::empty() })),
        ]);
        ListItem::new(line)
    }).collect();

    f.render_widget(List::new(list_items).block(list_block), list_area);

    // ── Content pane ─────────────────────────────────────────────────────────
    let idx = app.plugin_selected.min(plugins.len() - 1);

    // Draw the outer border block and compute the inner area.
    let content_block = Block::default()
        .title(format!(" {} ", plugins[idx].name()))
        .borders(Borders::ALL);
    let inner = content_block.inner(content_area);
    f.render_widget(content_block, content_area);

    // Keep page_size in sync with visible height for Ctrl+d/u.
    app.page_size = inner.height as usize;

    // Ask the plugin to render itself.  If it returns false, fall back to the
    // standard scrollable-paragraph renderer.
    let scroll = app.plugin_scroll;
    if !plugins[idx].render_custom(f, inner, scroll) {
        let all_lines: Vec<Line> = plugins[idx]
            .render_lines()
            .into_iter()
            .map(|l| l.into_ratatui_line())
            .collect();

        let max_scroll = all_lines.len().saturating_sub(inner.height as usize);
        app.plugin_scroll = scroll.min(max_scroll);

        let visible: Vec<Line> = all_lines
            .into_iter()
            .skip(app.plugin_scroll)
            .take(inner.height as usize)
            .collect();

        f.render_widget(
            Paragraph::new(visible).wrap(Wrap { trim: false }),
            inner,
        );
    }
}

// ---------------------------------------------------------------------------
// Device tree row model
// ---------------------------------------------------------------------------

/// A single rendered row in the device tree.
pub struct DeviceTreeRow {
    pub indent: usize,
    /// Node key used for expand/collapse state (None = leaf / field).
    pub expand_key: Option<String>,
    pub text: String,
    pub style: Style,
}

/// Build the flat list of visible rows for the device tree, respecting
/// expansion state.
pub fn device_tree_rows(
    devices: &[UsbDeviceInfo],
    expanded: &HashMap<String, bool>,
) -> Vec<DeviceTreeRow> {
    let mut out = Vec::new();
    for dev in devices {
        emit_device(&mut out, dev, expanded);
    }
    out
}

fn is_expanded(expanded: &HashMap<String, bool>, key: &str) -> bool {
    *expanded.get(key).unwrap_or(&false)
}

fn bcd_str(v: u16) -> String {
    format!("{}.{:02}", v >> 8, v & 0xFF)
}

fn emit_device(out: &mut Vec<DeviceTreeRow>, dev: &UsbDeviceInfo, expanded: &HashMap<String, bool>) {
    let key = format!("d:{}", dev.address);
    let exp = is_expanded(expanded, &key);
    let icon = if exp { "▼" } else { "▶" };
    let name = dev.product.as_deref().unwrap_or("Unknown Device");
    let header = format!(
        "{icon} Device addr={:03}  {:04X}:{:04X}  \"{}\"",
        dev.address, dev.vendor_id, dev.product_id, name
    );
    out.push(DeviceTreeRow {
        indent: 0,
        expand_key: Some(key.clone()),
        text: header,
        style: Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
    });
    if !exp { return; }

    // ── Device Descriptor fields ──────────────────────────────────────────
    let desc_key = format!("{key}:desc");
    let desc_exp = is_expanded(expanded, &desc_key);
    let desc_icon = if desc_exp { "▼" } else { "▶" };
    out.push(DeviceTreeRow {
        indent: 1,
        expand_key: Some(desc_key.clone()),
        text: format!("  {desc_icon} Device Descriptor"),
        style: Style::default().fg(Color::Yellow),
    });
    if desc_exp {
        let fields = [
            ("bcdUSB",            bcd_str(dev.bcd_usb)),
            ("bDeviceClass",      format!("0x{:02X}  ({})", dev.class, dev.class_name())),
            ("bDeviceSubClass",   format!("0x{:02X}", dev.subclass)),
            ("bDeviceProtocol",   format!("0x{:02X}", dev.protocol)),
            ("bMaxPacketSize0",   format!("{}", dev.max_packet_size0)),
            ("idVendor",          format!("0x{:04X}", dev.vendor_id)),
            ("idProduct",         format!("0x{:04X}", dev.product_id)),
            ("bcdDevice",         bcd_str(dev.bcd_device)),
            ("iManufacturer",     dev.manufacturer.clone().unwrap_or_default()),
            ("iProduct",          dev.product.clone().unwrap_or_default()),
            ("iSerialNumber",     dev.serial.clone().unwrap_or_default()),
            ("bNumConfigurations",format!("{}", dev.num_configurations)),
        ];
        for (k, v) in &fields {
            if v.is_empty() { continue; }
            out.push(field_row(2, k, v));
        }
    }

    // ── Configurations ────────────────────────────────────────────────────
    for cfg in &dev.configurations {
        emit_config(out, &key, cfg, expanded);
    }
}

fn emit_config(out: &mut Vec<DeviceTreeRow>, dev_key: &str, cfg: &UsbConfigInfo, expanded: &HashMap<String, bool>) {
    let key = format!("{dev_key}:c:{}", cfg.configuration_value);
    let exp = is_expanded(expanded, &key);
    let icon = if exp { "▼" } else { "▶" };

    let mut attrs_str = String::new();
    if cfg.self_powered()  { attrs_str.push_str("Self-powered "); }
    if cfg.remote_wakeup() { attrs_str.push_str("Remote-wakeup "); }
    let attrs_str = attrs_str.trim();

    out.push(DeviceTreeRow {
        indent: 1,
        expand_key: Some(key.clone()),
        text: format!(
            "  {icon} Configuration {}  ({attrs_str}, {}mA, {} interface{})",
            cfg.configuration_value,
            cfg.max_power_ma(),
            cfg.num_interfaces,
            if cfg.num_interfaces == 1 { "" } else { "s" },
        ),
        style: Style::default().fg(Color::Cyan),
    });
    if !exp { return; }

    // Config descriptor fields.
    out.push(field_row(2, "bConfigurationValue", &format!("{}", cfg.configuration_value)));
    out.push(field_row(2, "bmAttributes",        &format!("0x{:02X}  ({attrs_str})", cfg.attributes)));
    out.push(field_row(2, "bMaxPower",           &format!("{}  ({}mA)", cfg.max_power, cfg.max_power_ma())));
    out.push(field_row(2, "bNumInterfaces",      &format!("{}", cfg.num_interfaces)));

    for iface in &cfg.interfaces {
        emit_interface(out, &key, iface, expanded);
    }
}

fn emit_interface(out: &mut Vec<DeviceTreeRow>, cfg_key: &str, iface: &UsbInterfaceInfo, expanded: &HashMap<String, bool>) {
    let key = format!("{cfg_key}:i:{}:{}", iface.interface_number, iface.alternate_setting);
    let exp = is_expanded(expanded, &key);
    let icon = if exp { "▼" } else { "▶" };

    let alt_str = if iface.alternate_setting > 0 {
        format!(" alt={}", iface.alternate_setting)
    } else {
        String::new()
    };

    out.push(DeviceTreeRow {
        indent: 2,
        expand_key: Some(key.clone()),
        text: format!(
            "    {icon} Interface {}{}  ({})  {} endpoint{}",
            iface.interface_number,
            alt_str,
            iface.class_name(),
            iface.num_endpoints,
            if iface.num_endpoints == 1 { "" } else { "s" },
        ),
        style: Style::default().fg(Color::Magenta),
    });
    if !exp { return; }

    // Interface descriptor fields.
    out.push(field_row(3, "bInterfaceNumber",   &format!("{}", iface.interface_number)));
    out.push(field_row(3, "bAlternateSetting",  &format!("{}", iface.alternate_setting)));
    out.push(field_row(3, "bNumEndpoints",      &format!("{}", iface.num_endpoints)));
    out.push(field_row(3, "bInterfaceClass",    &format!("0x{:02X}  ({})", iface.class, iface.class_name())));
    out.push(field_row(3, "bInterfaceSubClass", &format!("0x{:02X}", iface.subclass)));
    out.push(field_row(3, "bInterfaceProtocol", &format!("0x{:02X}", iface.protocol)));

    for ep in &iface.endpoints {
        emit_endpoint(out, &key, ep, expanded);
    }
}

fn emit_endpoint(out: &mut Vec<DeviceTreeRow>, if_key: &str, ep: &UsbEndpointInfo, expanded: &HashMap<String, bool>) {
    let key = format!("{if_key}:e:0x{:02X}", ep.address);
    let exp = is_expanded(expanded, &key);
    let icon = if exp { "▼" } else { "▶" };

    out.push(DeviceTreeRow {
        indent: 3,
        expand_key: Some(key.clone()),
        text: format!(
            "      {icon} Endpoint 0x{:02X}  ({} {}  {}B  interval={})",
            ep.address, ep.transfer_type(), ep.direction(),
            ep.max_packet_size, ep.interval,
        ),
        style: Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
    });
    if !exp { return; }

    let ep_num = ep.ep_number();
    out.push(field_row(4, "bEndpointAddress",
        &format!("0x{:02X}  (EP {} {})", ep.address, ep_num, ep.direction())));
    out.push(field_row(4, "bmAttributes",
        &format!("0x{:02X}  ({})", ep.attributes, ep.transfer_type())));
    out.push(field_row(4, "wMaxPacketSize",
        &format!("{}", ep.max_packet_size)));
    out.push(field_row(4, "bInterval",
        &format!("{}", ep.interval)));
}

fn field_row(indent: usize, key: &str, value: &str) -> DeviceTreeRow {
    let prefix = "  ".repeat(indent + 1);
    DeviceTreeRow {
        indent,
        expand_key: None,
        text: format!("{prefix}{:<22}{}", format!("{key}:"), value),
        style: Style::default().fg(Color::Gray),
    }
}

// ---------------------------------------------------------------------------
// Error screen
// ---------------------------------------------------------------------------

fn draw_error(f: &mut Frame, main: Rect, status: Rect, app: &App) {
    let block = Block::default()
        .title(" Error ")
        .borders(Borders::ALL)
        .style(Style::default().fg(Color::Red));

    let msg = app.error_message.as_deref().unwrap_or("An unknown error occurred.");
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(msg, Style::default().fg(Color::Red))),
        Line::from(""),
        Line::from(Span::styled(
            "Press Enter to return to device selection.",
            Style::default().fg(Color::Gray),
        )),
    ];

    f.render_widget(
        Paragraph::new(text).block(block).alignment(Alignment::Center),
        main,
    );
    render_status(f, status, "Error", "Enter = retry");
}

// ---------------------------------------------------------------------------
// Load-file dialog
// ---------------------------------------------------------------------------

fn draw_load_file(f: &mut Frame, _main: Rect, status: Rect, app: &mut App) {
    if let Some(explorer) = app.file_explorer.as_mut() {
        tui_file_explorer::render(explorer, f, f.area());
    }
    render_status(f, status, "Open a saved capture file (.pcap)", "Esc / q = cancel   Enter / l = open");
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn render_search_bar(f: &mut Frame, area: Rect, input: &str) {
    let line = Line::from(vec![
        Span::styled("/", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Span::styled(input, Style::default().fg(Color::White)),
        Span::styled("█", Style::default().fg(Color::White)),
    ]);
    f.render_widget(
        Paragraph::new(line).style(Style::default().bg(Color::Reset)),
        area,
    );
}

fn render_status(f: &mut Frame, area: Rect, left: &str, right: &str) {
    let line = if right.is_empty() {
        Line::from(Span::styled(left, Style::default().fg(Color::Gray)))
    } else {
        let total = area.width as usize;
        // Use char counts for display-width comparisons (arrows are 1 display column each).
        let left_chars: usize = left.chars().count();
        let right_chars: usize = right.chars().count();
        let left_truncated = if left_chars + right_chars + 2 > total {
            let keep_chars = total.saturating_sub(right_chars + 3);
            // Convert char count back to a safe byte boundary.
            let byte_end = left
                .char_indices()
                .nth(keep_chars)
                .map(|(i, _)| i)
                .unwrap_or(left.len());
            &left[..byte_end]
        } else {
            left
        };
        let left_display = left_truncated.chars().count();
        let padding = total.saturating_sub(left_display + right_chars);
        Line::from(vec![
            Span::styled(left_truncated, Style::default().fg(Color::Gray)),
            Span::raw(" ".repeat(padding)),
            Span::styled(right, Style::default().fg(Color::DarkGray)),
        ])
    };

    f.render_widget(
        Paragraph::new(line).style(Style::default().bg(Color::Reset)),
        area,
    );
}

// Silence unused import warning – TransactionKind is used via App::kind_color.
const _: fn() = || { let _ = TransactionKind::Other; };

// ---------------------------------------------------------------------------
// Help popup
// ---------------------------------------------------------------------------

fn centered_rect(width: u16, height: u16, r: Rect) -> Rect {
    let x = r.x + r.width.saturating_sub(width) / 2;
    let y = r.y + r.height.saturating_sub(height) / 2;
    Rect::new(x, y, width.min(r.width), height.min(r.height))
}

fn draw_help_popup(f: &mut Frame, app: &App) {
    let lines = help_lines(app);

    const KEY_W: usize = 16;
    const DESC_W: usize = 40;
    const POPUP_W: u16  = (KEY_W + DESC_W + 4) as u16;  // +4 for borders + padding

    let popup_h = (lines.len() as u16 + 2).min(f.area().height.saturating_sub(2));
    let area = centered_rect(POPUP_W, popup_h, f.area());

    f.render_widget(Clear, area);

    let block = Block::default()
        .title(" Help  (? or Esc to close) ")
        .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Scroll if content taller than inner area.
    let visible: Vec<Line> = lines
        .into_iter()
        .take(inner.height as usize)
        .collect();

    f.render_widget(Paragraph::new(visible), inner);
}

/// Build the context-sensitive list of help lines.
fn help_lines(app: &App) -> Vec<Line<'static>> {
    use crate::app::AppState;

    let mut out: Vec<Line<'static>> = Vec::new();

    macro_rules! header {
        ($t:expr) => {
            out.push(Line::from(Span::styled(
                $t,
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )));
        };
    }
    macro_rules! entry {
        ($k:expr, $d:expr) => {
            out.push(Line::from(vec![
                Span::styled(
                    format!("  {:<width$}", $k, width = 14),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled($d, Style::default().fg(Color::White)),
            ]));
        };
    }
    macro_rules! blank { () => { out.push(Line::from("")); }; }

    // ── Global ───────────────────────────────────────────────────────────────
    header!(" Global");
    entry!("?",          "Toggle this help");
    entry!("q / Esc",    "Quit");
    entry!("Ctrl+C",     "Force quit");
    entry!("Tab",        "Cycle views (Traffic / Devices / Plugins)");
    entry!("o",          "Open a saved .pcap file");

    match app.state {
        AppState::WaitingForDevice | AppState::Connecting => {
            // Nothing extra; global keys are enough.
        }

        AppState::SpeedSelection => {
            blank!();
            header!(" Speed Selection");
            entry!("↑ / ↓",     "Move selection");
            entry!("Enter",      "Confirm speed and connect");
            entry!("o",          "Open a pcap file (no capture)");
        }

        AppState::Capturing => {
            match app.active_view {
                crate::app::ActiveView::Traffic => {
                    blank!();
                    header!(" Traffic View");
                    entry!("↑ k / ↓ j",  "Move cursor up / down");
                    entry!("→ l / ← h",  "Expand / collapse transaction");
                    entry!("Enter",       "Toggle expand / collapse");
                    entry!("Ctrl+d / u",  "Scroll ½ page down / up");
                    entry!("PgDn / PgUp", "Scroll full page down / up");
                    entry!("G",           "Jump to last");
                    entry!("gg",          "Jump to first");
                    if app.load_label.is_some() {
                        entry!("/",       "Open search");
                        entry!("n / p",   "Next / previous match");
                    } else {
                        entry!("s",       "Change capture speed");
                        entry!("v",       "Toggle VBUS (TARGET-C)");
                        entry!("Ctrl+S",  "Start / stop saving to .pcap");
                    }
                }

                crate::app::ActiveView::Devices => {
                    blank!();
                    header!(" Devices View");
                    entry!("↑ k / ↓ j",  "Move cursor up / down");
                    entry!("→ l",         "Expand node");
                    entry!("← h",         "Collapse node / go to parent");
                    entry!("Enter",        "Toggle expand / collapse");
                    entry!("Ctrl+d / u",  "Scroll ½ page down / up");
                    entry!("G",           "Jump to last");
                    entry!("gg",          "Jump to first");
                }

                crate::app::ActiveView::Plugins => {
                    blank!();
                    header!(" Plugins View");
                    entry!("↑ k / ↓ j",  "Select previous / next plugin");
                    entry!("Ctrl+d / u",  "Scroll content ½ page");
                    entry!("PgDn / PgUp", "Scroll content full page");
                    entry!("G",           "Scroll to bottom");
                    entry!("gg",          "Scroll to top");

                    // Plugin-specific keys
                    let plugins = app.plugin_manager.plugins();
                    if !plugins.is_empty() {
                        let idx = app.plugin_selected.min(plugins.len() - 1);
                        let plugin_help = plugins[idx].help_keys();
                        if !plugin_help.is_empty() {
                            blank!();
                            let name = plugins[idx].name();
                            out.push(Line::from(Span::styled(
                                format!(" {name} Plugin"),
                                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                            )));
                            for (k, d) in plugin_help {
                                out.push(Line::from(vec![
                                    Span::styled(
                                        format!("  {:<14}", k),
                                        Style::default().fg(Color::Cyan),
                                    ),
                                    Span::styled(d, Style::default().fg(Color::White)),
                                ]));
                            }
                        }
                    }
                }
            }
        }

        AppState::Error => {
            blank!();
            header!(" Error");
            entry!("Enter", "Return to device selection");
        }

        AppState::LoadFile => {
            blank!();
            header!(" File Browser");
            entry!("↑ / ↓",  "Navigate files");
            entry!("Enter / l", "Open selected file");
            entry!("Esc",    "Cancel");
        }
    }

    out
}

