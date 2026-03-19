mod app;
mod ui;
mod backend;
mod models;
mod pcap;
mod plugins;

use anyhow::Result;
use app::App;
use crossterm::{
    event,
    execute,
    terminal::{enable_raw_mode, disable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};
use std::io;
use std::sync::{Arc, Mutex};
use std::fs::OpenOptions;

// ---------------------------------------------------------------------------
// File-based logger that bypasses stdout/stderr (safe to use inside TUI)
// ---------------------------------------------------------------------------

static LOG_FILE: std::sync::OnceLock<Arc<Mutex<std::fs::File>>> = std::sync::OnceLock::new();

macro_rules! dbg_log {
    ($($arg:tt)*) => {
        if let Some(f) = crate::LOG_FILE.get() {
            if let Ok(mut guard) = f.lock() {
                use std::io::Write as _;
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis();
                let file: &mut std::fs::File = &mut *guard;
                let _ = writeln!(file, "[{ts}] {}", format_args!($($arg)*));
                let _ = file.flush();
            }
        }
    };
}
pub(crate) use dbg_log;

fn init_log() {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("packetry-term.log")
        .expect("Cannot open log file");
    LOG_FILE.get_or_init(|| Arc::new(Mutex::new(file)));
    dbg_log!("=== packetry-term started ===");
}

/// RAII guard: restores the terminal when dropped, even through `resume_unwind`.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Restore the terminal to a sane state.  Safe to call multiple times.
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
}

// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    init_log();

    // Install a panic hook that restores the terminal BEFORE printing the
    // panic message, so escape codes are never shown as raw text.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        dbg_log!("PANIC: {info}");
        restore_terminal();
        eprintln!();
        original_hook(info);
    }));

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    dbg_log!("terminal: raw mode + alternate screen enabled");

    // RAII guard: restores terminal even on panic (including resume_unwind panics).
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new().await?;

    // If --load <path> was given, start replaying that file immediately.
    let load_path: Option<std::path::PathBuf> = {
        let args: Vec<String> = std::env::args().collect();
        let pos = args.iter().position(|a| a == "--load");
        pos.and_then(|i| args.get(i + 1)).map(std::path::PathBuf::from)
    };
    if let Some(path) = load_path {
        app.start_load(path).await?;
    }

    let result = run_app(&mut terminal, &mut app).await;

    // _guard drops here, restoring the terminal.
    drop(_guard);
    let _ = terminal.show_cursor();

    dbg_log!("terminal restored");

    if let Err(ref err) = result {
        dbg_log!("run_app error: {err}");
        eprintln!("Application error: {err}");
        std::process::exit(1);
    }

    Ok(())
}

async fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()>
where
    B::Error: Send + Sync + 'static, <B as Backend>::Error: 'static
{
    loop {
        terminal.draw(|f| ui::draw(f, app))?;

        // Drain ALL pending input events each tick to avoid stale queue build-up.
        while crossterm::event::poll(std::time::Duration::from_millis(0))? {
            match event::read()? {
                event::Event::Key(key) => {
                    if app.handle_input(key) {
                        dbg_log!("quit requested by user");
                        return Ok(());
                    }
                }
                event::Event::Resize(w, h) => {
                    dbg_log!("terminal resize: {w}×{h}");
                    // ratatui's draw() calls autoresize() internally; just drain the event.
                }
                // Mouse / focus events — discard.
                _ => {}
            }
        }

        // Sleep briefly so we don't busy-spin.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        app.update().await?;
    }
}
