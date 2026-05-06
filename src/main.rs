use std::time::Duration;

use crate::app::App;

pub mod app;
pub mod event;
pub mod ui;

/// Drain any keys already in the terminal input buffer (e.g. Enter from starting the app in
/// PowerShell). Prevents the first key from opening process info or other views on Windows.
fn drain_pending_input() {
    while crossterm::event::poll(Duration::from_millis(1)).unwrap_or(false) {
        let _ = crossterm::event::read();
    }
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    crossterm::terminal::enable_raw_mode()?;
    drain_pending_input();
    let terminal = ratatui::init();
    let result = App::new().run(terminal).await;
    crossterm::terminal::disable_raw_mode()?;
    ratatui::restore();
    result
}
