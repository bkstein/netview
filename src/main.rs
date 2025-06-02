use pprof::ProfilerGuard;

use crate::app::App;

pub mod app;
pub mod event;
pub mod ui;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    let guard = if std::env::var("NETVIEW_PROFILE").is_ok() {
        Some(ProfilerGuard::new(100).unwrap()) // 100 Hz sampling
    } else {
        None
    };

    color_eyre::install()?;
    crossterm::terminal::enable_raw_mode()?;
    let terminal = ratatui::init();
    let result = App::new().run(terminal).await;
    crossterm::terminal::disable_raw_mode()?;
    ratatui::restore();

    if let Some(guard) = guard {
        if let Ok(report) = guard.report().build() {
            let file = std::fs::File::create("flamegraph.svg").unwrap();
            report.flamegraph(file).unwrap();
            println!("Flamegraph written to flamegraph.svg");
        } else {
            println!("Failed to build pprof report");
        }
    }
    result
}
