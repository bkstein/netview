use std::{io, time::{Duration, Instant}};
use crossterm::{
    event::{Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, get_sockets_info};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table},
};
use sysinfo::System;
use tokio::time;

use crate::app::App;

pub mod app;
pub mod event;
pub mod ui;

struct AppState {
    /// Current connection entries
    entries: Vec<ConnectionEntry>,
    /// Vertical scroll position
    scroll: usize,
    /// true, if table updates are suspended
    paused: bool,
    /// The column used to sort table lines
    sort_column: SortColumn,
    /// Sort ascending or descending
    sort_order: SortOrder,
    /// The visible height of the table
    visible_height: usize,
}

impl AppState {
    fn new() -> Self {
        Self {
            entries: vec![],
            scroll: 0,
            paused: false,
            sort_column: SortColumn::LocalPort,
            sort_order: SortOrder::Asc,
            visible_height: 0,
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum SortColumn {
    Proto,
    LocalIP,
    LocalPort,
    RemoteIP,
    RemotePort,
    State,
    PID,
    Process,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum SortOrder {
    Asc,
    Desc,
}

#[derive(Clone)]
struct ConnectionEntry {
    proto: String,
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    state: String,
    pid: u32,
    process: String,
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    crossterm::terminal::enable_raw_mode()?;
    let terminal = ratatui::init();
    let result = App::new().run(terminal).await;
    ratatui::restore();
    result
}

//#[tokio::main]
async fn main2() -> color_eyre::Result<()> {
     color_eyre::install()?;
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let update_interval = Duration::from_secs(1);
    let mut last_update = Instant::now();

    let mut last_entries = vec![];

    let mut app = AppState::new();

    loop {
        terminal.draw(|f| {
            let size = f.area();
            let table_height = size.height as usize;

            app.visible_height = table_height.saturating_sub(2);

            if !app.paused && last_update.elapsed() >= update_interval {
                app.entries = get_connection_entries();
                sort_entries(&mut app.entries, app.sort_column, app.sort_order);
                last_entries = app.entries.clone();
                last_update = Instant::now();
            } else {
                sort_entries(&mut last_entries, app.sort_column, app.sort_order);
            }

            let rows = entries_to_rows(&last_entries, app.sort_column);
            let header = render_header(app.sort_column, app.sort_order);

            let connections_title = if app.paused {
                "Connections (paused - press 'SPACE' to resume)"
            } else {
                "Connections (live - press 'SPACE' to pause)"
            };
            let rows_to_show = &rows[app.scroll..(app.scroll + app.visible_height).min(rows.len())];
            let table = Table::new(
                rows_to_show.iter().cloned(),
                [
                    Constraint::Length(7),  // Proto
                    Constraint::Length(40), // Local IP
                    Constraint::Length(7),  // Local Port
                    Constraint::Length(40), // Remote IP
                    Constraint::Length(7),  // Remote Port
                    Constraint::Length(12), // State
                    Constraint::Length(7),  // PID
                    Constraint::Length(20), // Process
                ],
            )
            .header(header)
            .block(
                Block::default()
                    .title(connections_title)
                    .borders(Borders::ALL),
            );

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1)].as_ref())
                .split(size);

            f.render_widget(table, chunks[0]);
        })?;

        if crossterm::event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = crossterm::event::read()? {
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char(' ') => app.paused = !app.paused,
                    KeyCode::Down | KeyCode::Char('j') => {
                        if app.scroll + 1 < app.entries.len().saturating_sub(app.visible_height) {
                            app.scroll += 1;
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if app.scroll > 0 {
                            app.scroll -= 1;
                        }
                    }
                    KeyCode::PageDown => {
                        app.scroll = (app.scroll + app.visible_height)
                            .min(app.entries.len().saturating_sub(app.visible_height));
                    }
                    KeyCode::PageUp => {
                        app.scroll = app.scroll.saturating_sub(app.visible_height);
                    }
                    KeyCode::Char('1') => {
                        toggle_sort(&mut app.sort_column, &mut app.sort_order, SortColumn::Proto)
                    }
                    KeyCode::Char('2') => toggle_sort(
                        &mut app.sort_column,
                        &mut app.sort_order,
                        SortColumn::LocalIP,
                    ),
                    KeyCode::Char('3') => toggle_sort(
                        &mut app.sort_column,
                        &mut app.sort_order,
                        SortColumn::LocalPort,
                    ),
                    KeyCode::Char('4') => toggle_sort(
                        &mut app.sort_column,
                        &mut app.sort_order,
                        SortColumn::RemoteIP,
                    ),
                    KeyCode::Char('5') => toggle_sort(
                        &mut app.sort_column,
                        &mut app.sort_order,
                        SortColumn::RemotePort,
                    ),
                    KeyCode::Char('6') => {
                        toggle_sort(&mut app.sort_column, &mut app.sort_order, SortColumn::State)
                    }
                    KeyCode::Char('7') => {
                        toggle_sort(&mut app.sort_column, &mut app.sort_order, SortColumn::PID)
                    }
                    KeyCode::Char('8') => toggle_sort(
                        &mut app.sort_column,
                        &mut app.sort_order,
                        SortColumn::Process,
                    ),
                    _ => {}
                }
            }
        }
        time::interval(update_interval).tick().await;
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn get_connection_entries() -> Vec<ConnectionEntry> {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let mut sys = System::new_all();
    sys.refresh_processes();

    let mut entries = vec![];

    if let Ok(sockets) = get_sockets_info(af_flags, proto_flags) {
        for conn in sockets {
            let pid = conn.associated_pids.first().copied().unwrap_or(0);
            let proc_name = sys
                .process(sysinfo::Pid::from_u32(pid))
                .map(|p| p.name().to_string())
                .unwrap_or_default();

            match conn.protocol_socket_info {
                ProtocolSocketInfo::Tcp(tcp) => {
                    entries.push(ConnectionEntry {
                        proto: "TCP".into(),
                        local_ip: tcp.local_addr.to_string(),
                        local_port: tcp.local_port,
                        remote_ip: tcp.remote_addr.to_string(),
                        remote_port: tcp.remote_port,
                        state: format!("{:?}", tcp.state),
                        pid,
                        process: proc_name,
                    });
                }
                ProtocolSocketInfo::Udp(udp) => {
                    entries.push(ConnectionEntry {
                        proto: "UDP".into(),
                        local_ip: udp.local_addr.to_string(),
                        local_port: udp.local_port,
                        remote_ip: "".into(),
                        remote_port: 0,
                        state: "".into(),
                        pid,
                        process: proc_name,
                    });
                }
            }
        }
    }

    entries
}

fn sort_entries(entries: &mut Vec<ConnectionEntry>, column: SortColumn, order: SortOrder) {
    entries.sort_by(|a, b| {
        use SortColumn::*;
        let ord = match column {
            Proto => a.proto.cmp(&b.proto),
            LocalIP => a.local_ip.cmp(&b.local_ip),
            LocalPort => a.local_port.cmp(&b.local_port),
            RemoteIP => a.remote_ip.cmp(&b.remote_ip),
            RemotePort => a.remote_port.cmp(&b.remote_port),
            State => a.state.cmp(&b.state),
            PID => a.pid.cmp(&b.pid),
            Process => a.process.cmp(&b.process),
        };
        if order == SortOrder::Asc {
            ord
        } else {
            ord.reverse()
        }
    });
}

fn entries_to_rows(entries: &[ConnectionEntry], sort_column: SortColumn) -> Vec<Row<'_>> {
    entries
        .iter()
        .map(|e| {
            let highlight_style = Style::default().fg(Color::Green);
            let normal = Style::default();

            let cells = vec![
                Cell::from(e.proto.clone()).style(if sort_column == SortColumn::Proto {
                    highlight_style
                } else {
                    normal
                }),
                Cell::from(e.local_ip.clone()).style(if sort_column == SortColumn::LocalIP {
                    highlight_style
                } else {
                    normal
                }),
                Cell::from(e.local_port.to_string()).style(
                    if sort_column == SortColumn::LocalPort {
                        highlight_style
                    } else {
                        normal
                    },
                ),
                Cell::from(e.remote_ip.clone()).style(if sort_column == SortColumn::RemoteIP {
                    highlight_style
                } else {
                    normal
                }),
                Cell::from(if e.remote_port != 0 {
                    e.remote_port.to_string()
                } else {
                    "".to_string()
                })
                .style(if sort_column == SortColumn::RemotePort {
                    highlight_style
                } else {
                    normal
                }),
                Cell::from(e.state.clone()).style(if sort_column == SortColumn::State {
                    highlight_style
                } else {
                    normal
                }),
                Cell::from(e.pid.to_string()).style(if sort_column == SortColumn::PID {
                    highlight_style
                } else {
                    normal
                }),
                Cell::from(e.process.clone()).style(if sort_column == SortColumn::Process {
                    highlight_style
                } else {
                    normal
                }),
            ];

            Row::new(cells)
        })
        .collect()
}

fn toggle_sort(current_col: &mut SortColumn, current_order: &mut SortOrder, selected: SortColumn) {
    if *current_col == selected {
        *current_order = match *current_order {
            SortOrder::Asc => SortOrder::Desc,
            SortOrder::Desc => SortOrder::Asc,
        };
    } else {
        *current_col = selected;
        *current_order = SortOrder::Asc;
    }
}

fn render_header(sort_col: SortColumn, sort_order: SortOrder) -> Row<'static> {
    use SortColumn::*;

    let arrow = match sort_order {
        SortOrder::Asc => " ↑",
        SortOrder::Desc => " ↓",
    };

    let header_cells = vec![
        ("Prot", Proto),
        ("Local IP", LocalIP),
        ("LPort", LocalPort),
        ("Remote IP", RemoteIP),
        ("RPort", RemotePort),
        ("State", State),
        ("PID", PID),
        ("Process", Process),
    ]
    .into_iter()
    .map(|(label, col)| {
        let text = if col == sort_col {
            format!("{label}{arrow}")
        } else {
            label.to_string()
        };
        Cell::from(text).style(Style::default().add_modifier(Modifier::BOLD))
    })
    .collect::<Vec<_>>();

    Row::new(header_cells)
}
