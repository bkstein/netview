use chrono::DateTime;
use humantime::format_duration;
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, Widget},
};
use std::{time::Duration};
use sysinfo::{Pid, ProcessesToUpdate, ProcessRefreshKind};

use crate::app::{App, SortColumn, SortOrder};

impl Widget for &App {
    /// Renders the user interface widgets.
    fn render(self, area: Rect, buf: &mut Buffer) {
        match self.ui_state {
            crate::app::UiState::ConnectionTable => self.render_connection_table(area, buf),
            crate::app::UiState::Help => self.render_connection_table(area, buf),
            crate::app::UiState::ProcessInfo => self.render_process_info(area, buf),
        }
    }
}

impl App {
    fn entries_to_rows(&self) -> Vec<Row<'_>> {
        self.entries
            .iter()
            .map(|e| {
                let sorted_column_style = Style::default().fg(Color::Green);
                let selected_row_style = Style::default().add_modifier(Modifier::REVERSED);
                let normal = Style::default();

                let cells = vec![
                    Cell::from(e.proto.clone()).style(if Some(e) == self.selected.as_ref() {
                        selected_row_style
                    } else if self.sort_column == SortColumn::Proto {
                        sorted_column_style
                    } else {
                        normal
                    }),
                    Cell::from(e.local_ip.clone()).style(if Some(e) == self.selected.as_ref() {
                        selected_row_style
                    } else if self.sort_column == SortColumn::LocalIP {
                        sorted_column_style
                    } else {
                        normal
                    }),
                    Cell::from(e.local_port.to_string()).style(
                        if Some(e) == self.selected.as_ref() {
                            selected_row_style
                        } else if self.sort_column == SortColumn::LocalPort {
                            sorted_column_style
                        } else {
                            normal
                        },
                    ),
                    Cell::from(e.remote_ip.clone()).style(if Some(e) == self.selected.as_ref() {
                        selected_row_style
                    } else if self.sort_column == SortColumn::RemoteIP {
                        sorted_column_style
                    } else {
                        normal
                    }),
                    Cell::from(if e.remote_port != 0 {
                        e.remote_port.to_string()
                    } else {
                        "".to_string()
                    })
                    .style(if Some(e) == self.selected.as_ref() {
                        selected_row_style
                    } else if self.sort_column == SortColumn::RemotePort {
                        sorted_column_style
                    } else {
                        normal
                    }),
                    Cell::from(e.state.clone()).style(if Some(e) == self.selected.as_ref() {
                        selected_row_style
                    } else if self.sort_column == SortColumn::State {
                        sorted_column_style
                    } else {
                        normal
                    }),
                    Cell::from(e.pid.to_string()).style(if Some(e) == self.selected.as_ref() {
                        selected_row_style
                    } else if self.sort_column == SortColumn::PID {
                        sorted_column_style
                    } else {
                        normal
                    }),
                    Cell::from(e.process.clone()).style(if Some(e) == self.selected.as_ref() {
                        selected_row_style
                    } else if self.sort_column == SortColumn::Process {
                        sorted_column_style
                    } else {
                        normal
                    }),
                ];
                Row::new(cells)
            })
            .collect()
    }

    fn render_connection_table(&self, area: Rect, buf: &mut Buffer) {
        let table_height = area.height as usize;

        let visible_height = table_height.saturating_sub(2);

        let rows = self.entries_to_rows();
        let header = render_header(self.sort_column, self.sort_order);

        let connections_title = if self.paused {
            "Connections (paused - press 'SPACE' to resume)"
        } else {
            "Connections (live - press 'SPACE' to pause)"
        };

        if let Some(index) = self.selected_index {
            if self.scroll.get() > index {
                self.scroll.set(index);
            } else if self.scroll.get() + (visible_height - 1) <= index {
                self.scroll.set(index - (visible_height - 1) + 1);
            }
        };
        let rows_to_show =
            &rows[self.scroll.get()..(self.scroll.get() + visible_height).min(rows.len())];
        let table = Table::new(
            rows_to_show.iter().cloned(),
            [
                Constraint::Length(7),  // Proto
                Constraint::Length(40), // Local IP
                Constraint::Length(5),  // Local Port
                Constraint::Length(40), // Remote IP
                Constraint::Length(5),  // Remote Port
                Constraint::Length(11), // State
                Constraint::Length(7),  // PID
                Constraint::Length(25), // Process
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title(connections_title)
                .borders(Borders::ALL),
        );

        table.render(area, buf);
    }

    fn render_process_info(&self, area: Rect, buf: &mut Buffer) {
        if let Some(selection) = &self.selected {
            let rows = process_info_to_rows(Pid::from_u32(selection.pid));

            let title = "Process Info";

            let table = Table::new(
                rows.iter().cloned(),
                [
                    Constraint::Length(15),  // Process property
                    Constraint::Length(100), // Value
                ],
            )
            .block(Block::default().title(title).borders(Borders::ALL));

            table.render(area, buf);
        }
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

fn process_info_to_rows(pid: Pid) -> Vec<Row<'static>> {
    let mut system = sysinfo::System::new_all();
    // Wait a bit because CPU usage is based on diff.
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    // Refresh CPU usage to get actual value.
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_cpu()
    );

    let normal = Style::default();
    if let Some(process) = system.process(pid) {
        let process_name = process.name().to_string_lossy().to_string();
        let pid_u32 = pid.as_u32();
        let cmdline = process.cmd()
        .iter()
        .map(|s| s.to_string_lossy())  // Cow<str>
        .collect::<Vec<_>>()
        .join(" ");
        let path = process
            .exe()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or("path not available".to_string());
        let cwd = process
            .cwd()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or("cwd not available".to_string());
        let mem = bytesize::ByteSize::b(process.memory()).to_string();
        let vmem = bytesize::ByteSize::b(process.virtual_memory()).to_string();

        let epoch_seconds = process.start_time();
        let started = DateTime::from_timestamp(epoch_seconds as i64, 0)
            .unwrap_or_default()
            .to_string();
        let run_time = format_duration(Duration::from_secs(process.run_time())).to_string();

        let cpu_usage = format!("{:.2} %", process.cpu_usage());

        let mut process_info = vec![
            ("Name:", process_name),
            ("Pid:", pid_u32.to_string()),
            ("Path:", path),
            ("Command line:", cmdline),
            ("Working dir:", cwd),
            ("Memory:", mem),
            ("Virtual memory:", vmem),
            ("Started:", started),
            ("Run time:", run_time),
            ("CPU %:", cpu_usage),
        ];
        for env in process.environ() {
            process_info.push(("env", env.to_string_lossy().to_string()));
        }

        process_info
            .iter()
            .map(|e| {
                let cells = vec![
                    Cell::from(e.0.to_string()).style(normal),
                    Cell::from(e.1.clone()).style(normal),
                ];
                Row::new(cells)
            })
            .collect()
    } else {
        vec![Row::new(vec![
            Cell::from("Process".to_string()).style(normal),
            Cell::from("not available".to_string()).style(normal),
        ])]
    }
}
