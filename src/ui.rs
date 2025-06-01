use chrono::DateTime;
use humantime::format_duration;
use ratatui::{
    buffer::Buffer,
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, Cell, Row, Table, Widget},
};
use std::time::Duration;
use sysinfo::Pid;

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
        let visible_table_height = table_height.saturating_sub(2);
        self.visible_table_height.set(visible_table_height);

        let rows = self.entries_to_rows();
        let header = render_connections_header(self.sort_column, self.sort_order);

        let connections_title = if self.paused {
            "Connections (paused - press 'SPACE' to resume)"
        } else {
            "Connections (live - press 'SPACE' to pause)"
        };

        if let Some(index) = self.selected_index {
            if self.scroll_connection_table.get() > index {
                self.scroll_connection_table.set(index);
            } else if self.scroll_connection_table.get() + (visible_table_height - 1) <= index {
                self.scroll_connection_table
                    .set(index - (visible_table_height - 1) + 1);
            }
        };
        let rows_to_show = &rows[self.scroll_connection_table.get()
            ..(self.scroll_connection_table.get() + visible_table_height).min(rows.len())];
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
        let table_height = area.height as usize;
        self.visible_table_height
            .set(table_height.saturating_sub(1));
        let visible_table_width = area.width.saturating_sub(2);

        if let Some(selection) = &self.selected {
            let rows = process_info_to_rows(Pid::from_u32(selection.pid));
            self.process_info_list_length.set(rows.len());

            let title = "Process Info";

            let scroll_position = self.scroll_process_info.get().min(rows.len() - 1);

            let rows_to_show = &rows[scroll_position
                ..(scroll_position + self.visible_table_height.get()).min(rows.len())];

            let column_width_property = 15;
            let column_width_value = visible_table_width.saturating_sub(column_width_property + 1);

            let table = Table::new(
                rows_to_show.iter().cloned(),
                [
                    Constraint::Length(column_width_property),  // Process property
                    Constraint::Length(column_width_value), // Value
                ],
            )
            .block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_type(BorderType::Double),
            );

            table.render(area, buf);
        }
    }
}

fn render_connections_header(sort_col: SortColumn, sort_order: SortOrder) -> Row<'static> {
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
    let system = sysinfo::System::new_all();
    let users = sysinfo::Users::new_with_refreshed_list();

    let normal = Style::default();
    if let Some(process) = system.process(pid) {
        let process_name = process.name().to_string_lossy().to_string();
        let pid_u32 = pid.as_u32();
        let user = if let Some(user_id) = process.user_id() {
            if let Some(user) = users.get_user_by_id(user_id) {
                format!("{}", user.name())
            } else {
                format!("unknown")
            }
        } else {
            format!("unkown")
        };
        let effective_user = if let Some(user_id) = process.effective_user_id() {
            if let Some(user) = users.get_user_by_id(user_id) {
                format!("{}", user.name())
            } else {
                format!("unknown")
            }
        } else {
            format!("unkown")
        };
        let cmdline = process
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy()) // Cow<str>
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
        let status = process.status().to_string();

        let mut process_info = vec![
            ("Name:", process_name),
            ("Pid:", pid_u32.to_string()),
            ("User:", user),
            ("Effective user:", effective_user),
            ("Path:", path),
            ("Command line:", cmdline),
            ("Working dir:", cwd),
            ("Memory:", mem),
            ("Virtual memory:", vmem),
            ("Started:", started),
            ("Run time:", run_time),
            ("Status:", status),
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
