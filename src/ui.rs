use ratatui::{
    Frame,
    buffer::Buffer,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, Widget},
};

use crate::app::{App, ConnectionEntry, SortColumn, SortOrder};

impl Widget for &App {
    /// Renders the user interface widgets.
    ///
    // This is where you add new widgets.
    // See the following resources:
    // - https://docs.rs/ratatui/latest/ratatui/widgets/index.html
    // - https://github.com/ratatui/ratatui/tree/master/examples
    // fn render(self, area: Rect, buf: &mut Buffer) {
    //     let block = Block::bordered()
    //         .title("netview")
    //         .title_alignment(Alignment::Center)
    //         .border_type(BorderType::Rounded);

    //     let text = format!(
    //         "This is a tui template.\n\
    //             Press `Esc`, `Ctrl-C` or `q` to stop running.\n\
    //             Press left and right to increment and decrement the counter respectively.\n\
    //             Counter: {}",
    //         self.counter
    //     );

    //     let paragraph = Paragraph::new(text)
    //         .block(block)
    //         .fg(Color::Cyan)
    //         .bg(Color::Black)
    //         .centered();

    //     paragraph.render(area, buf);
    // }
    fn render(self, area: Rect, buf: &mut Buffer) {
        let table_height = area.height as usize;

        let visible_height = table_height.saturating_sub(2);

        let rows = self.entries_to_rows();
        let header = render_header(self.sort_column, self.sort_order);

        let connections_title = if self.paused {
            "Connections (paused - press 'SPACE' to resume)"
        } else {
            "Connections (live - press 'SPACE' to pause)"
        };
        let rows_to_show = &rows[self.scroll..(self.scroll + visible_height).min(rows.len())];
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

        // let layout = Layout::default()
        //     .direction(Direction::Vertical)
        //     .constraints([Constraint::Min(1)].as_ref())
        //     .split(area);

        table.render(area, buf);
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
            let entry_id = e.get_id();

            let cells = vec![
                Cell::from(e.proto.clone()).style(if Some(e) ==  self.selected.as_ref() {
                    selected_row_style
                } else if self.sort_column == SortColumn::Proto {
                    sorted_column_style
                } else {
                    normal
                }),
                Cell::from(e.local_ip.clone()).style(if Some(e) ==  self.selected.as_ref() {
                    selected_row_style
                } else if self.sort_column == SortColumn::LocalIP {
                    sorted_column_style
                } else {
                    normal
                }),
                Cell::from(e.local_port.to_string()).style(if Some(e) ==  self.selected.as_ref() {
                    selected_row_style
                } else if self.sort_column == SortColumn::LocalPort {
                    sorted_column_style
                } else {
                    normal
                }),
                Cell::from(e.remote_ip.clone()).style(if Some(e) ==  self.selected.as_ref() {
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
                .style(if Some(e) ==  self.selected.as_ref() {
                    selected_row_style
                } else if self.sort_column == SortColumn::RemotePort {
                    sorted_column_style
                } else {
                    normal
                }),
                Cell::from(e.state.clone()).style(if Some(e) ==  self.selected.as_ref() {
                    selected_row_style
                } else if self.sort_column == SortColumn::State {
                    sorted_column_style
                } else {
                    normal
                }),
                Cell::from(e.pid.to_string()).style(if Some(e) ==  self.selected.as_ref() {
                    selected_row_style
                } else if self.sort_column == SortColumn::PID {
                    sorted_column_style
                } else {
                    normal
                }),
                Cell::from(e.process.clone()).style(if Some(e) ==  self.selected.as_ref() {
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

