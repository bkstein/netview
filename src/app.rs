use netstat2::{
    AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo, get_sockets_info,
};
use num_enum::TryFromPrimitive;
use std::{
    cell::{Cell, RefCell},
    cmp::Ordering,
    collections::HashMap,
    net::IpAddr,
    process::Command,
    time::{Duration, Instant},
};
use sysinfo::System;

use crate::event::{AppEvent, Event, EventHandler};
use ratatui::{
    DefaultTerminal,
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    widgets::Row,
};

#[derive(PartialEq, Eq, Clone, Copy, Debug, TryFromPrimitive)]
#[repr(u8)]
pub enum SortColumn {
    Proto = 1,
    LocalIP = 2,
    LocalPort = 3,
    RemoteIP = 4,
    RemotePort = 5,
    State = 6,
    PID = 7,
    Process = 8,
    DataRate = 9,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum SortOrder {
    Asc,
    Desc,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum IpVersionFilter {
    Ipv4Only,
    Ipv6Only,
    Ipv4AndIpv6,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum ProtocolFilter {
    TcpOnly,
    UdpOnly,
    TcpAndUdp,
}

#[derive(Clone, Debug)]
pub struct ConnectionEntry {
    pub proto: String,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
    pub process: String,
    pub creation_time: Instant,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub data_rate: String, // Display string like "1.2 MB/s"
    pub last_update: Instant,
}

impl PartialEq for ConnectionEntry {
    fn eq(&self, other: &Self) -> bool {
        self.proto == other.proto
            && self.local_ip == other.local_ip
            && self.local_port == other.local_port
            && self.remote_ip == other.remote_ip
            && self.remote_port == other.remote_port
            && self.state == other.state
            && self.pid == other.pid
    }
}

impl Eq for ConnectionEntry {}

impl Ord for ConnectionEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        self.proto
            .cmp(&other.proto)
            .then(self.local_ip.cmp(&other.local_ip))
            .then(self.local_port.cmp(&other.local_port))
            .then(self.remote_ip.cmp(&other.remote_ip))
            .then(self.remote_port.cmp(&other.remote_port))
            .then(self.state.cmp(&other.state))
            .then(self.pid.cmp(&other.pid))
    }
}

impl PartialOrd for ConnectionEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ConnectionEntry {
    pub fn get_id(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.local_port, self.remote_port, self.pid, self.proto
        )
    }
}

#[derive(Eq, PartialEq, Debug)]
pub enum UiState {
    /// Showing the main frame containing the connections table
    ConnectionTable,
    /// Showing the help page
    Help,
    /// Showing info about the process of the selected connection
    ProcessInfo,
}

/// Application.
#[derive(Debug)]
pub struct App {
    /// Is the application running?
    pub running: bool,
    /// Event handler.
    pub events: EventHandler,
    /// Current connection entries
    pub entries: Vec<ConnectionEntry>,
    /// Vertical scroll position of connection table
    pub scroll_connection_table: Cell<usize>,
    /// Length of process info list
    pub process_info_list_length: Cell<usize>,
    /// Vertical scroll position of process info
    pub scroll_process_info: Cell<usize>,
    /// true, if table updates are suspended
    pub paused: bool,
    /// The column used to sort table lines
    pub sort_column: SortColumn,
    /// Sort ascending or descending
    pub sort_order: SortOrder,
    /// The visible height of the tables
    pub visible_table_height: Cell<usize>,
    /// Filter connections by ip version
    pub ip_version_filter: IpVersionFilter,
    /// Filter connections by protocol
    pub protocol_filter: ProtocolFilter,
    /// Resolve names of ip addresses
    pub resolve_address_names: bool,
    /// Show process info
    pub show_process_info: bool,
    /// Cache for DNS name resolutions
    dns_cache: HashMap<IpAddr, String>,
    /// Selected network connection
    pub selected: Option<ConnectionEntry>,
    /// Index of the selected `ConnectionEntry`
    pub selected_index: Option<usize>,
    /// Ui state
    pub ui_state: UiState,
    /// Last time the connection list was refreshed (for throttling).
    last_connection_refresh: RefCell<Option<Instant>>,
    /// Last time the user pressed a key (skip heavy refresh while actively scrolling).
    last_user_input: RefCell<Option<Instant>>,
    /// Cached process info rows by PID and width so scrolling doesn't recompute every frame.
    pub(crate) process_info_cache: RefCell<Option<(u32, usize, Vec<Row<'static>>)>>,
    /// Previous connection data for rate calculation: (rx_bytes, tx_bytes, timestamp)
    previous_connections: RefCell<HashMap<String, (u64, u64, Instant)>>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            running: true,
            events: EventHandler::new(),
            entries: vec![],
            scroll_connection_table: Cell::new(0),
            process_info_list_length: Cell::new(0),
            scroll_process_info: Cell::new(0),
            paused: false,
            sort_column: SortColumn::LocalPort,
            sort_order: SortOrder::Asc,
            visible_table_height: Cell::new(0),
            ip_version_filter: IpVersionFilter::Ipv4AndIpv6,
            protocol_filter: ProtocolFilter::TcpAndUdp,
            resolve_address_names: false,
            show_process_info: false,
            dns_cache: HashMap::new(),
            selected: None,
            selected_index: None,
            ui_state: UiState::ConnectionTable,
            last_connection_refresh: RefCell::new(None),
            last_user_input: RefCell::new(None),
            process_info_cache: RefCell::new(None),
            previous_connections: RefCell::new(HashMap::new()),
        }
    }
}

impl App {
    /// Constructs a new instance of [`App`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Run the application's main loop.
    #[allow(clippy::single_match)]
    pub async fn run(mut self, mut terminal: DefaultTerminal) -> color_eyre::Result<()> {
        if self.ui_state == UiState::ConnectionTable && !self.paused {
            self.update_connection_entries();
            *self.last_connection_refresh.borrow_mut() = Some(Instant::now());
        }
        let mut should_draw = true;
        while self.running {
            if should_draw {
                terminal.draw(|frame|
                    // At this point, a more complex ui could be rendered, e.g. by
                    // calling a function, that uses a layout. The current example
                    // directly renders a widget without any specified layout.
                    frame.render_widget(&self, frame.area()))?;
            }
            should_draw = match self.events.next().await? {
                Event::Tick => self.tick(),
                Event::Crossterm(event) => {
                    match event {
                        ::ratatui::crossterm::event::Event::Key(key_event) => {
                            self.record_user_input();
                            self.handle_key_events(key_event)?;
                        }
                        ::ratatui::crossterm::event::Event::Resize(_, _) => {
                            // Clear process info cache on resize so it recalculates with new width
                            *self.process_info_cache.borrow_mut() = None;
                        }
                        _ => {}
                    }
                    true
                }
                Event::App(app_event) => {
                    self.record_user_input();
                    match app_event {
                        AppEvent::Quit => self.quit(),
                        AppEvent::Pause => self.pause(),
                        AppEvent::ScrollUpSelection => self.scroll_up_selection(),
                        AppEvent::ScrollDownSelection => self.scroll_down_selection(),
                        AppEvent::ScrollUpPage => self.scroll_up_page(),
                        AppEvent::ScrollDownPage => self.scroll_down_page(),
                        AppEvent::ToggleIpVersion => self.toggle_ip_version(),
                        AppEvent::ToggleProtoVersion => self.toggle_proto_version(),
                        AppEvent::ToggleDnsResolution => self.toggle_dns_resolution(),
                        AppEvent::Sort(sort_column) => self.sort_by_column(sort_column),
                        AppEvent::ShowHelp => self.show_help(),
                        AppEvent::ShowProcessInfo => self.show_process_info(),
                    }
                    true
                }
            };
        }
        Ok(())
    }

    /// Handles the key events and converts them into `AppEvent`s.
    pub fn handle_key_events(&mut self, key_event: KeyEvent) -> color_eyre::Result<()> {
        match key_event.code {
            KeyCode::Esc | KeyCode::Char('q') => self.events.send(AppEvent::Quit),
            KeyCode::Char('c' | 'C') if key_event.modifiers == KeyModifiers::CONTROL => {
                self.events.send(AppEvent::Quit)
            }
            KeyCode::Pause | KeyCode::Char(' ') => self.events.send(AppEvent::Pause),
            KeyCode::Enter => self.events.send(AppEvent::ShowProcessInfo),
            KeyCode::Up => self.events.send(AppEvent::ScrollUpSelection),
            KeyCode::Down => self.events.send(AppEvent::ScrollDownSelection),
            KeyCode::PageUp => self.events.send(AppEvent::ScrollUpPage),
            KeyCode::PageDown => self.events.send(AppEvent::ScrollDownPage),
            KeyCode::Char('i' | 'I') => self.events.send(AppEvent::ToggleIpVersion),
            KeyCode::Char('p' | 'P') => self.events.send(AppEvent::ToggleProtoVersion),
            KeyCode::Char('d' | 'D') => self.events.send(AppEvent::ToggleDnsResolution),
            KeyCode::Char('h' | 'H') => self.events.send(AppEvent::ShowHelp),
            KeyCode::Char('1') => self
                .events
                .send(AppEvent::Sort(SortColumn::try_from_primitive(1)?)),
            KeyCode::Char('2') => self
                .events
                .send(AppEvent::Sort(SortColumn::try_from_primitive(2)?)),
            KeyCode::Char('3') => self
                .events
                .send(AppEvent::Sort(SortColumn::try_from_primitive(3)?)),
            KeyCode::Char('4') => self
                .events
                .send(AppEvent::Sort(SortColumn::try_from_primitive(4)?)),
            KeyCode::Char('5') => self
                .events
                .send(AppEvent::Sort(SortColumn::try_from_primitive(5)?)),
            KeyCode::Char('6') => self
                .events
                .send(AppEvent::Sort(SortColumn::try_from_primitive(6)?)),
            KeyCode::Char('7') => self
                .events
                .send(AppEvent::Sort(SortColumn::try_from_primitive(7)?)),
            KeyCode::Char('8') => self
                .events
                .send(AppEvent::Sort(SortColumn::try_from_primitive(8)?)),
            KeyCode::Char('9') => self
                .events
                .send(AppEvent::Sort(SortColumn::try_from_primitive(9)?)),
            // Other handlers you could add here.
            _ => {}
        }
        Ok(())
    }

    /// Handles the tick event of the terminal.
    ///
    /// The tick event is where you can update the state of your application with any logic that
    /// needs to be updated at a fixed frame rate. E.g. polling a server, updating an animation.
    /// Returns true if the connection list was refreshed (caller should redraw).
    fn tick(&mut self) -> bool {
        if self.paused || self.ui_state != UiState::ConnectionTable {
            return false;
        }
        const REFRESH_INTERVAL: Duration = Duration::from_secs(1);
        /// Skip heavy refresh shortly after user input so scrolling stays smooth.
        const IDLE_BEFORE_REFRESH: Duration = Duration::from_millis(400);
        let now = Instant::now();
        if self
            .last_user_input
            .borrow()
            .is_some_and(|t| now.saturating_duration_since(t) < IDLE_BEFORE_REFRESH)
        {
            return false;
        }
        let should_refresh = self
            .last_connection_refresh
            .borrow()
            .is_none_or(|t| now.saturating_duration_since(t) >= REFRESH_INTERVAL);
        if should_refresh {
            self.update_connection_entries();
            *self.last_connection_refresh.borrow_mut() = Some(Instant::now());
            true
        } else {
            false
        }
    }

    /// Records that the user pressed a key; used to defer heavy refresh while scrolling.
    fn record_user_input(&self) {
        *self.last_user_input.borrow_mut() = Some(Instant::now());
    }

    /// Refreshes the connection list immediately (e.g. after filter/setting changes) and updates
    /// the throttle so the next tick does not refresh again right away.
    fn refresh_connection_list(&mut self) {
        if self.ui_state != UiState::ConnectionTable {
            return;
        }
        self.update_connection_entries();
        *self.last_connection_refresh.borrow_mut() = Some(Instant::now());
    }

    /// Set running to false to quit the application.
    fn quit(&mut self) {
        match self.ui_state {
            UiState::ConnectionTable => self.running = false,
            UiState::Help => {
                self.ui_state = UiState::ConnectionTable;
            }
            UiState::ProcessInfo => {
                self.scroll_process_info.set(0);
                self.process_info_cache.replace(None);
                self.ui_state = UiState::ConnectionTable;
            }
        }
    }

    /// Suspend table updates
    fn pause(&mut self) {
        self.paused = !self.paused;
    }

    fn scroll_up_selection(&mut self) {
        match self.ui_state {
            UiState::ConnectionTable => self.scroll_up_connections(),
            UiState::Help => {}
            UiState::ProcessInfo => self.scroll_up_process_info(),
        }
    }

    fn scroll_up_connections(&mut self) {
        if self.entries.is_empty() {
            return;
        }

        if let Some(selected) = self.selected.clone() {
            if let Some(previous) = self.find_previous_entry(&selected) {
                self.selected = Some(previous.clone());
            }
        } else {
            self.selected = self.entries.first().cloned();
        }

        self.selected_index = self
            .entries
            .iter()
            .position(|entry| Some(entry) == self.selected.as_ref());
    }

    fn scroll_up_process_info(&mut self) {
        let current_scroll_position = self.scroll_process_info.get();
        if current_scroll_position > 0 {
            self.scroll_process_info
                .set(current_scroll_position.saturating_sub(1));
        }
    }

    fn scroll_down_selection(&mut self) {
        match self.ui_state {
            UiState::ConnectionTable => self.scroll_down_connections(),
            UiState::Help => {}
            UiState::ProcessInfo => self.scroll_down_process_info(),
        }
    }

    fn scroll_down_connections(&mut self) {
        if self.entries.is_empty() {
            return;
        }

        if let Some(selected) = self.selected.clone() {
            if let Some(next) = self.find_next_entry(&selected) {
                self.selected = Some(next.clone());
            }
        } else {
            self.selected = self.entries.first().cloned();
        }

        self.selected_index = self
            .entries
            .iter()
            .position(|entry| Some(entry) == self.selected.as_ref());
    }

    fn scroll_down_process_info(&mut self) {
        let current_scroll_position = self.scroll_process_info.get();
        if current_scroll_position
            < self
                .process_info_list_length
                .get()
                .saturating_sub(self.visible_table_height.get())
        {
            self.scroll_process_info.set(current_scroll_position + 1);
        }
    }

    fn scroll_up_page(&mut self) {
        match self.ui_state {
            UiState::ConnectionTable => self.scroll_up_connections_page(),
            UiState::Help => {}
            UiState::ProcessInfo => self.scroll_up_process_info_page(),
        }
    }

    fn scroll_down_page(&mut self) {
        match self.ui_state {
            UiState::ConnectionTable => self.scroll_down_connections_page(),
            UiState::Help => {}
            UiState::ProcessInfo => self.scroll_down_process_info_page(),
        }
    }

    fn scroll_up_connections_page(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        let page = self.visible_table_height.get().max(1);
        let current = self.selected_index.unwrap_or(0);
        let new_index = current.saturating_sub(page);
        self.selected = Some(self.entries[new_index].clone());
        self.selected_index = Some(new_index);
    }

    fn scroll_down_connections_page(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        let page = self.visible_table_height.get().max(1);
        let len = self.entries.len();
        let current = self.selected_index.unwrap_or(0);
        let new_index = (current + page).min(len.saturating_sub(1));
        self.selected = Some(self.entries[new_index].clone());
        self.selected_index = Some(new_index);
    }

    fn scroll_up_process_info_page(&mut self) {
        let page = self.visible_table_height.get().max(1);
        let current = self.scroll_process_info.get();
        self.scroll_process_info.set(current.saturating_sub(page));
    }

    fn scroll_down_process_info_page(&mut self) {
        let current = self.scroll_process_info.get();
        let max_scroll = self
            .process_info_list_length
            .get()
            .saturating_sub(self.visible_table_height.get());
        let page = self.visible_table_height.get().max(1);
        self.scroll_process_info
            .set((current + page).min(max_scroll));
    }

    fn toggle_ip_version(&mut self) {
        self.ip_version_filter = match self.ip_version_filter {
            IpVersionFilter::Ipv4Only => IpVersionFilter::Ipv6Only,
            IpVersionFilter::Ipv6Only => IpVersionFilter::Ipv4AndIpv6,
            IpVersionFilter::Ipv4AndIpv6 => IpVersionFilter::Ipv4Only,
        };
        self.refresh_connection_list();
    }

    fn toggle_proto_version(&mut self) {
        self.protocol_filter = match self.protocol_filter {
            ProtocolFilter::TcpOnly => ProtocolFilter::UdpOnly,
            ProtocolFilter::UdpOnly => ProtocolFilter::TcpAndUdp,
            ProtocolFilter::TcpAndUdp => ProtocolFilter::TcpOnly,
        };
        self.refresh_connection_list();
    }

    fn toggle_dns_resolution(&mut self) {
        self.resolve_address_names = !self.resolve_address_names;
        self.refresh_connection_list();
    }

    fn sort_by_column(&mut self, sort_column: SortColumn) {
        if self.sort_column == sort_column {
            self.sort_order = match self.sort_order {
                SortOrder::Asc => SortOrder::Desc,
                SortOrder::Desc => SortOrder::Asc,
            }
        } else {
            self.sort_column = sort_column;
        }
        self.sort_entries_by_column();
    }

    fn show_help(&mut self) {
        self.ui_state = match self.ui_state {
            UiState::Help => UiState::ConnectionTable,
            _ => UiState::Help,
        };
    }

    fn show_process_info(&mut self) {
        self.ui_state = UiState::ProcessInfo;
    }

    fn get_connection_bytes(&self) -> HashMap<String, (u64, u64)> {
        #[cfg(target_os = "macos")]
        return self.get_connection_bytes_macos();
        #[cfg(target_os = "linux")]
        return self.get_connection_bytes_linux();
        #[cfg(target_os = "windows")]
        return self.get_connection_bytes_windows();
        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        HashMap::new()
    }

    #[cfg(target_os = "macos")]
    fn get_connection_bytes_macos(&self) -> HashMap<String, (u64, u64)> {
        let output = Command::new("netstat")
            .args(["-b", "-n"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();
        let mut bytes_map = HashMap::new();
        let lines: Vec<&str> = output.lines().collect();
        let mut i = 0;
        while i < lines.len() && !lines[i].contains("Local Address") {
            i += 1;
        }
        i += 1;
        while i < lines.len() {
            let line = lines[i].trim();
            if line.is_empty() {
                i += 1;
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                i += 1;
                continue;
            }
            let local_addr = parts[3];
            let foreign_addr = parts[4];
            let (rxbytes, txbytes) = if parts.len() >= 8 && parts[6].chars().all(char::is_numeric) {
                (parts[6].parse().unwrap_or(0), parts[7].parse().unwrap_or(0))
            } else if parts.len() >= 7 && parts[5].chars().all(char::is_numeric) {
                (parts[5].parse().unwrap_or(0), parts[6].parse().unwrap_or(0))
            } else {
                i += 1;
                continue;
            };
            if let Some((local_ip, local_port)) = self.parse_address_macos(local_addr)
                && let Some((remote_ip, remote_port)) = self.parse_address_macos(foreign_addr)
            {
                let key = format!("{}:{}:{}:{}", local_ip, local_port, remote_ip, remote_port);
                bytes_map.insert(key, (rxbytes, txbytes));
            }
            i += 1;
        }
        bytes_map
    }

    #[cfg(target_os = "linux")]
    fn get_connection_bytes_linux(&self) -> HashMap<String, (u64, u64)> {
        let mut bytes_map = HashMap::new();
        for (is_udp, cmd) in [(false, "ss -tni"), (true, "ss -uni")] {
            let output = Command::new("sh")
                .args(["-c", cmd])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .unwrap_or_default();
            let lines: Vec<&str> = output.lines().collect();
            let mut i = 0;
            let mut last_key: Option<String> = None;
            while i < lines.len() {
                let line = lines[i];
                if line.starts_with('\t') || line.starts_with("  ") {
                    let rx = Self::parse_ss_bytes(line, "bytes_received:");
                    let tx = Self::parse_ss_bytes(line, "bytes_sent:");
                    if let Some(key) = last_key.take() {
                        bytes_map.insert(key, (rx, tx));
                    }
                } else {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 && parts[0] != "State" {
                        if let Some(local) = Self::parse_ss_addr_port(parts[3]) {
                            let key = if is_udp {
                                format!("{}:{}:", local.0, local.1)
                            } else if let Some(peer) = Self::parse_ss_addr_port(parts[4]) {
                                format!("{}:{}:{}:{}", local.0, local.1, peer.0, peer.1)
                            } else {
                                continue;
                            };
                            last_key = Some(key);
                        }
                    }
                }
                i += 1;
            }
        }
        bytes_map
    }

    #[cfg(target_os = "linux")]
    fn parse_ss_addr_port(addr_port: &str) -> Option<(String, u16)> {
        let addr_port = addr_port.trim();
        let port_str = addr_port.rsplit(':').next()?;
        let port = port_str.parse().ok()?;
        let rest = addr_port.strip_suffix(&format!(":{}", port_str))?;
        let addr = rest
            .strip_prefix('[')
            .unwrap_or(rest)
            .strip_suffix(']')
            .unwrap_or(rest);
        Some((addr.to_string(), port))
    }

    #[cfg(target_os = "linux")]
    fn parse_ss_bytes(line: &str, prefix: &str) -> u64 {
        for token in line.split_whitespace() {
            if let Some(val) = token.strip_prefix(prefix) {
                return val.parse().unwrap_or(0);
            }
        }
        0
    }

    #[cfg(target_os = "windows")]
    fn get_connection_bytes_windows(&self) -> HashMap<String, (u64, u64)> {
        // Windows netstat does not provide per-connection byte counts; return empty.
        // Data rate will show "0 B/s" until a sample is available.
        let _ = self;
        HashMap::new()
    }

    #[cfg(target_os = "macos")]
    fn parse_address_macos(&self, addr: &str) -> Option<(String, u16)> {
        let parts: Vec<&str> = addr.split('.').collect();
        if parts.len() < 2 {
            return None;
        }
        let port_str = parts.last()?;
        let port = port_str.parse().ok()?;
        let ip = parts[..parts.len() - 1].join(".");
        Some((ip, port))
    }

    #[cfg(not(target_os = "macos"))]
    #[allow(dead_code)]
    fn parse_address(&self, _addr: &str) -> Option<(String, u16)> {
        None
    }

    #[cfg(target_os = "macos")]
    fn parse_address(&self, addr: &str) -> Option<(String, u16)> {
        self.parse_address_macos(addr)
    }

    fn calculate_rate(
        &self,
        conn_key: &str,
        current_bytes: &HashMap<String, (u64, u64)>,
        now: Instant,
    ) -> (u64, u64, String, Instant) {
        let (rx_bytes, tx_bytes) = current_bytes.get(conn_key).copied().unwrap_or((0, 0));

        let prev_conns = self.previous_connections.borrow();
        let rate = if let Some((prev_rx, prev_tx, prev_time)) = prev_conns.get(conn_key) {
            let duration = now.duration_since(*prev_time).as_secs_f64();
            if duration > 0.0 {
                let rx_rate = ((rx_bytes.saturating_sub(*prev_rx)) as f64 / duration) as u64;
                let tx_rate = ((tx_bytes.saturating_sub(*prev_tx)) as f64 / duration) as u64;
                let total_rate = rx_rate + tx_rate;
                self.format_rate(total_rate)
            } else {
                "0 B/s".to_string()
            }
        } else {
            "0 B/s".to_string()
        };

        (rx_bytes, tx_bytes, rate, now)
    }

    fn format_rate(&self, bytes_per_sec: u64) -> String {
        const UNITS: &[&str] = &["B/s", "KB/s", "MB/s", "GB/s"];
        let mut rate = bytes_per_sec as f64;
        let mut unit_idx = 0;

        while rate >= 1024.0 && unit_idx < UNITS.len() - 1 {
            rate /= 1024.0;
            unit_idx += 1;
        }

        if unit_idx == 0 {
            format!("{} {}", bytes_per_sec, UNITS[0])
        } else {
            format!("{:.1} {}", rate, UNITS[unit_idx])
        }
    }

    fn parse_rate(rate_str: &str) -> u64 {
        let parts: Vec<&str> = rate_str.split_whitespace().collect();
        if parts.len() != 2 {
            return 0;
        }
        let value: f64 = parts[0].parse().unwrap_or(0.0);
        let unit = parts[1];

        let multiplier = match unit {
            "B/s" => 1,
            "KB/s" => 1024,
            "MB/s" => 1024 * 1024,
            "GB/s" => 1024 * 1024 * 1024,
            _ => 1,
        };

        (value * multiplier as f64) as u64
    }

    fn update_connection_entries(&mut self) {
        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

        let mut sys = System::new_all();
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        // Get current byte counts
        let current_bytes = self.get_connection_bytes();
        let now = Instant::now();

        self.entries = vec![];

        if let Ok(sockets) = get_sockets_info(af_flags, proto_flags) {
            for conn in sockets {
                let pid = conn.associated_pids.first().copied().unwrap_or(0);
                let proc_name = sys
                    .process(sysinfo::Pid::from_u32(pid))
                    .map(|p| p.name().to_string_lossy().to_string())
                    .unwrap_or_default();

                match conn.protocol_socket_info {
                    ProtocolSocketInfo::Tcp(ref tcp) => {
                        if self.show_connection(&conn) {
                            let local_ip = self.ip_to_string(&tcp.local_addr);
                            let remote_ip = self.ip_to_string(&tcp.remote_addr);
                            let conn_key = format!(
                                "{}:{}:{}:{}",
                                local_ip, tcp.local_port, remote_ip, tcp.remote_port
                            );

                            let (rx_bytes, tx_bytes, data_rate, last_update) =
                                self.calculate_rate(&conn_key, &current_bytes, now);

                            self.entries.push(ConnectionEntry {
                                proto: if tcp.local_addr.is_ipv4() {
                                    "TCPv4".into()
                                } else {
                                    "TCPv6".into()
                                },
                                local_ip,
                                local_port: tcp.local_port,
                                remote_ip,
                                remote_port: tcp.remote_port,
                                state: format!("{:?}", tcp.state),
                                pid,
                                process: proc_name,
                                creation_time: Instant::now(),
                                rx_bytes,
                                tx_bytes,
                                data_rate,
                                last_update,
                            });
                        }
                    }
                    ProtocolSocketInfo::Udp(ref udp) => {
                        if self.show_connection(&conn) {
                            let local_ip = self.ip_to_string(&udp.local_addr);
                            let conn_key = format!("{}:{}:{}", local_ip, udp.local_port, "");

                            let (rx_bytes, tx_bytes, data_rate, last_update) =
                                self.calculate_rate(&conn_key, &current_bytes, now);

                            self.entries.push(ConnectionEntry {
                                proto: if udp.local_addr.is_ipv4() {
                                    "UDPv4".into()
                                } else {
                                    "UDPv6".into()
                                },
                                local_ip,
                                local_port: udp.local_port,
                                remote_ip: "".into(),
                                remote_port: 0,
                                state: "".into(),
                                pid,
                                process: proc_name,
                                creation_time: Instant::now(),
                                rx_bytes,
                                tx_bytes,
                                data_rate,
                                last_update,
                            });
                        }
                    }
                }
            }
        }

        self.entries.sort();
        self.entries.dedup();
        self.sort_entries_by_column();
        self.reconcile_selection_after_refresh();

        // Update previous connections for next rate calculation
        let mut prev_conns = self.previous_connections.borrow_mut();
        prev_conns.clear();
        for entry in &self.entries {
            let conn_key = format!(
                "{}:{}:{}:{}",
                entry.local_ip, entry.local_port, entry.remote_ip, entry.remote_port
            );
            prev_conns.insert(
                conn_key,
                (entry.rx_bytes, entry.tx_bytes, entry.last_update),
            );
        }
    }

    /// Keeps selection in sync after the entries list has been refreshed (e.g. on tick).
    /// If the previously selected connection still exists, it remains selected; otherwise
    /// selection is moved to a valid row or cleared so the current line marker is not lost.
    fn reconcile_selection_after_refresh(&mut self) {
        if self.entries.is_empty() {
            self.selected = None;
            self.selected_index = None;
            return;
        }
        let len = self.entries.len();
        if let Some(ref prev_selected) = self.selected
            && let Some(idx) = self.entries.iter().position(|e| e == prev_selected)
        {
            self.selected = Some(self.entries[idx].clone());
            self.selected_index = Some(idx);
            return;
        }

        // Selected connection no longer in list (or no selection): keep index if valid, else pick a valid one
        let idx = self
            .selected_index
            .map_or(0, |i| i.min(len.saturating_sub(1)));
        self.selected = Some(self.entries[idx].clone());
        self.selected_index = Some(idx);
    }

    /// Convert ip address to string taking name resolution into account
    fn ip_to_string(&mut self, ip: &IpAddr) -> String {
        if self.resolve_address_names {
            self.resolve_dns(*ip)
        } else {
            ip.to_string()
        }
    }

    fn resolve_dns(&mut self, ip: IpAddr) -> String {
        if let Some(name) = self.dns_cache.get(&ip) {
            return name.clone();
        }

        let hostname = dns_lookup::lookup_addr(&ip).unwrap_or_else(|_| ip.to_string());
        self.dns_cache.insert(ip, hostname.clone());

        self.dns_cache.insert(ip, hostname.clone());
        hostname
    }

    /// Return true, if a connection is not filtered out and shall be displayed
    fn show_connection(&self, socket_info: &SocketInfo) -> bool {
        match &socket_info.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => {
                if self.protocol_filter == ProtocolFilter::UdpOnly {
                    return false;
                }
                if tcp.local_addr.is_ipv4() && self.ip_version_filter == IpVersionFilter::Ipv6Only {
                    return false;
                }
                if tcp.local_addr.is_ipv6() && self.ip_version_filter == IpVersionFilter::Ipv4Only {
                    return false;
                }
            }
            ProtocolSocketInfo::Udp(udp) => {
                if self.protocol_filter == ProtocolFilter::TcpOnly {
                    return false;
                }
                if udp.local_addr.is_ipv4() && self.ip_version_filter == IpVersionFilter::Ipv6Only {
                    return false;
                }
                if udp.local_addr.is_ipv6() && self.ip_version_filter == IpVersionFilter::Ipv4Only {
                    return false;
                }
            }
        }
        true
    }

    fn sort_entries_by_column(&mut self) {
        use SortColumn::*;
        self.entries.sort_by(|a, b| {
            let ord = match self.sort_column {
                Proto => a.proto.cmp(&b.proto),
                LocalIP => a.local_ip.cmp(&b.local_ip),
                LocalPort => a.local_port.cmp(&b.local_port),
                RemoteIP => string_compare_with_empty(&a.remote_ip, &b.remote_ip, self.sort_order),
                RemotePort => remote_port_compare(a.remote_port, b.remote_port, self.sort_order),
                State => string_compare_with_empty(&a.state, &b.state, self.sort_order),
                PID => a.pid.cmp(&b.pid),
                Process => string_compare_with_empty(&a.process, &b.process, self.sort_order),
                DataRate => Self::parse_rate(&a.data_rate).cmp(&Self::parse_rate(&b.data_rate)),
            };
            if self.sort_order == SortOrder::Asc {
                ord
            } else {
                ord.reverse()
            }
        });
    }

    fn find_previous_entry(&self, entry: &ConnectionEntry) -> Option<&ConnectionEntry> {
        for window in self.entries.windows(2) {
            let (prev, curr) = (&window[0], &window[1]);
            if curr == entry {
                return Some(prev);
            }
        }
        None
    }

    fn find_next_entry(&self, entry: &ConnectionEntry) -> Option<&ConnectionEntry> {
        for window in self.entries.windows(2) {
            let (curr, next) = (&window[0], &window[1]);
            if curr == entry {
                return Some(next);
            }
        }
        None
    }
}

/// Compare strings, but always push empty strings to the end
fn string_compare_with_empty(a: &str, b: &str, sort_order: SortOrder) -> Ordering {
    match sort_order {
        SortOrder::Asc => match (a.is_empty(), b.is_empty()) {
            (true, true) => std::cmp::Ordering::Equal,
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            (false, false) => a.cmp(b),
        },
        SortOrder::Desc => match (a.is_empty(), b.is_empty()) {
            (true, true) => std::cmp::Ordering::Equal,
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            (false, false) => a.cmp(b),
        },
    }
}

fn remote_port_compare(a: u16, b: u16, sort_order: SortOrder) -> Ordering {
    match sort_order {
        SortOrder::Asc => match (a == 0, b == 0) {
            (true, true) => std::cmp::Ordering::Equal,
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            (false, false) => a.cmp(&b),
        },
        SortOrder::Desc => match (a == 0, b == 0) {
            (true, true) => std::cmp::Ordering::Equal,
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            (false, false) => a.cmp(&b),
        },
    }
}
