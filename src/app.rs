use netstat2::{
    AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo, get_sockets_info,
};
use num_enum::TryFromPrimitive;
use std::{
    cmp::Ordering,
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
    net::IpAddr,
    ops::Deref,
    time::Instant,
};
use sysinfo::System;

use crate::event::{AppEvent, Event, EventHandler};
use ratatui::{
    DefaultTerminal,
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
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

#[derive(Clone, Debug, Ord, PartialOrd, Hash)]
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

impl ConnectionEntry {
    pub fn get_id(&self) -> String {
        // let mut hasher = fxhash::FxHasher::default();
        // self.hash(&mut hasher);
        // hasher.finish()
        format!(
            "{}:{}:{}:{}",
            self.local_port, self.remote_port, self.pid, self.proto
        )
    }
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
    /// Vertical scroll position
    pub scroll: usize,
    /// true, if table updates are suspended
    pub paused: bool,
    /// The column used to sort table lines
    pub sort_column: SortColumn,
    /// Sort ascending or descending
    pub sort_order: SortOrder,
    /// The visible height of the table
    pub visible_height: usize,
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
}

impl Default for App {
    fn default() -> Self {
        Self {
            running: true,
            events: EventHandler::new(),
            entries: vec![],
            scroll: 0,
            paused: false,
            sort_column: SortColumn::LocalPort,
            sort_order: SortOrder::Asc,
            visible_height: 0,
            ip_version_filter: IpVersionFilter::Ipv4AndIpv6,
            protocol_filter: ProtocolFilter::TcpAndUdp,
            resolve_address_names: false,
            show_process_info: false,
            dns_cache: HashMap::new(),
            selected: None,
        }
    }
}

impl App {
    /// Constructs a new instance of [`App`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Run the application's main loop.
    pub async fn run(mut self, mut terminal: DefaultTerminal) -> color_eyre::Result<()> {
        while self.running {
            terminal.draw(|frame|
                // At this point, a more complex ui could be rendered, e.g. by
                // calling a function, that uses a layout. The current example
                // directly renders a widget without any specified layout.
                frame.render_widget(&self, frame.area()))?;
            match self.events.next().await? {
                Event::Tick => self.tick(),
                Event::Crossterm(event) => match event {
                    crossterm::event::Event::Key(key_event) => self.handle_key_events(key_event)?,
                    _ => {}
                },
                Event::App(app_event) => match app_event {
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
                    AppEvent::ToggleProcessInfo => self.toggle_process_info(),
                },
            }
        }
        Ok(())
    }

    /// Handles the key events and converts them into `AppEvent`s.
    pub fn handle_key_events(&mut self, key_event: KeyEvent) -> color_eyre::Result<()> {
        match key_event.code {
            KeyCode::Esc | KeyCode::Char('q') => self.events.send(AppEvent::Quit),
            KeyCode::Pause | KeyCode::Char(' ') => self.events.send(AppEvent::Pause),
            KeyCode::Char('c' | 'C') if key_event.modifiers == KeyModifiers::CONTROL => {
                self.events.send(AppEvent::Quit)
            }
            KeyCode::Up => self.events.send(AppEvent::ScrollUpSelection),
            KeyCode::Down => self.events.send(AppEvent::ScrollDownSelection),
            KeyCode::PageUp => self.events.send(AppEvent::ScrollUpPage),
            KeyCode::PageDown => self.events.send(AppEvent::ScrollDownPage),
            KeyCode::Char('v' | 'V') => self.events.send(AppEvent::ToggleIpVersion),
            KeyCode::Char('p' | 'P') => self.events.send(AppEvent::ToggleProtoVersion),
            KeyCode::Char('d' | 'D') => self.events.send(AppEvent::ToggleDnsResolution),
            KeyCode::Char('h' | 'H') => self.events.send(AppEvent::ShowHelp),
            KeyCode::Char('i' | 'I') => self.events.send(AppEvent::ToggleProcessInfo),
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
            // Other handlers you could add here.
            _ => {}
        }
        Ok(())
    }

    /// Handles the tick event of the terminal.
    ///
    /// The tick event is where you can update the state of your application with any logic that
    /// needs to be updated at a fixed frame rate. E.g. polling a server, updating an animation.
    fn tick(&mut self) {
        if !self.paused {
            self.update_connection_entries();
        }
    }

    /// Set running to false to quit the application.
    fn quit(&mut self) {
        self.running = false;
    }

    /// Suspend table updates
    fn pause(&mut self) {
        self.paused = !self.paused;
    }

    fn scroll_up_selection(&mut self) {
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
    }

    fn scroll_down_selection(&mut self) {
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
    }

    fn scroll_up_page(&mut self) {}

    fn scroll_down_page(&mut self) {}

    fn toggle_ip_version(&mut self) {
        self.ip_version_filter = match self.ip_version_filter {
            IpVersionFilter::Ipv4Only => IpVersionFilter::Ipv6Only,
            IpVersionFilter::Ipv6Only => IpVersionFilter::Ipv4AndIpv6,
            IpVersionFilter::Ipv4AndIpv6 => IpVersionFilter::Ipv4Only,
        };
    }

    fn toggle_proto_version(&mut self) {
        self.protocol_filter = match self.protocol_filter {
            ProtocolFilter::TcpOnly => ProtocolFilter::UdpOnly,
            ProtocolFilter::UdpOnly => ProtocolFilter::TcpAndUdp,
            ProtocolFilter::TcpAndUdp => ProtocolFilter::TcpOnly,
        };
    }

    fn toggle_dns_resolution(&mut self) {
        self.resolve_address_names = !self.resolve_address_names;
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
        self.sort_entries();
    }

    fn show_help(&mut self) {}

    fn toggle_process_info(&mut self) {
        self.show_process_info = !self.show_process_info;
    }

    fn update_connection_entries(&mut self) {
        let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

        let mut sys = System::new_all();
        sys.refresh_processes();

        self.entries = vec![];

        if let Ok(sockets) = get_sockets_info(af_flags, proto_flags) {
            for conn in sockets {
                let pid = conn.associated_pids.first().copied().unwrap_or(0);
                let proc_name = sys
                    .process(sysinfo::Pid::from_u32(pid))
                    .map(|p| p.name().to_string())
                    .unwrap_or_default();

                match conn.protocol_socket_info {
                    ProtocolSocketInfo::Tcp(ref tcp) => {
                        if self.show_connection(&conn) {
                            let local_ip = self.ip_to_string(&tcp.local_addr);
                            let remote_ip = self.ip_to_string(&tcp.remote_addr);
                            self.entries.push(ConnectionEntry {
                                proto: "TCP".into(),
                                local_ip,
                                local_port: tcp.local_port,
                                remote_ip,
                                remote_port: tcp.remote_port,
                                state: format!("{:?}", tcp.state),
                                pid,
                                process: proc_name,
                                creation_time: Instant::now(),
                            });
                        }
                    }
                    ProtocolSocketInfo::Udp(ref udp) => {
                        if self.show_connection(&conn) {
                            let local_ip = self.ip_to_string(&udp.local_addr);
                            self.entries.push(ConnectionEntry {
                                proto: "UDP".into(),
                                local_ip,
                                local_port: udp.local_port,
                                remote_ip: "".into(),
                                remote_port: 0,
                                state: "".into(),
                                pid,
                                process: proc_name,
                                creation_time: Instant::now(),
                            });
                        }
                    }
                }
            }
        }

        self.sort_entries();
        self.entries.dedup();
    }

    /// Convert ip address to string taking name resolution into account
    fn ip_to_string(&mut self, ip: &IpAddr) -> String {
        if self.resolve_address_names {
            self.resolve_dns(ip.clone())
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

    fn sort_entries(&mut self) {
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
