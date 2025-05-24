use netstat2::{
    AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo, get_sockets_info,
};
use num_enum::TryFromPrimitive;
use std::{collections::HashMap, net::{IpAddr, ToSocketAddrs}, time::Instant};
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
                frame.render_widget(&self, frame.area())
            )?;
            match self.events.next().await? {
                Event::Tick => self.tick(),
                Event::Crossterm(event) => match event {
                    crossterm::event::Event::Key(key_event) => self.handle_key_events(key_event)?,
                    _ => {}
                },
                Event::App(app_event) => match app_event {
                    AppEvent::Quit => self.quit(),
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
                .send(AppEvent::Sort(SortColumn::try_from_primitive(4)?)),
            KeyCode::Char('6') => self
                .events
                .send(AppEvent::Sort(SortColumn::try_from_primitive(5)?)),
            KeyCode::Char('7') => self
                .events
                .send(AppEvent::Sort(SortColumn::try_from_primitive(6)?)),
            KeyCode::Char('8') => self
                .events
                .send(AppEvent::Sort(SortColumn::try_from_primitive(7)?)),
            KeyCode::Char('9') => self
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
    pub fn tick(&mut self) {
        if !self.paused {
            self.update_connection_entries();
        }
    }

    /// Set running to false to quit the application.
    pub fn quit(&mut self) {
        self.running = false;
    }

    pub fn scroll_up_selection(&mut self) {}

    pub fn scroll_down_selection(&mut self) {}

    pub fn scroll_up_page(&mut self) {}

    pub fn scroll_down_page(&mut self) {}

    pub fn toggle_ip_version(&mut self) {
        self.ip_version_filter = match self.ip_version_filter {
            IpVersionFilter::Ipv4Only => IpVersionFilter::Ipv6Only,
            IpVersionFilter::Ipv6Only => IpVersionFilter::Ipv4AndIpv6,
            IpVersionFilter::Ipv4AndIpv6 => IpVersionFilter::Ipv4Only,
        };
    }

    pub fn toggle_proto_version(&mut self) {
        self.protocol_filter = match self.protocol_filter {
            ProtocolFilter::TcpOnly => ProtocolFilter::UdpOnly,
            ProtocolFilter::UdpOnly => ProtocolFilter::TcpAndUdp,
            ProtocolFilter::TcpAndUdp => ProtocolFilter::TcpOnly,
        };
    }

    pub fn toggle_dns_resolution(&mut self) {
        self.resolve_address_names = !self.resolve_address_names;
    }

    pub fn sort_by_column(&mut self, sort_column: SortColumn) {
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

    pub fn show_help(&mut self) {}

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
                            self.entries.push(ConnectionEntry {
                                proto: "TCP".into(),
                                local_ip: tcp.local_addr.to_string(),
                                local_port: tcp.local_port,
                                remote_ip: tcp.remote_addr.to_string(),
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
                            self.entries.push(ConnectionEntry {
                                proto: "UDP".into(),
                                local_ip: udp.local_addr.to_string(),
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
    }

    /// Convert ip address to string taking name resolution into account
    fn ip_to_string(&mut self, ip: &IpAddr) -> String {
        if self.resolve_address_names {
            self.resolve_dns(ip.clone())
        } else {
            ip.to_string()
        }
    }

    fn resolve_dns(&mut self, addr: IpAddr, ) -> String {
        if let Some(name) = self.dns_cache.get(&addr) {
            return name.clone();
        }

        let socket = (addr, 0);
        let name = match socket.to_socket_addrs() {
            Ok(mut iter) => iter.next().map(|sa| sa.to_string()).unwrap_or(addr.to_string()),
            Err(_) => addr.to_string(),
        };

        // Strip port (if any)
        let hostname = name.split(':').next().unwrap_or(&name).to_string();

        self.dns_cache.insert(addr, hostname.clone());
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
                RemoteIP => a.remote_ip.cmp(&b.remote_ip),
                RemotePort => a.remote_port.cmp(&b.remote_port),
                State => a.state.cmp(&b.state),
                PID => a.pid.cmp(&b.pid),
                Process => a.process.cmp(&b.process),
            };
            if self.sort_order == SortOrder::Asc {
                ord
            } else {
                ord.reverse()
            }
        });        
    }

}

