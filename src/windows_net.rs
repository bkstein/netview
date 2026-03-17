//! Windows-only: per-connection byte counts via IP Helper API (GetExtendedTcpTable +
//! GetPerTcpConnectionEStats). Used for data rate calculation.

use std::collections::HashMap;
use std::mem::size_of;
use std::net::Ipv4Addr;

use windows::Win32::Networking::WinSock::AF_INET;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetPerTcpConnectionEStats, MIB_TCPROW_LH, MIB_TCPROW_LH_0,
    MIB_TCPROW_OWNER_PID, TcpConnectionEstatsData, TCP_ESTATS_DATA_ROD_v0, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::System::Diagnostics::Debug::ERROR_INSUFFICIENT_BUFFER;

/// Returns a map of connection key -> (rx_bytes, tx_bytes) for IPv4 TCP only.
/// Key format: "local_ip:local_port:remote_ip:remote_port" to match app.rs.
/// IPv6 TCP and UDP are not included (no extended stats in this path); those connections show 0 B/s.
pub fn get_connection_bytes() -> HashMap<String, (u64, u64)> {
    let mut out = HashMap::new();
    let mut size: u32 = 0;

    // First call: get required buffer size (expect ERROR_INSUFFICIENT_BUFFER).
    unsafe {
        let ret = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if ret != ERROR_INSUFFICIENT_BUFFER.0 && ret != 0 {
            return out;
        }
    }

    if size == 0 {
        return out;
    }

    let mut buffer = vec![0u8; size as usize];
    let mut size = size;

    unsafe {
        let ret = GetExtendedTcpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if ret != 0 {
            return out;
        }
    }

    // Layout: first 4 bytes = dwNumEntries, then array of MIB_TCPROW_OWNER_PID.
    let base = buffer.as_ptr() as *const u8;
    let num_entries = (base as *const u32).read();
    let row_size = size_of::<MIB_TCPROW_OWNER_PID>();

    for i in 0..num_entries {
        let row_ptr = base.add(4 + i as usize * row_size) as *const MIB_TCPROW_OWNER_PID;
        let row = row_ptr.read();

        let key = connection_key(
            row.dwLocalAddr,
            row.dwLocalPort,
            row.dwRemoteAddr,
            row.dwRemotePort,
        );
        let (rx, tx) = get_per_connection_estats(&row);
        out.insert(key, (rx, tx));
    }

    out
}

fn connection_key(local_addr: u32, local_port: u32, remote_addr: u32, remote_port: u32) -> String {
    let local_ip = ipv4_to_string(local_addr);
    let remote_ip = ipv4_to_string(remote_addr);
    let local_p = port_from_network(local_port);
    let remote_p = port_from_network(remote_port);
    format!("{}:{}:{}:{}", local_ip, local_p, remote_ip, remote_p)
}

fn ipv4_to_string(addr: u32) -> String {
    Ipv4Addr::from(addr.to_be_bytes()).to_string()
}

/// Port is stored in network byte order (big-endian); lower 16 bits only.
fn port_from_network(port: u32) -> u16 {
    let p = (port & 0xFFFF) as u16;
    u16::from_be(p)
}

/// Build MIB_TCPROW_LH from OWNER_PID row and call GetPerTcpConnectionEStats(TcpConnectionEstatsData).
fn get_per_connection_estats(row: &MIB_TCPROW_OWNER_PID) -> (u64, u64) {
    let row_lh = MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 { dwState: row.dwState },
        dwLocalAddr: row.dwLocalAddr,
        dwLocalPort: row.dwLocalPort,
        dwRemoteAddr: row.dwRemoteAddr,
        dwRemotePort: row.dwRemotePort,
    };

    let mut rod_buf = [0u8; size_of::<TCP_ESTATS_DATA_ROD_v0>()];

    unsafe {
        let ret = GetPerTcpConnectionEStats(
            &row_lh as *const _ as *const MIB_TCPROW_LH,
            TcpConnectionEstatsData,
            None,
            0,
            None,
            0,
            Some(&mut rod_buf),
            0,
        );
        if ret != 0 {
            return (0, 0);
        }
    }

    let rod = unsafe { (rod_buf.as_ptr() as *const TCP_ESTATS_DATA_ROD_v0).read() };
    (rod.DataBytesIn, rod.DataBytesOut)
}
