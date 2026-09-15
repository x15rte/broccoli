//! Owning-PID verification of the loopback control-plane listener.
//! The gRPC API inbound is loopback-only and carries no credentials;
//! readiness is trusted only after this module proves the listener on the
//! active API port belongs to the spawned core child. `GetExtendedTcpTable`
//! reports the owning PID of every TCP endpoint, so the app can compare the
//! listener's owner against the child PID it spawned.

use std::alloc::Layout;
use std::mem::align_of;
use std::net::Ipv4Addr;

use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows::Win32::Networking::WinSock::AF_INET;

/// `MIB_TCP_STATE_LISTEN`: only LISTEN rows prove a bound listener.
const MIB_TCP_STATE_LISTEN: u32 = 2;

/// One decoded row of the IPv4 TCP endpoint table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpRow {
    pub state: u32,
    pub local_addr: Ipv4Addr,
    pub local_port: u16,
    pub owning_pid: u32,
}

/// Snapshot every IPv4 TCP endpoint's local address/port and owning PID via
/// `GetExtendedTcpTable`. `None` when the table cannot be read (allocation
/// failure or an unexpected API error) — callers must fail closed on `None`.
pub fn tcp_table() -> Option<Vec<TcpRow>> {
    // First call sizes the buffer: with `ptcptable = None` the API reports the
    // required byte count in `size` and returns ERROR_INSUFFICIENT_BUFFER.
    let mut size = 0u32;
    // SAFETY: `pdwSize` points to a valid, writable `u32`; with `ptcptable =
    // None` the call only writes the required size and never dereferences a
    // table pointer.
    let status = unsafe {
        GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if status == NO_ERROR.0 {
        // A zero-size request returned success: there are no IPv4 endpoints.
        return Some(Vec::new());
    }
    if status != ERROR_INSUFFICIENT_BUFFER.0 || size == 0 {
        return None;
    }

    let Ok(layout) = Layout::from_size_align(size as usize, align_of::<MIB_TCPTABLE_OWNER_PID>())
    else {
        return None;
    };
    // SAFETY: `layout` has nonzero size (the API reported the required bytes)
    // and a valid alignment; `alloc` returns a suitably aligned pointer, or
    // null on allocation failure.
    let raw = unsafe { std::alloc::alloc(layout) };
    if raw.is_null() {
        return None;
    }

    // SAFETY: `raw` is valid for `layout` (allocated above, not yet freed) and
    // aligned for `MIB_TCPTABLE_OWNER_PID`, so the API may write the table
    // into it; `size` is the capacity the API itself requested.
    let status = unsafe {
        GetExtendedTcpTable(
            Some(raw.cast()),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    let rows = if status == NO_ERROR.0 {
        // SAFETY: on NO_ERROR the API initialized the buffer as a
        // `MIB_TCPTABLE_OWNER_PID` — `dwNumEntries` followed by that many rows
        // packed immediately after the header — and the buffer covers the size
        // the API requested, so every row lies inside the allocation.
        let header = unsafe { &*raw.cast::<MIB_TCPTABLE_OWNER_PID>() };
        let count = header.dwNumEntries as usize;
        // SAFETY: `header.table.as_ptr()` points at the first row; the API
        // wrote `count` packed rows (the `[T; 1]` field is the flexible-array
        // pattern), all within the `layout`-sized allocation above.
        let slice = unsafe { std::slice::from_raw_parts(header.table.as_ptr(), count) };
        Some(
            slice
                .iter()
                .map(|row| TcpRow {
                    state: row.dwState,
                    // MIB addresses/ports are in network byte order; the
                    // native u32 reads must be byte-swapped to decode them.
                    local_addr: Ipv4Addr::from(u32::from_be(row.dwLocalAddr)),
                    local_port: u16::from_be((row.dwLocalPort & 0xFFFF) as u16),
                    owning_pid: row.dwOwningPid,
                })
                .collect(),
        )
    } else {
        None
    };
    // SAFETY: `raw` is the pointer `alloc(layout)` returned and has not been
    // freed; this deallocates it exactly once.
    unsafe { std::alloc::dealloc(raw, layout) };
    rows
}

/// Whether the loopback TCP listener on `port` is owned by `expected_pid` —
/// and only by it. Requires at least one LISTEN row on the loopback `port`
/// and rejects the verdict when any LISTEN row there belongs to a different
/// process. Fails closed: `false` for an empty table, an unknown owner (`0`),
/// or any foreign listener, so a spoofed responder can never be trusted.
pub fn loopback_api_listener_owned_by(rows: &[TcpRow], port: u16, expected_pid: u32) -> bool {
    if expected_pid == 0 {
        return false;
    }
    let mut listeners = 0usize;
    let mut owned = 0usize;
    for row in rows {
        if row.state == MIB_TCP_STATE_LISTEN
            && row.local_addr.is_loopback()
            && row.local_port == port
        {
            listeners += 1;
            if row.owning_pid == expected_pid {
                owned += 1;
            }
        }
    }
    listeners != 0 && listeners == owned
}

#[cfg(test)]
mod tests {
    use super::{MIB_TCP_STATE_LISTEN, TcpRow, loopback_api_listener_owned_by};
    use std::net::Ipv4Addr;

    const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

    fn row(state: u32, addr: Ipv4Addr, port: u16, pid: u32) -> TcpRow {
        TcpRow {
            state,
            local_addr: addr,
            local_port: port,
            owning_pid: pid,
        }
    }

    fn listening(port: u16, pid: u32) -> TcpRow {
        row(MIB_TCP_STATE_LISTEN, LOOPBACK, port, pid)
    }

    #[test]
    fn listener_owned_by_the_spawned_child_is_trusted() {
        let rows = [listening(10853, 4242)];
        assert!(loopback_api_listener_owned_by(&rows, 10853, 4242));
    }

    #[test]
    fn listener_owned_by_a_foreign_process_is_rejected() {
        // The spoof scenario: a same-user process bound the API port first.
        let rows = [listening(10853, 31337)];
        assert!(!loopback_api_listener_owned_by(&rows, 10853, 4242));
    }

    #[test]
    fn established_connections_do_not_mask_a_missing_listener() {
        // The app's own gRPC client connections are ESTABLISHED rows owned by
        // the app; without a LISTEN row the verdict must still fail closed.
        let rows = [
            row(MIB_TCP_STATE_LISTEN, LOOPBACK, 10853, 4242),
            // ESTABLISHED client-side row owned by the app itself.
            row(5, LOOPBACK, 50981, 1000),
        ];
        assert!(loopback_api_listener_owned_by(&rows, 10853, 4242));
    }

    #[test]
    fn no_listener_on_the_port_fails_closed() {
        let rows = [listening(10854, 4242)];
        assert!(!loopback_api_listener_owned_by(&rows, 10853, 4242));
    }

    #[test]
    fn any_foreign_listener_on_the_port_fails_closed() {
        // Two LISTEN rows on the same port (dual bind): one owned, one not.
        let rows = [
            listening(10853, 4242),
            row(MIB_TCP_STATE_LISTEN, Ipv4Addr::LOCALHOST, 10853, 31337),
        ];
        assert!(!loopback_api_listener_owned_by(&rows, 10853, 4242));
    }

    #[test]
    fn unknown_owner_pid_fails_closed() {
        let rows = [listening(10853, 4242)];
        assert!(!loopback_api_listener_owned_by(&rows, 10853, 0));
        assert!(!loopback_api_listener_owned_by(&[], 10853, 4242));
    }

    #[test]
    fn non_loopback_listener_is_not_the_control_plane() {
        let rows = [row(
            MIB_TCP_STATE_LISTEN,
            Ipv4Addr::new(192, 168, 1, 5),
            10853,
            4242,
        )];
        assert!(!loopback_api_listener_owned_by(&rows, 10853, 4242));
    }
}
