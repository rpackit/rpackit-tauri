//! Audited `WinSock` options that do not have a safe `socket2` wrapper.

#![allow(unsafe_code)]

use std::{io, mem::size_of_val, os::windows::io::AsRawSocket};

use socket2::Socket;
use windows_sys::Win32::Networking::WinSock::{
    SO_EXCLUSIVEADDRUSE, SOCKET_ERROR, SOL_SOCKET, setsockopt,
};

/// Require exclusive ownership of a local address before it is bound.
pub(super) fn set_exclusive_address_use(socket: &Socket) -> io::Result<()> {
    let enabled = 1_i32;
    let raw_socket = usize::try_from(socket.as_raw_socket())
        .map_err(|_| io::Error::other("socket handle does not fit WinSock SOCKET"))?;
    let option_length = i32::try_from(size_of_val(&enabled))
        .map_err(|_| io::Error::other("socket option size does not fit WinSock length"))?;
    // SAFETY: `socket` owns a live WinSock handle for the duration of this
    // call. `enabled` is an initialized `i32`, and its pointer and exact byte
    // length are passed only for this synchronous `setsockopt` invocation.
    let result = unsafe {
        setsockopt(
            raw_socket,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            std::ptr::from_ref(&enabled).cast::<u8>(),
            option_length,
        )
    };
    if result == SOCKET_ERROR {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
