//! Low-level socket options for IP_PKTINFO and IPV6_RECVPKTINFO on multi-homed systems.

#![allow(clippy::all, clippy::pedantic)]

use std::net::{IpAddr, SocketAddr};
use std::os::fd::RawFd;
use tracing::warn;

/// Enable packet info reception on the raw socket file descriptor.
pub fn enable_pktinfo(fd: RawFd, addr: &SocketAddr) -> bool {
    let res = match addr {
        SocketAddr::V4(_) => {
            let opt: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(_) => {
            let opt: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_RECVPKTINFO,
                    &opt as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&opt) as libc::socklen_t,
                )
            }
        }
    };

    if res != 0 {
        warn!(
            "Failed to enable PKTINFO on socket for {addr}, falling back to standard socket operations"
        );
        false
    } else {
        true
    }
}

/// Receive a packet along with the local destination address it was sent to, if available.
pub fn recv_with_pktinfo(
    fd: RawFd,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let mut src_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut control_buf = [0u8; 512];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src_storage as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of_val(&src_storage) as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control_buf.len() as _;

    let bytes_read = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if bytes_read < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let src_addr = sockaddr_to_socket_addr(&src_storage)?;
    let mut dst_ip = None;

    // Parse control messages
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let level = (*cmsg).cmsg_level;
            let msg_type = (*cmsg).cmsg_type;

            if level == libc::IPPROTO_IP && msg_type == libc::IP_PKTINFO {
                let pktinfo = libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo;
                if !pktinfo.is_null() {
                    let in_addr = (*pktinfo).ipi_spec_dst;
                    let v4 = std::net::Ipv4Addr::from(u32::from_be(in_addr.s_addr));
                    dst_ip = Some(IpAddr::V4(v4));
                }
            } else if level == libc::IPPROTO_IPV6 && msg_type == libc::IPV6_PKTINFO {
                let pktinfo = libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo;
                if !pktinfo.is_null() {
                    let in6_addr = (*pktinfo).ipi6_addr;
                    let v6 = std::net::Ipv6Addr::from(in6_addr.s6_addr);
                    dst_ip = Some(IpAddr::V6(v6));
                }
            }

            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok((bytes_read as usize, src_addr, dst_ip))
}

/// Send a packet ensuring the source address matches local_dst_ip, if specified.
pub fn send_with_pktinfo(
    fd: RawFd,
    buf: &[u8],
    peer_addr: &SocketAddr,
    local_src_ip: Option<IpAddr>,
) -> std::io::Result<usize> {
    let Some(src_ip) = local_src_ip else {
        // Fallback to sendto
        return send_to_raw(fd, buf, peer_addr);
    };

    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let mut target_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let target_len = socket_addr_to_sockaddr(peer_addr, &mut target_storage);

    let mut control_buf = [0u8; 128];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut target_storage as *mut _ as *mut libc::c_void;
    msg.msg_namelen = target_len;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = 0;

    match (src_ip, peer_addr) {
        (IpAddr::V4(v4), SocketAddr::V4(_)) => unsafe {
            let cmsg_space =
                libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize;
            if cmsg_space <= control_buf.len() {
                msg.msg_controllen = cmsg_space as _;
                let cmsg = libc::CMSG_FIRSTHDR(&mut msg);
                if !cmsg.is_null() {
                    (*cmsg).cmsg_level = libc::IPPROTO_IP;
                    (*cmsg).cmsg_type = libc::IP_PKTINFO;
                    (*cmsg).cmsg_len =
                        libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as _;

                    let data = libc::CMSG_DATA(cmsg) as *mut libc::in_pktinfo;
                    (*data).ipi_ifindex = 0;
                    (*data).ipi_spec_dst = libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    };
                }
            }
        },
        (IpAddr::V6(v6), SocketAddr::V6(_)) => unsafe {
            let cmsg_space =
                libc::CMSG_SPACE(std::mem::size_of::<libc::in6_pktinfo>() as u32) as usize;
            if cmsg_space <= control_buf.len() {
                msg.msg_controllen = cmsg_space as _;
                let cmsg = libc::CMSG_FIRSTHDR(&mut msg);
                if !cmsg.is_null() {
                    (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                    (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                    (*cmsg).cmsg_len =
                        libc::CMSG_LEN(std::mem::size_of::<libc::in6_pktinfo>() as u32) as _;

                    let data = libc::CMSG_DATA(cmsg) as *mut libc::in6_pktinfo;
                    (*data).ipi6_ifindex = 0;
                    (*data).ipi6_addr = libc::in6_addr {
                        s6_addr: v6.octets(),
                    };
                }
            }
        },
        _ => {
            // Mismatched IP families, fallback to standard send
            return send_to_raw(fd, buf, peer_addr);
        }
    }

    let bytes_sent = unsafe { libc::sendmsg(fd, &msg, 0) };
    if bytes_sent < 0 {
        // If sendmsg fails (e.g. invalid source address), fall back to standard send_to
        send_to_raw(fd, buf, peer_addr)
    } else {
        Ok(bytes_sent as usize)
    }
}

fn send_to_raw(fd: RawFd, buf: &[u8], peer_addr: &SocketAddr) -> std::io::Result<usize> {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = socket_addr_to_sockaddr(peer_addr, &mut storage);
    let bytes_sent = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            0,
            &storage as *const _ as *const libc::sockaddr,
            len,
        )
    };
    if bytes_sent < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(bytes_sent as usize)
    }
}

fn sockaddr_to_socket_addr(storage: &libc::sockaddr_storage) -> std::io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { *(storage as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { *(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsupported address family",
        )),
    }
}

fn socket_addr_to_sockaddr(
    addr: &SocketAddr,
    storage: &mut libc::sockaddr_storage,
) -> libc::socklen_t {
    match addr {
        SocketAddr::V4(v4) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin as *const _ as *const u8,
                    storage as *mut _ as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    &sin6 as *const _ as *const u8,
                    storage as *mut _ as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in6>(),
                );
            }
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}
