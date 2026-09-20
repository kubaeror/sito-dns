//! Socket helpers shared by the TCP-based listeners.

use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use tokio::net::TcpListener;

/// Binds a TCP listener with explicit socket options.
///
/// `SO_REUSEADDR` is enabled so a restart or an in-process listener rebind can
/// succeed while old connections are still in `TIME_WAIT`.
///
/// IPv6 sockets are set to `IPV6_V6ONLY` so the default
/// `dns.bind = ["0.0.0.0", "::"]` list can bind both families. Without this,
/// Linux (`net.ipv6.bindv6only = 0`) makes the `::` socket dual-stack, and
/// binding it after `0.0.0.0` fails with `EADDRINUSE`.
pub fn bind_tcp_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = Domain::for_address(addr);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&socket2::SockAddr::from(addr))?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shipped default bind list must not self-conflict on dual-stack hosts.
    #[tokio::test]
    async fn test_default_bind_list_binds_both_families() {
        let v4 = bind_tcp_listener("0.0.0.0:0".parse().expect("addr")).expect("bind v4");
        let port = v4.local_addr().expect("local_addr").port();
        let v6 = bind_tcp_listener(SocketAddr::new("::".parse().expect("ip"), port))
            .expect("bind v6 after v4");
        assert!(v4.local_addr().expect("v4").port() > 0);
        assert!(v6.local_addr().expect("v6").port() > 0);
    }

    /// A rebind must succeed while a client connection is in TIME_WAIT.
    #[tokio::test]
    async fn test_rebind_with_reuseaddr() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let first = bind_tcp_listener("127.0.0.1:0".parse().expect("addr")).expect("bind");
        let addr = first.local_addr().expect("addr");
        let task = tokio::spawn(async move {
            if let Ok((mut stream, _)) = first.accept().await {
                let _ = stream.write_all(b"x").await;
                let _ = stream.shutdown().await;
            }
        });
        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut buf = [0u8; 1];
        let _ = client.read(&mut buf).await;
        drop(client);
        let again = bind_tcp_listener(addr).expect("rebind with SO_REUSEADDR");
        assert_eq!(again.local_addr().expect("addr"), addr);
        let _ = task.await;
    }
}
