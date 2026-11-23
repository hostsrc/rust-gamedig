use crate::{
    protocols::types::TimeoutSettings,
    GDErrorKind::{PacketReceive, PacketSend, SocketBind, SocketConnect},
    GDResult,
};

use std::{
    io::{Read, Write},
    net::{self, Ipv4Addr, Ipv6Addr, SocketAddr},
};

/// Receive buffer for one UDP datagram: 64 KiB, more than the largest UDP
/// payload (65 507 bytes over IPv4, 65 527 over IPv6). A datagram longer
/// than the buffer is cut off silently by the OS, so UDP sockets always read
/// into a buffer this size, whatever size the caller asks for.
pub(crate) const UDP_RECEIVE_BUFFER: usize = 64 * 1024;

/// The local address to bind a UDP socket to for `target`: the wildcard
/// address of the same family, any port. An IPv4 socket can't send to an IPv6
/// address and the reverse.
pub(crate) fn udp_bind_address(target: &SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    }
}

/// A trait defining the basic functionalities of a network socket.
pub trait Socket {
    /// Create a new socket and connect to the remote address.
    ///
    /// # Arguments
    /// * `address` - The address to connect the socket to.
    /// * `timeout_settings` - Optional timeout settings for the socket.
    ///
    /// # Returns
    /// A result containing the socket instance or an error.
    fn new(address: &SocketAddr, timeout_settings: &Option<TimeoutSettings>) -> GDResult<Self>
    where Self: Sized;

    /// Apply read and write timeouts to the socket.
    ///
    /// # Arguments
    /// * `timeout_settings` - Optional timeout settings to apply.
    ///
    /// # Returns
    /// A result indicating success or error in applying timeouts.
    fn apply_timeout(&self, timeout_settings: &Option<TimeoutSettings>) -> GDResult<()>;

    /// Send data over the socket.
    ///
    /// # Arguments
    /// * `data` - Data to be sent.
    ///
    /// # Returns
    /// A result indicating success or error in sending data.
    fn send(&mut self, data: &[u8]) -> GDResult<()>;

    /// Receive data from the socket.
    ///
    /// # Arguments
    /// * `size` - Optional size of data to receive.
    ///
    /// # Returns
    /// A result containing received data or an error.
    fn receive(&mut self, size: Option<usize>) -> GDResult<Vec<u8>>;

    /// Get the remote port of the socket.
    ///
    /// # Returns
    /// The port number.
    fn port(&self) -> u16;

    /// Get the local SocketAddr.
    ///
    /// # Returns
    /// The local SocketAddr.
    #[cfg(feature = "packet_capture")]
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
}

/// Implementation of a TCP socket.
pub struct TcpSocketImpl {
    /// The underlying TCP socket stream.
    socket: net::TcpStream,
    /// The address of the remote host.
    address: SocketAddr,
}

impl Socket for TcpSocketImpl {
    fn new(address: &SocketAddr, timeout_settings: &Option<TimeoutSettings>) -> GDResult<Self> {
        let socket = TimeoutSettings::get_connect_or_default(timeout_settings).map_or_else(
            || net::TcpStream::connect(address),
            |timeout| net::TcpStream::connect_timeout(address, timeout),
        );

        let socket = Self {
            socket: socket.map_err(|e| SocketConnect.context(e))?,
            address: *address,
        };

        socket.apply_timeout(timeout_settings)?;

        Ok(socket)
    }

    fn apply_timeout(&self, timeout_settings: &Option<TimeoutSettings>) -> GDResult<()> {
        let (read, write) = TimeoutSettings::get_read_and_write_or_defaults(timeout_settings);
        self.socket.set_read_timeout(read).unwrap(); // unwrapping because TimeoutSettings::new
        self.socket.set_write_timeout(write).unwrap(); // checks if these are 0 and throws an error

        Ok(())
    }

    fn send(&mut self, data: &[u8]) -> GDResult<()> {
        self.socket.write(data).map_err(|e| PacketSend.context(e))?;
        Ok(())
    }

    fn receive(&mut self, size: Option<usize>) -> GDResult<Vec<u8>> {
        let mut buf = Vec::with_capacity(size.unwrap_or(1024));
        self.socket
            .read_to_end(&mut buf)
            .map_err(|e| PacketReceive.context(e))?;

        Ok(buf)
    }

    fn port(&self) -> u16 { self.address.port() }

    #[cfg(feature = "packet_capture")]
    fn local_addr(&self) -> std::io::Result<SocketAddr> { self.socket.local_addr() }
}

/// Implementation of a UDP socket.
///
/// The socket is bound to the target's address family and connected to the
/// target, so the OS only delivers datagrams that come from the target's
/// address and port: stray or spoofed replies from anywhere else are dropped.
pub struct UdpSocketImpl {
    /// The underlying UDP socket, connected to the remote host.
    socket: net::UdpSocket,
    /// Reused receive buffer of [UDP_RECEIVE_BUFFER] bytes.
    buffer: Vec<u8>,
}

impl Socket for UdpSocketImpl {
    fn new(address: &SocketAddr, timeout_settings: &Option<TimeoutSettings>) -> GDResult<Self> {
        let socket = net::UdpSocket::bind(udp_bind_address(address)).map_err(|e| SocketBind.context(e))?;
        socket
            .connect(address)
            .map_err(|e| SocketConnect.context(e))?;

        let socket = Self {
            socket,
            buffer: vec![0; UDP_RECEIVE_BUFFER],
        };

        socket.apply_timeout(timeout_settings)?;

        Ok(socket)
    }

    fn apply_timeout(&self, timeout_settings: &Option<TimeoutSettings>) -> GDResult<()> {
        let (read, write) = TimeoutSettings::get_read_and_write_or_defaults(timeout_settings);
        self.socket.set_read_timeout(read).unwrap(); // unwrapping because TimeoutSettings::new
        self.socket.set_write_timeout(write).unwrap(); // checks if these are 0 and throws an error

        Ok(())
    }

    fn send(&mut self, data: &[u8]) -> GDResult<()> {
        self.socket.send(data).map_err(|e| PacketSend.context(e))?;

        Ok(())
    }

    /// Receive one datagram from the target. `size` is ignored: the whole
    /// datagram is always read (up to [UDP_RECEIVE_BUFFER] bytes), because a
    /// smaller buffer would only cut it off.
    fn receive(&mut self, _size: Option<usize>) -> GDResult<Vec<u8>> {
        let number_of_bytes_received = self
            .socket
            .recv(&mut self.buffer)
            .map_err(|e| PacketReceive.context(e))?;

        Ok(self.buffer[.. number_of_bytes_received].to_vec())
    }

    fn port(&self) -> u16 {
        // The socket is connected in `new`, so it always has a peer.
        self.socket.peer_addr().map_or(0, |address| address.port())
    }

    #[cfg(feature = "packet_capture")]
    fn local_addr(&self) -> std::io::Result<SocketAddr> { self.socket.local_addr() }
}

/// Non-blocking UDP socket built on Tokio.
///
/// Mirrors [UdpSocketImpl]: binds an ephemeral local port of the target's
/// address family, connects to the target (so datagrams from any other source
/// are dropped by the OS) and reads whole datagrams into a
/// [UDP_RECEIVE_BUFFER] buffer. Read and write timeouts from
/// [TimeoutSettings] are enforced with [tokio::time::timeout]; an elapsed
/// timeout is reported as [PacketReceive] / [PacketSend] so the existing retry
/// logic applies.
///
/// Packet capture is not supported on this socket.
#[cfg(feature = "tokio")]
pub(crate) struct AsyncUdpSocket {
    socket: ::tokio::net::UdpSocket,
    read_timeout: Option<std::time::Duration>,
    write_timeout: Option<std::time::Duration>,
    buffer: Vec<u8>,
}

#[cfg(feature = "tokio")]
impl AsyncUdpSocket {
    pub(crate) async fn new(address: &SocketAddr, timeout_settings: &Option<TimeoutSettings>) -> GDResult<Self> {
        let socket = ::tokio::net::UdpSocket::bind(udp_bind_address(address))
            .await
            .map_err(|e| SocketBind.context(e))?;
        socket
            .connect(address)
            .await
            .map_err(|e| SocketConnect.context(e))?;
        let (read_timeout, write_timeout) = TimeoutSettings::get_read_and_write_or_defaults(timeout_settings);

        Ok(Self {
            socket,
            read_timeout,
            write_timeout,
            buffer: vec![0; UDP_RECEIVE_BUFFER],
        })
    }

    pub(crate) async fn send(&mut self, data: &[u8]) -> GDResult<()> {
        let send = self.socket.send(data);
        let result = match self.write_timeout {
            Some(timeout) => {
                ::tokio::time::timeout(timeout, send)
                    .await
                    .map_err(|e| PacketSend.context(e))?
            }
            None => send.await,
        };

        result.map_err(|e| PacketSend.context(e))?;
        Ok(())
    }

    /// Receive one datagram from the target. `size` is ignored, as in
    /// [UdpSocketImpl::receive].
    pub(crate) async fn receive(&mut self, _size: Option<usize>) -> GDResult<Vec<u8>> {
        let recv = self.socket.recv(&mut self.buffer);
        let result = match self.read_timeout {
            Some(timeout) => {
                ::tokio::time::timeout(timeout, recv)
                    .await
                    .map_err(|e| PacketReceive.context(e))?
            }
            None => recv.await,
        };

        let number_of_bytes_received = result.map_err(|e| PacketReceive.context(e))?;
        Ok(self.buffer[.. number_of_bytes_received].to_vec())
    }
}

#[cfg(not(feature = "packet_capture"))]
pub type UdpSocket = UdpSocketImpl;
#[cfg(not(feature = "packet_capture"))]
pub type TcpSocket = TcpSocketImpl;

#[cfg(feature = "packet_capture")]
pub(crate) type UdpSocket = crate::capture::socket::CapturedUdpSocket;
#[cfg(feature = "packet_capture")]
pub(crate) type TcpSocket = crate::capture::socket::CapturedTcpSocket;

#[cfg(test)]
mod tests {
    use std::{io::Read, thread};

    use super::*;

    #[test]
    fn test_tcp_socket_send_and_receive() {
        // Spawn a thread to run the server
        let listener = net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bound_address = listener.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0; 1024];
            let _ = stream.read(&mut buf).unwrap();
            let _ = stream.write(&buf).unwrap();
        });

        // Create a TCP socket and send a message to the server
        let mut socket = TcpSocket::new(&bound_address, &None).unwrap();
        let message = b"hello, world!";
        socket.send(message).unwrap();

        // Receive the response from the server
        let received_message: Vec<u8> = socket
            .receive(None)
            .unwrap()
            // Iterate over the buffer and remove 0s that are alone in the buffer
            // just added to pass default size
            .into_iter()
            .filter(|&x| x != 0)
            .collect();

        server_thread.join().expect("server thread panicked");

        assert_eq!(message, &received_message[..]);
    }

    #[test]
    fn test_udp_socket_send_and_receive() {
        // Spawn a thread to run the server
        let socket = net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let bound_address = socket.local_addr().unwrap();
        let server_thread = thread::spawn(move || {
            let mut buf = [0; 1024];
            let (_, src_addr) = socket.recv_from(&mut buf).unwrap();
            socket.send_to(&buf, src_addr).unwrap();
        });

        // Create a UDP socket and send a message to the server
        let mut socket = UdpSocket::new(&bound_address, &None).unwrap();
        let message = b"hello, world!";
        socket.send(message).unwrap();

        // Receive the response from the server
        let received_message: Vec<u8> = socket
            .receive(None)
            .unwrap()
            // Iterate over the buffer and remove 0s that are alone in the buffer
            // just added to pass default size
            .into_iter()
            .filter(|&x| x != 0)
            .collect();

        server_thread.join().expect("server thread panicked");

        assert_eq!(message, &received_message[..]);
    }

    fn short_timeouts() -> Option<TimeoutSettings> {
        TimeoutSettings::new(
            Some(std::time::Duration::from_secs(2)),
            Some(std::time::Duration::from_secs(2)),
            None,
            0,
        )
        .ok()
    }

    /// An IPv6 loopback UDP server, or `None` when the host has no IPv6.
    fn ipv6_loopback() -> Option<net::UdpSocket> {
        match net::UdpSocket::bind("[::1]:0") {
            Ok(socket) => Some(socket),
            Err(e) => {
                eprintln!("skipping: no IPv6 loopback ({e})");
                None
            }
        }
    }

    /// Echo one datagram back to its sender.
    fn echo_once(server: net::UdpSocket) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut buf = [0; 2048];
            let (n, peer) = server.recv_from(&mut buf).unwrap();
            server.send_to(&buf[.. n], peer).unwrap();
        })
    }

    /// The socket used to be bound to `0.0.0.0:0` whatever the target, so
    /// sending to an IPv6 address failed.
    #[test]
    fn udp_socket_reaches_an_ipv6_target() {
        let Some(server) = ipv6_loopback() else { return };
        let address = server.local_addr().unwrap();
        let server_thread = echo_once(server);

        let mut socket = UdpSocket::new(&address, &short_timeouts()).unwrap();
        socket.send(b"hello over ipv6").unwrap();
        assert_eq!(socket.receive(None).unwrap(), b"hello over ipv6");
        server_thread.join().unwrap();
    }

    /// Send `spoof` to the client from another port, then `reply` from the
    /// server itself.
    fn reply_after_a_spoofed_datagram(server: net::UdpSocket) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let mut buf = [0; 2048];
            let (_, peer) = server.recv_from(&mut buf).unwrap();
            let other = net::UdpSocket::bind("127.0.0.1:0").unwrap();
            other.send_to(b"spoof", peer).unwrap();
            server.send_to(b"reply", peer).unwrap();
        })
    }

    /// The socket used to take the first datagram from any source; connected,
    /// the OS drops datagrams that don't come from the target.
    #[test]
    fn udp_socket_ignores_datagrams_from_other_sources() {
        let server = net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let server_thread = reply_after_a_spoofed_datagram(server);

        let mut socket = UdpSocket::new(&address, &short_timeouts()).unwrap();
        socket.send(b"request").unwrap();
        server_thread.join().unwrap();
        assert_eq!(socket.receive(None).unwrap(), b"reply");
    }

    /// A datagram larger than the old 1024-byte default (or than the size the
    /// caller asks for) is read whole. 9000 bytes stays under macOS's default
    /// `net.inet.udp.maxdgram` (9216).
    #[test]
    fn udp_socket_reads_a_whole_large_datagram() {
        let server = net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let big: Vec<u8> = (0 .. 9000u32).map(|i| (i % 251) as u8 + 1).collect();
        let expected = big.clone();
        let server_thread = thread::spawn(move || {
            let mut buf = [0; 64];
            let (_, peer) = server.recv_from(&mut buf).unwrap();
            server.send_to(&big, peer).unwrap();
            server.send_to(&big, peer).unwrap();
        });

        let mut socket = UdpSocket::new(&address, &short_timeouts()).unwrap();
        socket.send(b"request").unwrap();
        assert_eq!(socket.receive(None).unwrap(), expected);
        assert_eq!(socket.receive(Some(16)).unwrap(), expected);
        server_thread.join().unwrap();
    }

    #[cfg(feature = "tokio")]
    #[::tokio::test]
    async fn async_udp_socket_reaches_an_ipv6_target() {
        let Some(server) = ipv6_loopback() else { return };
        let address = server.local_addr().unwrap();
        let server_thread = echo_once(server);

        let mut socket = AsyncUdpSocket::new(&address, &short_timeouts())
            .await
            .unwrap();
        socket.send(b"hello over ipv6").await.unwrap();
        assert_eq!(socket.receive(None).await.unwrap(), b"hello over ipv6");
        server_thread.join().unwrap();
    }

    #[cfg(feature = "tokio")]
    #[::tokio::test]
    async fn async_udp_socket_ignores_datagrams_from_other_sources() {
        let server = net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let server_thread = reply_after_a_spoofed_datagram(server);

        let mut socket = AsyncUdpSocket::new(&address, &short_timeouts())
            .await
            .unwrap();
        socket.send(b"request").await.unwrap();
        server_thread.join().unwrap();
        assert_eq!(socket.receive(None).await.unwrap(), b"reply");
    }

    #[cfg(feature = "tokio")]
    #[::tokio::test]
    async fn async_udp_socket_reads_a_whole_large_datagram() {
        let server = net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let big: Vec<u8> = (0 .. 9000u32).map(|i| (i % 251) as u8 + 1).collect();
        let expected = big.clone();
        let server_thread = thread::spawn(move || {
            let mut buf = [0; 64];
            let (_, peer) = server.recv_from(&mut buf).unwrap();
            server.send_to(&big, peer).unwrap();
        });

        let mut socket = AsyncUdpSocket::new(&address, &short_timeouts())
            .await
            .unwrap();
        socket.send(b"request").await.unwrap();
        server_thread.join().unwrap();
        assert_eq!(socket.receive(Some(1400)).await.unwrap(), expected);
    }
}
