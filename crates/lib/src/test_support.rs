//! Loopback fakes and recorded packets for unit tests (no real game servers).

use std::{
    net::{SocketAddr, UdpSocket},
    thread,
};

/// The bytes of a fixture file under `crates/lib/tests/fixtures/`.
macro_rules! fixture {
    ($path: literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/",
            $path
        ))
        .as_slice()
    };
}

pub(crate) use fixture;

/// A UDP server on `127.0.0.1` that answers every request with `replies`, in
/// order, one datagram each. It runs until the test process ends.
pub(crate) fn fake_udp_server(replies: Vec<Vec<u8>>) -> SocketAddr {
    fake_udp_server_with(move |_request| replies.clone())
}

/// A UDP server on `127.0.0.1` that answers each request with the datagrams
/// `answer` returns for it. It runs until the test process ends.
pub(crate) fn fake_udp_server_with(answer: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static) -> SocketAddr {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = server.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = server.recv_from(&mut buf) {
            for reply in answer(&buf[.. n]) {
                server.send_to(&reply, peer).unwrap();
            }
        }
    });
    address
}
