//! Loopback fakes and recorded packets for unit tests (no real game servers).

use crate::protocols::types::TimeoutSettings;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, UdpSocket},
    thread,
    time::Duration,
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

/// Like [fake_udp_server_with], but the server stops after two seconds without
/// a request, so a test can start one per hostile reply.
pub(crate) fn short_lived_udp_server(answer: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static) -> SocketAddr {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let address = server.local_addr().unwrap();
    thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, peer)) = server.recv_from(&mut buf) {
            for reply in answer(&buf[.. n]) {
                // The client may be gone already; that's fine.
                let _ = server.send_to(&reply, peer);
            }
        }
    });
    address
}

/// A TCP server on `127.0.0.1` for one connection: it reads the request (until
/// the client pauses), sends `reply`, and closes its side.
#[cfg_attr(not(feature = "games"), allow(dead_code))] // Minecraft and Eco tests
pub(crate) fn one_shot_tcp_server(reply: Vec<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else { return };
        let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
        let mut request = [0; 4096];
        while matches!(stream.read(&mut request), Ok(n) if n > 0) {}
        // The client may stop reading early (a capped reply); ignore errors.
        let _ = stream.write_all(&reply);
        let _ = stream.shutdown(Shutdown::Write);
        // Drain until the client closes, so unread data doesn't turn the close
        // into a reset that could drop the reply.
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        while matches!(stream.read(&mut request), Ok(n) if n > 0) {}
    });
    address
}

/// An HTTP/1.1 response with `body` and a Content-Length header.
#[cfg_attr(not(feature = "games"), allow(dead_code))] // Minecraft and Eco tests
pub(crate) fn http_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

/// Read and write timeouts of 300 ms and no retries, for queries that are
/// expected to fail fast.
pub(crate) fn short_timeouts() -> Option<TimeoutSettings> {
    TimeoutSettings::new(
        Some(Duration::from_millis(300)),
        Some(Duration::from_millis(300)),
        Some(Duration::from_millis(300)),
        0,
    )
    .ok()
}

/// `length` bytes of deterministic garbage (xorshift), seeded by `seed`.
pub(crate) fn garbage(length: usize, seed: u32) -> Vec<u8> {
    let mut state = seed | 1;
    (0 .. length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

/// Hostile versions of the valid reply `valid`, each with a label:
/// - empty;
/// - every truncation of `valid`;
/// - NUL-filled, 0xFF-filled and garbage of the same length;
/// - `valid` followed by garbage, garbage, and NULs, `oversized` bytes long.
pub(crate) fn hostile_variants(valid: &[u8], oversized: usize) -> Vec<(String, Vec<u8>)> {
    let mut variants = vec![("empty".to_string(), Vec::new())];
    for length in 1 .. valid.len() {
        variants.push((
            format!("truncated to {length} bytes"),
            valid[.. length].to_vec(),
        ));
    }
    variants.push(("NUL-filled".to_string(), vec![0; valid.len()]));
    variants.push(("0xFF-filled".to_string(), vec![0xFF; valid.len()]));
    variants.push(("garbage".to_string(), garbage(valid.len(), 7)));
    let mut long = valid.to_vec();
    long.extend(garbage(oversized.saturating_sub(valid.len()), 11));
    variants.push((format!("valid then garbage to {oversized} bytes"), long));
    variants.push((
        format!("{oversized} bytes of garbage"),
        garbage(oversized, 13),
    ));
    variants.push((format!("{oversized} NUL bytes"), vec![0; oversized]));
    variants
}

/// The largest datagram the loopback tests send. macOS limits UDP datagrams to
/// 9216 bytes by default (`net.inet.udp.maxdgram`).
pub(crate) const LARGE_DATAGRAM: usize = 9000;

/// Run `check` on every variant, 32 at a time in their own threads, and fail
/// with the labels of the variants it panicked on.
pub(crate) fn assert_no_panics(variants: &[(String, Vec<u8>)], check: impl Fn(&[u8]) + Sync) {
    let mut panicked = Vec::new();
    for batch in variants.chunks(32) {
        thread::scope(|scope| {
            let handles: Vec<_> = batch
                .iter()
                .map(|(label, bytes)| (label, scope.spawn(|| check(bytes))))
                .collect();
            for (label, handle) in handles {
                if handle.join().is_err() {
                    panicked.push(label.clone());
                }
            }
        });
    }
    assert!(panicked.is_empty(), "panicked on: {panicked:?}");
}

/// The test binary's allocator: the system one, which also records the largest
/// single allocation made on a thread inside [largest_allocation]. Allocations
/// on other threads (the fake servers) aren't recorded.
struct TrackingAllocator;

thread_local! {
    /// The largest allocation so far, while a [largest_allocation] call runs.
    static LARGEST: Cell<Option<usize>> = const { Cell::new(None) };
}

fn note_allocation(size: usize) {
    // `try_with`: the thread-local may already be gone while a thread exits.
    let _ = LARGEST.try_with(|largest| {
        if let Some(max) = largest.get() {
            largest.set(Some(max.max(size)));
        }
    });
}

// SAFETY: every call is forwarded unchanged to `System`; only sizes are noted.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_allocation(layout.size());
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_allocation(layout.size());
        // SAFETY: as for `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note_allocation(new_size);
        // SAFETY: the caller upholds `GlobalAlloc::realloc`'s contract.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller upholds `GlobalAlloc::dealloc`'s contract.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

/// Run `f` and return its result with the size of the largest single
/// allocation it made on this thread. Some platforms hand out huge allocations
/// lazily, so a test can't rely on one failing.
pub(crate) fn largest_allocation<T>(f: impl FnOnce() -> T) -> (T, usize) {
    LARGEST.with(|largest| largest.set(Some(0)));
    let result = f();
    let largest = LARGEST.with(|largest| largest.replace(None)).unwrap_or(0);
    (result, largest)
}

/// A bound for one query's largest allocation: the 64 KiB UDP buffer and a
/// 1 MiB TCP/HTTP reply fit, anything sized from a hostile count doesn't.
pub(crate) const ALLOCATION_LIMIT: usize = 2 * 1024 * 1024;
