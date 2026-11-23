//! Hostile replies: Quake 1, 2 and 3 must return an error or a capped result,
//! never panic.

use crate::protocols::quake::{one, three, two};
use crate::test_support::{
    assert_no_panics,
    fixture,
    hostile_variants,
    short_lived_udp_server,
    short_timeouts,
    LARGE_DATAGRAM,
};
use std::net::SocketAddr;

fn server(reply: &[u8]) -> SocketAddr {
    let reply = reply.to_vec();
    short_lived_udp_server(move |_| vec![reply.clone()])
}

/// `players_online` was `players.len() as u8`: 300 players gave 44.
#[test]
fn more_than_255_players_saturate() {
    let mut reply = b"\xFF\xFF\xFF\xFFstatusResponse\n\\sv_hostname\\h\\mapname\\m\\sv_maxclients\\64\n".to_vec();
    for i in 0 .. 300 {
        reply.extend(format!("{i} 0 \"p{i}\"\n").into_bytes());
    }

    let response = three::query(&server(&reply), short_timeouts()).unwrap();

    assert_eq!(response.players.len(), 300);
    assert_eq!(response.players_online, 255);
}

#[test]
fn hostile_replies_do_not_panic() {
    let q1 = hostile_variants(fixture!("quake/q1_status_2_players.bin"), LARGE_DATAGRAM);
    assert_no_panics(&q1, |bytes| {
        let _ = one::query(&server(bytes), short_timeouts());
    });

    let q2 = hostile_variants(fixture!("quake/q2_status_2_players.bin"), LARGE_DATAGRAM);
    assert_no_panics(&q2, |bytes| {
        let _ = two::query(&server(bytes), short_timeouts());
    });

    let q3 = hostile_variants(fixture!("quake/q3_status_3_players.bin"), LARGE_DATAGRAM);
    assert_no_panics(&q3, |bytes| {
        let _ = three::query(&server(bytes), short_timeouts());
    });
}

/// The header followed by NULs, by lone quotes, and by player lines with
/// numbers too large for their fields.
#[test]
fn hostile_bodies_do_not_panic() {
    let header = b"\xFF\xFF\xFF\xFFstatusResponse\n".to_vec();
    let bodies: Vec<(String, Vec<u8>)> = [
        &b"\x00\x00\x00\x00"[..],
        b"\\sv_hostname\\h\\mapname\\m\\sv_maxclients\\8\n\"\n\"\"\n\" \" \"\n",
        b"\\sv_hostname\\h\\mapname\\m\\sv_maxclients\\99999\n",
        b"\\sv_hostname\\h\\mapname\\m\\sv_maxclients\\8\n99999999999 99999999999 \"x\"\n",
        b"\\\\\\\\\\\\\n\n\n",
    ]
    .iter()
    .enumerate()
    .map(|(i, body)| (format!("body {i}"), [&header[..], body].concat()))
    .collect();

    assert_no_panics(&bodies, |bytes| {
        let _ = three::query(&server(bytes), short_timeouts());
        let _ = two::query(&server(bytes), short_timeouts());
        let _ = one::query(&server(bytes), short_timeouts());
    });
}
