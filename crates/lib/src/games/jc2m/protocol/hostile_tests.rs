//! Hostile replies: JC2M (GameSpy 3, single packet) must return an error or a
//! capped result, never panic or size an allocation from the reply.

use super::*;
use crate::test_support::{
    assert_no_panics,
    fixture,
    hostile_variants,
    largest_allocation,
    short_lived_udp_server,
    short_timeouts,
    ALLOCATION_LIMIT,
    LARGE_DATAGRAM,
};

fn query_data(data: Vec<u8>) -> GDResult<Response> {
    let address = short_lived_udp_server(move |request| {
        match request.get(2) {
            Some(9) => vec![fixture!("gamespy3/challenge.bin").to_vec()],
            _ => vec![data.clone()],
        }
    });
    query_with_timeout(&address.ip(), Some(address.port()), short_timeouts())
}

/// `reply` with the bytes `from` replaced by `to` (once).
fn edited(reply: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let at = reply
        .windows(from.len())
        .position(|window| window == from)
        .unwrap();
    [&reply[.. at], to, &reply[at + from.len() ..]].concat()
}

#[test]
fn valid_reply_is_parsed() {
    let response = query_data(fixture!("jc2m/status.bin").to_vec()).unwrap();

    assert_eq!(response.name, "hostsrc JC2MP test");
    assert_eq!(
        (response.players_online, response.players_maximum),
        (2, 500)
    );
    assert_eq!(response.players[1].name, "bob");
}

/// The player count pre-allocated up to 65535 players.
#[test]
fn player_count_does_not_size_an_allocation() {
    let reply = edited(
        fixture!("jc2m/status.bin"),
        b"\x00\x00\x02alice",
        b"\x00\xFF\xFFalice",
    );

    let (response, largest) = largest_allocation(|| query_data(reply));

    assert!(largest < ALLOCATION_LIMIT, "allocated {largest} bytes");
    assert_eq!(response.unwrap().players.len(), 2);
}

/// `numplayers` above u32::MAX was cast with `as` and wrapped.
#[test]
fn huge_numplayers_saturates() {
    let reply = edited(
        fixture!("jc2m/status.bin"),
        b"numplayers\x002\x00",
        b"numplayers\x0099999999999\x00",
    );

    assert_eq!(query_data(reply).unwrap().players_online, u32::MAX);
}

#[test]
fn hostile_replies_do_not_panic() {
    let variants = hostile_variants(fixture!("jc2m/status.bin"), LARGE_DATAGRAM);

    assert_no_panics(&variants, |bytes| {
        let _ = query_data(bytes.to_vec());
    });
}
