//! Hostile replies: GameSpy 2 must return an error or a capped result, never
//! panic.

use super::*;
use crate::test_support::{
    assert_no_panics,
    fixture,
    hostile_variants,
    short_lived_udp_server,
    short_timeouts,
    LARGE_DATAGRAM,
};

fn query_reply(reply: Vec<u8>) -> GDResult<Response> {
    let address = short_lived_udp_server(move |_| vec![reply.clone()]);
    query(&address, short_timeouts())
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
    let response = query_reply(fixture!("gamespy2/status.bin").to_vec()).unwrap();

    assert_eq!(response.name, "hostsrc GS2 test");
    assert_eq!((response.players_online, response.players_maximum), (2, 16));
    assert_eq!(response.players[1].name, "bob");
    assert_eq!(response.teams[0].name, "Red");
}

/// `numplayers` above u32::MAX was cast with `as` and wrapped.
#[test]
fn huge_numplayers_saturates() {
    let reply = edited(
        fixture!("gamespy2/status.bin"),
        b"numplayers\x002\x00",
        b"numplayers\x0099999999999\x00",
    );

    assert_eq!(query_reply(reply).unwrap().players_online, u32::MAX);
}

/// A table claiming 255 rows when 2 arrived is an error.
#[test]
fn table_claiming_255_rows_is_an_error() {
    let reply = edited(
        fixture!("gamespy2/status.bin"),
        b"\x00\x02player_",
        b"\x00\xFFplayer_",
    );

    assert!(query_reply(reply).is_err());
}

#[test]
fn hostile_replies_do_not_panic() {
    let variants = hostile_variants(fixture!("gamespy2/status.bin"), LARGE_DATAGRAM);

    assert_no_panics(&variants, |bytes| {
        let _ = query_reply(bytes.to_vec());
    });
}
