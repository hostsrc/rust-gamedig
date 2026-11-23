//! Hostile replies: Mindustry must return an error, never panic.

use super::*;
use crate::buffer::Utf8LengthPrefixedDecoder;
use crate::test_support::{
    assert_no_panics,
    fixture,
    hostile_variants,
    short_lived_udp_server,
    short_timeouts,
    LARGE_DATAGRAM,
};
use byteorder::BigEndian;

fn query_reply(reply: &[u8]) -> GDResult<ServerData> {
    let reply = reply.to_vec();
    let address = short_lived_udp_server(move |_| vec![reply.clone()]);
    query(&address, &short_timeouts())
}

fn parse(data: &[u8]) -> GDResult<ServerData> {
    parse_server_data::<BigEndian, Utf8LengthPrefixedDecoder>(&mut Buffer::new(data))
}

#[test]
fn valid_reply_is_parsed() {
    let response = query_reply(fixture!("mindustry/pong.bin")).unwrap();

    assert_eq!(response.host, "hostsrc Mindustry");
    assert_eq!((response.players, response.player_limit), (3, 20));
    assert_eq!(response.mode_name.as_deref(), Some("survival"));
}

#[test]
fn hostile_replies_do_not_panic() {
    let datagrams = hostile_variants(fixture!("mindustry/pong.bin"), LARGE_DATAGRAM);
    assert_no_panics(&datagrams, |bytes| {
        let _ = query_reply(bytes);
    });

    // The parser alone, with payloads larger than a datagram.
    let payloads = hostile_variants(fixture!("mindustry/pong.bin"), 70_000);
    assert_no_panics(&payloads, |bytes| {
        let _ = parse(bytes);
    });
}
