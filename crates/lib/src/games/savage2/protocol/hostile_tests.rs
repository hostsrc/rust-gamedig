//! Hostile replies: Savage 2 must return an error, never panic.

use super::*;
use crate::test_support::{
    assert_no_panics,
    fixture,
    hostile_variants,
    short_lived_udp_server,
    short_timeouts,
    LARGE_DATAGRAM,
};

fn query_reply(reply: &[u8]) -> GDResult<Response> {
    let reply = reply.to_vec();
    let address = short_lived_udp_server(move |_| vec![reply.clone()]);
    query_with_timeout(&address.ip(), Some(address.port()), short_timeouts())
}

#[test]
fn valid_reply_is_parsed() {
    let response = query_reply(fixture!("savage2/info.bin")).unwrap();

    assert_eq!(response.name, "hostsrc Savage2 test");
    assert_eq!((response.players_online, response.players_maximum), (4, 32));
    assert_eq!(response.level_minimum, 1);
}

#[test]
fn hostile_replies_do_not_panic() {
    let variants = hostile_variants(fixture!("savage2/info.bin"), LARGE_DATAGRAM);

    assert_no_panics(&variants, |bytes| {
        let _ = query_reply(bytes);
    });
}
