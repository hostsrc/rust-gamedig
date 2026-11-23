//! Hostile replies: The Ship (Valve with extra fields) must return an error,
//! never panic.

use super::*;
use crate::test_support::{
    assert_no_panics,
    fixture,
    hostile_variants,
    short_lived_udp_server,
    short_timeouts,
    LARGE_DATAGRAM,
};

/// The Source info payload with The Ship's app id (2400) and its three extra
/// bytes after VAC.
fn ship_info() -> Vec<u8> {
    let source = fixture!("valve/source_info_payload.bin");
    let app_id = source
        .windows(2)
        .position(|window| window == 730u16.to_le_bytes())
        .unwrap();
    let info = [
        &source[.. app_id],
        &2400u16.to_le_bytes(),
        &source[app_id + 2 ..],
    ]
    .concat();
    let version = info
        .windows(9)
        .position(|window| window == b"1.40.0.0\x00")
        .unwrap();
    [&info[.. version], &[1, 2, 3], &info[version ..]].concat()
}

/// The players payload with The Ship's deaths and money after each player.
fn ship_players() -> Vec<u8> {
    let mut players = vec![2];
    for (index, name) in [(0, "alice"), (1, "bob")] {
        players.push(index);
        players.extend(name.as_bytes());
        players.push(0);
        players.extend(5i32.to_le_bytes()); // score
        players.extend(10f32.to_le_bytes()); // duration
        players.extend(1u32.to_le_bytes()); // deaths
        players.extend(100u32.to_le_bytes()); // money
    }
    players
}

/// A fake answering info, players and rules with the given payloads.
fn query_replies(info: Vec<u8>, players: Vec<u8>, rules: Vec<u8>) -> GDResult<Response> {
    let address = short_lived_udp_server(move |request| {
        let (kind, payload) = match request.get(4) {
            Some(0x54) => (0x49, &info),
            Some(0x55) => (0x44, &players),
            Some(0x56) => (0x45, &rules),
            _ => return Vec::new(),
        };
        vec![[&[0xFF, 0xFF, 0xFF, 0xFF, kind][..], payload].concat()]
    });
    query_with_timeout(&address.ip(), Some(address.port()), short_timeouts())
}

#[test]
fn valid_reply_is_parsed() {
    let response = query_replies(
        ship_info(),
        ship_players(),
        fixture!("valve/rules_payload.bin").to_vec(),
    )
    .unwrap();

    assert_eq!(response.name, "hostsrc CS2 test");
    assert_eq!(
        (response.mode, response.witnesses, response.duration),
        (1, 2, 3)
    );
    assert_eq!(response.players[1].name, "bob");
}

#[test]
fn hostile_replies_do_not_panic() {
    let rules = fixture!("valve/rules_payload.bin").to_vec();

    let infos = hostile_variants(&ship_info(), LARGE_DATAGRAM);
    assert_no_panics(&infos, |bytes| {
        let _ = query_replies(bytes.to_vec(), ship_players(), rules.clone());
    });

    let players = hostile_variants(&ship_players(), LARGE_DATAGRAM);
    assert_no_panics(&players, |bytes| {
        let _ = query_replies(ship_info(), bytes.to_vec(), rules.clone());
    });
}
