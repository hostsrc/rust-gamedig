//! Hostile replies: GameSpy 1 must return an error or a capped result, never
//! panic or size an allocation from a value the server sent.

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

/// A short valid reply with one player and the given extra entries.
fn reply_with(extra: &str) -> Vec<u8> {
    format!("\\hostname\\h\\mapname\\m\\gametype\\g\\gamever\\1\\password\\0\\maxplayers\\8{extra}\\final\\")
        .into_bytes()
}

fn query_replies(replies: Vec<Vec<u8>>) -> GDResult<Response> {
    let address = short_lived_udp_server(move |_| replies.clone());
    query(&address, short_timeouts())
}

/// `as_string.remove(0)` panicked on an empty datagram.
#[test]
fn empty_datagram_is_an_error() {
    let error = query_replies(vec![Vec::new()]).unwrap_err();
    assert_eq!(error.kind, GDErrorKind::PacketBad);
}

/// `Vec::with_capacity(maxplayers)` asked for 4294967295 player maps.
#[test]
fn huge_maxplayers_does_not_size_an_allocation() {
    let reply = String::from_utf8(reply_with("\\player_0\\alice\\frags_0\\1\\ping_0\\2"))
        .unwrap()
        .replace("\\maxplayers\\8", "\\maxplayers\\4294967295");

    let (response, largest) = largest_allocation(|| query_replies(vec![reply.into_bytes()]));
    let response = response.unwrap();

    assert!(largest < ALLOCATION_LIMIT, "allocated {largest} bytes");
    assert_eq!(response.players_maximum, u32::MAX);
    assert_eq!(response.players.len(), 1);
}

/// A player id was an index: `id - len + 1` overflowed for the largest id, and
/// a large id allocated that many player maps.
#[test]
fn huge_player_id_is_not_an_index() {
    let id = usize::MAX;
    let reply = reply_with(&format!(
        "\\player_{id}\\alice\\frags_{id}\\1\\ping_{id}\\2"
    ));

    let response = query_replies(vec![reply]).unwrap();

    assert_eq!(response.players.len(), 1);
    assert_eq!(response.players[0].name, "alice");
}

/// Players are capped at 1024; the rest stay in `unused_entries`.
#[test]
fn more_than_1024_players_are_capped() {
    let players: Vec<String> = (0 .. 2000)
        .map(|i| format!("\\player_{i}\\p{i}\\frags_{i}\\0\\ping_{i}\\0"))
        .collect();
    // Several datagrams (macOS caps loopback datagrams near 9 KB), numbered
    // with `queryid` parts; the last one carries the server values and final.
    let mut replies: Vec<Vec<u8>> = players
        .chunks(150)
        .enumerate()
        .map(|(part, chunk)| format!("{}\\queryid\\7.{}", chunk.concat(), part + 1).into_bytes())
        .collect();
    let last = String::from_utf8(reply_with(&format!("\\queryid\\7.{}", replies.len() + 1))).unwrap();
    replies.push(last.into_bytes());

    let response = query_replies(replies).unwrap();

    assert_eq!(response.players.len(), 1024);
    assert_eq!(response.players_online, 1024);
    assert_eq!(response.players[1023].name, "p1023");
    assert_eq!(response.unused_entries["player_1024"], "p1024");
}

/// Datagrams without `final` used to be read until the server stopped.
#[test]
fn endless_parts_are_an_error() {
    let replies = (1 ..= 200)
        .map(|part| format!("\\queryid\\7.{part}\\key{part}\\value").into_bytes())
        .collect();

    let error = query_replies(replies).unwrap_err();

    assert_eq!(error.kind, GDErrorKind::PacketOverflow);
}

/// Empty, truncated, NUL-filled, garbage and oversized datagrams. Truncated
/// ones are also sent with `\final\` appended, so they are parsed at once.
#[test]
fn hostile_datagrams_do_not_panic() {
    let valid = reply_with("\\player_0\\alice\\team_0\\1\\frags_0\\3\\ping_0\\40\\deaths_0\\1");
    let mut variants = hostile_variants(&valid, LARGE_DATAGRAM);
    for (label, bytes) in variants.clone() {
        variants.push((
            format!("{label}, then final"),
            [bytes, b"\\final\\".to_vec()].concat(),
        ));
    }
    let big = fixture!("gamespy1/status_3k_one_datagram.bin");
    for length in (0 .. big.len()).step_by(97) {
        variants.push((
            format!("3k reply cut at {length}, then final"),
            [&big[.. length], b"\\final\\"].concat(),
        ));
    }

    assert_no_panics(&variants, |bytes| {
        let _ = query_replies(vec![bytes.to_vec()]);
    });
}
