//! Hostile replies: GameSpy 3 must return an error or a capped result, never
//! panic or loop for as long as the server keeps sending.

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

/// A fake that answers the challenge request with `challenge` and the data
/// request with `data`.
fn query_replies(challenge: Vec<u8>, data: Vec<Vec<u8>>) -> GDResult<Response> {
    let address = short_lived_udp_server(move |request| {
        match request.get(2) {
            Some(9) => vec![challenge.clone()],
            _ => data.clone(),
        }
    });
    query(&address, short_timeouts())
}

fn query_data(data: Vec<Vec<u8>>) -> GDResult<Response> {
    query_replies(fixture!("gamespy3/challenge.bin").to_vec(), data)
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
    let response = query_data(vec![fixture!("gamespy3/status_one_packet.bin").to_vec()]).unwrap();

    assert_eq!(response.name, "hostsrc GS3 test");
    assert_eq!((response.players_online, response.players_maximum), (2, 32));
    assert_eq!(response.players[1].name, "bob");
}

/// Split packets that are never the last one used to be read until the server
/// stopped sending.
#[test]
fn endless_split_packets_are_an_error() {
    let packet = edited(
        fixture!("gamespy3/status_one_packet.bin"),
        b"splitnum\x00\x80",
        b"splitnum\x00\x00",
    );

    let error = query_data(vec![packet; 300]).unwrap_err();

    assert_eq!(error.kind, GDErrorKind::PacketOverflow);
}

/// `numplayers` above u32::MAX was cast with `as` and wrapped.
#[test]
fn huge_numplayers_saturates() {
    let packet = edited(
        fixture!("gamespy3/status_one_packet.bin"),
        b"numplayers\x002\x00",
        b"numplayers\x0099999999999\x00",
    );

    assert_eq!(query_data(vec![packet]).unwrap().players_online, u32::MAX);
}

/// Item offsets of 255 and split numbers of 127 only use what arrived.
#[test]
fn huge_offsets_and_split_numbers_are_bounded() {
    let high_offset = edited(
        fixture!("gamespy3/status_one_packet.bin"),
        b"player_\x00\x00",
        b"player_\x00\xFF",
    );
    let high_split = edited(
        fixture!("gamespy3/status_one_packet.bin"),
        b"splitnum\x00\x80",
        b"splitnum\x00\xFF",
    );

    for packet in [high_offset, high_split] {
        let (_, largest) = largest_allocation(|| query_data(vec![packet]));
        assert!(largest < ALLOCATION_LIMIT, "allocated {largest} bytes");
    }
}

#[test]
fn hostile_replies_do_not_panic() {
    let data = hostile_variants(fixture!("gamespy3/status_one_packet.bin"), LARGE_DATAGRAM);
    assert_no_panics(&data, |bytes| {
        let _ = query_data(vec![bytes.to_vec()]);
    });

    let challenges = hostile_variants(fixture!("gamespy3/challenge.bin"), LARGE_DATAGRAM);
    assert_no_panics(&challenges, |bytes| {
        let _ = query_replies(
            bytes.to_vec(),
            vec![fixture!("gamespy3/status_one_packet.bin").to_vec()],
        );
    });
}

/// The player section as real servers send it (laid out like a live
/// Battlefield 2 reply): a field name right after a separator byte below 3,
/// a list split over two packets that continues at the offset byte, and
/// fields some games leave out. Stepping forward over the first letter of
/// each field name used to leave every list empty.
#[test]
fn players_split_over_packets_with_missing_fields() {
    let first = b"\x01player_\x00\x00alice\x00bob\x00\x00\x01score_\x00\x00\x31\x30\x00x\x00\x00".to_vec();
    let second = b"player_\x00\x02carol\x00\x00\x01ping_\x00\x00\x35\x30\x00\x00\x00\x01team_t\x00\x00Red\x00\x00".to_vec();

    let (players, teams) = parse_players_and_teams(vec![first, second]).unwrap();

    let names: Vec<&str> = players.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["alice", "bob", "carol"]);
    assert_eq!((players[0].score, players[0].ping), (Some(10), Some(50)));
    // "x" isn't a number and bob sent no ping; carol sent neither.
    assert_eq!((players[1].score, players[1].ping), (None, None));
    assert_eq!((players[2].score, players[2].skill, players[2].deaths), (None, None, None));
    assert_eq!(teams.len(), 1);
    assert_eq!((teams[0].name.as_str(), teams[0].score), ("Red", None));
}
