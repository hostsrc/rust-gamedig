//! Hostile replies: the Valve parsers (A2S info, players, rules, split and
//! compressed responses) must return an error or a capped result, never panic
//! or size an allocation from the reply.

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
use crate::GDErrorKind;

const SOURCE: Engine = Engine::Source(None);

/// A Source split datagram (total 1, number 0) with a compressed payload that
/// claims `size` decompressed bytes with checksum `crc`.
fn compressed_split(size: u32, crc: u32, payload: &[u8]) -> Vec<u8> {
    [
        &0xFFFF_FFFEu32.to_le_bytes()[..],
        &0x8000_0001u32.to_le_bytes(), // id, high bit: compressed
        &[1, 0],                       // total, number
        &1248u16.to_le_bytes(),        // size
        &size.to_le_bytes(),
        &crc.to_le_bytes(),
        payload,
    ]
    .concat()
}

fn assemble(engine: &Engine, datagram: &[u8]) -> GDResult<Packet> {
    match FirstPacket::parse(engine, 17, datagram)? {
        FirstPacket::Single(packet) => Ok(packet),
        FirstPacket::Split(split) => split.assemble(Vec::new()),
    }
}

#[test]
fn valid_payloads_are_parsed() {
    let info = parse_server_info(
        &SOURCE,
        INFO_REPLY_SOURCE,
        fixture!("valve/source_info_payload.bin"),
    )
    .unwrap();
    assert_eq!(info.name, "hostsrc CS2 test");
    assert_eq!(
        (info.players_online, info.players_maximum, info.appid),
        (2, 32, 730)
    );

    let players = parse_server_players(&SOURCE, fixture!("valve/players_payload.bin")).unwrap();
    assert_eq!(players[1].name, "bob");

    let rules = parse_server_rules(&SOURCE, fixture!("valve/rules_payload.bin")).unwrap();
    assert_eq!(rules["sv_cheats"], "0");
}

/// The decompressed size in a compressed split header was allocated as sent
/// (up to 4 GiB) before decompressing.
#[test]
fn huge_decompressed_size_is_refused_before_allocating() {
    let datagram = compressed_split(64 * 1024 * 1024, 0, fixture!("valve/rules_packet.bz2"));

    let (result, largest) = largest_allocation(|| assemble(&SOURCE, &datagram));

    assert!(largest < ALLOCATION_LIMIT, "allocated {largest} bytes");
    assert_eq!(result.unwrap_err().kind, GDErrorKind::PacketOverflow);
}

/// A rules count of 65535 reserved a map for 65535 rules before reading any.
#[test]
fn rules_count_does_not_size_an_allocation() {
    let payload = [&[0xFF, 0xFF][..], b"sv_cheats\x000\x00"].concat();

    let (result, largest) = largest_allocation(|| parse_server_rules(&SOURCE, &payload));

    assert!(result.is_err());
    assert!(largest < ALLOCATION_LIMIT, "allocated {largest} bytes");
}

/// A split response claiming 255 parts, of which one arrives, fails when the
/// rest time out.
#[test]
fn split_response_claiming_255_parts_is_an_error() {
    let first = [
        &0xFFFF_FFFEu32.to_le_bytes()[..],
        &1u32.to_le_bytes(),
        &[255, 0],
        &1248u16.to_le_bytes(),
        b"\xFF\xFF\xFF\xFFE\x00\x00",
    ]
    .concat();
    let address = short_lived_udp_server(move |_| vec![first.clone()]);

    let result = largest_allocation(|| {
        ValveProtocol::new(&address, short_timeouts())
            .unwrap()
            .get_request_data(&SOURCE, 17, Request::Rules as u8, Vec::new())
    });

    assert!(result.0.is_err());
    assert!(result.1 < ALLOCATION_LIMIT, "allocated {} bytes", result.1);
}

#[test]
fn hostile_payloads_do_not_panic() {
    let oversized = 70_000;
    let goldsrc = Engine::GoldSrc(false);
    let the_ship = Engine::new(2400);

    let info = hostile_variants(fixture!("valve/source_info_payload.bin"), oversized);
    assert_no_panics(&info, |bytes| {
        for kind in [INFO_REPLY_SOURCE, INFO_REPLY_GOLDSRC] {
            for engine in [&SOURCE, &goldsrc, &the_ship] {
                let _ = parse_server_info(engine, kind, bytes);
            }
        }
    });

    let players = hostile_variants(fixture!("valve/players_payload.bin"), oversized);
    assert_no_panics(&players, |bytes| {
        let _ = parse_server_players(&SOURCE, bytes);
        let _ = parse_server_players(&the_ship, bytes);
    });

    let rules = hostile_variants(fixture!("valve/rules_payload.bin"), oversized);
    assert_no_panics(&rules, |bytes| {
        let _ = parse_server_rules(&SOURCE, bytes);
    });

    let split = compressed_split(100, 0, fixture!("valve/rules_packet.bz2"));
    let splits = hostile_variants(&split, LARGE_DATAGRAM);
    assert_no_panics(&splits, |bytes| {
        let _ = assemble(&SOURCE, bytes);
        let _ = assemble(&goldsrc, bytes);
    });
}
