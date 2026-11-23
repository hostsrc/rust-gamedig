//! Hostile replies: Unreal 2 must return an error or a capped result, never
//! panic or read for as long as the server keeps sending.

use super::*;
use crate::test_support::{assert_no_panics, fixture, hostile_variants, short_lived_udp_server, short_timeouts};

/// A response datagram: the 4-byte header, the packet kind and the payload.
fn datagram(kind: PacketKind, payload: &[u8]) -> Vec<u8> { [&[0x80, 0, 0, 0, kind as u8][..], payload].concat() }

/// A latin-1 Unreal 2 string: its length (with the NUL), the text and a NUL.
fn string(text: &str) -> Vec<u8> { [&[text.len() as u8 + 1][..], text.as_bytes(), &[0]].concat() }

fn read_string(data: &[u8]) -> GDResult<String> {
    Buffer::<LittleEndian>::new(data).read_string::<Unreal2StringDecoder>(None)
}

#[test]
fn valid_payloads_are_parsed() {
    let info = ServerInfo::parse(&mut Buffer::<LittleEndian>::new(fixture!(
        "unreal2/server_info.bin"
    )))
    .unwrap();
    assert_eq!(info.name, "hostsrc UT2004 test");
    assert_eq!((info.num_players, info.max_players), (2, 16));

    let mut rules = MutatorsAndRules::default();
    rules
        .parse(&mut Buffer::<LittleEndian>::new(fixture!(
            "unreal2/rules.bin"
        )))
        .unwrap();
    assert!(rules.mutators.contains("MutInstaGib"));
    assert_eq!(rules.rules["MaxSpectators"], ["2"]);

    let mut players = Players::default();
    players
        .parse(&mut Buffer::<LittleEndian>::new(fixture!(
            "unreal2/players.bin"
        )))
        .unwrap();
    assert_eq!((players.players.len(), players.bots.len()), (1, 1));
}

/// A UCS-2 length past the end of the reply sliced out of bounds.
#[test]
fn ucs2_string_longer_than_the_reply_is_an_error() {
    for data in [
        &[0xFF, 0x41, 0x00][..],
        &[0x81],
        &[0x81, 0x01],
        &[0x82, 0x01, 0x41, 0x00],
    ] {
        assert!(read_string(data).is_err(), "{data:?}");
    }
    // Control: a whole UCS-2 string still decodes.
    assert_eq!(read_string(&[0x82, 0x41, 0x00, 0x42, 0x00]).unwrap(), "AB");
}

#[test]
fn hostile_payloads_do_not_panic() {
    let oversized = 70_000;

    let info = hostile_variants(fixture!("unreal2/server_info.bin"), oversized);
    assert_no_panics(&info, |bytes| {
        let _ = ServerInfo::parse(&mut Buffer::<LittleEndian>::new(bytes));
    });

    let rules = hostile_variants(fixture!("unreal2/rules.bin"), oversized);
    assert_no_panics(&rules, |bytes| {
        let _ = MutatorsAndRules::default().parse(&mut Buffer::<LittleEndian>::new(bytes));
    });

    let players = hostile_variants(fixture!("unreal2/players.bin"), oversized);
    assert_no_panics(&players, |bytes| {
        let _ = Players::default().parse(&mut Buffer::<LittleEndian>::new(bytes));
    });
}

/// Rules datagrams were read until the server stopped sending.
#[test]
fn endless_rules_datagrams_are_capped() {
    let address = short_lived_udp_server(|_| {
        (0 .. 200)
            .map(|i| {
                datagram(
                    PacketKind::MutatorsAndRules,
                    &[string(&format!("key{i}")), string("value")].concat(),
                )
            })
            .collect()
    });

    let rules = Unreal2Protocol::new(&address, short_timeouts())
        .unwrap()
        .query_mutators_and_rules()
        .unwrap();

    assert_eq!(rules.rules.len(), 64);
}

/// With `num_players` u32::MAX from the server info, player datagrams were read
/// until the server stopped sending.
#[test]
fn endless_player_datagrams_are_capped() {
    let address = short_lived_udp_server(|_| {
        (0 .. 200u32)
            .map(|i| {
                let player = [
                    &i.to_le_bytes()[..],
                    &string(&format!("p{i}")),
                    &50u32.to_le_bytes(),
                    &0i32.to_le_bytes(),
                    &0u32.to_le_bytes(),
                ]
                .concat();
                datagram(PacketKind::Players, &player)
            })
            .collect()
    });
    let info = ServerInfo {
        server_id: 0,
        ip: String::new(),
        game_port: 0,
        query_port: 0,
        name: String::new(),
        map: String::new(),
        game_type: String::new(),
        num_players: u32::MAX,
        max_players: u32::MAX,
        password: false,
    };

    let players = Unreal2Protocol::new(&address, short_timeouts())
        .unwrap()
        .query_players(Some(&info))
        .unwrap();

    assert_eq!(players.total_len(), 64);
}
