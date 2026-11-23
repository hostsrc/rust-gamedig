//! Hostile replies: Minecraft Java, Bedrock and Legacy must return an error or
//! a capped result, never panic or size an allocation from the reply.

use super::*;
use crate::buffer::Buffer;
use crate::games::minecraft::get_string;
use crate::test_support::{
    assert_no_panics,
    fixture,
    hostile_variants,
    largest_allocation,
    one_shot_tcp_server,
    short_lived_udp_server,
    short_timeouts,
    ALLOCATION_LIMIT,
    LARGE_DATAGRAM,
};
use byteorder::LittleEndian;

fn java(reply: &[u8]) -> GDResult<JavaResponse> {
    query_java(&one_shot_tcp_server(reply.to_vec()), short_timeouts(), None)
}

fn legacy(group: LegacyGroup, reply: &[u8]) -> GDResult<JavaResponse> {
    query_legacy_specific(
        group,
        &one_shot_tcp_server(reply.to_vec()),
        short_timeouts(),
    )
}

fn bedrock(reply: &[u8]) -> GDResult<BedrockResponse> {
    let reply = reply.to_vec();
    query_bedrock(
        &short_lived_udp_server(move |_| vec![reply.clone()]),
        short_timeouts(),
    )
}

#[test]
fn valid_replies_are_parsed() {
    let response = java(fixture!("minecraft/java_status.bin")).unwrap();
    assert_eq!(
        (response.players_online, response.players_maximum),
        (2, 100)
    );

    let response = bedrock(fixture!("minecraft/bedrock_pong.bin")).unwrap();
    assert_eq!(response.name, "hostsrc Bedrock");

    let response = legacy(LegacyGroup::V1_6, fixture!("minecraft/legacy_v1_6.bin")).unwrap();
    assert_eq!(response.game_version, "1.6.4");

    let response = legacy(LegacyGroup::V1_4, fixture!("minecraft/legacy_v1_4.bin")).unwrap();
    assert_eq!((response.players_online, response.players_maximum), (3, 20));
}

/// A negative string length was cast to usize and overflowed the capacity.
#[test]
fn negative_string_length_is_an_error() {
    let data = [0xFF, 0xFF, 0xFF, 0xFF, 0x0F, b'a'];
    assert!(get_string(&mut Buffer::<LittleEndian>::new(&data)).is_err());
}

/// A string length of 2^31 - 1 allocated 2 GB before reading 3 bytes.
#[test]
fn huge_string_length_does_not_size_an_allocation() {
    let data = [0xFF, 0xFF, 0xFF, 0xFF, 0x07, b'a', b'b', b'c'];

    let (result, largest) = largest_allocation(|| get_string(&mut Buffer::<LittleEndian>::new(&data)));

    assert!(result.is_err());
    assert!(largest < ALLOCATION_LIMIT, "allocated {largest} bytes");
}

/// The legacy length `u16 * 2 + 3` overflowed u16 for lengths from 0x7FFF.
#[test]
fn huge_legacy_length_is_an_error() {
    for reply in [&b"\xFF\xFF\xFF\x00\xA7"[..], b"\xFF\x7F\xFF\x00\xA7"] {
        for group in [LegacyGroup::V1_6, LegacyGroup::V1_4, LegacyGroup::VB1_8] {
            assert!(legacy(group, reply).is_err());
        }
    }
}

#[test]
fn hostile_java_replies_do_not_panic() {
    let variants = hostile_variants(fixture!("minecraft/java_status.bin"), 70_000);
    assert_no_panics(&variants, |bytes| {
        let _ = java(bytes);
    });
}

#[test]
fn hostile_legacy_replies_do_not_panic() {
    for fixture in [
        fixture!("minecraft/legacy_v1_6.bin"),
        fixture!("minecraft/legacy_v1_4.bin"),
    ] {
        let variants = hostile_variants(fixture, 70_000);
        assert_no_panics(&variants, |bytes| {
            for group in [LegacyGroup::V1_6, LegacyGroup::V1_4, LegacyGroup::VB1_8] {
                let _ = legacy(group, bytes);
            }
        });
    }
}

#[test]
fn hostile_bedrock_replies_do_not_panic() {
    let mut variants = hostile_variants(fixture!("minecraft/bedrock_pong.bin"), LARGE_DATAGRAM);
    let valid = fixture!("minecraft/bedrock_pong.bin");
    // Player counts too large for u32, and fewer fields than required.
    for status in [&b"MCPE;n;1;v;99999999999;99999999999"[..], b"MCPE;n;1"] {
        let mut reply = valid[.. 33].to_vec();
        reply.extend((status.len() as u16).to_be_bytes());
        reply.extend(status);
        variants.push((String::from_utf8_lossy(status).into_owned(), reply));
    }

    assert_no_panics(&variants, |bytes| {
        let _ = bedrock(bytes);
    });
}
