//! Hostile replies: Eco (HTTP JSON) must return an error, never panic or read
//! more than the 1 MiB reply cap.

use super::*;
use crate::test_support::{
    assert_no_panics,
    garbage,
    http_response,
    largest_allocation,
    one_shot_tcp_server,
    short_timeouts,
    ALLOCATION_LIMIT,
};
use crate::GDErrorKind;

fn query_body(body: &[u8]) -> GDResult<Response> {
    let address = one_shot_tcp_server(http_response(body));
    query_with_timeout(&address.ip(), Some(address.port()), &short_timeouts())
}

fn valid_body() -> Vec<u8> {
    let mut root = Root::default();
    root.info.description = "hostsrc Eco test".to_string();
    root.info.online_players = 2;
    root.info.online_players_names = vec!["alice".to_string(), "bob".to_string()];
    serde_json::to_vec(&root).unwrap()
}

#[test]
fn valid_reply_is_parsed() {
    let response = query_body(&valid_body()).unwrap();

    assert_eq!(response.description, "hostsrc Eco test");
    assert_eq!(response.players.len(), 2);
}

/// A body over 1 MiB is an overflow error, and isn't buffered whole.
#[test]
fn body_over_1_mib_is_an_error() {
    let mut body = br#"{"Info":{"OnlinePlayersNames":["#.to_vec();
    while body.len() <= 1024 * 1024 {
        body.extend_from_slice(br#""a","#);
    }

    let (result, largest) = largest_allocation(|| query_body(&body));

    assert_eq!(result.unwrap_err().kind, GDErrorKind::PacketOverflow);
    // The cap reads at most 1 MiB + 1 byte, so the buffer doubles once.
    assert!(largest <= ALLOCATION_LIMIT, "allocated {largest} bytes");
}

#[test]
fn hostile_bodies_do_not_panic() {
    let valid = valid_body();
    let mut variants: Vec<(String, Vec<u8>)> = vec![
        ("empty".to_string(), Vec::new()),
        ("NUL-filled".to_string(), vec![0; valid.len()]),
        ("garbage".to_string(), garbage(valid.len(), 3)),
        ("null".to_string(), b"null".to_vec()),
        (
            "wrong types".to_string(),
            br#"{"Info":{"OnlinePlayers":-1}}"#.to_vec(),
        ),
        (
            "deep nesting".to_string(),
            [vec![b'['; 100_000], vec![b']'; 100_000]].concat(),
        ),
    ];
    for length in (1 .. valid.len()).step_by(17) {
        variants.push((format!("truncated to {length}"), valid[.. length].to_vec()));
    }

    assert_no_panics(&variants, |bytes| {
        assert!(query_body(bytes).is_err());
    });
}

/// Live servers leave out eight of the fields; the rest still parse.
#[test]
fn reply_without_the_fields_live_servers_leave_out_is_parsed() {
    let mut body: serde_json::Value = serde_json::from_slice(&valid_body()).unwrap();
    let info = body["Info"].as_object_mut().unwrap();
    for key in [
        "GamePort",
        "TimeSinceStart",
        "TimeLeft",
        "SkillSpecializationSetting",
        "MaxActivePlayers",
        "IsLimitingHours",
        "RelayAddress",
        "JoinUrl",
    ] {
        assert!(info.remove(key).is_some(), "{key}");
    }

    let response = query_body(&serde_json::to_vec(&body).unwrap()).unwrap();

    assert_eq!(response.description, "hostsrc Eco test");
    assert_eq!(response.players.len(), 2);
}
