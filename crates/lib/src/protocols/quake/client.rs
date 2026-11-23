use byteorder::LittleEndian;

use crate::buffer::{Buffer, Utf8Decoder};
use crate::protocols::quake::types::Response;
use crate::protocols::types::TimeoutSettings;
use crate::socket::{Socket, UdpSocket};
use crate::utils::retry_on_timeout;
use crate::GDErrorKind::{PacketBad, TypeParse};
use crate::{GDErrorKind, GDResult};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::slice::Iter;

pub trait QuakeClient {
    type Player;

    fn get_send_header<'a>() -> &'a str;
    fn get_response_header<'a>() -> &'a str;
    fn parse_player_string(data: Iter<&str>) -> GDResult<Self::Player>;
}

/// Send request and return result buffer.
/// This function will retry fetch on timeouts.
fn get_data<Client: QuakeClient>(
    address: &SocketAddr,
    timeout_settings: &Option<TimeoutSettings>,
) -> GDResult<Vec<u8>> {
    let mut socket = UdpSocket::new(address, timeout_settings)?;
    retry_on_timeout(
        TimeoutSettings::get_retries_or_default(timeout_settings),
        move || get_data_impl::<Client>(&mut socket),
    )
}

/// Send request and return result buffer (without retry logic).
fn get_data_impl<Client: QuakeClient>(socket: &mut UdpSocket) -> GDResult<Vec<u8>> {
    socket.send(
        &[
            &[0xFF, 0xFF, 0xFF, 0xFF],
            Client::get_send_header().as_bytes(),
            &[0x00],
        ]
        .concat(),
    )?;

    let data = socket.receive(None)?;
    let mut bufferer = Buffer::<LittleEndian>::new(&data);

    if bufferer.read::<u32>()? != u32::MAX {
        return Err(PacketBad.context("Expected 4294967295"));
    }

    let response_header = Client::get_response_header().as_bytes();
    if !bufferer.remaining_bytes().starts_with(response_header) {
        Err(GDErrorKind::PacketBad)?;
    }

    bufferer.move_cursor(response_header.len() as isize)?;

    Ok(bufferer.remaining_bytes().to_vec())
}

fn get_server_values(bufferer: &mut Buffer<LittleEndian>) -> GDResult<HashMap<String, String>> {
    let data = bufferer.read_string::<Utf8Decoder>(Some([0x0A]))?;
    let mut data_split = data.split('\\').collect::<Vec<&str>>();
    if let Some(first) = data_split.first() {
        if first == &"" {
            data_split.remove(0);
        }
    }

    let values = data_split.chunks(2);

    let mut vars: HashMap<String, String> = HashMap::new();
    for data in values {
        let key = data.first();
        let value = data.get(1);

        if let Some(k) = key {
            if let Some(v) = value {
                vars.insert((*k).to_string(), (*v).to_string());
            }
        }
    }

    Ok(vars)
}

fn get_players<Client: QuakeClient>(bufferer: &mut Buffer<LittleEndian>) -> GDResult<Vec<Client::Player>> {
    let mut players: Vec<Client::Player> = Vec::new();

    // One player per line until the end of the reply. Blank lines and a
    // trailing NUL (some servers end the reply with one) are not players.
    while bufferer.remaining_length() > 0 {
        let line = bufferer.read_string::<Utf8Decoder>(Some([0x0A]))?;
        let line = line.trim_matches(|c: char| c == '\0' || c.is_whitespace());
        if line.is_empty() {
            continue;
        }

        let data_split = split_player_line(line);
        players.push(Client::parse_player_string(data_split.iter())?);
    }

    Ok(players)
}

/// Split a player line on spaces, keeping a double-quoted field (a name or a
/// skin, which may contain spaces) as one field, quotes included.
fn split_player_line(line: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut rest = line.trim_start();
    while !rest.is_empty() {
        let end = match rest.strip_prefix('"') {
            Some(quoted) => quoted.find('"').map_or(rest.len(), |close| close + 2),
            None => rest.find(' ').unwrap_or(rest.len()),
        };
        fields.push(&rest[.. end]);
        rest = rest[end ..].trim_start();
    }
    fields
}

pub fn client_query<Client: QuakeClient>(
    address: &SocketAddr,
    timeout_settings: Option<TimeoutSettings>,
) -> GDResult<Response<Client::Player>> {
    let data = get_data::<Client>(address, &timeout_settings)?;
    let mut bufferer = Buffer::<LittleEndian>::new(&data);

    let mut server_vars = get_server_values(&mut bufferer)?;
    let players = get_players::<Client>(&mut bufferer)?;

    Ok(Response {
        name: server_vars
            .remove("hostname")
            .or_else(|| server_vars.remove("sv_hostname"))
            .ok_or(GDErrorKind::PacketBad)?,
        map: server_vars
            .remove("mapname")
            .or_else(|| server_vars.remove("map"))
            .ok_or(GDErrorKind::PacketBad)?,
        players_online: players.len() as u8,
        players_maximum: server_vars
            .remove("maxclients")
            .or_else(|| server_vars.remove("sv_maxclients"))
            .ok_or(GDErrorKind::PacketBad)?
            .parse()
            .map_err(|e| TypeParse.context(e))?,
        players,
        game_version: server_vars
            .remove("version")
            .or_else(|| server_vars.remove("*version")),
        unused_entries: server_vars,
    })
}

pub fn remove_wrapping_quotes<'a>(string: &&'a str) -> &'a str {
    string
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .unwrap_or(string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::quake::{one, three, two};
    use crate::test_support::{fake_udp_server, fixture};
    use std::time::Duration;

    fn timeouts() -> Option<TimeoutSettings> {
        TimeoutSettings::new(
            Some(Duration::from_secs(2)),
            Some(Duration::from_secs(2)),
            None,
            0,
        )
        .ok()
    }

    /// The player loop never ran (`!len == 0`), so every Quake reply had no
    /// players and `players_online` 0.
    #[test]
    fn quake3_reply_with_three_players() {
        let address = fake_udp_server(vec![fixture!("quake/q3_status_3_players.bin").to_vec()]);
        let response = three::query(&address, timeouts()).unwrap();

        assert_eq!(response.name, "hostsrc Q3 test");
        assert_eq!(response.map, "q3dm17");
        assert_eq!((response.players_online, response.players_maximum), (3, 16));
        let players: Vec<(&str, i32, u16)> = response
            .players
            .iter()
            .map(|p| (p.name.as_str(), p.score, p.ping))
            .collect();
        assert_eq!(
            players,
            [
                ("alice", 12, 50),
                ("Big Name", 3, 0),
                ("^1red^7bot", -1, 999)
            ]
        );
        assert_eq!(response.unused_entries["g_gametype"], "0");
    }

    #[test]
    fn quake2_reply_with_two_players() {
        let address = fake_udp_server(vec![fixture!("quake/q2_status_2_players.bin").to_vec()]);
        let response = two::query(&address, timeouts()).unwrap();

        assert_eq!((response.players_online, response.players_maximum), (2, 12));
        assert_eq!(response.players[1].name, "bob");
        assert_eq!(response.players[1].ping, 120);
        assert_eq!(response.game_version.as_deref(), Some("R1Q2 b8012 x86_64"));
    }

    /// QuakeWorld reply ending in "\n\0": the trailing NUL isn't a player.
    #[test]
    fn quake1_reply_with_two_players_and_trailing_nul() {
        let address = fake_udp_server(vec![fixture!("quake/q1_status_2_players.bin").to_vec()]);
        let response = one::query(&address, timeouts()).unwrap();

        assert_eq!((response.players_online, response.players_maximum), (2, 8));
        let second = &response.players[1];
        assert_eq!((second.id, second.score, second.ping), (2, 3, 80));
        assert_eq!(second.name, "Big Name");
        assert_eq!(second.skin, "base");
        assert_eq!((second.color_primary, second.color_secondary), (13, 13));
    }

    /// A reply with server values and no players (and no final newline).
    #[test]
    fn quake3_reply_without_players() {
        let reply = b"\xFF\xFF\xFF\xFFstatusResponse\n\\sv_hostname\\empty\\mapname\\q3dm1\\sv_maxclients\\8";
        let address = fake_udp_server(vec![reply.to_vec()]);
        let response = three::query(&address, timeouts()).unwrap();

        assert_eq!(response.name, "empty");
        assert_eq!(response.players_online, 0);
        assert!(response.players.is_empty());
    }

    #[test]
    fn player_line_keeps_quoted_fields_whole() {
        assert_eq!(
            split_player_line(r#"1 10 15 40 "a b c" "base" 4 4"#),
            ["1", "10", "15", "40", r#""a b c""#, r#""base""#, "4", "4"]
        );
        assert_eq!(
            split_player_line(r#"  3  0 "unterminated"#),
            ["3", "0", r#""unterminated"#]
        );
    }

    /// A lone quote used to slice `[1 .. 0]` and panic.
    #[test]
    fn lone_quote_field_does_not_panic() {
        assert_eq!(remove_wrapping_quotes(&"\""), "\"");
        assert_eq!(remove_wrapping_quotes(&"\"\""), "");
        assert_eq!(remove_wrapping_quotes(&"\"name\""), "name");
        assert!(two::QuakeTwo::parse_player_string(split_player_line("3 0 \"").iter()).is_ok());
    }
}
