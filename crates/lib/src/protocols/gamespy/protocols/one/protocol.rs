use byteorder::LittleEndian;

use crate::buffer::Utf8Decoder;
use crate::protocols::gamespy::common::has_password;
use crate::GDErrorKind::TypeParse;

use crate::utils::retry_on_timeout;
use crate::{
    buffer::Buffer,
    protocols::{
        gamespy::one::{Player, Response},
        types::TimeoutSettings,
    },
    socket::{Socket, UdpSocket},
    GDErrorKind,
    GDResult,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;

/// Most datagrams read for one status reply. A reply that hasn't sent `final`
/// by then is an error, so a server can't keep a query looping.
const MAX_PARTS: usize = 128;

/// Most players read from one reply; later player ids are left in
/// `unused_entries`.
const MAX_PLAYERS: usize = 1024;

/// Send status request, and parse response into HashMap.
/// This function will retry fetch on timeouts.
fn get_server_values(
    address: &SocketAddr,
    timeout_settings: &Option<TimeoutSettings>,
) -> GDResult<HashMap<String, String>> {
    let mut socket = UdpSocket::new(address, timeout_settings)?;
    retry_on_timeout(
        TimeoutSettings::get_retries_or_default(timeout_settings),
        move || get_server_values_impl(&mut socket),
    )
}

/// Send status request, and parse response into HashMap (without retry logic).
fn get_server_values_impl(socket: &mut UdpSocket) -> GDResult<HashMap<String, String>> {
    socket.send(b"\\status\\xserverquery")?;

    let mut received_query_id: Option<usize> = None;
    let mut parts: Vec<usize> = Vec::new();
    let mut is_finished = false;

    let mut server_values = HashMap::new();

    while !is_finished {
        if parts.len() >= MAX_PARTS {
            return Err(GDErrorKind::PacketOverflow.context(format!("no final part in {MAX_PARTS} datagrams")));
        }

        let data = socket.receive(None)?;
        let mut bufferer = Buffer::<LittleEndian>::new(&data);

        let mut as_string = bufferer.read_string::<Utf8Decoder>(None)?;
        if as_string.is_empty() {
            return Err(GDErrorKind::PacketBad.context("Empty status datagram"));
        }
        as_string.remove(0);

        let splited: Vec<String> = as_string.split('\\').map(str::to_string).collect();

        for i in 0 .. splited.len() / 2 {
            let position = i * 2;
            let key = splited[position].clone();
            let value = splited
                .get(position + 1)
                .map_or_else(String::new, Clone::clone);

            server_values.insert(key, value);
        }

        is_finished = server_values.remove("final").is_some();

        let query_data = server_values.get("queryid");

        let mut part = parts.len(); // if the part number isn't provided, it's value is the parts length
        let mut query_id = None;
        if let Some(qid) = query_data {
            let split: Vec<&str> = qid.split('.').collect();

            query_id = Some(split[0].parse().map_err(|e| TypeParse.context(e))?);
            match split.len() {
                1 => (),
                2 => part = split[1].parse().map_err(|e| TypeParse.context(e))?,
                _ => Err(GDErrorKind::PacketBad)?, /* the queryid can't be splitted in more than 2
                                                    * elements */
            };
        }

        server_values.remove("queryid");

        if received_query_id.is_some() && received_query_id != query_id {
            return Err(GDErrorKind::PacketBad.into()); // wrong query id!
        }

        received_query_id = query_id;

        match parts.contains(&part) {
            true => Err(GDErrorKind::PacketBad)?,
            false => parts.push(part),
        }
    }

    Ok(server_values)
}

/// Split a `<field>_<id>` player key into its field and id.
fn player_field(key: &str) -> Option<(&str, usize)> {
    let split: Vec<&str> = key.split('_').collect();

    if split.len() != 2 {
        return None;
    }

    let kind = split[0];
    let id: usize = split[1].parse().ok()?;

    match kind {
        "team" | "player" | "playername" | "ping" | "face" | "skin" | "mesh" | "frags" | "ngsecret" | "deaths"
        | "health" => Some((kind, id)),
        _ => None,
    }
}

/// Collect the `<field>_<id>` entries into players, ordered by id. Nothing is
/// sized from the reply: `maxplayers` and the ids only order the players. Only
/// the [MAX_PLAYERS] lowest ids are read; the rest stay in `server_vars`.
fn extract_players(server_vars: &mut HashMap<String, String>) -> GDResult<Vec<Player>> {
    let ids: BTreeSet<usize> = server_vars
        .keys()
        .filter_map(|key| player_field(key))
        .map(|(_, id)| id)
        .collect();
    let last_id = ids
        .iter()
        .nth(MAX_PLAYERS - 1)
        .copied()
        .unwrap_or(usize::MAX);

    let mut players_data: BTreeMap<usize, HashMap<String, String>> = BTreeMap::new();

    server_vars.retain(|key, value| {
        let Some((kind, id)) = player_field(key) else {
            return true;
        };

        if id > last_id {
            return true;
        }

        players_data
            .entry(id)
            .or_default()
            .insert(kind.to_string(), value.to_string());

        false
    });

    let mut players: Vec<Player> = Vec::with_capacity(players_data.len());

    for player_data in players_data.into_values() {
        let new_player = Player {
            name: match player_data.get("player") {
                Some(v) => v.clone(),
                None => {
                    player_data
                        .get("playername")
                        .ok_or(GDErrorKind::PacketBad)?
                        .clone()
                }
            },
            team: match player_data.get("team") {
                Some(t) => Some(t.trim().parse().map_err(|e| TypeParse.context(e))?),
                None => None,
            },
            ping: player_data
                .get("ping")
                .ok_or(GDErrorKind::PacketBad)?
                .trim()
                .parse()
                .map_err(|e| TypeParse.context(e))?,
            face: player_data.get("face").cloned(),
            skin: player_data.get("skin").cloned(),
            mesh: player_data.get("mesh").cloned(),
            score: player_data
                .get("frags")
                .ok_or(GDErrorKind::PacketBad)?
                .trim()
                .parse()
                .map_err(|e| TypeParse.context(e))?,
            deaths: match player_data.get("deaths") {
                Some(v) => Some(v.trim().parse().map_err(|e| TypeParse.context(e))?),
                None => None,
            },
            health: match player_data.get("health") {
                Some(v) => Some(v.trim().parse().map_err(|e| TypeParse.context(e))?),
                None => None,
            },
            secret: match player_data.get("ngsecret") {
                Some(s) => Some(s.to_lowercase().parse().map_err(|e| TypeParse.context(e))?),
                None => None,
            },
        };

        players.push(new_player);
    }

    Ok(players)
}

/// If there are parsing problems using the `query` function, you can directly
/// get the server's values using this function.
pub fn query_vars(
    address: &SocketAddr,
    timeout_settings: Option<TimeoutSettings>,
) -> GDResult<HashMap<String, String>> {
    get_server_values(address, &timeout_settings)
}

/// Query a server by providing the address, the port and timeout settings.
/// Providing None to the timeout settings results in using the default values.
/// (TimeoutSettings::[default](TimeoutSettings::default)).
pub fn query(address: &SocketAddr, timeout_settings: Option<TimeoutSettings>) -> GDResult<Response> {
    let mut server_vars = query_vars(address, timeout_settings)?;

    let players_maximum: u32 = server_vars
        .remove("maxplayers")
        .ok_or(GDErrorKind::PacketBad)?
        .parse()
        .map_err(|e| TypeParse.context(e))?;
    let players_minimum = match server_vars.remove("minplayers") {
        None => None,
        Some(v) => Some(v.parse::<u8>().map_err(|e| TypeParse.context(e))?),
    };

    let players = extract_players(&mut server_vars)?;

    Ok(Response {
        name: server_vars
            .remove("hostname")
            .ok_or(GDErrorKind::PacketBad)?,
        map: server_vars
            .remove("mapname")
            .ok_or(GDErrorKind::PacketBad)?,
        map_title: server_vars.remove("maptitle"),
        admin_contact: server_vars.remove("AdminEMail"),
        admin_name: server_vars
            .remove("AdminName")
            .or_else(|| server_vars.remove("admin")),
        has_password: has_password(&mut server_vars)?,
        game_mode: server_vars
            .remove("gametype")
            .ok_or(GDErrorKind::PacketBad)?,
        game_version: server_vars
            .remove("gamever")
            .ok_or(GDErrorKind::PacketBad)?,
        players_maximum,
        players_online: players.len() as u32,
        players_minimum,
        players,
        tournament: server_vars
            .remove("tournament")
            .unwrap_or_else(|| "true".to_string())
            .to_lowercase()
            .parse()
            .map_err(|e| TypeParse.context(e))?,
        unused_entries: server_vars,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{fake_udp_server, fixture};
    use std::time::Duration;

    /// A 3.5 KB reply in one datagram. With the old 1024-byte receive buffer it
    /// was cut off before `\final\`, so the query waited for more and failed.
    #[test]
    fn reply_larger_than_1024_bytes_is_read_whole() {
        let datagram = fixture!("gamespy1/status_3k_one_datagram.bin");
        assert!(datagram.len() > 3000);
        let address = fake_udp_server(vec![datagram.to_vec()]);
        let timeouts = TimeoutSettings::new(
            Some(Duration::from_secs(2)),
            Some(Duration::from_secs(2)),
            None,
            0,
        )
        .ok();

        let response = query(&address, timeouts).unwrap();

        assert_eq!(response.name, "hostsrc UT99 test");
        assert_eq!(response.map, "DM-Deck16][");
        assert_eq!(
            (response.players_online, response.players_maximum),
            (16, 16)
        );
        assert_eq!(
            response.players[15].name,
            "Player number 15 with a long name"
        );
        assert_eq!(
            response.unused_entries["last_key"],
            "after the first kilobyte"
        );
    }
}

#[cfg(test)]
mod hostile_tests;
