use byteorder::{BigEndian, LittleEndian};

use crate::buffer::{Buffer, Utf8Decoder};
use crate::protocols::gamespy::common::has_password;
use crate::protocols::gamespy::three::{Player, Response, Team};
use crate::protocols::types::TimeoutSettings;
use crate::socket::{Socket, UdpSocket};
use crate::utils::retry_on_timeout;
use crate::GDErrorKind::{PacketBad, TypeParse};
use crate::{GDErrorKind, GDResult};
use std::collections::HashMap;
use std::net::SocketAddr;

const THIS_SESSION_ID: u32 = 1;

struct RequestPacket {
    header: u16,
    kind: u8,
    session_id: u32,
    challenge: Option<i32>,
    payload: Option<[u8; 4]>,
}

impl RequestPacket {
    fn to_bytes(&self) -> Vec<u8> {
        let mut packet: Vec<u8> = Vec::with_capacity(7);
        packet.extend_from_slice(&self.header.to_be_bytes());
        packet.push(self.kind);
        packet.extend_from_slice(&self.session_id.to_be_bytes());

        if let Some(challenge) = self.challenge {
            packet.extend_from_slice(&challenge.to_be_bytes());
        }

        if let Some(payload) = self.payload {
            packet.extend_from_slice(&payload);
        }

        packet
    }
}

pub(crate) struct GameSpy3 {
    socket: UdpSocket,
    payload: [u8; 4],
    single_packets: bool,
    retry_count: usize,
}

const PACKET_SIZE: usize = 2048;
/// Most datagrams read for one reply (the split number has 7 bits, so a reply
/// has at most 128 parts). More is
/// [PacketOverflow](GDErrorKind::PacketOverflow), so a server can't keep a
/// query looping.
const MAX_PACKETS: usize = 128;
const DEFAULT_PAYLOAD: [u8; 4] = [0xFF, 0xFF, 0xFF, 0x01];

impl GameSpy3 {
    fn new(address: &SocketAddr, timeout_settings: Option<TimeoutSettings>) -> GDResult<Self> {
        let socket = UdpSocket::new(address, &timeout_settings)?;
        let retry_count = TimeoutSettings::get_retries_or_default(&timeout_settings);

        Ok(Self {
            socket,
            payload: DEFAULT_PAYLOAD,
            single_packets: false,
            retry_count,
        })
    }

    pub(crate) fn new_custom(
        address: &SocketAddr,
        timeout_settings: Option<TimeoutSettings>,
        payload: [u8; 4],
        single_packets: bool,
    ) -> GDResult<Self> {
        let socket = UdpSocket::new(address, &timeout_settings)?;
        let retry_count = TimeoutSettings::get_retries_or_default(&timeout_settings);

        Ok(Self {
            socket,
            payload,
            single_packets,
            retry_count,
        })
    }

    fn receive(&mut self, size: Option<usize>, kind: u8) -> GDResult<Vec<u8>> {
        let received = self.socket.receive(size.or(Some(PACKET_SIZE)))?;
        let mut buf = Buffer::<BigEndian>::new(&received);

        if buf.read::<u8>()? != kind {
            return Err(PacketBad.context("Kind of packet did not match"));
        }

        if buf.read::<u32>()? != THIS_SESSION_ID {
            return Err(PacketBad.context("Session ID did not match"));
        }

        Ok(buf.remaining_bytes().to_vec())
    }

    fn make_initial_handshake(&mut self) -> GDResult<Option<i32>> {
        self.socket.send(
            &RequestPacket {
                header: 65277,
                kind: 9,
                session_id: THIS_SESSION_ID,
                challenge: None,
                payload: None,
            }
            .to_bytes(),
        )?;

        let data = self.receive(Some(16), 9)?;
        let mut buf = Buffer::<LittleEndian>::new(&data);

        let challenge_as_string = buf.read_string::<Utf8Decoder>(None)?;
        let challenge = challenge_as_string
            .parse()
            .map_err(|e| TypeParse.context(e))?;

        Ok(match challenge == 0 {
            true => None,
            false => Some(challenge),
        })
    }

    fn send_data_request(&mut self, challenge: Option<i32>) -> GDResult<()> {
        self.socket.send(
            &RequestPacket {
                header: 65277,
                kind: 0,
                session_id: THIS_SESSION_ID,
                challenge,
                payload: Some(self.payload),
            }
            .to_bytes(),
        )
    }

    /// Fetch packets from server and store in buffer.
    /// This function will retry fetch on timeouts.
    pub(crate) fn get_server_packets(&mut self) -> GDResult<Vec<Vec<u8>>> {
        retry_on_timeout(self.retry_count, move || self.get_server_packets_impl())
    }

    /// Fetch packets from server and store in buffer (without retry logic).
    fn get_server_packets_impl(&mut self) -> GDResult<Vec<Vec<u8>>> {
        let challenge = self.make_initial_handshake()?;
        self.send_data_request(challenge)?;

        let mut values: Vec<Vec<u8>> = Vec::new();

        let mut reached_expected_packets_size = false;
        let mut received_packets = 0;

        while !reached_expected_packets_size {
            if received_packets == MAX_PACKETS {
                return Err(GDErrorKind::PacketOverflow.context(format!("no last part in {MAX_PACKETS} datagrams")));
            }
            received_packets += 1;

            let received_data = self.receive(None, 0)?;
            let mut buf = Buffer::<BigEndian>::new(&received_data);

            if self.single_packets {
                buf.move_cursor(11)?;
                return Ok(vec![buf.remaining_bytes().to_vec()]);
            }

            if buf.read_string::<Utf8Decoder>(None)? != "splitnum" {
                return Err(PacketBad.context("Expected string \"splitnum\""));
            }

            let id = buf.read::<u8>()?;
            let is_last = (id & 0x80) > 0;
            let packet_id = (id & 0x7f) as usize;
            buf.move_cursor(1)?; // unknown byte regarding packet no.

            if is_last && packet_id + 1 != values.len() {
                reached_expected_packets_size = true;
            }

            while values.len() <= packet_id {
                values.push(Vec::new());
            }

            values[packet_id] = buf.remaining_bytes().to_vec();
        }

        if values.iter().any(Vec::is_empty) {
            return Err(PacketBad.context("One (or more) packets is empty"));
        }

        Ok(values)
    }
}

pub(crate) fn data_to_map(packet: &[u8]) -> GDResult<(HashMap<String, String>, Vec<u8>)> {
    let mut vars = HashMap::new();

    let mut buf = Buffer::<BigEndian>::new(packet);
    while buf.remaining_length() != 0 {
        let key = buf.read_string::<Utf8Decoder>(None)?;
        if key.is_empty() {
            break;
        }

        let value = buf.read_string::<Utf8Decoder>(None)?;

        vars.insert(key, value);
    }

    Ok((vars, buf.remaining_bytes().to_vec()))
}

/// If there are parsing problems using the `query` function, you can directly
/// get the server's values using this function.
pub fn query_vars(
    address: &SocketAddr,
    timeout_settings: Option<TimeoutSettings>,
) -> GDResult<HashMap<String, String>> {
    let mut client = GameSpy3::new(address, timeout_settings)?;
    let packets = client.get_server_packets()?;

    let mut vars = HashMap::new();

    for packet in &packets {
        let (key_values, _remaining_data) = data_to_map(packet)?;
        vars.extend(key_values);
    }

    Ok(vars)
}

fn parse_players_and_teams(packets: Vec<Vec<u8>>) -> GDResult<(Vec<Player>, Vec<Team>)> {
    let mut players_data: Vec<HashMap<String, String>> = vec![HashMap::new()];
    let mut teams_data: Vec<HashMap<String, String>> = vec![HashMap::new()];

    for packet in packets {
        let mut buf = Buffer::<LittleEndian>::new(&packet);

        while buf.remaining_length() != 0 {
            // Bytes below 3 separate the sections; anything else is the first
            // letter of a field name, so step back onto it (GameDig's
            // `reader.skip(-1)`). Stepping forward instead cut the first letter
            // ("layer_"), so no field matched and every player list was empty.
            if buf.read::<u8>()? < 3 {
                continue;
            }

            buf.move_cursor(-1)?;

            let field = buf.read_string::<Utf8Decoder>(None)?;
            if field.is_empty() {
                continue;
            }

            let field_split: Vec<&str> = field.split('_').collect();
            let field_name = field_split.first().ok_or(GDErrorKind::PacketBad)?;
            if !["player", "score", "ping", "team", "deaths", "pid", "skill"].contains(field_name) {
                continue;
            }

            let field_type = match field_split.get(1) {
                None => None,
                Some(v) => {
                    match v.is_empty() {
                        true => None,
                        false => {
                            if v != &"t" {
                                Err(GDErrorKind::PacketBad)?;
                            }

                            Some(v)
                        }
                    }
                }
            };

            let mut offset = buf.read::<u8>()? as usize;

            let data = match field_type.is_none() {
                true => &mut players_data,
                false => &mut teams_data,
            };

            while buf.remaining_length() != 0 {
                let item = buf.read_string::<Utf8Decoder>(None)?;
                if item.is_empty() {
                    break;
                }

                while data.len() <= offset {
                    data.push(HashMap::new());
                }

                let entry_data = data.get_mut(offset).ok_or(PacketBad)?;
                entry_data.insert((*field_name).to_string(), item);

                offset += 1;
            }
        }
    }

    // Games send different player fields (Crysis Wars has no `skill_`, some
    // servers no `deaths_`), so each is optional, and a value that isn't a
    // number reads as not reported rather than failing the whole query. A row
    // without a name isn't a player.
    fn number<T: std::str::FromStr>(data: &HashMap<String, String>, key: &str) -> Option<T> {
        data.get(key).and_then(|value| value.trim().parse().ok())
    }

    let players = players_data
        .iter()
        .filter_map(|data| {
            Some(Player {
                name: data.get("player")?.to_string(),
                score: number(data, "score"),
                ping: number(data, "ping"),
                team: number(data, "team"),
                deaths: number(data, "deaths"),
                skill: number(data, "skill"),
            })
        })
        .collect();

    let teams = teams_data
        .iter()
        .filter_map(|data| {
            Some(Team {
                name: data.get("team")?.to_string(),
                score: number(data, "score"),
            })
        })
        .collect();

    Ok((players, teams))
}

/// Query a server by providing the address, the port and timeout settings.
/// Providing None to the timeout settings results in using the default values.
/// (TimeoutSettings::[default](TimeoutSettings::default)).
pub fn query(address: &SocketAddr, timeout_settings: Option<TimeoutSettings>) -> GDResult<Response> {
    let mut client = GameSpy3::new(address, timeout_settings)?;
    let packets = client.get_server_packets()?;

    let (mut server_vars, remaining_data) = data_to_map(packets.first().ok_or(GDErrorKind::PacketBad)?)?;

    let mut remaining_data_packets = vec![remaining_data];
    remaining_data_packets.extend_from_slice(&packets[1 ..]);
    let (players, teams) = parse_players_and_teams(remaining_data_packets)?;

    let players_maximum = server_vars
        .remove("maxplayers")
        .ok_or(GDErrorKind::PacketBad)?
        .parse()
        .map_err(|e| TypeParse.context(e))?;
    let players_minimum = match server_vars.remove("minplayers") {
        None => None,
        Some(v) => Some(v.parse::<u8>().map_err(|e| TypeParse.context(e))?),
    };
    let players_online = match server_vars.remove("numplayers") {
        None => players.len(),
        Some(v) => {
            let reported_players = v.parse().map_err(|e| TypeParse.context(e))?;
            match reported_players < players.len() {
                true => players.len(),
                false => reported_players,
            }
        }
    };
    let players_online = u32::try_from(players_online).unwrap_or(u32::MAX);

    Ok(Response {
        name: server_vars
            .remove("hostname")
            .ok_or(GDErrorKind::PacketBad)?,
        map: server_vars
            .remove("mapname")
            .ok_or(GDErrorKind::PacketBad)?,
        has_password: has_password(&mut server_vars)?,
        game_mode: server_vars
            .remove("gametype")
            .ok_or(GDErrorKind::PacketBad)?,
        game_version: server_vars
            .remove("gamever")
            .ok_or(GDErrorKind::PacketBad)?,
        players_maximum,
        players_online,
        players_minimum,
        players,
        teams,
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
mod hostile_tests;
