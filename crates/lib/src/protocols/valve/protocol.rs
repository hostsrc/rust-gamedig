use crate::{
    buffer::Buffer,
    protocols::{
        types::TimeoutSettings,
        valve::{
            types::{
                Environment,
                ExtraData,
                GatheringSettings,
                Request,
                Response,
                Server,
                ServerInfo,
                ServerPlayer,
                TheShip,
            },
            Engine,
            ModData,
        },
    },
    socket::{Socket, UdpSocket},
    utils::{maybe_gather, retry_on_timeout, u8_lower_upper},
    GDErrorKind::{BadGame, Decompress, PacketBad},
    GDResult,
};

use bzip2_rs::decoder::Decoder;

use crate::buffer::Utf8Decoder;
use crate::protocols::valve::Packet;
use byteorder::LittleEndian;
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Debug)]
#[allow(dead_code)] // remove this later on
pub(super) struct SplitPacket {
    pub header: u32,
    pub id: u32,
    pub total: u8,
    pub number: u8,
    pub size: u16,
    /// None means its not compressed, Some means it is
    /// and it contains (size and crc32)
    pub decompressed: Option<(u32, u32)>,
    payload: Vec<u8>,
}

impl SplitPacket {
    fn new(engine: &Engine, protocol: u8, buffer: &mut Buffer<LittleEndian>) -> GDResult<Self> {
        let header = buffer.read()?; // buffer.get_u32()?;
        let id = buffer.read()?;
        let (total, number, size, decompressed) = match engine {
            Engine::GoldSrc(_) => {
                let (lower, upper) = u8_lower_upper(buffer.read()?);
                (lower, upper, 0, None)
            }
            Engine::Source(_) => {
                let total = buffer.read()?;
                let number = buffer.read()?;
                let size = match protocol == 7 && (*engine == Engine::new(240)) {
                    // certain apps with protocol = 7 dont have this field, such as CSS
                    false => buffer.read()?,
                    true => 1248,
                };

                let is_compressed = ((id >> 31) & 1u32) == 1u32;
                let decompressed = match is_compressed {
                    false => None,
                    true => Some((buffer.read()?, buffer.read()?)),
                };

                (total, number, size, decompressed)
            }
        };

        Ok(Self {
            header,
            id,
            total,
            number,
            size,
            decompressed,
            payload: buffer.remaining_bytes().to_vec(),
        })
    }

    fn get_payload(&self) -> GDResult<Vec<u8>> {
        if let Some(decompressed) = self.decompressed {
            let mut decoder = Decoder::new();
            decoder
                .write(&self.payload)
                .map_err(|e| Decompress.context(e))?;

            let decompressed_size = decompressed.0 as usize;

            let mut decompressed_payload = vec![0; decompressed_size];

            decoder
                .read(&mut decompressed_payload)
                .map_err(|e| Decompress.context(e))?;

            if decompressed_payload.len() != decompressed_size
                || crc32fast::hash(&decompressed_payload) != decompressed.1
            {
                Err(Decompress.context(format!(
                    "Decompressed size {} was not expected {}",
                    decompressed_payload.len(),
                    decompressed_size
                )))
            } else {
                Ok(decompressed_payload)
            }
        } else {
            Ok(self.payload.clone())
        }
    }
}

/// The first datagram of a response: either a complete packet, or the first
/// chunk of a split response that needs `total - 1` more chunks.
pub(super) enum FirstPacket {
    Single(Packet),
    Split(SplitPacket),
}

impl FirstPacket {
    pub(super) fn parse(engine: &Engine, protocol: u8, data: &[u8]) -> GDResult<Self> {
        let mut buffer = Buffer::<LittleEndian>::new(data);

        let header: u8 = buffer.read()?;
        buffer.move_cursor(-1)?;
        if header == 0xFE {
            // the packet is split
            Ok(Self::Split(SplitPacket::new(
                engine,
                protocol,
                &mut buffer,
            )?))
        } else {
            Ok(Self::Single(Packet::new_from_bufferer(&mut buffer)?))
        }
    }
}

impl SplitPacket {
    /// Parse a follow-up chunk of a split response.
    pub(super) fn parse_chunk(engine: &Engine, protocol: u8, data: &[u8]) -> GDResult<Self> {
        let mut buffer = Buffer::<LittleEndian>::new(data);
        Self::new(engine, protocol, &mut buffer)
    }

    /// Number of chunks this response was split into.
    pub(super) const fn total(&self) -> u8 { self.total }

    /// Join the first received chunk with the remaining chunks and decode the
    /// packet.
    ///
    /// UDP does not preserve order, so the first datagram received is not
    /// necessarily chunk 0: every chunk, including this one, is sorted by its
    /// number before the payloads are concatenated.
    pub(super) fn assemble(self, mut chunk_packets: Vec<Self>) -> GDResult<Packet> {
        chunk_packets.push(self);
        chunk_packets.sort_by_key(|chunk_packet| chunk_packet.number);

        // Never empty: `self` was just pushed.
        let mut main_packet = chunk_packets.remove(0);
        for chunk_packet in chunk_packets {
            main_packet.payload.extend(chunk_packet.payload);
        }

        let payload = main_packet.get_payload()?; // Creating a non-temporary value here
        let mut new_packet_buffer = Buffer::<LittleEndian>::new(&payload); // Using the non-temporary value here
        Packet::new_from_bufferer(&mut new_packet_buffer)
    }
}

/// Header of a challenge reply ('A').
pub(super) const CHALLENGE_REPLY: u8 = 0x41;
/// Header of the `A2S_INFO` reply in the Source format ('I').
pub(super) const INFO_REPLY_SOURCE: u8 = 0x49;
/// Header of the obsolete GoldSrc `A2S_INFO` reply ('m').
pub(super) const INFO_REPLY_GOLDSRC: u8 = 0x6D;
/// Datagrams read for one request (challenges and stray replies included)
/// before giving up, so a misbehaving server cannot keep a query looping.
pub(super) const MAX_REPLIES: usize = 8;

/// What a received packet means for the request that is waiting for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reply {
    /// The server wants the request again with this challenge.
    Challenge,
    /// Left over from an earlier request: skip it and keep reading.
    Stray,
    /// The answer.
    Answer,
}

/// Classify a packet of kind `reply` received for a request of kind
/// `request`.
///
/// Older HLDS builds answer one `A2S_INFO` with two datagrams, the GoldSrc
/// 'm' reply and then the Source 'I' one. The info query returns on the
/// first, so the second can arrive while the player or rules request is
/// waiting; it must not be taken for their answer.
pub(super) fn classify_reply(request: u8, reply: u8) -> Reply {
    const PLAYERS: u8 = Request::Players as u8;
    const RULES: u8 = Request::Rules as u8;
    match (request, reply) {
        (_, CHALLENGE_REPLY) => Reply::Challenge,
        (PLAYERS | RULES, INFO_REPLY_SOURCE | INFO_REPLY_GOLDSRC) => Reply::Stray,
        _ => Reply::Answer,
    }
}

/// The error when [MAX_REPLIES] datagrams came without an answer.
pub(super) fn too_many_replies() -> crate::GDError { PacketBad.context(format!("no answer in {MAX_REPLIES} replies")) }

/// Build the request to resend after the server answered with a challenge
/// (`0x41`, 'A').
pub(super) fn challenge_request(kind: u8, challenge: Vec<u8>) -> Vec<u8> {
    const INFO: u8 = Request::Info as u8;
    Packet::new(
        kind,
        match kind {
            INFO => [Request::Info.get_default_payload(), challenge].concat(),
            _ => challenge,
        },
    )
    .to_bytes()
}

pub(crate) struct ValveProtocol {
    socket: UdpSocket,
    retry_count: usize,
}

pub(super) static PACKET_SIZE: usize = 6144;

impl ValveProtocol {
    pub fn new(address: &SocketAddr, timeout_settings: Option<TimeoutSettings>) -> GDResult<Self> {
        let socket = UdpSocket::new(address, &timeout_settings)?;
        let retry_count = timeout_settings.as_ref().map_or_else(
            || TimeoutSettings::default().get_retries(),
            TimeoutSettings::get_retries,
        );

        Ok(Self {
            socket,
            retry_count,
        })
    }

    fn receive(&mut self, engine: &Engine, protocol: u8, buffer_size: usize) -> GDResult<Packet> {
        let data = self.socket.receive(Some(buffer_size))?;

        match FirstPacket::parse(engine, protocol, &data)? {
            FirstPacket::Single(packet) => Ok(packet),
            FirstPacket::Split(main_packet) => {
                let total = main_packet.total();
                let mut chunk_packets = Vec::with_capacity(total.saturating_sub(1) as usize);

                for _ in 1 .. total {
                    let new_data = self.socket.receive(Some(buffer_size))?;
                    chunk_packets.push(SplitPacket::parse_chunk(engine, protocol, &new_data)?);
                }

                main_packet.assemble(chunk_packets)
            }
        }
    }

    fn get_kind_request_packet(&mut self, engine: &Engine, protocol: u8, kind: Request) -> GDResult<Packet> {
        retry_on_timeout(self.retry_count, || {
            self.get_request_packet(engine, protocol, kind as u8, kind.get_default_payload())
        })
    }

    /// Ask for a specific request only.
    /// This function will retry fetch on timeouts.
    pub fn get_request_data(&mut self, engine: &Engine, protocol: u8, kind: u8, payload: Vec<u8>) -> GDResult<Vec<u8>> {
        retry_on_timeout(self.retry_count, || {
            self.get_request_packet(engine, protocol, kind, payload.clone())
                .map(|packet| packet.payload)
        })
    }

    /// Ask for a specific request only (without retry logic), answering
    /// challenges and skipping stray replies (see [classify_reply]).
    fn get_request_packet(&mut self, engine: &Engine, protocol: u8, kind: u8, payload: Vec<u8>) -> GDResult<Packet> {
        let request_initial_packet = Packet::new(kind, payload).to_bytes();
        self.socket.send(&request_initial_packet)?;

        for _ in 0 .. MAX_REPLIES {
            let packet = self.receive(engine, protocol, PACKET_SIZE)?;
            match classify_reply(kind, packet.kind) {
                Reply::Answer => return Ok(packet),
                Reply::Stray => {}
                Reply::Challenge => self.socket.send(&challenge_request(kind, packet.payload))?,
            }
        }

        Err(too_many_replies())
    }

    /// Get the server information's.
    fn get_server_info(&mut self, engine: &Engine) -> GDResult<ServerInfo> {
        let packet = self.get_kind_request_packet(engine, 0, Request::Info)?;
        parse_server_info(engine, packet.kind, &packet.payload)
    }

    /// Get the server player's.
    fn get_server_players(&mut self, engine: &Engine, protocol: u8) -> GDResult<Vec<ServerPlayer>> {
        let packet = self.get_kind_request_packet(engine, protocol, Request::Players)?;
        parse_server_players(engine, &packet.payload)
    }

    /// Get the server's rules.
    fn get_server_rules(&mut self, engine: &Engine, protocol: u8) -> GDResult<HashMap<String, String>> {
        let packet = self.get_kind_request_packet(engine, protocol, Request::Rules)?;
        parse_server_rules(engine, &packet.payload)
    }
}

/// Parse the obsolete GoldSrc `A2S_INFO` reply ('m'), header already read.
fn parse_goldsrc_server_info(buffer: &mut Buffer<LittleEndian>) -> GDResult<ServerInfo> {
    let _address: String = buffer.read_string::<Utf8Decoder>(None)?; // get the server address (useless info)
    let name = buffer.read_string::<Utf8Decoder>(None)?;
    let map = buffer.read_string::<Utf8Decoder>(None)?;
    let folder = buffer.read_string::<Utf8Decoder>(None)?;
    let game_mode = buffer.read_string::<Utf8Decoder>(None)?;
    let players = buffer.read()?;
    let max_players = buffer.read()?;
    let protocol = buffer.read()?;
    // Documented upper case, but HLDS / ReHLDS send lower case ('d', 'l').
    let server_type = Server::from_gldsrc(buffer.read()?)?;
    let environment_type = Environment::from_gldsrc(buffer.read()?)?;
    let has_password = buffer.read::<u8>()? == 1;
    let is_mod = buffer.read::<u8>()? == 1;
    let mod_data = match is_mod {
        false => None,
        true => {
            Some(ModData {
                link: buffer.read_string::<Utf8Decoder>(None)?,
                download_link: buffer.read_string::<Utf8Decoder>(None)?,
                version: {
                    let _null: u8 = buffer.read()?; // a NULL byte before the version
                    buffer.read()?
                },
                size: buffer.read()?,
                multiplayer_only: buffer.read::<u8>()? == 1,
                has_own_dll: buffer.read::<u8>()? == 1,
            })
        }
    };
    let vac_secured = buffer.read::<u8>()? == 1;
    let bots = buffer.read::<u8>()?;

    Ok(ServerInfo {
        protocol_version: protocol,
        name,
        map,
        folder,
        game_mode,
        appid: 0, // not present in the obsolete response
        players_online: players,
        players_maximum: max_players,
        players_bots: bots,
        server_type,
        environment_type,
        has_password,
        vac_secured,
        the_ship: None,
        game_version: String::new(), // a version field only for the mod
        extra_data: None,
        is_mod,
        mod_data,
    })
}

/// Parse an `A2S_INFO` response payload; `kind` is the reply header, which
/// picks the format: 'm' is the obsolete GoldSrc layout, 'I' the Source one
/// (sent by GoldSrc servers too). Any other header falls back to the engine:
/// GoldSrc layout when it is forced, else Source.
pub(super) fn parse_server_info(engine: &Engine, kind: u8, data: &[u8]) -> GDResult<ServerInfo> {
    let mut buffer = Buffer::<LittleEndian>::new(data);

    let goldsrc_layout = match kind {
        INFO_REPLY_GOLDSRC => true,
        INFO_REPLY_SOURCE => false,
        _ => *engine == Engine::GoldSrc(true),
    };
    if goldsrc_layout {
        return parse_goldsrc_server_info(&mut buffer);
    }

    let protocol = buffer.read()?;
    let name = buffer.read_string::<Utf8Decoder>(None)?;
    let map = buffer.read_string::<Utf8Decoder>(None)?;
    let folder = buffer.read_string::<Utf8Decoder>(None)?;
    let game_mode = buffer.read_string::<Utf8Decoder>(None)?;
    let mut appid = buffer.read::<u16>()? as u32;
    let players = buffer.read()?;
    let max_players = buffer.read()?;
    let bots = buffer.read()?;
    let server_type = Server::from_gldsrc(buffer.read()?)?;
    let environment_type = Environment::from_gldsrc(buffer.read()?)?;
    let has_password = buffer.read::<u8>()? == 1;
    let vac_secured = buffer.read::<u8>()? == 1;
    let the_ship = match *engine == Engine::new(2400) {
        false => None,
        true => {
            Some(TheShip {
                mode: buffer.read()?,
                witnesses: buffer.read()?,
                duration: buffer.read()?,
            })
        }
    };
    let game_version = buffer.read_string::<Utf8Decoder>(None)?;
    let extra_data = match buffer.read::<u8>() {
        Err(_) => None,
        Ok(value) => {
            Some(ExtraData {
                port: match (value & 0x80) > 0 {
                    false => None,
                    true => Some(buffer.read()?),
                },
                steam_id: match (value & 0x10) > 0 {
                    false => None,
                    true => Some(buffer.read()?),
                },
                tv_port: match (value & 0x40) > 0 {
                    false => None,
                    true => Some(buffer.read()?),
                },
                tv_name: match (value & 0x40) > 0 {
                    false => None,
                    true => Some(buffer.read_string::<Utf8Decoder>(None)?),
                },
                keywords: match (value & 0x20) > 0 {
                    false => None,
                    true => Some(buffer.read_string::<Utf8Decoder>(None)?),
                },
                game_id: match (value & 0x01) > 0 {
                    false => None,
                    true => {
                        let gid = buffer.read()?;
                        appid = (gid & ((1 << 24) - 1)) as u32;

                        Some(gid)
                    }
                },
            })
        }
    };

    Ok(ServerInfo {
        protocol_version: protocol,
        name,
        map,
        folder,
        game_mode,
        appid,
        players_online: players,
        players_maximum: max_players,
        players_bots: bots,
        server_type,
        environment_type,
        has_password,
        vac_secured,
        the_ship,
        game_version,
        extra_data,
        is_mod: false,
        mod_data: None,
    })
}

/// Parse an `A2S_PLAYER` response payload.
pub(super) fn parse_server_players(engine: &Engine, data: &[u8]) -> GDResult<Vec<ServerPlayer>> {
    let mut buffer = Buffer::<LittleEndian>::new(data);

    let count = buffer.read::<u8>()? as usize;
    let mut players: Vec<ServerPlayer> = Vec::with_capacity(count);

    for _ in 0 .. count {
        buffer.move_cursor(1)?; // skip the index byte

        players.push(ServerPlayer {
            name: buffer.read_string::<Utf8Decoder>(None)?,
            score: buffer.read()?,
            duration: buffer.read()?,
            deaths: match *engine == Engine::new(2400) {
                false => None,
                true => Some(buffer.read()?),
            },
            money: match *engine == Engine::new(2400) {
                false => None,
                true => Some(buffer.read()?),
            },
        });
    }

    Ok(players)
}

/// Parse an `A2S_RULES` response payload.
pub(super) fn parse_server_rules(engine: &Engine, data: &[u8]) -> GDResult<HashMap<String, String>> {
    let mut buffer = Buffer::<LittleEndian>::new(data);

    let count = buffer.read::<u16>()? as usize;
    let mut rules: HashMap<String, String> = HashMap::with_capacity(count);

    for _ in 0 .. count {
        let name = buffer.read_string::<Utf8Decoder>(None)?;
        let value = buffer.read_string::<Utf8Decoder>(None)?;

        rules.insert(name, value);
    }

    if *engine == Engine::new(632_360) {
        // ROR2
        rules.remove("Test");
    }

    Ok(rules)
}

/// Fail with [BadGame] if the engine pins app ids and the server reports a
/// different one (unless `check_app_id` is disabled).
pub(super) fn check_app_id(engine: &Engine, info: &ServerInfo, gather_settings: &GatheringSettings) -> GDResult<()> {
    if let Engine::Source(Some(appids)) = engine {
        let mut is_specified_id = false;

        if appids.0 == info.appid {
            is_specified_id = true;
        } else if let Some(dedicated_appid) = appids.1 {
            if dedicated_appid == info.appid {
                is_specified_id = true;
            }
        }

        if !is_specified_id && gather_settings.check_app_id {
            return Err(BadGame.context(format!("AppId: {}", info.appid)));
        }
    }

    Ok(())
}

/// Query a server by providing the address, the port, the app, gather and
/// timeout settings. Providing None to the settings results in using the
/// default values for them
/// (GatherSettings::[default](GatheringSettings::default),
/// TimeoutSettings::[default](TimeoutSettings::default)).
pub fn query(
    address: &SocketAddr,
    engine: Engine,
    gather_settings: Option<GatheringSettings>,
    timeout_settings: Option<TimeoutSettings>,
) -> GDResult<Response> {
    let response_gather_settings = gather_settings.unwrap_or_default();
    get_response(address, engine, response_gather_settings, timeout_settings)
}

fn get_response(
    address: &SocketAddr,
    engine: Engine,
    gather_settings: GatheringSettings,
    timeout_settings: Option<TimeoutSettings>,
) -> GDResult<Response> {
    let mut client = ValveProtocol::new(address, timeout_settings)?;

    let info = client.get_server_info(&engine)?;

    check_app_id(&engine, &info, &gather_settings)?;

    let protocol = info.protocol_version;

    Ok(Response {
        info,
        players: maybe_gather!(
            gather_settings.players,
            client.get_server_players(&engine, protocol)
        ),
        rules: maybe_gather!(
            gather_settings.rules,
            client.get_server_rules(&engine, protocol)
        ),
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// Captured from a hostsrc CS 1.6 server (81.181.244.29:27015,
    /// 2026-11-22): it answers one `A2S_INFO` with these two datagrams, the
    /// obsolete GoldSrc reply first.
    pub(in crate::protocols::valve) const CAPTURED_INFO_GOLDSRC: &str = "ffffffff6d38312e3138312e3234342e32393a32373031350053657276657220686f7374617420646520484f53545352432e494f007a655f6a70345f726576657273650063737472696b65005a4f4d424945204553434150452044454c55584500020e2f646c00000100";
    pub(in crate::protocols::valve) const CAPTURED_INFO_SOURCE: &str = "ffffffff493053657276657220686f7374617420646520484f53545352432e494f007a655f6a70345f726576657273650063737472696b65005a4f4d424945204553434150452044454c555845000a00020e00646c0001312e312e322e372f537464696f00808769";

    pub(in crate::protocols::valve) fn unhex(hex: &str) -> Vec<u8> {
        (0 .. hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i .. i + 2], 16).unwrap())
            .collect()
    }

    fn parse_datagram(engine: Engine, hex: &str) -> GDResult<ServerInfo> {
        let data = unhex(hex);
        let packet = Packet::new_from_bufferer(&mut Buffer::<LittleEndian>::new(&data))?;
        parse_server_info(&engine, packet.kind, &packet.payload)
    }

    /// The bug: with `GoldSrc(false)` the 'm' reply was parsed in the Source
    /// layout (the address string became the name) and failed with
    /// `UnknownEnumCast` on a byte of the hostname.
    #[test]
    fn goldsrc_info_reply_is_parsed_in_its_own_layout() {
        for engine in [
            Engine::new_gold_src(false),
            Engine::new_gold_src(true),
            Engine::Source(None),
        ] {
            let info = parse_datagram(engine, CAPTURED_INFO_GOLDSRC).unwrap();
            assert_eq!(info.name, "Server hostat de HOSTSRC.IO");
            assert_eq!(info.map, "ze_jp4_reverse");
            assert_eq!(info.folder, "cstrike");
            assert_eq!(info.game_mode, "ZOMBIE ESCAPE DELUXE");
            assert_eq!(
                (info.players_online, info.players_maximum, info.players_bots),
                (2, 14, 0)
            );
            assert_eq!(info.protocol_version, 47);
            assert_eq!(info.server_type, Server::Dedicated, "lower-case 'd'");
            assert_eq!(info.environment_type, Environment::Linux, "lower-case 'l'");
            assert!(!info.has_password);
            assert!(info.vac_secured);
            assert!(!info.is_mod);
        }
    }

    #[test]
    fn source_info_reply_from_the_same_server() {
        for engine in [Engine::new_gold_src(false), Engine::new_gold_src(true)] {
            let info = parse_datagram(engine, CAPTURED_INFO_SOURCE).unwrap();
            assert_eq!(info.name, "Server hostat de HOSTSRC.IO");
            assert_eq!(info.appid, 10);
            assert_eq!(info.protocol_version, 48);
            assert_eq!(info.game_version, "1.1.2.7/Stdio");
            assert_eq!(info.extra_data.unwrap().port, Some(27015));
        }
    }

    #[test]
    fn goldsrc_mod_fields_skip_the_null_byte() {
        let payload = [
            &b"1.2.3.4:27015\0name\0map\0mymod\0My Mod\0"[..],
            &[3, 16, 48, b'D', b'W', 1, 1],
            b"http://mod\0http://dl\0",
            &[0],
            &7u32.to_le_bytes(),
            &1234u32.to_le_bytes(),
            &[1, 1, 1, 2],
        ]
        .concat();
        let info = parse_server_info(&Engine::new_gold_src(false), INFO_REPLY_GOLDSRC, &payload).unwrap();
        let mod_data = info.mod_data.unwrap();
        assert_eq!((mod_data.version, mod_data.size), (7, 1234));
        assert!(mod_data.multiplayer_only && mod_data.has_own_dll);
        assert!(info.vac_secured);
        assert_eq!(info.players_bots, 2);
        assert_eq!(info.environment_type, Environment::Windows);
    }

    #[test]
    fn unknown_server_type_and_environment_are_kept() {
        let mut data = unhex(CAPTURED_INFO_SOURCE);
        // server type and environment follow players, max players and bots.
        let at = data.windows(3).position(|w| w == [2, 14, 0]).unwrap() + 3;
        data[at] = b'x';
        data[at + 1] = 0;
        let packet = Packet::new_from_bufferer(&mut Buffer::<LittleEndian>::new(&data)).unwrap();
        let info = parse_server_info(&Engine::new_gold_src(false), packet.kind, &packet.payload).unwrap();
        assert_eq!(info.server_type, Server::Unknown(b'x'));
        assert_eq!(info.environment_type, Environment::Unknown(0));
        assert_eq!(info.game_version, "1.1.2.7/Stdio");
    }

    #[test]
    fn late_info_replies_are_not_taken_for_players_or_rules() {
        let (info, players, rules) = (
            Request::Info as u8,
            Request::Players as u8,
            Request::Rules as u8,
        );
        for request in [info, players, rules] {
            assert_eq!(classify_reply(request, CHALLENGE_REPLY), Reply::Challenge);
        }
        for late in [INFO_REPLY_SOURCE, INFO_REPLY_GOLDSRC] {
            assert_eq!(classify_reply(info, late), Reply::Answer);
            assert_eq!(classify_reply(players, late), Reply::Stray);
            assert_eq!(classify_reply(rules, late), Reply::Stray);
        }
        assert_eq!(classify_reply(players, 0x44), Reply::Answer);
        assert_eq!(classify_reply(rules, 0x45), Reply::Answer);
        // Other request kinds (e.g. FFOW's 0x46) keep taking any reply.
        assert_eq!(classify_reply(0x46, INFO_REPLY_SOURCE), Reply::Answer);
    }
}
