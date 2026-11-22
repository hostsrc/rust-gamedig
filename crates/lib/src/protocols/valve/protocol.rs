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
    GDErrorKind::{BadGame, Decompress, UnknownEnumCast},
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

    pub fn get_kind_request_data(&mut self, engine: &Engine, protocol: u8, kind: Request) -> GDResult<Vec<u8>> {
        let data = self.get_request_data(engine, protocol, kind as u8, kind.get_default_payload())?;
        Ok(data)
    }

    /// Ask for a specific request only.
    /// This function will retry fetch on timeouts.
    pub fn get_request_data(&mut self, engine: &Engine, protocol: u8, kind: u8, payload: Vec<u8>) -> GDResult<Vec<u8>> {
        retry_on_timeout(self.retry_count, || {
            self.get_request_data_impl(engine, protocol, kind, payload.clone())
        })
    }

    /// Ask for a specific request only (without retry logic).
    fn get_request_data_impl(
        &mut self,
        engine: &Engine,
        protocol: u8,
        kind: u8,
        payload: Vec<u8>,
    ) -> GDResult<Vec<u8>> {
        let request_initial_packet = Packet::new(kind, payload).to_bytes();
        self.socket.send(&request_initial_packet)?;

        let mut packet = self.receive(engine, protocol, PACKET_SIZE)?;
        while packet.kind == 0x41 {
            // 'A'
            let challenge_packet = challenge_request(kind, packet.payload);

            self.socket.send(&challenge_packet)?;

            packet = self.receive(engine, protocol, PACKET_SIZE)?;
        }

        Ok(packet.payload)
    }

    /// Get the server information's.
    fn get_server_info(&mut self, engine: &Engine) -> GDResult<ServerInfo> {
        let data = self.get_kind_request_data(engine, 0, Request::Info)?;
        parse_server_info(engine, &data)
    }

    /// Get the server player's.
    fn get_server_players(&mut self, engine: &Engine, protocol: u8) -> GDResult<Vec<ServerPlayer>> {
        let data = self.get_kind_request_data(engine, protocol, Request::Players)?;
        parse_server_players(engine, &data)
    }

    /// Get the server's rules.
    fn get_server_rules(&mut self, engine: &Engine, protocol: u8) -> GDResult<HashMap<String, String>> {
        let data = self.get_kind_request_data(engine, protocol, Request::Rules)?;
        parse_server_rules(engine, &data)
    }
}

fn parse_goldsrc_server_info(buffer: &mut Buffer<LittleEndian>) -> GDResult<ServerInfo> {
    let _header: u8 = buffer.read()?; // get the header (useless info)
    let _address: String = buffer.read_string::<Utf8Decoder>(None)?; // get the server address (useless info)
    let name = buffer.read_string::<Utf8Decoder>(None)?;
    let map = buffer.read_string::<Utf8Decoder>(None)?;
    let folder = buffer.read_string::<Utf8Decoder>(None)?;
    let game_mode = buffer.read_string::<Utf8Decoder>(None)?;
    let players = buffer.read()?;
    let max_players = buffer.read()?;
    let protocol = buffer.read()?;
    let server_type = match buffer.read::<u8>()? {
        68 => Server::Dedicated,    //'D'
        76 => Server::NonDedicated, //'L'
        80 => Server::TV,           //'P'
        _ => Err(UnknownEnumCast)?,
    };
    let environment_type = match buffer.read::<u8>()? {
        76 => Environment::Linux,   //'L'
        87 => Environment::Windows, //'W'
        _ => Err(UnknownEnumCast)?,
    };
    let has_password = buffer.read::<u8>()? == 1;
    let is_mod = buffer.read::<u8>()? == 1;
    let mod_data = match is_mod {
        false => None,
        true => {
            Some(ModData {
                link: buffer.read_string::<Utf8Decoder>(None)?,
                download_link: buffer.read_string::<Utf8Decoder>(None)?,
                version: buffer.read()?,
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

/// Parse an `A2S_INFO` response payload.
pub(super) fn parse_server_info(engine: &Engine, data: &[u8]) -> GDResult<ServerInfo> {
    let mut buffer = Buffer::<LittleEndian>::new(data);

    if let Engine::GoldSrc(force) = engine {
        if *force {
            return parse_goldsrc_server_info(&mut buffer);
        }
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
