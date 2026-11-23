//! Non-blocking Valve (A2S) queries on the Tokio runtime.
//!
//! Enabled with the `tokio` feature. The packet parsing is shared with the
//! blocking [query](super::query); only the socket I/O differs, so both return
//! identical [Response]s for the same server.
//!
//! ```no_run
//! # async fn run() -> gamedig::GDResult<()> {
//! use gamedig::protocols::valve::{self, Engine};
//!
//! let address = "127.0.0.1:27015".parse().unwrap();
//! let response = valve::tokio::query(&address, Engine::new_gold_src(false), None, None).await?;
//! println!("{} on {}", response.info.name, response.info.map);
//! # Ok(())
//! # }
//! ```
//!
//! Timeouts and retries come from [TimeoutSettings] and apply per packet,
//! exactly like the blocking implementation. To bound a whole query, wrap the
//! future in [`tokio::time::timeout`].

use super::protocol::{
    challenge_request,
    check_app_id,
    classify_reply,
    parse_server_info,
    parse_server_players,
    parse_server_rules,
    too_many_replies,
    FirstPacket,
    Reply,
    SplitPacket,
    MAX_REPLIES,
    PACKET_SIZE,
};
use crate::{
    protocols::{
        types::TimeoutSettings,
        valve::{Engine, GatheringSettings, Packet, Request, Response, ServerInfo, ServerPlayer},
    },
    socket::AsyncUdpSocket,
    utils::maybe_gather,
    GDErrorKind::{PacketReceive, PacketSend},
    GDResult,
};

use std::{collections::HashMap, net::SocketAddr};

/// Async counterpart of the blocking `ValveProtocol` client.
struct AsyncValveProtocol {
    socket: AsyncUdpSocket,
    retry_count: usize,
}

impl AsyncValveProtocol {
    async fn new(address: &SocketAddr, timeout_settings: Option<TimeoutSettings>) -> GDResult<Self> {
        let socket = AsyncUdpSocket::new(address, &timeout_settings).await?;
        let retry_count = timeout_settings.as_ref().map_or_else(
            || TimeoutSettings::default().get_retries(),
            TimeoutSettings::get_retries,
        );

        Ok(Self {
            socket,
            retry_count,
        })
    }

    async fn receive(&mut self, engine: &Engine, protocol: u8, buffer_size: usize) -> GDResult<Packet> {
        let data = self.socket.receive(Some(buffer_size)).await?;

        match FirstPacket::parse(engine, protocol, &data)? {
            FirstPacket::Single(packet) => Ok(packet),
            FirstPacket::Split(main_packet) => {
                let total = main_packet.total();
                let mut chunk_packets = Vec::with_capacity(total.saturating_sub(1) as usize);

                for _ in 1 .. total {
                    let new_data = self.socket.receive(Some(buffer_size)).await?;
                    chunk_packets.push(SplitPacket::parse_chunk(engine, protocol, &new_data)?);
                }

                main_packet.assemble(chunk_packets)
            }
        }
    }

    /// Ask for a specific request only, retrying on send/receive failures
    /// (including timeouts) like the blocking `retry_on_timeout`.
    async fn get_kind_request_packet(&mut self, engine: &Engine, protocol: u8, kind: Request) -> GDResult<Packet> {
        let mut last_err = PacketReceive.context("Retry count was 0");

        for _ in 0 ..= self.retry_count {
            last_err = match self
                .get_request_packet(engine, protocol, kind as u8, kind.get_default_payload())
                .await
            {
                Ok(r) => return Ok(r),
                Err(e) if e.kind == PacketReceive || e.kind == PacketSend => e,
                Err(e) => return Err(e),
            };
        }

        Err(last_err)
    }

    /// Ask for a specific request only (without retry logic), answering
    /// challenges and skipping stray replies like the blocking client.
    async fn get_request_packet(
        &mut self,
        engine: &Engine,
        protocol: u8,
        kind: u8,
        payload: Vec<u8>,
    ) -> GDResult<Packet> {
        let request_initial_packet = Packet::new(kind, payload).to_bytes();
        self.socket.send(&request_initial_packet).await?;

        for _ in 0 .. MAX_REPLIES {
            let packet = self.receive(engine, protocol, PACKET_SIZE).await?;
            match classify_reply(kind, packet.kind) {
                Reply::Answer => return Ok(packet),
                Reply::Stray => {}
                Reply::Challenge => {
                    self.socket
                        .send(&challenge_request(kind, packet.payload))
                        .await?
                }
            }
        }

        Err(too_many_replies())
    }

    async fn get_server_info(&mut self, engine: &Engine) -> GDResult<ServerInfo> {
        let packet = self
            .get_kind_request_packet(engine, 0, Request::Info)
            .await?;
        parse_server_info(engine, packet.kind, &packet.payload)
    }

    async fn get_server_players(&mut self, engine: &Engine, protocol: u8) -> GDResult<Vec<ServerPlayer>> {
        let packet = self
            .get_kind_request_packet(engine, protocol, Request::Players)
            .await?;
        parse_server_players(engine, &packet.payload)
    }

    async fn get_server_rules(&mut self, engine: &Engine, protocol: u8) -> GDResult<HashMap<String, String>> {
        let packet = self
            .get_kind_request_packet(engine, protocol, Request::Rules)
            .await?;
        parse_server_rules(engine, &packet.payload)
    }
}

/// Query a server without blocking the current thread.
///
/// Same arguments, defaults and result as the blocking
/// [query](super::query): providing None to the settings uses
/// GatherSettings::[default](GatheringSettings::default) and
/// TimeoutSettings::[default](TimeoutSettings::default).
pub async fn query(
    address: &SocketAddr,
    engine: Engine,
    gather_settings: Option<GatheringSettings>,
    timeout_settings: Option<TimeoutSettings>,
) -> GDResult<Response> {
    let gather_settings = gather_settings.unwrap_or_default();
    let mut client = AsyncValveProtocol::new(address, timeout_settings).await?;

    let info = client.get_server_info(&engine).await?;

    check_app_id(&engine, &info, &gather_settings)?;

    let protocol = info.protocol_version;

    // maybe_gather! expands `$gather_fn?`, so await inside the expression.
    let players = maybe_gather!(
        gather_settings.players,
        client.get_server_players(&engine, protocol).await
    );
    let rules = maybe_gather!(
        gather_settings.rules,
        client.get_server_rules(&engine, protocol).await
    );

    Ok(Response {
        info,
        players,
        rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::types::GatherToggle;
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    const SIMPLE: [u8; 4] = [0xFF; 4];

    fn cstr(s: &str) -> Vec<u8> { [s.as_bytes(), &[0]].concat() }

    /// A Source `A2S_INFO` reply (header 'I').
    fn source_info() -> Vec<u8> {
        [
            &SIMPLE[..],
            &[0x49, 17],
            &cstr("hostsrc test"),
            &cstr("de_dust2"),
            &cstr("cstrike"),
            &cstr("Counter-Strike: Source"),
            &240u16.to_le_bytes(),
            &[5, 32, 1, b'd', b'l', 0, 1],
            &cstr("1.0.0.0"),
        ]
        .concat()
    }

    fn players_payload() -> Vec<u8> {
        [
            &[0x44, 2][..],
            &[0],
            &cstr("alice"),
            &10i32.to_le_bytes(),
            &60.5f32.to_le_bytes(),
            &[1],
            &cstr("bob"),
            &3i32.to_le_bytes(),
            &12.0f32.to_le_bytes(),
        ]
        .concat()
    }

    fn rules_payload() -> Vec<u8> {
        let mut out = vec![0x45];
        out.extend(3u16.to_le_bytes());
        for (k, v) in [
            ("mp_timelimit", "30"),
            ("sv_gravity", "800"),
            ("hostsrc", "1"),
        ] {
            out.extend(cstr(k));
            out.extend(cstr(v));
        }
        out
    }

    /// Split `payload` into Source-format chunks (header 0xFE, id, total,
    /// number, size).
    fn source_split(payload: &[u8], id: u32, chunk: usize) -> Vec<Vec<u8>> {
        let full = [&SIMPLE[..], payload].concat();
        let parts: Vec<&[u8]> = full.chunks(chunk).collect();
        let total = parts.len() as u8;
        parts
            .iter()
            .enumerate()
            .map(|(n, part)| {
                [
                    &[0xFE, 0xFF, 0xFF, 0xFF][..],
                    &id.to_le_bytes(),
                    &[total, n as u8],
                    &1248u16.to_le_bytes(),
                    part,
                ]
                .concat()
            })
            .collect()
    }

    /// Split `payload` into GoldSrc-format chunks (header 0xFE, id, one byte
    /// with total in the low nibble and number in the high nibble).
    fn goldsrc_split(payload: &[u8], id: u32, chunk: usize) -> Vec<Vec<u8>> {
        let full = [&SIMPLE[..], payload].concat();
        let parts: Vec<&[u8]> = full.chunks(chunk).collect();
        let total = parts.len() as u8;
        parts
            .iter()
            .enumerate()
            .map(|(n, part)| {
                [
                    &[0xFE, 0xFF, 0xFF, 0xFF][..],
                    &id.to_le_bytes(),
                    &[total | ((n as u8) << 4)],
                    part,
                ]
                .concat()
            })
            .collect()
    }

    /// A fake game server: info reply, challenge on players/rules, and split
    /// replies (sent in reverse order to exercise reassembly).
    async fn spawn_server(goldsrc_split_format: bool) -> (SocketAddr, Arc<AtomicUsize>) {
        let server = ::tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = requests.clone();
        let challenge = [0xDE, 0xAD, 0xBE, 0xEF];

        ::tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let req = &buf[.. n];
                let kind = req[4];
                let has_challenge = req.ends_with(&challenge);
                let replies: Vec<Vec<u8>> = match kind {
                    0x54 => vec![source_info()],
                    0x55 | 0x56 if !has_challenge => vec![[&SIMPLE[..], &[0x41], &challenge].concat()],
                    0x55 => vec![[&SIMPLE[..], &players_payload()].concat()],
                    0x56 => {
                        let mut chunks = if goldsrc_split_format {
                            goldsrc_split(&rules_payload(), 7, 16)
                        } else {
                            source_split(&rules_payload(), 7, 16)
                        };
                        chunks.reverse();
                        chunks
                    }
                    _ => vec![],
                };
                for reply in replies {
                    server.send_to(&reply, peer).await.unwrap();
                }
            }
        });

        (address, requests)
    }

    fn timeouts(retries: usize) -> Option<TimeoutSettings> {
        Some(
            TimeoutSettings::new(
                Some(Duration::from_millis(300)),
                Some(Duration::from_millis(300)),
                None,
                retries,
            )
            .unwrap(),
        )
    }

    #[::tokio::test]
    async fn source_query_with_challenge_and_split_rules() {
        let (address, _) = spawn_server(false).await;

        let response = query(&address, Engine::new(240), None, timeouts(0))
            .await
            .unwrap();

        assert_eq!(response.info.name, "hostsrc test");
        assert_eq!(response.info.map, "de_dust2");
        assert_eq!(response.info.appid, 240);
        let players = response.players.unwrap();
        assert_eq!(players.len(), 2);
        assert_eq!(players[0].name, "alice");
        assert_eq!(players[1].score, 3);
        let rules = response.rules.unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules["sv_gravity"], "800");
    }

    #[::tokio::test]
    async fn goldsrc_split_format_reassembles() {
        let (address, _) = spawn_server(true).await;

        let response = query(&address, Engine::new_gold_src(false), None, timeouts(0))
            .await
            .unwrap();

        let rules = response.rules.unwrap();
        assert_eq!(rules["mp_timelimit"], "30");
        assert_eq!(rules["hostsrc"], "1");
    }

    /// The async client must return exactly what the blocking client returns.
    #[::tokio::test(flavor = "multi_thread")]
    async fn matches_blocking_query() {
        for goldsrc in [false, true] {
            let (address, _) = spawn_server(goldsrc).await;
            let engine = if goldsrc {
                Engine::new_gold_src(false)
            } else {
                Engine::new(240)
            };
            let gather = GatheringSettings {
                players: GatherToggle::Enforce,
                rules: GatherToggle::Enforce,
                check_app_id: true,
            };

            let blocking =
                ::tokio::task::spawn_blocking(move || super::super::query(&address, engine, Some(gather), timeouts(0)))
                    .await
                    .unwrap()
                    .unwrap();
            let non_blocking = query(&address, engine, Some(gather), timeouts(0))
                .await
                .unwrap();

            assert_eq!(blocking, non_blocking);
        }
    }

    #[::tokio::test]
    async fn timeout_retries_then_fails_with_packet_receive() {
        // Bound but never answers.
        let silent = ::tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = silent.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = requests.clone();
        ::tokio::spawn(async move {
            let mut buf = [0u8; 64];
            while silent.recv_from(&mut buf).await.is_ok() {
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });

        let err = query(&address, Engine::new(240), None, timeouts(2))
            .await
            .unwrap_err();

        assert_eq!(err.kind, PacketReceive);
        assert_eq!(requests.load(Ordering::SeqCst), 3, "1 try + 2 retries");
    }

    #[::tokio::test]
    async fn wrong_app_id_is_bad_game() {
        let (address, _) = spawn_server(false).await;

        let err = query(&address, Engine::new(730), None, timeouts(0))
            .await
            .unwrap_err();

        assert_eq!(err.kind, crate::GDErrorKind::BadGame);
    }

    /// Regression (hostsrc servers, "UnknownEnumCast"): the server answers
    /// `A2S_INFO` with the GoldSrc 'm' reply and then the Source 'I' one
    /// (captured bytes). The info comes from the first, and the second must
    /// not be read as the answer to the players request that follows.
    #[::tokio::test(flavor = "multi_thread")]
    async fn double_info_reply_from_hlds() {
        use crate::protocols::valve::protocol::tests::{unhex, CAPTURED_INFO_GOLDSRC, CAPTURED_INFO_SOURCE};

        let server = ::tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let challenge = [0x12, 0x34, 0x56, 0x78];
        ::tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (n, peer) = server.recv_from(&mut buf).await.unwrap();
                let req = &buf[.. n];
                let replies = match req[4] {
                    0x54 => vec![unhex(CAPTURED_INFO_GOLDSRC), unhex(CAPTURED_INFO_SOURCE)],
                    0x55 | 0x56 if !req.ends_with(&challenge) => vec![[&SIMPLE[..], &[0x41], &challenge].concat()],
                    0x55 => vec![[&SIMPLE[..], &players_payload()].concat()],
                    0x56 => vec![[&SIMPLE[..], &rules_payload()].concat()],
                    _ => vec![],
                };
                for reply in replies {
                    server.send_to(&reply, peer).await.unwrap();
                }
            }
        });

        let gather = GatheringSettings {
            players: GatherToggle::Enforce,
            rules: GatherToggle::Enforce,
            check_app_id: false,
        };
        let engine = Engine::new_gold_src(false);
        let response = query(&address, engine, Some(gather), timeouts(0))
            .await
            .unwrap();
        assert_eq!(response.info.name, "Server hostat de HOSTSRC.IO");
        assert_eq!(response.info.map, "ze_jp4_reverse");
        assert_eq!(response.info.players_online, 2);
        let players = response.players.as_ref().unwrap();
        assert_eq!(players.len(), 2);
        assert_eq!(players[0].name, "alice");
        assert_eq!(response.rules.as_ref().unwrap()["sv_gravity"], "800");

        let blocking =
            ::tokio::task::spawn_blocking(move || super::super::query(&address, engine, Some(gather), timeouts(0)))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(blocking, response);
    }

    /// Same as the blocking `goldsrc_info_reply_with_latin1_name`, on tokio.
    #[::tokio::test]
    async fn goldsrc_info_reply_with_latin1_name() {
        use crate::protocols::valve::protocol::tests::INFO_ONLY;
        use crate::test_support::{fake_udp_server_with, fixture};

        let address = fake_udp_server_with(|request| {
            match request.get(4) {
                Some(0x54) => vec![fixture!("valve/goldsrc_info_latin1_name.bin").to_vec()],
                _ => vec![],
            }
        });

        let response = query(
            &address,
            Engine::new_gold_src(false),
            Some(INFO_ONLY),
            timeouts(0),
        )
        .await
        .unwrap();

        assert_eq!(response.info.name, "S\u{FFFD}rver hostat de HOSTSRC.IO");
        assert_eq!(response.info.players_online, 2);
    }

    #[test]
    fn query_future_is_send() {
        fn assert_send<T: Send>(_: &T) {}
        let address: SocketAddr = "127.0.0.1:27015".parse().unwrap();
        let future = query(&address, Engine::new(240), None, None);
        assert_send(&future);
    }
}
