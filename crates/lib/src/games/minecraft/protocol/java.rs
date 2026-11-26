use crate::{
    buffer::Buffer,
    games::minecraft::{as_string, as_varint, get_string, get_varint, JavaResponse, Player, RequestSettings, Server},
    protocols::types::TimeoutSettings,
    socket::{Socket, TcpSocket},
    utils::{retry_on_timeout, MAX_STREAM_RESPONSE},
    GDErrorKind::{JsonParse, PacketBad},
    GDResult,
};

use byteorder::LittleEndian;
use serde_json::Value;
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

pub struct Java {
    socket: TcpSocket,
    request_settings: RequestSettings,
    retry_count: usize,
}

impl Java {
    fn new(
        address: &SocketAddr,
        timeout_settings: Option<TimeoutSettings>,
        request_settings: Option<RequestSettings>,
    ) -> GDResult<Self> {
        let socket = TcpSocket::new(address, &timeout_settings)?;

        let retry_count = TimeoutSettings::get_retries_or_default(&timeout_settings);
        Ok(Self {
            socket,
            request_settings: request_settings.unwrap_or_default(),
            retry_count,
        })
    }

    fn send(&mut self, data: Vec<u8>) -> GDResult<()> {
        self.socket
            .send(&[as_varint(data.len() as i32), data].concat())
    }

    /// Read one packet by its frame: the VarInt length, then exactly that many
    /// bytes (at most [MAX_STREAM_RESPONSE]). After the status reply the
    /// server keeps the connection open, so reading until it closes would
    /// wait for the timeout and lose the reply.
    ///
    /// Also returns when the packet's first byte arrived.
    fn receive(&mut self) -> GDResult<(Vec<u8>, Instant)> {
        let mut length: u32 = 0;
        let mut first_byte = None;
        for i in 0 .. 5 {
            let byte = self.socket.receive_exact(1)?[0];
            let first_byte = *first_byte.get_or_insert_with(Instant::now);
            length |= u32::from(byte & 0x7f) << (7 * i);
            if byte & 0x80 == 0 {
                let length = length as usize;
                if length == 0 || length > MAX_STREAM_RESPONSE {
                    return Err(PacketBad.context(format!("Bad packet length {length}")));
                }
                return Ok((self.socket.receive_exact(length)?, first_byte));
            }
        }
        Err(PacketBad.context("Packet length is longer than 5 bytes"))
    }

    fn send_handshake(&mut self) -> GDResult<()> {
        let handshake_payload = [
            &[
                // Packet ID (0)
                0x00,
            ], // Protocol Version (-1 to determine version)
            as_varint(self.request_settings.protocol_version).as_slice(),
            // Server address (can be anything)
            as_string(&self.request_settings.hostname)?.as_slice(),
            // Server port (unsigned short, big-endian like every protocol number)
            &self.socket.port().to_be_bytes(),
            &[
                // Next state (1 for status)
                0x01,
            ],
        ]
        .concat();

        self.send(handshake_payload)?;

        Ok(())
    }

    fn send_status_request(&mut self) -> GDResult<()> {
        self.send(
            [0x00] // Packet ID (0)
                .to_vec(),
        )?;

        Ok(())
    }

    /// Send minecraft ping request and parse the response.
    /// This function will retry fetch on timeouts.
    fn get_info(&mut self) -> GDResult<(JavaResponse, Duration)> {
        retry_on_timeout(self.retry_count, move || self.get_info_impl())
    }

    /// Send minecraft ping request and parse the response (without retry
    /// logic). Also returns the round-trip time: from sending the request to
    /// the first byte of the status reply. The TCP connect before it and the
    /// rest of a long reply (a favicon is often 10 KB or more) aren't counted,
    /// so it reads like the ping a Minecraft client shows.
    fn get_info_impl(&mut self) -> GDResult<(JavaResponse, Duration)> {
        // No ping before the status reply: proxies such as Velocity answer a
        // ping sent that early with something other than the status, and the
        // pong isn't used.
        let sent = Instant::now();
        self.send_handshake()?;
        self.send_status_request()?;

        let (socket_data, first_byte) = self.receive()?;
        let round_trip = first_byte.saturating_duration_since(sent);
        let mut buffer = Buffer::<LittleEndian>::new(&socket_data);

        if get_varint(&mut buffer)? != 0 {
            // first var int is the packet id
            return Err(PacketBad.context("Expected 0"));
        }

        let json_response = get_string(&mut buffer)?;
        let value_response: Value = serde_json::from_str(&json_response).map_err(|e| JsonParse.context(e))?;

        let game_version = value_response["version"]["name"]
            .as_str()
            .ok_or(PacketBad)?
            .to_string();
        let protocol_version = value_response["version"]["protocol"]
            .as_i64()
            .ok_or(PacketBad)? as i32;

        let max_players = value_response["players"]["max"].as_u64().ok_or(PacketBad)? as u32;
        let online_players = value_response["players"]["online"]
            .as_u64()
            .ok_or(PacketBad)? as u32;
        let players: Option<Vec<Player>> = match value_response["players"]["sample"].is_null() {
            true => None,
            false => {
                Some({
                    let players_values = value_response["players"]["sample"]
                        .as_array()
                        .ok_or(PacketBad)?;

                    let mut players = Vec::with_capacity(players_values.len());
                    for player in players_values {
                        players.push(Player {
                            name: player["name"].as_str().ok_or(PacketBad)?.to_string(),
                            id: player["id"].as_str().ok_or(PacketBad)?.to_string(),
                        });
                    }

                    players
                })
            }
        };

        let response = JavaResponse {
            game_version,
            protocol_version,
            players_maximum: max_players,
            players_online: online_players,
            players,
            description: value_response["description"].to_string(),
            favicon: value_response["favicon"].as_str().map(str::to_string),
            previews_chat: value_response["previewsChat"].as_bool(),
            enforces_secure_chat: value_response["enforcesSecureChat"].as_bool(),
            server_type: Server::Java,
        };
        Ok((response, round_trip))
    }

    pub fn query(
        address: &SocketAddr,
        timeout_settings: Option<TimeoutSettings>,
        request_settings: Option<RequestSettings>,
    ) -> GDResult<JavaResponse> {
        Self::query_timed(address, timeout_settings, request_settings).map(|timed| timed.response)
    }

    pub fn query_timed(
        address: &SocketAddr,
        timeout_settings: Option<TimeoutSettings>,
        request_settings: Option<RequestSettings>,
    ) -> GDResult<TimedJavaResponse> {
        let (response, round_trip) = Self::new(address, timeout_settings, request_settings)?.get_info()?;
        Ok(TimedJavaResponse {
            response,
            round_trip,
        })
    }
}

/// A [JavaResponse] and the server's ping as the query measured it.
#[derive(Debug, Clone, PartialEq)]
pub struct TimedJavaResponse {
    pub response: JavaResponse,
    /// From sending the status request to the first byte of the reply: one
    /// round trip, without the TCP connect or the rest of a long reply. A
    /// request that timed out and was retried counts from the retry.
    pub round_trip: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    fn varint(value: i32) -> Vec<u8> { as_varint(value) }

    fn frame(body: &[u8]) -> Vec<u8> { [varint(body.len() as i32), body.to_vec()].concat() }

    const STATUS: &str = r#"{"version":{"name":"1.21.4","protocol":769},"players":{"max":100,"online":12},"description":{"text":"hi"}}"#;

    fn status_reply() -> Vec<u8> {
        let json = STATUS.as_bytes();
        frame(&[vec![0x00], varint(json.len() as i32), json.to_vec()].concat())
    }

    /// A server that reads what the client sends for 300 ms, writes `reply`
    /// in two chunks, then keeps the connection open for 3 s (as Minecraft
    /// servers do, waiting for a ping). Returns its address and what the
    /// client sent.
    fn fake(reply: Vec<u8>) -> (SocketAddr, mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (sent, seen) = mpsc::channel();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 1024];
            while let Ok(n) = stream.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[.. n]);
            }
            sent.send(request).unwrap();
            let half = reply.len() / 2;
            let _ = stream.write_all(&reply[.. half]);
            thread::sleep(Duration::from_millis(50));
            let _ = stream.write_all(&reply[half ..]);
            thread::sleep(Duration::from_secs(3));
        });
        (addr, seen)
    }

    fn timeouts() -> Option<TimeoutSettings> {
        Some(TimeoutSettings::new(Some(Duration::from_secs(2)), Some(Duration::from_secs(2)), None, 0).unwrap())
    }

    #[test]
    fn the_status_is_read_by_its_frame_while_the_server_keeps_the_connection_open() {
        let (addr, seen) = fake(status_reply());
        let started = Instant::now();
        let response = Java::query(&addr, timeouts(), None).unwrap();
        // Well under the 2 s read timeout: nothing waited for the server to close.
        assert!(started.elapsed() < Duration::from_millis(1500), "{:?}", started.elapsed());
        assert_eq!((response.players_online, response.players_maximum), (12, 100));
        assert_eq!(response.game_version, "1.21.4");

        // What the client sent: the handshake and the status request, no ping.
        let request = seen.recv().unwrap();
        let mut buffer = Buffer::<LittleEndian>::new(&request);
        let mut frames = Vec::new();
        while buffer.remaining_length() > 0 {
            let length = get_varint(&mut buffer).unwrap() as usize;
            frames.push(buffer.remaining_bytes()[.. length].to_vec());
            buffer.move_cursor(length as isize).unwrap();
        }
        assert_eq!(frames.len(), 2, "{frames:?}");
        assert_eq!(frames[1], [0x00]);
        // The handshake ends with the port, big-endian, then next state 1.
        let handshake = &frames[0];
        assert_eq!(handshake[0], 0x00);
        let port = addr.port().to_be_bytes();
        assert_eq!(&handshake[handshake.len() - 3 ..], &[port[0], port[1], 0x01]);
    }

    /// A server that answers as soon as the status request is in: the first
    /// byte of the reply at once, the rest `rest_after` later.
    fn slow_tail(rest_after: Duration) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 1024];
            // The status request (frame length 1, packet id 0) ends what the
            // client sends.
            while !request.ends_with(&[0x01, 0x00]) {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => request.extend_from_slice(&chunk[.. n]),
                }
            }
            let reply = status_reply();
            let _ = stream.write_all(&reply[.. 1]);
            thread::sleep(rest_after);
            let _ = stream.write_all(&reply[1 ..]);
            thread::sleep(Duration::from_secs(1));
        });
        addr
    }

    #[test]
    fn the_round_trip_ends_at_the_first_byte_of_the_reply() {
        let rest_after = Duration::from_millis(400);
        let addr = slow_tail(rest_after);
        let started = Instant::now();
        let timed = Java::query_timed(&addr, timeouts(), None).unwrap();
        assert!(started.elapsed() >= rest_after, "{:?}", started.elapsed());
        assert!(timed.round_trip < Duration::from_millis(200), "{:?}", timed.round_trip);
        assert_eq!(timed.response.players_online, 12);
    }

    #[test]
    fn a_huge_declared_length_is_refused_before_anything_is_allocated() {
        let (addr, _seen) = fake(varint(i32::MAX));
        let error = Java::query(&addr, timeouts(), None).unwrap_err();
        assert_eq!(error.kind, PacketBad, "{error:?}");
    }

    #[test]
    fn a_reply_cut_short_is_an_error_not_a_wait() {
        let full = status_reply();
        let short = full[.. full.len() - 10].to_vec();
        // The fake keeps the connection open after the short reply, so the
        // read ends at the 2 s timeout with an error, never with a result.
        let (addr, _seen) = fake(short);
        assert!(Java::query(&addr, timeouts(), None).is_err());
    }
}
