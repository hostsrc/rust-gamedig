//! Query one or more Valve servers concurrently with the `tokio` feature.
//!
//! ```sh
//! cargo run -p gamedig --features tokio --example valve_protocol_query_tokio -- 127.0.0.1:27015 127.0.0.1:27016
//! # GoldSrc servers (CS 1.6, HL1 mods) split large replies differently:
//! cargo run -p gamedig --features tokio --example valve_protocol_query_tokio -- --goldsrc 127.0.0.1:27015
//! ```

use gamedig::protocols::types::GatherToggle;
use gamedig::protocols::valve::{self, Engine, GatheringSettings};
use gamedig::TimeoutSettings;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

#[tokio::main]
async fn main() {
    let goldsrc = std::env::args().any(|arg| arg == "--goldsrc");
    let mut addresses: Vec<SocketAddr> = std::env::args()
        .skip(1)
        .filter(|arg| arg != "--goldsrc")
        .map(|arg| arg.parse().expect("expected ip:port"))
        .collect();
    if addresses.is_empty() {
        addresses.push("127.0.0.1:27015".parse().unwrap());
    }

    // Don't pin an app id. GoldSrc and Source share the info/players format but
    // use different split-packet headers, which matters for large rules replies.
    let engine = if goldsrc {
        Engine::new_gold_src(false)
    } else {
        Engine::Source(None)
    };
    let gather_settings = GatheringSettings {
        players: GatherToggle::Try,
        rules: GatherToggle::Try,
        check_app_id: false,
    };
    let timeout_settings = TimeoutSettings::new(
        Some(Duration::from_secs(2)),
        Some(Duration::from_secs(2)),
        None,
        1, // one retry per request
    )
    .unwrap();

    // Every query runs concurrently on the runtime; none of them blocks a thread.
    let tasks: Vec<_> = addresses
        .into_iter()
        .map(|address| {
            tokio::spawn(async move {
                let started = Instant::now();
                let response = valve::tokio::query(
                    &address,
                    engine,
                    Some(gather_settings),
                    Some(timeout_settings),
                )
                .await;
                (address, started.elapsed(), response)
            })
        })
        .collect();

    for task in tasks {
        let (address, elapsed, response) = task.await.unwrap();
        match response {
            Ok(response) => {
                println!(
                    "{address} in {elapsed:?}: {:?} on {} ({}/{} players, {} player entries, {} rules)",
                    response.info.name,
                    response.info.map,
                    response.info.players_online,
                    response.info.players_maximum,
                    response.players.map_or(0, |players| players.len()),
                    response.rules.map_or(0, |rules| rules.len()),
                );
            }
            Err(error) => println!("{address} in {elapsed:?}: error {error}"),
        }
    }
}
