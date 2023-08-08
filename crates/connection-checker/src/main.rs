#![warn(clippy::missing_docs_in_private_items)]
//! # connection-checker
//! Use methods to test connections to Tor: directly or by using
//! pluggable transports snowflake, obfs4, and meek
//!
//! ### Intro
//! This project aims to illustrate how to make connections to Tor using
//! different methods, and uses those to create a tool that users can run
//! to see if they can connect to the Tor network in any way from their own
//! networks.
//!
//! For more info on pluggable transports, you can refer to
//! [these docs](https://tb-manual.torproject.org/circumvention/)
//!
//! ### Usage
//! Run the program:
//! `cargo run`
//!
//! The program tests connections using snowflake, obfs4, and meek,
//! and thus requires the pluggable transports are installed.
//! To install the pluggable transports, you can check your package manager
//! or build "lyrebird", "meek" and "snowflake" from source, obtainable
//! from the [corresponding Tor Project's GitLab repositories](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/)
//!
//! ### Disclaimer
//! The connection-checker is experimental, not for production use. It's
//! intended for experimental purposes, providing insights into
//! connection methods.
use arti_client::config::pt::ManagedTransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath, Reconfigure};
use arti_client::{TorClient, TorClientConfig};
use tor_error::ErrorReport;
use tor_rtcompat::PreferredRuntime;
use tracing::{error, info};

/// The host and port we will attempt to connect to for testing purposes
const HOST_PORT: &str = "torproject.org:80";

/// Connect to a sample host and print the path it used to get there.
/// Note that due to the way Tor works, other requests may use a different
/// path than the one we obtain using this function, so this is mostly
/// for demonstration purposes.
async fn build_circuit(tor_client: &TorClient<PreferredRuntime>) -> bool {
    info!("Attempting to build circuit...");
    match tor_client.connect(HOST_PORT).await {
        Ok(stream) => {
            let circ = stream.circuit().path_ref();
            for node in circ.iter() {
                println!("Node: {}", node);
            }
            true
        }
        Err(e) => {
            eprintln!("{}", e.report());
            false
        }
    }
}

/// Attempts to build a pluggable transport-enabled [TorClientConfig] using
/// the supplied data
fn build_pt_config(
    bridge_line: &str,
    protocol_name: &str,
    client_path: &str,
) -> anyhow::Result<TorClientConfig> {
    let mut builder = TorClientConfig::builder();
    let bridge: BridgeConfigBuilder = bridge_line.parse()?;
    builder.bridges().bridges().push(bridge);
    let mut transport = ManagedTransportConfigBuilder::default();
    transport
        .protocols(vec![protocol_name.parse()?])
        // THIS IS DISTRO SPECIFIC
        // If this function doesn't work, check by what name snowflake client
        // goes by on your system
        .path(CfgPath::new(client_path.into()))
        .run_on_startup(true);
    builder.bridges().transports().push(transport);
    Ok(builder.build()?)
}

/// Reconfigure a given [TorClient] and try getting the circuit
async fn test_connection_via_config(
    tor_client: &TorClient<PreferredRuntime>,
    config: TorClientConfig,
    msg: &str,
) {
    let isolated = tor_client.isolated_client();
    println!("Testing {}...", msg);
    match isolated.reconfigure(&config, Reconfigure::WarnOnFailures) {
        Ok(_) => match build_circuit(&isolated).await {
            true => println!("{} successful!", msg),
            false => println!("{} FAILED", msg),
        },
        Err(e) => {
            error!("{}", e.report());
            println!("{} FAILED", msg);
        }
    }
}

/// Main function ends up running most of the tests one by one
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let initialconfig = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(initialconfig).await?;
    test_connection_via_config(
        &tor_client,
        TorClientConfig::default(),
        "Normal Tor connection",
    )
    .await;
    let snowflake_bridge_line = "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=cdn.sstatic.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.net:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn";
    let snowflakeconfig = build_pt_config(snowflake_bridge_line, "snowflake", "client")?;
    test_connection_via_config(&tor_client, snowflakeconfig, "Snowflake Tor connection").await;
    let obfs4_bridge_line = "obfs4 193.11.166.194:27025 1AE2C08904527FEA90C4C4F8C1083EA59FBC6FAF cert=ItvYZzW5tn6v3G4UnQa6Qz04Npro6e81AP70YujmK/KXwDFPTs3aHXcHp4n8Vt6w/bv8cA iat-mode=0";
    let obfs4config = build_pt_config(obfs4_bridge_line, "obfs4", "lyrebird")?;
    test_connection_via_config(&tor_client, obfs4config, "obfs4 Tor connection").await;
    // meek is usually overloaded these days
    // by default we don't test meek; it is more efficient to check the other two
    // transports since they are more widely used
    // let meek_bridge_line = "meek_lite 192.0.2.18:80 BE776A53492E1E044A26F17306E1BC46A55A1625 url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com";
    // let meekconfig = build_pt_config(meek_bridge_line, "meek", "meek-client")?;
    // test_connection_via_config(&tor_client, meekconfig, "meek Tor connection").await;
    Ok(())
}
