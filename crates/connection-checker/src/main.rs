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
//! `cargo run -- --test <TEST>`
//!
//! where <TEST> is a comma separated string made up of <protocol>:<pt-binary-path>
//! values
//!
//! For example, if you wished to test a direct connection,
//! <TEST> would be "direct:", if you wished to test an obfs4 and snowflake connection,
//! <TEST> would be "obfs4:lyrebird,snowflake:snowflake-client", where `lyrebird` is
//! the obfs4 pluggable transport binary and `snowflake-client` is the Snowflake counterpart
//!
//! You can also optionally specify a different host:port than the default `torproject.org:80`
//! to be tested by passing the value using the `--connect-to` argument.
//!
//! For more information please refer to `cargo run -- --help`
//!
//! The program can test connections using snowflake, obfs4, and meek,
//! and thus requires the pluggable transports which are to be tested are already installed.
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
use clap::Parser;
use std::collections::HashMap;
use std::str::FromStr;
use tor_error::ErrorReport;
use tor_rtcompat::PreferredRuntime;
use tracing::{error, info};

/// Test connections to the Tor network via different methods
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    /// List of tests to run
    #[clap(long, required = true)]
    test: TestValues,

    /// Specify a custom host:port to connect to for testing purposes
    #[clap(long, required = false, default_value = "torproject.org:80")]
    connect_to: String,
}

#[derive(Clone)]
struct TestValues {
    values: HashMap<String, String>,
}

impl FromStr for TestValues {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut values = HashMap::new();
        for pair in s.split(',') {
            let parts: Vec<&str> = pair.split(':').collect();
            if parts.len() == 2 {
                let protocol_name = match parts[0] {
                    "meek" => "meek",
                    "snowflake" => "snowflake",
                    "obfs4" => "obfs4",
                    _ => "direct",
                }
                .to_string();
                let pt_binary_path = parts[1].to_string();
                values.insert(protocol_name, pt_binary_path);
            }
        }
        Ok(TestValues { values })
    }
}

/// Connect to a sample host and print the path it used to get there.
/// Note that due to the way Tor works, other requests may use a different
/// path than the one we obtain using this function, so this is mostly
/// for demonstration purposes.
async fn build_circuit(tor_client: &TorClient<PreferredRuntime>, remote: &str) -> bool {
    info!("Attempting to build circuit...");
    match tor_client.connect(remote).await {
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
    remote_url: &str,
) {
    let isolated = tor_client.isolated_client();
    println!("Testing {}...", msg);
    match isolated.reconfigure(&config, Reconfigure::WarnOnFailures) {
        Ok(_) => match build_circuit(&isolated, remote_url).await {
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
    let obfs4_bridge_line: &str = include_str!("../bridges/bridge_obfs4.txt");
    let snowflake_bridge_line: &str = include_str!("../bridges/bridge_snowflake.txt");
    let meek_bridge_line: &str = include_str!("../bridges/bridge_meek.txt");

    let opts = Opts::parse();
    let initialconfig = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(initialconfig).await?;

    for (connection_type, connection_bin) in opts.test.values.iter() {
        let config = match connection_type.as_str() {
            "obfs4" => build_pt_config(obfs4_bridge_line, "obfs4", &connection_bin)?,
            "snowflake" => build_pt_config(snowflake_bridge_line, "snowflake", &connection_type)?,
            "meek" => build_pt_config(meek_bridge_line, "meek", &connection_type)?,
            _ => TorClientConfig::default(),
        };
        let msg = format!("{} Tor connection", connection_type);
        test_connection_via_config(&tor_client, config, &msg, &opts.connect_to).await;
    }
    Ok(())
}
