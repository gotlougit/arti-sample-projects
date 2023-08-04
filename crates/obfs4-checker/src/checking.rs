use arti_client::config::pt::ManagedTransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use arti_client::{TorClient, TorClientConfig};
use chrono::prelude::*;
use futures::future::join_all;
use std::collections::HashMap;
use std::error::Error;
use tor_error::ErrorReport;
use tor_guardmgr::bridge::{BridgeConfig, BridgeParseError};
use tor_proto::channel::Channel;
use tor_rtcompat::PreferredRuntime;
use tracing::{error, info};

use crate::BridgeResult;

/// The maximum number of open connections to relays at any given time
const MAX_CONNECTIONS: usize = 10;

/// Attempt to create a Channel to a provided bridge
///
/// If successful, we will obtain a Channel, if not we get an error.
/// Based on this operation we simply return a boolean.
///
/// The channel is created using [tor_chanmgr::ChanMgr], accessed using
/// [TorClient::chanmgr()]
async fn is_bridge_online(
    bridge_config: &BridgeConfig,
    tor_client: &TorClient<PreferredRuntime>,
) -> (Option<Channel>, Option<String>) {
    info!("Seeing if the bridge is online or not...");
    let chanmgr = tor_client.chanmgr();
    match chanmgr.build_unmanaged_channel(bridge_config).await {
        Ok(chan) => {
            println!("Bridge {} is online", bridge_config);
            (Some(chan), None)
        }
        Err(e) => {
            error!("For bridge {}, {}", bridge_config, e.report());
            let report = e.report().to_string();
            (None, Some(report))
        }
    }
}

/// Just a small alias for building a default [TorClient] config. It will likely
/// be removed later
fn build_entry_node_config() -> TorClientConfigBuilder {
    TorClientConfig::builder()
}

/// Return a [TorClientConfigBuilder] which is set to use obfs4 pluggable transport
/// for all connections
///
/// Note that the `obfs4proxy` binaru may go by a different name depending on
/// which system you are using. This code is configured to find `lyrebird` in
/// $PATH, but it may need alterations if this isn't working on your system
fn build_obfs4_bridge_config() -> TorClientConfigBuilder {
    let mut builder = TorClientConfig::builder();
    let mut transport = ManagedTransportConfigBuilder::default();
    transport
        .protocols(vec!["obfs4".parse().unwrap()])
        // THIS IS DISTRO SPECIFIC
        // If this function doesn't work, check by what name obfs4 client
        // goes by on your system
        .path(CfgPath::new(("lyrebird").into()))
        .run_on_startup(true);
    builder.bridges().transports().push(transport);
    builder
}

/// Contains the main logic for testing each bridge.
///
/// It ends up taking in a slice of bridge lines, and creates [MAX_CONNECTIONS]
/// number of connections as tasks, then waits for these requests to be resolved,
/// either by successfully connecting or not (for a variety of reasons). The
/// actual work to check each single bridge is done by [is_bridge_online()]
///
/// This is done up until all the bridges in the slice are covered
async fn controlled_test_function(
    node_lines: &[String],
    common_tor_client: TorClient<PreferredRuntime>,
) -> (HashMap<String, BridgeResult>, HashMap<String, Channel>) {
    let mut results: HashMap<String, BridgeResult> = HashMap::new();
    let mut channels: HashMap<String, Channel> = HashMap::new();
    for counter in 0..node_lines.len() {
        let mut tasks = Vec::with_capacity(MAX_CONNECTIONS);
        println!("Getting more descriptors to test...");
        for _ in 0..MAX_CONNECTIONS {
            if counter >= node_lines.len() {
                break;
            }
            let rawbridgeline = node_lines[counter].clone();
            let maybe_bridge: Result<BridgeConfigBuilder, BridgeParseError> = rawbridgeline.parse();
            match maybe_bridge {
                Ok(bridge) => {
                    let bridge_config = bridge.build().unwrap();
                    let tor_client = common_tor_client.isolated_client();
                    tasks.push(tokio::spawn(async move {
                        let current_time = Utc::now();
                        let formatted_time =
                            current_time.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string();
                        let (functional, error) =
                            is_bridge_online(&bridge_config, &tor_client).await;
                        (rawbridgeline, functional, formatted_time, error)
                    }));
                }
                Err(e) => {
                    tasks.push(tokio::spawn(async move {
                        let current_time = Utc::now();
                        let formatted_time =
                            current_time.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string();
                        (
                            rawbridgeline,
                            None,
                            formatted_time,
                            Some(format!("{}", e.report())),
                        )
                    }));
                }
            }
        }
        println!("Now trying to get results of these connections");
        let task_results = join_all(tasks).await;
        for task in task_results {
            match task {
                Ok((bridgeline, chan, time, error)) => {
                    let res = BridgeResult {
                        functional: chan.is_some(),
                        last_tested: time,
                        error,
                    };
                    results.insert(bridgeline.clone(), res);
                    if let Some(channel) = chan {
                        channels.insert(bridgeline, channel);
                    }
                }
                Err(e) => {
                    error!("{}", e.report());
                }
            }
        }
    }
    (results, channels)
}

/// Main function to unite everything together
///
/// In summary,
///
/// 1. Create the common [`TorClient`] which will be used for every connection
///
/// 2. Give [controlled_test_function()] the bridge lines
///
/// 3. Return the results
pub async fn main_test(
    guard_lines: Vec<String>,
) -> Result<(HashMap<String, BridgeResult>, HashMap<String, Channel>), Box<dyn Error>> {
    let builder = build_entry_node_config().build()?;
    // let builder = build_obfs4_bridge_config().build()?;
    let common_tor_client = TorClient::create_bootstrapped(builder).await?;
    let (bridge_results, channels) =
        controlled_test_function(&guard_lines, common_tor_client).await;
    Ok((bridge_results, channels))
}
