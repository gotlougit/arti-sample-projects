use arti_client::config::pt::ManagedTransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use arti_client::{TorClient, TorClientConfig};
use chrono::prelude::*;
use futures::future::join_all;
use std::collections::HashMap;
use std::error::Error;
use tokio::join;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tor_error::ErrorReport;
use tor_guardmgr::bridge::{BridgeConfig, BridgeParseError};
use tor_proto::channel::Channel;
use tor_rtcompat::PreferredRuntime;

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
    let chanmgr = tor_client.chanmgr();
    match chanmgr.build_unmanaged_channel(bridge_config).await {
        Ok(chan) => (Some(chan), None),
        Err(e) => {
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
    let mut results = HashMap::new();
    let mut channels = HashMap::new();
    for mut counter in 0..node_lines.len() {
        let mut tasks = Vec::with_capacity(MAX_CONNECTIONS);
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
                            Some(e.report().to_string()),
                        )
                    }));
                }
            }
            counter += 1;
        }
        let task_results = join_all(tasks).await;
        for task in task_results {
            if let Ok((bridgeline, chan, time, error)) = task {
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
        }
    }
    (results, channels)
}

/// Calculates a list of bridge lines that have no channels
pub fn get_failed_bridges(
    guard_lines: &Vec<String>,
    channels: &HashMap<String, Channel>,
) -> Vec<String> {
    let mut failed_lines = Vec::new();
    for guard_line in guard_lines.iter() {
        if !channels.contains_key(guard_line) {
            failed_lines.push(guard_line.clone());
        }
    }
    failed_lines
}

/// Task which checks if failed bridges have come up online
pub async fn check_failed_bridges_task(
    initial_failed_bridges: Vec<String>,
    common_tor_client: TorClient<PreferredRuntime>,
    now_online_bridges: Sender<HashMap<String, Channel>>,
    mut once_online_bridges: Receiver<Vec<String>>,
) {
    let mut failed_bridges = initial_failed_bridges;
    loop {
        let (_, channels) =
            controlled_test_function(&failed_bridges, common_tor_client.clone()).await;
        // detect which bridges failed again
        failed_bridges = get_failed_bridges(&failed_bridges, &channels);
        for failed_bridge in failed_bridges.iter() {
            println!("{} failed to get new channel", failed_bridge);
        }
        for (bridge, _) in channels.iter() {
            println!("{} is now online", bridge);
        }
        // report online bridges to the appropriate task
        now_online_bridges.send(channels).await.unwrap();
        // get new failures from the other task
        while let Some(new_failures) = once_online_bridges.recv().await {
            failed_bridges.splice(..0, new_failures.iter().cloned());
        }
    }
}

/// Task which checks if online bridges have gone down
///
/// TODO: use new Arti APIs for detecting bridges going down
pub async fn detect_bridges_going_down(
    initial_channels: HashMap<String, Channel>,
    once_online_bridges: Sender<Vec<String>>,
    mut now_online_bridges: Receiver<HashMap<String, Channel>>,
) {
    let mut channels = initial_channels;
    loop {
        let mut failed_bridges = Vec::new();
        let mut new_channels = HashMap::new();
        for (bridgeline, channel) in channels.iter() {
            if channel.is_closing() {
                failed_bridges.push(bridgeline.to_string());
                println!("{}: existing channel has failed", bridgeline);
            } else {
                new_channels.insert(bridgeline.to_string(), channel.clone());
            }
        }
        // report failures to the appropriate task
        once_online_bridges.send(failed_bridges).await.unwrap();
        // get new channels from the other task
        while let Some(just_online_bridges) = now_online_bridges.recv().await {
            new_channels.extend(just_online_bridges);
        }
        channels = new_channels;
    }
}

/// Function which keeps track of the state of all the bridges given to it
pub async fn continuous_check(
    guard_lines: Vec<String>,
    channels: HashMap<String, Channel>,
    common_tor_client: TorClient<PreferredRuntime>,
) {
    let (once_online_sender, once_online_recv) = mpsc::channel(100);
    let (now_online_sender, now_online_recv) = mpsc::channel(100);
    let failed_bridges = get_failed_bridges(&guard_lines, &channels);
    let task1 = detect_bridges_going_down(channels, once_online_sender, now_online_recv);
    let task2 = check_failed_bridges_task(
        failed_bridges,
        common_tor_client,
        now_online_sender,
        once_online_recv,
    );
    join!(task1, task2);
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
    let common_isolated = common_tor_client.isolated_client();
    let (bridge_results, channels) =
        controlled_test_function(&guard_lines, common_tor_client).await;
    let channelscopy = channels.clone();
    tokio::spawn(async move {
        continuous_check(guard_lines, channelscopy, common_isolated).await;
    });
    Ok((bridge_results, channels))
}
