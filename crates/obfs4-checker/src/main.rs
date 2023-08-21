#![warn(clippy::missing_docs_in_private_items)]
//! # obfs4-checker
//! Check the state of the obfs4 bridges present in the Tor Network
//!
//! ### Intro
//! The obfs4 bridges are a vital part of the Tor Network, obfuscating the Tor
//! protocol so that censors are unable to block Tor connections in repressive
//! regimes or for customers of opressive Internet Service Providers.
//!
//! It would be wise to have a fast, secure tool which can be used by the Tor
//! Project to montior the health of these bridges, one aspect of which is to know
//! how many nodes and which nodes are online at a given moment in time.
//!
//! This tool aims to take a complete list of bridges and try to connect to several
//! at a time in a controlled but still fast manner in order to try and ascertain their
//! status.
//!
//! ### Usage
//! It is almost identical to the existing [bridgestrap](https://gitlab.torproject.org/tpo/anti-censorship/bridgestrap)
//! tool, except we use a POST request with Content-Type set to "application/json"
//!
//! By and large, the request and response formats are almost the same
//!
//! There is one additional endpoint "/updates", which is supposed to be polled
//! regularly in order to deliver updates on which bridges have failed/come back
//! online, and whose output is same as the normal /bridge-state endpoint in format
//!
//! ### Disclaimer
//! This tool is currently in active development and needs further work and feedback
//! from the Tor Project devs in order to one day make it to production
use crate::checking::RECEIVE_TIMEOUT;
use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::prelude::*;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr};
use tokio::sync::broadcast::{self, Receiver, Sender};
use tokio::time::timeout;
use tor_error::ErrorReport;
mod checking;

/// Utility to deliver real-time updates on bridge health
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, required = true)]
    /// Path to the `lyrebird` or `obfs4proxy`, required for making obfs4 connections
    obfs4_bin: String,
}

/// The input to our `bridge-state` handler
///
/// Just contains a list of bridge lines to test
#[derive(Deserialize)]
struct BridgeLines {
    /// List of bridge lines to test
    pub bridge_lines: Vec<String>,
}

/// Struct which represents one bridge's result
#[derive(Serialize, Clone, Debug)]
pub struct BridgeResult {
    /// Is bridge online or not?
    functional: bool,
    /// The time at which the bridge was last tested, written as a nice string
    last_tested: DateTime<Utc>,
    /// Error encountered while trying to connect to the bridge, if any
    ///
    /// It is generated using [tor_error::ErrorReport]
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// The output to our `bridge-state` handler
///
/// Contains the [BridgeResult] for each bridgeline,
/// an error (if any), and the total time it took
/// to run the entire test
#[derive(Serialize)]
struct BridgesResult {
    /// All the bridge results, mapped by bridge line
    bridge_results: HashMap<String, BridgeResult>,
    /// General error encountered, if any
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// The time it took to generate this result
    time: f64,
}

/// Wrapper around the main testing function
async fn check_bridges(
    bridge_lines: Vec<String>,
    updates_sender: Sender<HashMap<String, BridgeResult>>,
    obfs4_path: String,
    new_bridges_receiver: broadcast::Receiver<Vec<String>>,
) -> (StatusCode, Json<BridgesResult>) {
    let commencement_time = Utc::now();
    let mainop = crate::checking::main_test(bridge_lines.clone(), &obfs4_path).await;
    let end_time = Utc::now();
    let diff = end_time
        .signed_duration_since(commencement_time)
        .num_seconds() as f64;
    let (bridge_results, error) = match mainop {
        Ok((bridge_results, channels)) => {
            let failed_bridges = crate::checking::get_failed_bridges(&bridge_lines, &channels);
            let common_tor_client = crate::checking::build_common_tor_client(&obfs4_path)
                .await
                .unwrap();
            tokio::spawn(async move {
                crate::checking::continuous_check(
                    channels,
                    failed_bridges,
                    common_tor_client,
                    updates_sender,
                    new_bridges_receiver,
                )
                .await
            });
            (bridge_results, None)
        }
        Err(e) => {
            let error_report = e.report().to_string().replace("error: ", "");
            (HashMap::new(), Some(error_report))
        }
    };
    let finalresult = BridgesResult {
        bridge_results,
        error,
        time: diff,
    };
    (StatusCode::OK, Json(finalresult))
}

/// Wrapper around the main testing function
async fn updates(
    mut updates_recv: Receiver<HashMap<String, BridgeResult>>,
) -> (StatusCode, Json<BridgesResult>) {
    let mut bridge_results = HashMap::new();
    while let Ok(Ok(update)) = timeout(RECEIVE_TIMEOUT, updates_recv.recv()).await {
        if update.is_empty() {
            break;
        }
        bridge_results.extend(update);
    }
    let finalresult = BridgesResult {
        bridge_results,
        error: None,
        time: 0.0,
    };
    (StatusCode::OK, Json(finalresult))
}

async fn add_new_bridges(
    new_bridge_lines: Vec<String>,
    new_bridges_sender: Sender<Vec<String>>,
) -> StatusCode {
    match new_bridges_sender.send(new_bridge_lines) {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Run the HTTP server and call the required methods to initialize the testing
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let obfs4_bin_path = args.obfs4_bin;
    // unused Receiver prevents SendErrors
    let (updates_sender, _updates_recv_unused) =
        broadcast::channel::<HashMap<String, BridgeResult>>(100);
    let (new_bridges_sender, _new_bridges_receiver) = broadcast::channel::<Vec<String>>(100);
    let updates_sender_clone = updates_sender.clone();
    let new_bridges_sender_clone = new_bridges_sender.clone();
    let wrapped_bridge_check = move |Json(payload): Json<BridgeLines>| {
        let new_bridges_recv_clone = new_bridges_sender_clone.subscribe();
        async {
            check_bridges(
                payload.bridge_lines,
                updates_sender_clone,
                obfs4_bin_path,
                new_bridges_recv_clone,
            )
            .await
        }
    };
    let wrapped_updates = move || {
        let updates_recv = updates_sender.subscribe();
        async move { updates(updates_recv).await }
    };
    let wrapped_add_new_bridges = move |Json(payload): Json<BridgeLines>| async move {
        add_new_bridges(payload.bridge_lines, new_bridges_sender).await
    };
    let app = Router::new()
        .route("/bridge-state", post(wrapped_bridge_check))
        .route("/add-bridges", post(wrapped_add_new_bridges))
        .route("/updates", get(wrapped_updates));

    let addr = SocketAddr::from(([127, 0, 0, 1], 5000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
