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
//! Note that for testing purposes right now the program is only configured to
//! make connections to regular, public Tor entry nodes instead, hence the naming
//! differences here.
//!
//! ### Disclaimer
//! This tool is currently in active development and needs further work and feedback
//! from the Tor Project devs in order to one day make it to production
use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr};
use tor_error::ErrorReport;

mod checking;

/// The input to our `bridge-state` handler
///
/// Just contains a list of bridge lines to test
#[derive(Deserialize)]
struct BridgeLines {
    pub bridge_lines: Vec<String>,
}

/// Struct which represents one bridge's result
#[derive(Serialize, Clone)]
pub struct BridgeResult {
    functional: bool,
    last_tested: String,
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
    bridge_results: HashMap<String, BridgeResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    time: f64,
}

/// Wrapper for `updates` handler output
#[derive(Serialize)]
struct Updates {
    online: Vec<String>,
    offline: Vec<String>,
}

/// Wrapper around the main testing function
async fn check_bridges(bridge_lines: Vec<String>) -> (StatusCode, Json<BridgesResult>) {
    let commencement_time = Utc::now();
    let mainop = crate::checking::main_test(bridge_lines.clone()).await;
    let end_time = Utc::now();
    let diff = end_time
        .signed_duration_since(commencement_time)
        .num_seconds() as f64;
    let (bridge_results, error) = match mainop {
        Ok((bridge_results, channels)) => {
            let failed_bridges = crate::checking::get_failed_bridges(&bridge_lines, &channels);
            let common_tor_client = crate::checking::build_common_tor_client().await.unwrap();
            tokio::spawn(async move {
                crate::checking::continuous_check(channels, failed_bridges, common_tor_client).await
            });
            (bridge_results, None)
        }
        Err(e) => (HashMap::new(), Some(e.report().to_string())),
    };
    let finalresult = BridgesResult {
        bridge_results,
        error,
        time: diff,
    };
    (StatusCode::OK, Json(finalresult))
}

/// Wrapper around the main testing function
async fn updates() {}

/// Run the HTTP server and call the required methods to initialize the testing
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let wrapped_bridge_check =
        move |Json(payload): Json<BridgeLines>| async { check_bridges(payload.bridge_lines).await };

    //let wrapped_updates = move || async { updates(HashMap::new(), Vec::new()).await };
    let app = Router::new().route("/bridge-state", post(wrapped_bridge_check));
    // .route("/updates", get(wrapped_updates));

    let addr = SocketAddr::from(([127, 0, 0, 1], 5000));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
