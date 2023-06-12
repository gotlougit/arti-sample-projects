use arti_client::config::pt::ManagedTransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath};
use arti_client::{TorClient, TorClientConfig};
use arti_hyper::*;
use tls_api::{TlsConnector as TlsConnectorTrait, TlsConnectorBuilder};
use tls_api_native_tls::TlsConnector;
use tor_error::ErrorReport;
use tor_rtcompat::PreferredRuntime;
use tracing::{error, info};

const URL: &str = "https://www.torproject.org";
const HOST_PORT: &str = "torproject.org:80";

// Generic function to test HTTPS request to a particular host
async fn test_connection(tor_client: TorClient<PreferredRuntime>) {
    let tls_connector = TlsConnector::builder().unwrap().build().unwrap();
    let tor_connector = ArtiHttpConnector::new(tor_client, tls_connector);
    let http = hyper::Client::builder().build::<_, hyper::Body>(tor_connector);
    let resp = http.get(URL.try_into().unwrap()).await.unwrap();
    let status = resp.status();
    if status == 200 {
        println!("Got 200 status code, we are successfully connected to resource!");
    } else {
        error!("Non 200 status code encountered! {}", status);
    }
}

// Connect to a sample host and print the path it used to get there
// Note that due to the way Tor works, we can't guarantee this is the only
// path being used by any requests
async fn get_circuit(tor_client: &TorClient<PreferredRuntime>) {
    info!("Getting one possible circuit generated by Arti...");
    match tor_client.connect(HOST_PORT).await {
        Ok(stream) => {
            let circ = stream.circuit().path();
            for node in circ {
                println!("Node: {}", node);
            }
        }
        Err(e) => {
            eprintln!("{}", e.report());
        }
    }
}

// Make a normal connection using publicly known Tor entry nodes
async fn test_normal_connection() {
    info!("Testing a normal Tor connection...");
    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();
    get_circuit(&tor_client).await;
    test_connection(tor_client).await;
}

// FIXME: this doesn't work because Arti and bridges are somewhat broken right now
// Watch for arti#611
async fn test_snowflake_connection() {
    info!("Testing a Snowflake Tor connection...");
    let mut builder = TorClientConfig::builder();
    // Make sure it is up to date with
    // https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/blob/main/projects/common/bridges_list.snowflake.txt
    let bridge_line : &str = "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=cdn.sstatic.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn";
    let bridge: BridgeConfigBuilder = bridge_line.parse().unwrap();
    builder.bridges().bridges().push(bridge);
    let mut transport = ManagedTransportConfigBuilder::default();
    transport
        .protocols(vec!["snowflake".parse().unwrap()])
        // THIS IS DISTRO SPECIFIC
        // If this function doesn't work, check by what name snowflake client
        // goes by on your system
        .path(CfgPath::new(("client").into()))
        .run_on_startup(true);
    builder.bridges().transports().push(transport);
    let config = builder.build().unwrap();
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();
    get_circuit(&tor_client).await;
    test_connection(tor_client).await;
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    test_normal_connection().await;
    test_snowflake_connection().await;
}
