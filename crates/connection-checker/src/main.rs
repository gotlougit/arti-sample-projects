use arti_client::config::pt::ManagedTransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath};
use arti_client::{TorClient, TorClientConfig};
use tor_error::ErrorReport;
use tor_rtcompat::PreferredRuntime;
use tracing::{error, info};

const HOST_PORT: &str = "torproject.org:80";

// Connect to a sample host and print the path it used to get there
// Note that due to the way Tor works, we can't guarantee this is the only
// path being used by any requests
async fn get_circuit(tor_client: &TorClient<PreferredRuntime>) {
    info!("Getting one possible circuit generated by Arti...");
    match tor_client.connect(HOST_PORT).await {
        Ok(stream) => {
            let circ = stream.circuit().path_ref();
            for node in circ.iter() {
                println!("Node: {}", node);
            }
        }
        Err(e) => {
            eprintln!("{}", e.report());
        }
    }
}

fn build_snowflake_config() -> TorClientConfig {
    let mut builder = TorClientConfig::builder();
    // Make sure it is up to date with
    // https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/blob/main/projects/common/bridges_list.snowflake.txt
    let bridge_line: &str = "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=cdn.sstatic.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.net:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn";
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
    builder.build().unwrap()
}

async fn test_connection_via_config(
    tor_client: TorClient<PreferredRuntime>,
    config: TorClientConfig,
    msg: &str,
) {
    println!("{}", msg);
    match tor_client.reconfigure(&config, arti_client::config::Reconfigure::WarnOnFailures) {
        Ok(_) => {
            get_circuit(&tor_client).await;
        }
        Err(e) => error!("{}", e.report()),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let initialconfig = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(initialconfig).await.unwrap();
    let isolated1 = tor_client.isolated_client();
    test_connection_via_config(
        isolated1,
        TorClientConfig::default(),
        "Testing normal Tor connection",
    )
    .await;
    let isolated2 = tor_client.isolated_client();
    let snowflakeconfig = build_snowflake_config();
    test_connection_via_config(
        isolated2,
        snowflakeconfig,
        "Testing Snowflake Tor connection",
    )
    .await;
}
