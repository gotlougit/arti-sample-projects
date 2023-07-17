use arti_client::config::pt::ManagedTransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath, Reconfigure};
use arti_client::{TorClient, TorClientConfig};
use tor_error::ErrorReport;
use tor_rtcompat::PreferredRuntime;
use tracing::{error, info};

const HOST_PORT: &str = "torproject.org:80";

// Connect to a sample host and print the path it used to get there
// Note that due to the way Tor works, we can't guarantee this is the only
// path being used by any requests
async fn get_circuit(tor_client: &TorClient<PreferredRuntime>) -> bool {
    info!("Getting one possible circuit generated by Arti...");
    match tor_client.connect(HOST_PORT).await {
        Ok(stream) => {
            let circ = stream.circuit().path_ref();
            for node in circ.iter() {
                println!("Node: {}", node);
            }
            return true;
        }
        Err(e) => {
            eprintln!("{}", e.report());
            return false;
        }
    }
}

/// Use a hardcoded Snowflake bridge with broker info to generate a [TorClientConfig]
/// which uses the Snowflake binary on the user's computer to connect to the Tor
/// network via Snowflake.
///
/// Note that the binary name is hardcoded as "client" in the code, and may be different
/// depending upon your system.
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

/// Use a hardcoded obfs4 bridge with broker info to generate a [TorClientConfig]
/// which uses the obfs4 binary on the user's computer to connect to the Tor
/// network via obfs4.
///
/// Note that the binary name is hardcoded as "obfs4proxy" in the code, and may be different
/// depending upon your system.
fn build_obfs4_connection() -> TorClientConfig {
    let mut builder = TorClientConfig::builder();
    // Make sure it is up to date with
    // https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/blob/main/projects/common/bridges_list.obfs4.txt
    let bridge_line: &str = "obfs4 193.11.166.194:27025 1AE2C08904527FEA90C4C4F8C1083EA59FBC6FAF cert=ItvYZzW5tn6v3G4UnQa6Qz04Npro6e81AP70YujmK/KXwDFPTs3aHXcHp4n8Vt6w/bv8cA iat-mode=0";
    let bridge: BridgeConfigBuilder = bridge_line.parse().unwrap();
    builder.bridges().bridges().push(bridge);
    let mut transport = ManagedTransportConfigBuilder::default();
    transport
        .protocols(vec!["obfs4".parse().unwrap()])
        // THIS IS DISTRO SPECIFIC
        // If this function doesn't work, check by what name snowflake client
        // goes by on your system
        .path(CfgPath::new(("obfs4proxy").into()))
        .run_on_startup(true);
    builder.bridges().transports().push(transport);
    builder.build().unwrap()
}

/// Reconfigure a given [TorClient] and try getting the circuit
async fn test_connection_via_config(
    tor_client: &TorClient<PreferredRuntime>,
    config: TorClientConfig,
    msg: &str,
) {
    let isolated = tor_client.isolated_client();
    println!("Testing {}", msg);
    match isolated.reconfigure(&config, Reconfigure::WarnOnFailures) {
        Ok(_) => match get_circuit(&isolated).await {
            true => println!("{} successful!", msg),
            false => println!("{} FAILED", msg),
        },
        Err(e) => {
            error!("{}", e.report());
            println!("{} FAILED", msg);
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let initialconfig = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(initialconfig).await.unwrap();
    test_connection_via_config(
        &tor_client,
        TorClientConfig::default(),
        "Testing normal Tor connection",
    )
    .await;
    let snowflakeconfig = build_snowflake_config();
    test_connection_via_config(
        &tor_client,
        snowflakeconfig,
        "Testing Snowflake Tor connection",
    )
    .await;
    let obfs4config = build_obfs4_connection();
    test_connection_via_config(&tor_client, obfs4config, "obfs4 Tor connection").await;
}
