use arti_client::config::pt::ManagedTransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath, TorClientConfigBuilder};
use arti_client::{TorClient, TorClientConfig};
use futures::future::join_all;
use std::fs::File;
use std::io::{BufRead, BufReader};
use tor_chanmgr::ChannelUsage;
use tor_error::ErrorReport;
use tor_guardmgr::bridge::BridgeConfig;
use tor_rtcompat::PreferredRuntime;
use tracing::{error, info};

const MAX_CONNECTIONS: usize = 10;

async fn is_bridge_online(
    bridge_config: &BridgeConfig,
    tor_client: &TorClient<PreferredRuntime>,
) -> bool {
    info!("Seeing if the bridge is online or not...");
    let chanmgr = tor_client.chanmgr();
    match chanmgr
        .get_or_launch(bridge_config, ChannelUsage::UserTraffic)
        .await
    {
        Ok(_) => {
            println!("Bridge {} is online", bridge_config);
            true
        }
        Err(e) => {
            error!("For bridge {}, {}", bridge_config, e.report());
            false
        }
    }
}

fn read_lines_from_file(fname: &str) -> Vec<String> {
    let file = File::open(fname).unwrap();
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().collect::<Result<_, _>>().unwrap();
    lines
}

fn build_entry_node_config() -> TorClientConfigBuilder {
    TorClientConfig::builder()
}

fn build_obfs4_bridge_config() -> TorClientConfigBuilder {
    let mut builder = TorClientConfig::builder();
    let mut transport = ManagedTransportConfigBuilder::default();
    transport
        .protocols(vec!["obfs4".parse().unwrap()])
        // THIS IS DISTRO SPECIFIC
        // If this function doesn't work, check by what name obfs4 client
        // goes by on your system
        .path(CfgPath::new(("obfs4proxy").into()))
        .run_on_startup(true);
    builder.bridges().transports().push(transport);
    builder
}

async fn controlled_test_function(
    node_lines: &[String],
    common_tor_client: TorClient<PreferredRuntime>,
) -> u32 {
    let mut number_online = 0;
    let mut counter: usize = 0;
    while counter < node_lines.len() {
        let mut tasks = Vec::new();
        println!("Getting more descriptors to test...");
        for _ in 0..MAX_CONNECTIONS {
            if counter >= node_lines.len() {
                break;
            }
            let bridge: BridgeConfigBuilder = node_lines[counter].parse().unwrap();
            let bridge_config = bridge.build().unwrap();
            let tor_client = common_tor_client.isolated_client();
            tasks.push(tokio::spawn(async move {
                return is_bridge_online(&bridge_config, &tor_client).await;
            }));
            counter += 1;
        }
        println!("Now trying to get results of these connections");
        let task_results = join_all(tasks).await;
        for task in task_results {
            match task {
                Ok(result) => {
                    if result {
                        number_online += 1;
                    }
                }
                Err(e) => {
                    error!("{}", e.report());
                }
            }
        }
    }
    number_online
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    // Test data taken from:
    // https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/blob/main/projects/common/bridges_list.obfs4.txt
    let bridge_lines = [
        "obfs4 192.95.36.142:443 CDF2E852BF539B82BD10E27E9115A31734E378C2 cert=qUVQ0srL1JI/vO6V6m/24anYXiJD3QP2HgzUKQtQ7GRqqUvs7P+tG43RtAqdhLOALP7DJQ iat-mode=1",
        "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
        "obfs4 85.31.186.98:443 011F2599C0E9B27EE74B353155E244813763C3E5 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg iat-mode=0",
        "obfs4 85.31.186.26:443 91A6354697E6B02A386312F68D82CF86824D3606 cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw iat-mode=0",
        "obfs4 193.11.166.194:27015 2D82C2E354D531A68469ADF7F878FA6060C6BACA cert=4TLQPJrTSaDffMK7Nbao6LC7G9OW/NHkUwIdjLSS3KYf0Nv4/nQiiI8dY2TcsQx01NniOg iat-mode=0",
        "obfs4 193.11.166.194:27020 86AC7B8D430DAC4117E9F42C9EAED18133863AAF cert=0LDeJH4JzMDtkJJrFphJCiPqKx7loozKN7VNfuukMGfHO0Z8OGdzHVkhVAOfo1mUdv9cMg iat-mode=0",
        "obfs4 193.11.166.194:27025 1AE2C08904527FEA90C4C4F8C1083EA59FBC6FAF cert=ItvYZzW5tn6v3G4UnQa6Qz04Npro6e81AP70YujmK/KXwDFPTs3aHXcHp4n8Vt6w/bv8cA iat-mode=0",
        "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
        "obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq/mtAjp1BIC9vHKJ2FAEpGssTPw iat-mode=0",
        "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0",
        "obfs4 51.222.13.177:80 5EDAC3B810E12B01F6FD8050D2FD3E277B289A08 cert=2uplIpLQ0q9+0qMFrK5pkaYRDOe460LL9WHBvatgkuRr/SL31wBOEupaMMJ6koRE6Ld0ew iat-mode=0",
    ].to_vec();
    let guard_lines = read_lines_from_file("list_of_entry_nodes");
    for iters in 0..(guard_lines.len() / MAX_CONNECTIONS) {
        //let number_online = test_obfs4_bridges(&bridge_lines).await;
        let start = 100 * iters;
        if start >= guard_lines.len() {
            break;
        }
        let mut end = start + 100;
        while end >= guard_lines.len() {
            end -= 1;
        }
        let cpy = guard_lines[start..end].to_vec();
        let builder = build_entry_node_config().build().unwrap();
        let common_tor_client = TorClient::create_bootstrapped(builder).await.unwrap();
        tokio::spawn(async move {
            let number_online = controlled_test_function(&cpy, common_tor_client).await;
            println!(
                "STATUS: {} out of {} online",
                number_online,
                //bridge_lines.len()
                //guard_lines.len()
                100
            );
        });
    }
}
