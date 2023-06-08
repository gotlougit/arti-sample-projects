use arti_client::{TorClient, TorClientConfig};
use arti_hyper::*;
use tls_api::{TlsConnector as TlsConnectorTrait, TlsConnectorBuilder};
use tls_api_native_tls::TlsConnector;
use tor_rtcompat::PreferredRuntime;
use tracing::info;

const URL: &str = "https://www.torproject.org";
const HOST_PORT: &str = "torproject.org:80";

async fn test_connection(tor_client: TorClient<PreferredRuntime>) {
    let tls_connector = TlsConnector::builder().unwrap().build().unwrap();
    let tor_connector = ArtiHttpConnector::new(tor_client, tls_connector);
    let http = hyper::Client::builder().build::<_, hyper::Body>(tor_connector);
    let resp = http.get(URL.try_into().unwrap()).await.unwrap();
    let status = resp.status();
    println!("Status code: {}", status);
}

// Connect to a sample host and try to
async fn get_circuit(tor_client: &TorClient<PreferredRuntime>) {
    let stream = tor_client.connect(HOST_PORT).await.unwrap();
    let circ = stream.circuit().path();
    for node in circ {
        println!("{}", node);
    }
}

async fn test_normal_connection() {
    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();
    get_circuit(&tor_client).await;
    test_connection(tor_client).await;
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Hello world!");
    test_normal_connection().await;
}
