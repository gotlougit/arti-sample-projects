use arti_client::{TorClient, TorClientConfig};
use arti_hyper::*;

use hyper::{Body, Client};
use tls_api::{TlsConnector as TlsConnectorTrait, TlsConnectorBuilder};

use tls_api_native_tls::TlsConnector;
use tor_rtcompat;

async fn get_new_connection(
) -> Client<ArtiHttpConnector<tor_rtcompat::PreferredRuntime, TlsConnector>> {
    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();
    let tls_connector = TlsConnector::builder().unwrap().build().unwrap();

    let connection = ArtiHttpConnector::new(tor_client, tls_connector);
    let http = hyper::Client::builder().build::<_, Body>(connection);
    http
}

// get IP address via Tor
async fn get_ip_hyper() {
    let http = get_new_connection().await;
    eprintln!("requesting IP via Tor...");
    let mut resp = http
        .get("https://icanhazip.com".try_into().unwrap())
        .await
        .unwrap();

    eprintln!("status: {}", resp.status());

    let body = hyper::body::to_bytes(resp.body_mut()).await.unwrap();
    eprintln!("body: {}", std::str::from_utf8(&body).unwrap());
}

#[tokio::main]
async fn main() {
    println!("Hello, world!");
    get_ip_hyper().await;
}
