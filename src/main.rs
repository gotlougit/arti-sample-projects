use arti_client::{TorClient, TorClientConfig};
use arti_hyper::*;

use hyper::{Body, Client};
use tls_api::{TlsConnector as TlsConnectorTrait, TlsConnectorBuilder};

use tls_api_native_tls::TlsConnector;
use tor_rtcompat;

use std::fs::OpenOptions;
use memmap2::MmapMut;

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
async fn get_ip_hyper() -> Vec<u8> {
    let http = get_new_connection().await;
    eprintln!("requesting IP via Tor...");
    let mut resp = http
        .get("https://icanhazip.com".try_into().unwrap())
        .await
        .unwrap();

    eprintln!("status: {}", resp.status());

    let body = hyper::body::to_bytes(resp.body_mut()).await.unwrap().to_vec();
    body
}

#[tokio::main]
async fn main() {
    println!("Hello, world!");
    let fd = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("download")
        .unwrap();
    let body = get_ip_hyper().await;
    fd.set_len(body.len() as u64).unwrap();
    unsafe {
        let mut mmap = MmapMut::map_mut(&fd).unwrap();
        mmap.copy_from_slice(body.as_slice());
    };
}
