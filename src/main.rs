use arti_client::{TorClient, TorClientConfig};
use arti_hyper::*;

use hyper::{Body, Client, HeaderMap};
use tls_api::{TlsConnector as TlsConnectorTrait, TlsConnectorBuilder};

use tls_api_native_tls::TlsConnector;
use tor_rtcompat;

use memmap2::MmapMut;
use std::fs::OpenOptions;
use tracing::{debug, warn};

async fn get_new_connection(
) -> Client<ArtiHttpConnector<tor_rtcompat::PreferredRuntime, TlsConnector>> {
    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();
    let tls_connector = TlsConnector::builder().unwrap().build().unwrap();

    let connection = ArtiHttpConnector::new(tor_client, tls_connector);
    let http = hyper::Client::builder().build::<_, Body>(connection);
    http
}

async fn request(url: &str, start: usize, end: usize) -> Vec<u8> {
    let http = get_new_connection().await;
    debug!("Requesting {} via Tor...", url);
    let mut resp = http.get(url.try_into().unwrap()).await.unwrap();

    if resp.status() == 200 {
        debug!("Good request");
    } else {
        warn!("Non 200 Status code: {}", resp.status());
    }

    let body = hyper::body::to_bytes(resp.body_mut())
        .await
        .unwrap()
        .to_vec();
    body
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    debug!("Creating download file");
    let fd = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("download")
        .unwrap();
    let body = request("https://icanhazip.com", 0, 0).await;
    fd.set_len(body.len() as u64).unwrap();
    unsafe {
        let mut mmap = MmapMut::map_mut(&fd).unwrap();
        mmap.copy_from_slice(body.as_slice());
    };
}
