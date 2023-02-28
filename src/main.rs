use arti_client::{TorClient, TorClientConfig};
use arti_hyper::*;

use hyper::{Body, Client, Method, Request, Uri};
use tls_api::{TlsConnector as TlsConnectorTrait, TlsConnectorBuilder};

use tls_api_native_tls::TlsConnector;
use tor_rtcompat;

use memmap2::MmapMut;
use std::fs::OpenOptions;
use tracing::warn;

async fn get_new_connection(
) -> Client<ArtiHttpConnector<tor_rtcompat::PreferredRuntime, TlsConnector>> {
    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();
    let tls_connector = TlsConnector::builder().unwrap().build().unwrap();

    let connection = ArtiHttpConnector::new(tor_client, tls_connector);
    let http = hyper::Client::builder().build::<_, Body>(connection);
    http
}

async fn get_content_length(url: &'static str) -> u64 {
    let http = get_new_connection().await;
    let uri = Uri::from_static(url);
    warn!("Requesting content length of {} via Tor...", url);
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap();

    let resp = http.request(req).await.unwrap();
    let raw_length = resp.headers().get("Content-Length").unwrap();
    let length = raw_length.to_str().unwrap().parse::<u64>().unwrap();
    warn!("Content-Length of resource: {}", length);
    length
}

async fn request(url: &'static str, start: usize, end: usize) -> Vec<u8> {
    let http = get_new_connection().await;
    let uri = Uri::from_static(url);
    warn!("Requesting {} via Tor...", url);
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        //.header("Range", "bytes=0-")
        .body(Body::default())
        .unwrap();
    let mut resp = http.request(req).await.unwrap();

    if resp.status() == 200 {
        warn!("Good request");
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
    warn!("Creating download file");
    let fd = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("download")
        .unwrap();
    let url = "https://dist.torproject.org/torbrowser/12.0.3/tor-browser-linux64-12.0.3_ALL.tar.xz";
    let length = get_content_length(url).await;
    fd.set_len(length).unwrap();
    let body = request(url, 0, 0).await;
    unsafe {
        let mut mmap = MmapMut::map_mut(&fd).unwrap();
        mmap.copy_from_slice(body.as_slice());
    };
}
