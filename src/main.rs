use arti_client::*;
use arti_hyper::*;

use anyhow::Result;
use arti_client::{TorClient, TorClientConfig};
use hyper::Body;
use tls_api::{TlsConnector as TlsConnectorTrait, TlsConnectorBuilder};

// On apple-darwin targets there is an issue with the native and rustls
// tls implementation so this makes it fall back to the openssl variant.
//
// https://gitlab.torproject.org/tpo/core/arti/-/issues/715
#[cfg(not(target_vendor = "apple"))]
use tls_api_native_tls::TlsConnector;
#[cfg(target_vendor = "apple")]
use tls_api_openssl::TlsConnector;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn get_ip_raw() {
    match arti_client::TorClient::builder().bootstrap_behavior(BootstrapBehavior::OnDemand).create_bootstrapped().await {
        Ok(client) => {
            let mut stream = client.connect(("icanhazip.com", 80)).await.unwrap();

            // Write out an HTTP request.
            stream
                .write_all(b"GET / HTTP/1.1 \r\nHost: icanhazip.com\r\nConnection: close\r\n\r\n")
                .await.unwrap();

            // IMPORTANT: Make sure the request was written.
            // Arti buffers data, so flushing the buffer is usually required.
            stream.flush().await.unwrap();

            // Read and print the result.
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();

            println!("{}", String::from_utf8_lossy(&buf));
        },
        Err(e) => {
            println!("An error occurred!");
            eprintln!("{e}");
        },
    }
}

async fn get_ip_hyper() {
    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();
    let tls_connector = TlsConnector::builder().unwrap().build().unwrap();

    let connection = ArtiHttpConnector::new(tor_client, tls_connector);
    let http = hyper::Client::builder().build::<_, Body>(connection);

    eprintln!("requesting IP via Tor...");
    let mut resp = http.get("https://icanhazip.com".try_into().unwrap()).await.unwrap();

    eprintln!("status: {}", resp.status());

    let body = hyper::body::to_bytes(resp.body_mut()).await.unwrap();
    eprintln!("body: {}", std::str::from_utf8(&body).unwrap());
}

#[tokio::main]
async fn main() {
    println!("Hello, world!");
    get_ip_raw().await;
    get_ip_hyper().await;
}

