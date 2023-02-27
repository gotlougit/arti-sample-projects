use arti_client::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
    println!("Hello, world!");
    let client = arti_client::TorClient::builder().bootstrap_behavior(BootstrapBehavior::OnDemand).create_bootstrapped().await.unwrap();
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
}
