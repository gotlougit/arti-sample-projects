use arti_client::{TorClient, TorClientConfig};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Deserialize, Serialize};

// header will be used by both types of messages so need to serialize and deserialize
#[derive(Serialize, Deserialize)]
struct Header {
    identification: u16,
    qr: bool, // set to 0 for requests, check for 1 in response
    // set the following 4 fields to zero
    opcode0: bool,
    opcode1: bool,
    opcode2: bool,
    opcode3: bool,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    zandrcord: u8, // set to 0
    qdcount: u16,  // set to 1 since we have 1 question
    ancount: u16,  // set to 0 since client doesn't have answers
    nscount: u16,  // set to 0
    arcount: u16,  // set to 0
}

#[derive(Serialize)]
struct Query {
    header: Header,
    qname: u16,  // domain name
    qtype: u16,  // set to 0x0001 for A records
    qclass: u16, // set to 1 for Internet addresses
}

#[derive(Deserialize)]
struct Response {
    header: Header,
    name: u16,      // same as in Query
    restype: u16,   // same as in Query
    class: u16,     // Same as in Query
    ttl: u16,       // Number of seconds to cache the result
    rdlength: u16,  // Length of RDATA
    rdata: Vec<u8>, // IP address(es)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();
    let mut stream = tor_client.connect(("1.1.1.1", 53)).await.unwrap();
    stream.write_all(b"hi").await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    println!("{}", String::from_utf8_lossy(&buf));
}
