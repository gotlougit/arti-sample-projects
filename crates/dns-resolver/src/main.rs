use arti_client::{TorClient, TorClientConfig};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Deserialize, Serialize};

// header will be used by both types of messages so need to serialize and deserialize
#[derive(Serialize, Deserialize)]
struct Header {
    pub identification: u16,
    pub qr: bool,           // set to 0 for requests, check for 1 in response
    pub opcodes: [bool; 4], // set all 4 to zero
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub zandrcord: u8, // set to 0
    pub qdcount: u16,  // set to 1 since we have 1 question
    pub ancount: u16,  // set to 0 since client doesn't have answers
    pub nscount: u16,  // set to 0
    pub arcount: u16,  // set to 0
}

#[derive(Serialize)]
struct Query {
    pub header: Header,
    pub qname: Vec<u8>, // domain name
    pub qtype: u16,     // set to 0x0001 for A records
    pub qclass: u16,    // set to 1 for Internet addresses
}

#[derive(Deserialize)]
struct Response {
    pub header: Header,
    pub name: u16,      // same as in Query
    pub restype: u16,   // same as in Query
    pub class: u16,     // Same as in Query
    pub ttl: u16,       // Number of seconds to cache the result
    pub rdlength: u16,  // Length of RDATA
    pub rdata: Vec<u8>, // IP address(es)
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
