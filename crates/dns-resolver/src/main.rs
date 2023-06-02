use arti_client::{TorClient, TorClientConfig};
use bincode::{config, Decode, Encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// header will be used by both types of messages so need to serialize and deserialize
#[derive(Encode, Decode)]
#[repr(C)]
struct Header {
    pub identification: u16,
    // TODO: don't rely on cryptic packed bits
    pub packed_second_row: u16, // set to 0x100
    pub qdcount: u16,           // set to 1 since we have 1 question
    pub ancount: u16,           // set to 0 since client doesn't have answers
    pub nscount: u16,           // set to 0
    pub arcount: u16,           // set to 0
}

#[derive(Encode)]
#[repr(C)]
struct Query {
    pub header: Header,
    pub qname: Vec<u8>, // domain name
    pub qtype: u16,     // set to 0x0001 for A records
    pub qclass: u16,    // set to 1 for Internet addresses
}

#[derive(Decode)]
struct Response {
    pub header: Header,
    pub name: u16,      // same as in Query
    pub restype: u16,   // same as in Query
    pub class: u16,     // Same as in Query
    pub ttl: u16,       // Number of seconds to cache the result
    pub rdlength: u16,  // Length of RDATA
    pub rdata: Vec<u8>, // IP address(es)
}

fn craft_query(domain: &str) -> Query {
    // TODO: generate identification randomly
    let header = Header {
        identification: 0x0123, // chosen by random dice roll, secure
        packed_second_row: 0x0100,
        qdcount: 0x0001,
        ancount: 0x0000,
        nscount: 0x0000,
        arcount: 0x0000,
    };
    let mut qname: Vec<u8> = Vec::new();
    let split_domain: Vec<&str> = domain.split('.').collect();
    for part in split_domain {
        let l = part.len() as u8;
        qname.push(l);
        qname.extend(part.as_bytes().to_vec());
    }
    qname.push(0);
    Query {
        header,
        qname,
        qtype: 1,
        qclass: 1,
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let bincode_config = config::standard();
    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();
    let mut stream = tor_client.connect(("1.1.1.1", 53)).await.unwrap();
    let req = craft_query("google.com");
    let raw_req = bincode::encode_to_vec(&req, bincode_config).unwrap();
    dbg!("{}", &raw_req);
    stream.write_all(&raw_req).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    dbg!("{}", buf);
}
