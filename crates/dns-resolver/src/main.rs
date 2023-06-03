use arti_client::{TorClient, TorClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

trait AsBytes {
    fn as_bytes(self) -> Vec<u8>;
}

// header will be used by both types of messages so need to serialize and deserialize
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

impl AsBytes for Header {
    fn as_bytes(self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        let id_bits = u16::to_be_bytes(self.identification);
        let second_bits = u16::to_be_bytes(self.packed_second_row);
        let qd_bits = u16::to_be_bytes(self.qdcount);
        let an_bits = u16::to_be_bytes(self.ancount);
        let ns_bits = u16::to_be_bytes(self.nscount);
        let ar_bits = u16::to_be_bytes(self.arcount);
        v.extend_from_slice(&id_bits);
        v.extend_from_slice(&second_bits);
        v.extend_from_slice(&qd_bits);
        v.extend_from_slice(&an_bits);
        v.extend_from_slice(&ns_bits);
        v.extend_from_slice(&ar_bits);
        v
    }
}

#[repr(C)]
struct Query {
    pub header: Header,
    pub qname: Vec<u8>, // domain name
    pub qtype: u16,     // set to 0x0001 for A records
    pub qclass: u16,    // set to 1 for Internet addresses
}

impl AsBytes for Query {
    fn as_bytes(self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        let header_bytes = self.header.as_bytes();
        let qtype_bits = u16::to_be_bytes(self.qtype);
        let qclass_bits = u16::to_be_bytes(self.qclass);
        v.extend(header_bytes);
        v.extend(self.qname);
        v.extend_from_slice(&qtype_bits);
        v.extend_from_slice(&qclass_bits);
        v
    }
}

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
        identification: 0x304e, // chosen by random dice roll, secure
        packed_second_row: 0x0120,
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
        qname.extend_from_slice(part.as_bytes());
    }
    qname.push(0x00);
    Query {
        header,
        qname,
        qtype: 0x0001,
        qclass: 0x0001,
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    /*
    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();
    */
    let mut stream = UdpSocket::bind("0.0.0.0:8080").await.unwrap();
    stream.connect("1.1.1.1:53").await.unwrap();
    //let mut stream = tor_client.connect(("1.1.1.1", 53)).await.unwrap();
    let req = craft_query("google.com");
    let mut raw_req = req.as_bytes();
    dbg!("{}", &raw_req);
    stream.send(&raw_req).await.unwrap();
    let mut buf: Vec<u8> = Vec::new();
    let len = stream.recv(&mut buf).await.unwrap();
    dbg!("{}", buf);
    /*
     stream.write_all(raw_req.as_slice()).await.unwrap();
     stream.flush().await.unwrap();
     let mut buf = Vec::new();
     stream.read_to_end(&mut buf).await.unwrap();
     dbg!("{}", buf);
    */
}
