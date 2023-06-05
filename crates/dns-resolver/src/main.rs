use arti_client::{TorClient, TorClientConfig};
use std::fmt::Display;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
//use tokio::net::TcpStream;

// Used to convert to raw bytes to be sent over the network
trait AsBytes {
    fn as_bytes(self) -> Vec<u8>;
}

// Used to get a struct from raw bytes representation
trait FromBytes {
    fn u8_to_u16(upper: u8, lower: u8) -> u16 {
        (upper as u16) << 8 | lower as u16
    }
    fn from_bytes(bytes: &[u8]) -> Self;
}

// Note: repr(C) disables struct data shuffling to adhere to standards

// DNS Header to be used by both Query and Response
// The default values written below are from the perspective of the client
// TODO: For server we will have to interpret given values
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

// Ugly, repetitive code to convert all six 16-bit fields into Vec<u8>
impl AsBytes for Header {
    fn as_bytes(self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(14);
        // Add some magic numbers; these were observed using Wireshark
        v.push(0x00);
        v.push(0x33);
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

impl FromBytes for Header {
    fn from_bytes(bytes: &[u8]) -> Self {
        // Skip first two bytes
        Header {
            identification: Header::u8_to_u16(bytes[2], bytes[3]),
            packed_second_row: Header::u8_to_u16(bytes[4], bytes[5]),
            qdcount: Header::u8_to_u16(bytes[6], bytes[7]),
            ancount: Header::u8_to_u16(bytes[8], bytes[9]),
            nscount: Header::u8_to_u16(bytes[10], bytes[11]),
            arcount: Header::u8_to_u16(bytes[12], bytes[13]),
        }
    }
}

// The actual query we will send to a DNS server
// For now A records are fetched only
// TODO: add support for different records to be fetched
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
        // Add dummy bytes to query to make query work
        while v.len() != 53 {
            v.push(0x00);
        }
        v
    }
}

// Unused for now
// TODO: use this to interpret response
struct Response {
    pub header: Header,
    pub name: Vec<u8>,  // same as in Query
    pub restype: u16,   // same as in Query
    pub class: u16,     // Same as in Query
    pub ttl: u16,       // Number of seconds to cache the result
    pub rdlength: u16,  // Length of RDATA
    pub rdata: Vec<u8>, // IP address(es)
}

impl FromBytes for Response {
    fn from_bytes(bytes: &[u8]) -> Self {
        let l = bytes.len();
        let mut namevec: Vec<u8> = Vec::new();
        let mut lastnamebyte: usize = 0;
        for i in 14..l {
            if bytes[i] != 0 {
                namevec.push(bytes[i]);
            } else {
                lastnamebyte = i + 1;
                break;
            }
        }
        Response {
            header: Header::from_bytes(&bytes[..14]),
            name: namevec,
            restype: Response::u8_to_u16(bytes[lastnamebyte], bytes[lastnamebyte + 1]),
            class: Response::u8_to_u16(bytes[lastnamebyte + 2], bytes[lastnamebyte + 3]),
            ttl: Response::u8_to_u16(bytes[lastnamebyte + 4], bytes[lastnamebyte + 5]),
            rdlength: Response::u8_to_u16(bytes[lastnamebyte + 6], bytes[lastnamebyte + 7]),
            rdata: bytes[l - 4..].to_vec(),
        }
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Res type: {}\n", self.restype).unwrap();
        write!(f, "Class: {}\n", self.class).unwrap();
        write!(f, "TTL: {}\n", self.ttl).unwrap();
        write!(f, "RDLENGTH: {}\n", self.rdlength).unwrap();
        write!(
            f,
            "IP address: {}.{}.{}.{}\n",
            self.rdata[0], self.rdata[1], self.rdata[2], self.rdata[3]
        )
        .unwrap();
        Ok(())
    }
}

// Craft the actual query by hardcoding some values
fn craft_query(domain: &str) -> Query {
    // TODO: generate identification randomly
    let header = Header {
        identification: 0x304e, // chosen by random dice roll, secure
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
        qname.extend_from_slice(part.as_bytes());
    }
    qname.push(0x00); // Denote that hostname has ended by pushing 0x00
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
    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();
    let mut stream = tor_client.connect(("1.1.1.1", 53)).await.unwrap();
    let req = craft_query("google.com").as_bytes(); // Get raw bytes representation
    stream.write_all(req.as_slice()).await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = vec![0u8; 0];
    stream.read_to_end(&mut buf).await.unwrap();
    let resp = Response::from_bytes(&buf);
    println!("{}", resp);
    /*
    let mut stream = TcpStream::connect("1.1.1.1:53").await.unwrap();
    let req = craft_query("google.com").as_bytes(); // Get raw bytes representation
    stream.write_all(&req).await.unwrap();
    let mut buf = [0u8; 53];
    stream.read(&mut buf).await.unwrap();
    dbg!("{}", buf);
    */
}
