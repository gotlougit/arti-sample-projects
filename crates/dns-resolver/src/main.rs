use arti_client::{TorClient, TorClientConfig};
use std::env;
use std::fmt::Display;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error};
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
    fn u8_to_u32(bytes: &[u8]) -> u32 {
        let ans: u32 = (bytes[0] as u32) << 24
            | (bytes[1] as u32) << 16
            | (bytes[2] as u32) << 8
            | bytes[3] as u32;
        ans
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
        // TODO: don't pad message unnecessarily, change these values
        // These 2 bytes store size of the rest of the payload (including header)
        // Right now it denotes 51 byte size packet, excluding these 2 bytes
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

impl Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ID: 0x{:x}\n", self.identification).unwrap();
        write!(f, "Flags: 0x{:x}\n", self.packed_second_row).unwrap();
        write!(f, "QDCOUNT: 0x{:x}\n", self.qdcount).unwrap();
        write!(f, "ANCOUNT: 0x{:x}\n", self.ancount).unwrap();
        write!(f, "NSCOUNT: 0x{:x}\n", self.nscount).unwrap();
        write!(f, "ARCOUNT: 0x{:x}\n", self.arcount).unwrap();
        Ok(())
    }
}

impl FromBytes for Header {
    fn from_bytes(bytes: &[u8]) -> Self {
        debug!("Parsing the header");
        let packed_second_row = Header::u8_to_u16(bytes[2], bytes[3]);
        if packed_second_row == 0x8180 {
            debug!("Correct flags set in response");
        } else {
            error!("Incorrect flags set in response");
        }
        Header {
            identification: Header::u8_to_u16(bytes[0], bytes[1]),
            packed_second_row,
            qdcount: Header::u8_to_u16(bytes[4], bytes[5]),
            ancount: Header::u8_to_u16(bytes[6], bytes[7]),
            nscount: Header::u8_to_u16(bytes[8], bytes[9]),
            arcount: Header::u8_to_u16(bytes[10], bytes[11]),
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

// A struct which represents one RR
#[repr(C)]
struct ResourceRecord {
    pub name: String,   // preprocessed from raw bytes
    pub rtype: u16,     // same as in Query
    pub class: u16,     // same as in Query
    pub ttl: u32,       // number of seconds to cache the result
    pub rdlength: u16,  // Length of RDATA
    pub rdata: [u8; 4], // IP address
}

impl FromBytes for ResourceRecord {
    fn from_bytes(bytes: &[u8]) -> Self {
        let l = bytes.len();
        // Parse NAME field that has been sent back to us
        let mut name = String::new();
        let mut lastnamebyte = 0;
        let mut curcount = 0;
        let mut part_parsed = 0;
        for i in 14..l {
            if bytes[i] != 0 {
                // Allowed characters in domain name are appended to the string
                if bytes[i].is_ascii_alphanumeric() || bytes[i] == 45 {
                    name.push(bytes[i] as char);
                    part_parsed += 1;
                } else {
                    // Condition here is to prevent executing code at beginning of parsing
                    if i != 14 {
                        // We have parsed one part of the domain
                        if part_parsed == curcount {
                            dbg!("Parsed part successfully");
                        } else {
                            error!("Mismatch between expected and observed length of hostname part: {} and {}", curcount, part_parsed);
                        }
                        part_parsed = 0;
                        name.push('.');
                    }
                    curcount = bytes[i];
                }
            } else {
                // End of domain name, proceed to parse further fields
                debug!("Reached end of name, moving on to parse other fields");
                lastnamebyte = i + 1;
                break;
            }
        }
        Self {
            name,
            rtype: ResourceRecord::u8_to_u16(bytes[lastnamebyte], bytes[lastnamebyte + 1]),
            class: ResourceRecord::u8_to_u16(bytes[lastnamebyte + 2], bytes[lastnamebyte + 3]),
            ttl: ResourceRecord::u8_to_u32(&bytes[lastnamebyte + 10..lastnamebyte + 14]),
            rdlength: Response::u8_to_u16(bytes[lastnamebyte + 8], bytes[lastnamebyte + 9]),
            rdata: bytes[l - 4..],
        }
    }
}

// Stores the response in easy to interpret manner
#[repr(C)]
struct Response {
    pub header: Header,
    pub rr: Vec<ResourceRecord>,
}

impl FromBytes for Response {
    // Try to construct Response from raw byte data from network
    // We will also try to check if a valid DNS response has been sent back to us
    fn from_bytes(bytes: &[u8]) -> Self {
        debug!("Parsing response into struct");
        // Check message length
        let l = bytes.len();
        let messagelen = Response::u8_to_u16(bytes[0], bytes[1]);
        if messagelen == (l - 2) as u16 {
            debug!("Appear to have gotten good message from server");
        } else {
            error!(
                "Expected and observed message length don't match: {} and {} respectively",
                l - 2,
                messagelen
            );
        }
        // Parse NAME field that has been sent back to us
        let mut name = String::new();
        let mut lastnamebyte = 0;
        let mut curcount = 0;
        let mut part_parsed = 0;
        for i in 14..l {
            if bytes[i] != 0 {
                // Allowed characters in domain name are appended to the string
                if bytes[i].is_ascii_alphanumeric() || bytes[i] == 45 {
                    name.push(bytes[i] as char);
                    part_parsed += 1;
                } else {
                    // Condition here is to prevent executing code at beginning of parsing
                    if i != 14 {
                        // We have parsed one part of the domain
                        if part_parsed == curcount {
                            dbg!("Parsed part successfully");
                        } else {
                            error!("Mismatch between expected and observed length of hostname part: {} and {}", curcount, part_parsed);
                        }
                        part_parsed = 0;
                        name.push('.');
                    }
                    curcount = bytes[i];
                }
            } else {
                // End of domain name, proceed to parse further fields
                debug!("Reached end of name, moving on to parse other fields");
                lastnamebyte = i + 1;
                break;
            }
        }
        // Get length of IP address field to store all the responses we got
        let ip_addr_size =
            Response::u8_to_u16(bytes[lastnamebyte + 14], bytes[lastnamebyte + 15]) as usize;
        Response {
            header: Header::from_bytes(&bytes[2..14]),
            name,
            restype: Response::u8_to_u16(bytes[lastnamebyte], bytes[lastnamebyte + 1]),
            class: Response::u8_to_u16(bytes[lastnamebyte + 2], bytes[lastnamebyte + 3]),
            ttl: Response::u8_to_i32(&bytes[lastnamebyte + 10..lastnamebyte + 14]),
            rdlength: Response::u8_to_u16(bytes[lastnamebyte + 8], bytes[lastnamebyte + 9]),
            rdata: bytes[l - ip_addr_size..].to_vec(),
        }
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.header).unwrap();
        write!(f, "Name: {}\n", self.name).unwrap();
        write!(f, "Res type: 0x{:x}\n", self.restype).unwrap();
        write!(f, "Class: 0x{:x}\n", self.class).unwrap();
        write!(f, "TTL: {}\n", self.ttl).unwrap();
        write!(f, "RDLENGTH: 0x{:x}\n", self.rdlength).unwrap();
        let num_ip_addresses = self.rdata.len() / 4;
        for i in 0..num_ip_addresses {
            write!(
                f,
                "IP address: {}.{}.{}.{}\n",
                self.rdata[i],
                self.rdata[i + 1],
                self.rdata[i + 2],
                self.rdata[i + 3]
            )
            .unwrap();
        }
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
    debug!("Crafted query successfully!");
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
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: dns-resolver <hostname-to-lookup>");
        return;
    }
    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();
    debug!("Connecting to 1.1.1.1 port 53 for DNS over TCP lookup");
    let mut stream = tor_client.connect(("1.1.1.1", 53)).await.unwrap();
    let req = craft_query(args[1].as_str()).as_bytes(); // Get raw bytes representation
    stream.write_all(req.as_slice()).await.unwrap();
    stream.flush().await.unwrap();
    debug!("Awaiting response...");
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
