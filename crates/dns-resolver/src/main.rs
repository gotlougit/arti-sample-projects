#![warn(clippy::missing_docs_in_private_items)]
//! # dns-resolver
//! Use Tor to make a DNS over TCP request for a hostname, and get IP addresses back
//!
//! ### Intro
//! This is a project intended to illustrate how Arti can be used to tunnel
//! arbitrary TCP traffic. Here, a DNS client implementation has been hand crafted
//! to illustrate custom made protocols being able to be used seamlessly over Tor
//!
//! ### Usage
//! Simply run the program:
//! `cargo run <hostname-to-look-up>`
//!
//! The program will then attempt to create a new Tor connection, craft the DNS
//! query, and send it to a DNS server (right now, Cloudflare's 1.1.1.1)
//!
//! The response is then decoded into a struct and pretty printed to the user
//!
//! ### Note on DNS
//! The DNS implementation showcased is not really meant for production. It is just
//! a quick series of hacks to show you how, if you do have a very custom protocol
//! that you need tunnelled over Tor, to use that protocol with Arti. For actually
//! tunneling DNS requests over Tor, it is recommended to use a more tried-and-tested
//! crate.
//!
//! For more information on DNS, you can read [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)
//! or [this educational guide](https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf)
use arti_client::{TorClient, TorClientConfig};
use std::env;
use std::fmt::Display;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error};

/// Hardcoded DNS server, stored as (&str, u16) detailing host and port
const DNS_SERVER: (&str, u16) = ("1.1.1.1", 53);

/// Used to convert struct to raw bytes to be sent over the network
///
/// Example:
/// ```
/// // We have some struct S that implements this trait
/// let s = S::new();
/// // This prints the raw bytes as debug output
/// dbg!("{}", s.as_bytes());
/// ```
trait AsBytes {
    /// Return a `Vec<u8>` of the same information stored in struct
    ///
    /// This is ideal to convert typed values into raw bytes to be sent
    /// over the network.
    fn as_bytes(&self) -> Vec<u8>;
}

/// Used to convert raw bytes representation into a Rust struct
///
/// Example:
/// ```
/// let mut buf: Vec<u8> = Vec::new();
/// // Read the response from a stream
/// stream.read_to_end(&mut buf).await.unwrap();
/// // Interpret the response into a struct S
/// let resp = S::from_bytes(&buf);
/// ```
///
/// In the above code, `resp` is `Option<Box<S>>` type, so you will have to
/// deal with the `None` value appropriately. This helps denote invalid
/// situations, ie, parse failures
///
/// You will have to interpret each byte and convert it into each field
/// of your struct yourself when implementing this trait.
trait FromBytes {
    /// Convert two u8's into a u16
    ///
    /// It is just a thin wrapper over [u16::from_be_bytes()]
    fn u8_to_u16(upper: u8, lower: u8) -> u16 {
        let bytes = [upper, lower];
        u16::from_be_bytes(bytes)
    }
    /// Convert four u8's contained in a slice into a u32
    ///
    /// It is just a thin wrapper over [u32::from_be_bytes()] but also deals
    /// with converting &\[u8\] (u8 slice) into [u8; 4] (a fixed size array of u8)
    fn u8_to_u32(bytes_slice: &[u8]) -> u32 {
        let mut bytes = [0u8; 4];
        for (i, val) in bytes_slice.iter().enumerate() {
            bytes[i] = *val;
        }
        u32::from_be_bytes(bytes)
    }
    /// Try converting given bytes into the struct
    ///
    /// Returns an `Option<Box>` of the struct which implements
    /// this trait to help denote parsing failures
    fn from_bytes(bytes: &[u8]) -> Option<Box<Self>>;
}

/// Report length of the struct as in byte stream
///
/// Note that this doesn't mean length of struct
///
/// It is simply used to denote how long the struct is if it were
/// sent over the wire
trait Len {
    /// Report length of the struct as in byte stream
    fn len(&self) -> usize;
}

/// DNS Header to be used by both Query and Response
///
/// The default values chosen are from the perspective of the client
// TODO: For server we will have to interpret given values
struct Header {
    /// Random 16 bit number used to identify the DNS request
    identification: u16,
    /// Set of fields packed together into one 16 bit number
    ///
    /// Refer to RFC 1035 for more info
    // TODO: don't rely on cryptic packed bits
    packed_second_row: u16, // set to 0x100
    /// Number of questions we have
    ///
    /// Here, we set it to 1 since we only ask about one hostname in a query
    qdcount: u16, // set to 1 since we have 1 question
    /// Number of answers we have
    ///
    /// For a query it will be zero, for a response hopefully it is >= 1
    ancount: u16, // set to 0 since client doesn't have answers
    /// Refer to RFC 1035 section 4.1.1, NSCOUNT
    nscount: u16, // set to 0
    /// Refer to RFC 1035 section 4.1.1, ARCOUNT
    arcount: u16, // set to 0
}

// Ugly, repetitive code to convert all six 16-bit fields into Vec<u8>
impl AsBytes for Header {
    fn as_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(14);
        // These 2 bytes store size of the rest of the payload (including header)
        // Right now it denotes 51 byte size packet, excluding these 2 bytes
        // We will change this when we know the size of Query
        v.push(0x00);
        v.push(0x33);
        // Just break u16 into [u8, u8] array and copy into vector
        v.extend_from_slice(&u16::to_be_bytes(self.identification));
        v.extend_from_slice(&u16::to_be_bytes(self.packed_second_row));
        v.extend_from_slice(&u16::to_be_bytes(self.qdcount));
        v.extend_from_slice(&u16::to_be_bytes(self.ancount));
        v.extend_from_slice(&u16::to_be_bytes(self.nscount));
        v.extend_from_slice(&u16::to_be_bytes(self.arcount));
        v
    }
}

impl Display for Header {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "ID: 0x{:x}", self.identification)?;
        writeln!(f, "Flags: 0x{:x}", self.packed_second_row)?;
        writeln!(f, "QDCOUNT: 0x{:x}", self.qdcount)?;
        writeln!(f, "ANCOUNT: 0x{:x}", self.ancount)?;
        writeln!(f, "NSCOUNT: 0x{:x}", self.nscount)?;
        writeln!(f, "ARCOUNT: 0x{:x}", self.arcount)?;
        Ok(())
    }
}

impl FromBytes for Header {
    fn from_bytes(bytes: &[u8]) -> Option<Box<Self>> {
        debug!("Parsing the header");
        let packed_second_row = Header::u8_to_u16(bytes[2], bytes[3]);
        if packed_second_row == 0x8180 {
            debug!("Correct flags set in response");
        } else {
            error!("Incorrect flags set in response");
            return None;
        }
        // These offsets were determined by looking at RFC 1035
        Some(Box::new(Header {
            identification: Header::u8_to_u16(bytes[0], bytes[1]),
            packed_second_row,
            qdcount: Header::u8_to_u16(bytes[4], bytes[5]),
            ancount: Header::u8_to_u16(bytes[6], bytes[7]),
            nscount: Header::u8_to_u16(bytes[8], bytes[9]),
            arcount: Header::u8_to_u16(bytes[10], bytes[11]),
        }))
    }
}

/// The actual query we will send to a DNS server
///
/// For now A records are fetched only
// TODO: add support for different records to be fetched
struct Query {
    /// Header of the DNS packet, see [Header] for more info
    header: Header,
    /// The domain name, stored as a `Vec<u8>`
    ///
    /// When we call [Query::from_bytes()], `qname` is automatically
    /// converted into string stored in a `Vec<u8>` instead of the raw
    /// byte format used for `qname`
    qname: Vec<u8>, // domain name
    /// Denotes the type of record to get.
    ///
    /// Here we set to 1 to get an A record, ie, IPv4
    qtype: u16, // set to 0x0001 for A records
    /// Denotes the class of the record
    ///
    /// Here we set to 1 to get an Internet address
    qclass: u16, // set to 1 for Internet addresses
}

impl AsBytes for Query {
    fn as_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        let header_bytes = self.header.as_bytes();
        v.extend(header_bytes);
        v.extend(&self.qname);
        v.extend_from_slice(&u16::to_be_bytes(self.qtype));
        v.extend_from_slice(&u16::to_be_bytes(self.qclass));
        // Now that the packet is ready, we can calculate size and set that in
        // first two octets
        // Subtract 2 since these first 2 bits are never counted when reporting
        // length like this
        let len_bits = u16::to_be_bytes((v.len() - 2) as u16);
        v[0] = len_bits[0];
        v[1] = len_bits[1];
        v
    }
}

impl Len for Query {
    fn len(&self) -> usize {
        // extra 1 is for compensating for how we
        // use one byte more to store length of domain name
        12 + 1 + self.qname.len() + 2 + 2
    }
}

impl FromBytes for Query {
    // FIXME: the name struct isn't stored as it was sent over the wire
    fn from_bytes(bytes: &[u8]) -> Option<Box<Self>> {
        let l = bytes.len();
        let header = *Header::from_bytes(&bytes[..12])?;
        // Parse name
        let mut name = String::new();
        let mut lastnamebyte = 0;
        let mut curcount = 0;
        let mut part_parsed = 0;
        for (i, &byte) in bytes.iter().enumerate().take(l).skip(12) {
            if byte != 0 {
                // Allowed characters in domain name are appended to the string
                if byte.is_ascii_alphanumeric() || byte == 45 {
                    name.push(byte as char);
                    part_parsed += 1;
                } else {
                    // Condition here is to prevent executing code at beginning of parsing
                    if i != 12 {
                        // We have parsed one part of the domain
                        if part_parsed == curcount {
                            debug!("Parsed part successfully");
                        } else {
                            error!("Mismatch between expected and observed length of hostname part: {} and {}", curcount, part_parsed);
                        }
                        part_parsed = 0;
                        name.push('.');
                    }
                    curcount = byte;
                }
            } else {
                // End of domain name, proceed to parse further fields
                debug!("Reached end of name, moving on to parse other fields");
                lastnamebyte = i + 1;
                break;
            }
        }
        // These offsets were determined by looking at RFC 1035
        Some(Box::new(Self {
            header,
            qname: name.as_bytes().to_vec(),
            qtype: Query::u8_to_u16(bytes[lastnamebyte], bytes[lastnamebyte + 1]),
            qclass: Query::u8_to_u16(bytes[lastnamebyte + 2], bytes[lastnamebyte + 3]),
        }))
    }
}

/// A struct which represents one RR
struct ResourceRecord {
    rtype: u16,     // same as in Query
    class: u16,     // same as in Query
    ttl: u32,       // number of seconds to cache the result
    rdlength: u16,  // Length of RDATA
    rdata: [u8; 4], // IP address
}

impl Len for ResourceRecord {
    // return number of bytes it consumes
    fn len(&self) -> usize {
        let mut size = 0;
        size += 2; // name, even though we don't store it here
        size += 2; // rtype
        size += 2; // class
        size += 4; // ttl
        size += 2; // rdlength
        size += 4; // rdata
        size
    }
}

impl FromBytes for ResourceRecord {
    fn from_bytes(bytes: &[u8]) -> Option<Box<Self>> {
        let lastnamebyte = 1;
        let mut rdata = [0u8; 4];
        if bytes.len() < 15 {
            return None;
        }
        // Copy over IP address into rdata
        rdata.copy_from_slice(&bytes[lastnamebyte + 10..lastnamebyte + 14]);
        // These offsets were determined by looking at RFC 1035
        Some(Box::new(Self {
            rtype: ResourceRecord::u8_to_u16(bytes[lastnamebyte], bytes[lastnamebyte + 1]),
            class: ResourceRecord::u8_to_u16(bytes[lastnamebyte + 2], bytes[lastnamebyte + 3]),
            ttl: ResourceRecord::u8_to_u32(&bytes[lastnamebyte + 4..lastnamebyte + 8]),
            rdlength: Response::u8_to_u16(bytes[lastnamebyte + 8], bytes[lastnamebyte + 9]),
            rdata,
        }))
    }
}

impl Display for ResourceRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "RR record type: 0x{:x}", self.rtype)?;
        writeln!(f, "RR class: 0x{:x}", self.class)?;
        writeln!(f, "TTL: {}", self.ttl)?;
        writeln!(f, "RDLENGTH: 0x{:x}", self.rdlength)?;
        writeln!(
            f,
            "IP address: {}.{}.{}.{}",
            self.rdata[0], self.rdata[1], self.rdata[2], self.rdata[3]
        )?;
        Ok(())
    }
}

/// Stores the response in easy to interpret manner
///
/// A Response is made up of the query given to the server and a bunch of
/// Resource Records (RR). Each RR will include the resource type, class, and
/// name. For the A records we're requesting, we will get an A record, of Internet class,
/// ie an IPv4 address
struct Response {
    query: Query,
    rr: Vec<ResourceRecord>,
}

impl FromBytes for Response {
    // Try to construct Response from raw byte data from network
    // We will also try to check if a valid DNS response has been sent back to us
    fn from_bytes(bytes: &[u8]) -> Option<Box<Self>> {
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
        // Start index at 2 to skip over message length bytes
        let mut index = 2;
        let query = *Query::from_bytes(&bytes[index..])?;
        index += query.len() + 2; // TODO: needs explanation why it works
        let mut rrvec: Vec<ResourceRecord> = Vec::new();
        while index < l {
            match ResourceRecord::from_bytes(&bytes[index..]) {
                Some(rr) => {
                    index += rr.len();
                    rrvec.push(*rr);
                }
                None => break,
            }
        }
        Some(Box::new(Response { query, rr: rrvec }))
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.query.header)?;
        writeln!(
            f,
            "Name: {}",
            String::from_utf8(self.query.qname.to_owned()).unwrap()
        )?;
        writeln!(f, "Res type: 0x{:x}", self.query.qtype)?;
        writeln!(f, "Class: 0x{:x}", self.query.qclass)?;
        for record in self.rr.iter() {
            writeln!(f)?;
            writeln!(f, "{}", record)?;
        }
        Ok(())
    }
}

/// Craft the actual query for a particular domain and returns a Query object
///
/// The query is made for an A record of type Internet, ie, a normal IPv4 address
/// should be returned from the DNS server.
///
/// Convert this Query into bytes to be sent over the network by calling [Query::as_bytes()]
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
    // Start logging messages
    tracing_subscriber::fmt::init();
    // Get and check CLI arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: dns-resolver <hostname-to-lookup>");
        return;
    }
    // Create the default TorClientConfig and create a TorClient
    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();
    debug!("Connecting to 1.1.1.1 port 53 for DNS over TCP lookup");
    let mut stream = tor_client.connect(DNS_SERVER).await.unwrap();
    // We now have a TcpStream analogue to use
    let req = craft_query(args[1].as_str()).as_bytes(); // Get raw bytes representation
    stream.write_all(req.as_slice()).await.unwrap();
    // Flushing ensures we actually send data over network right then instead
    // of waiting for buffer to fill up
    stream.flush().await.unwrap();
    debug!("Awaiting response...");
    let mut buf: Vec<u8> = Vec::new();
    // Read the response
    stream.read_to_end(&mut buf).await.unwrap();
    // Interpret the response
    match Response::from_bytes(&buf) {
        Some(resp) => println!("{}", resp),
        None => eprintln!("No valid response!"),
    };
}
