use arti_client::config::pt::ManagedTransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath};
use arti_client::{TorClient, TorClientConfig};
use arti_hyper::*;
use futures::future::join_all;
use hyper::{Body, Client, Method, Request, Uri};
use std::fs::{File, OpenOptions};
use std::io::{Seek, Write};
use tls_api::{TlsConnector as TlsConnectorTrait, TlsConnectorBuilder};
use tls_api_native_tls::TlsConnector;
use tor_rtcompat::PreferredRuntime;
use tracing::warn;

/// REQSIZE is just the size of each chunk we get from a particular circuit
const REQSIZE: u64 = 1024 * 1024;
/// TORURL is the particular Tor Browser Bundle URL
const TORURL: &str =
    "https://dist.torproject.org/torbrowser/12.5.1/tor-browser-linux64-12.5.1_ALL.tar.xz";
/// Save the TBB with this filename
const DOWNLOAD_FILE_NAME: &str = "download.tar.xz";
/// Number of simultaneous connections that are made
// TODO: make this user configurable
const MAX_CONNECTIONS: usize = 6;
/// Number of retries to make if a particular request failed
const MAX_RETRIES: usize = 6;

// TODO: Handle all unwrap() effectively

// Create a single TorClient which will be used to spawn isolated connections
// This Client is configured to use Snowflake to connect to Tor
async fn get_snowflake_tor_client() -> TorClient<PreferredRuntime> {
    let mut builder = TorClientConfig::builder();
    // Make sure it is up to date with
    // https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/blob/main/projects/common/bridges_list.snowflake.txt
    let bridge_line : &str = "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ front=cdn.sstatic.net ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478 utls-imitate=hellorandomizedalpn";
    let bridge: BridgeConfigBuilder = bridge_line.parse().unwrap();
    builder.bridges().bridges().push(bridge);
    let mut transport = ManagedTransportConfigBuilder::default();
    transport
        .protocols(vec!["snowflake".parse().unwrap()])
        // THIS IS DISTRO SPECIFIC
        // If this function doesn't work, check by what name snowflake client
        // goes by on your system
        .path(CfgPath::new(("client").into()))
        .run_on_startup(true);
    builder.bridges().transports().push(transport);
    let config = builder.build().unwrap();
    TorClient::create_bootstrapped(config).await.unwrap()
}

// Create a single TorClient which will be used to spawn isolated connections
// This Client uses the default config with no other changes
async fn get_tor_client() -> TorClient<PreferredRuntime> {
    let config = TorClientConfig::default();
    let tor_client = TorClient::create_bootstrapped(config).await.unwrap();
    tor_client
}

// Create new HTTPS connection with a new circuit
async fn get_new_connection(
    baseconn: &TorClient<PreferredRuntime>,
) -> Client<ArtiHttpConnector<PreferredRuntime, TlsConnector>> {
    let tor_client = baseconn.isolated_client();
    let tls_connector = TlsConnector::builder().unwrap().build().unwrap();

    let connection = ArtiHttpConnector::new(tor_client, tls_connector);
    let http = hyper::Client::builder().build::<_, Body>(connection);
    http
}

// Get the size of file to be downloaded
async fn get_content_length(url: &'static str, baseconn: &TorClient<PreferredRuntime>) -> u64 {
    let http = get_new_connection(baseconn).await;
    let uri = Uri::from_static(url);
    warn!("Requesting content length of {} via Tor...", url);
    // Create a new request
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap();

    let resp = http.request(req).await.unwrap();
    // Get Content-Length
    let raw_length = resp.headers().get("Content-Length").unwrap();
    let length = raw_length.to_str().unwrap().parse::<u64>().unwrap();
    warn!("Content-Length of resource: {}", length);
    // Return it after a suitable typecast
    length
}

// Just get the file from the server and store it in a Vec
async fn request(
    url: &'static str,
    start: usize,
    end: usize,
    http: &Client<ArtiHttpConnector<PreferredRuntime, TlsConnector>>,
) -> Result<Vec<u8>, hyper::Error> {
    let uri = Uri::from_static(url);
    let partial_req_value =
        String::from("bytes=") + &start.to_string() + &String::from("-") + &end.to_string();
    warn!("Requesting {} via Tor...", url);
    // GET the contents of URL from byte offset "start" to "end"
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("Range", partial_req_value)
        .body(Body::default())
        .unwrap();
    let mut resp = http.request(req).await.unwrap();

    // Got partial content, this is good
    if resp.status() == 206 {
        warn!("Good request, getting partial content...");
    } else {
        warn!("Non 206 Status code: {}", resp.status());
    }

    // Get the body of the response
    match hyper::body::to_bytes(resp.body_mut()).await {
        Ok(bytes) => Ok(bytes.to_vec()),
        Err(e) => Err(e),
    }
}

// just write the bytes at the right position in the file
fn save_to_file(mut fd: File, start: usize, body: Vec<u8>) {
    warn!("Saving a chunk to disk...");
    fd.seek(std::io::SeekFrom::Start(start as u64)).unwrap();
    fd.write_all(&body).unwrap();
}

async fn get_segment(
    url: &'static str,
    start: usize,
    end: usize,
    newhttp: Client<ArtiHttpConnector<PreferredRuntime, TlsConnector>>,
    fd: File,
) {
    for _ in 0..MAX_RETRIES {
        // request via new Tor connection
        match request(url, start, end, &newhttp).await {
            // save to disk
            Ok(body) => {
                save_to_file(fd, start, body);
                break;
            }
            // retry if we failed
            Err(_) => {
                warn!("Error while trying to get a segment, retrying...");
            }
        }
    }
}

// Summary: create a new TorClient, determine the number of "chunks" to get
// the Tor Browser Bundle in, create a new isolated circuit for each chunk,
// get the chunk at that offset, save it to the disk

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    warn!("Creating download file");
    let fd = OpenOptions::new()
        .write(true)
        .create(true)
        .open(DOWNLOAD_FILE_NAME)
        .unwrap();
    let url = TORURL;
    let baseconn = get_tor_client().await;
    let length = get_content_length(url, &baseconn).await;

    // Initialize the connections we will use for this download
    let mut connections: Vec<Client<_>> = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let newhttp = get_new_connection(&baseconn).await;
        connections.push(newhttp);
    }

    // determine the amount of iterations required
    let steps = length / REQSIZE;
    let mut downloadtasks = Vec::new();
    let mut start = 0;
    for i in 0..steps {
        // the upper bound of what block we need from the server
        let end = start + (REQSIZE as usize) - 1;
        let newhttp = connections
            .get(i as usize % MAX_CONNECTIONS)
            .unwrap()
            .clone();
        let fd_clone = fd.try_clone().unwrap();
        downloadtasks.push(tokio::spawn(async move {
            get_segment(url, start, end, newhttp, fd_clone).await;
        }));
        start = end + 1;
    }
    join_all(downloadtasks).await;
    // if last portion of file is left, request it and write to disk
    if start < length as usize {
        let newhttp = get_new_connection(&baseconn).await;
        get_segment(url, start, length as usize, newhttp, fd).await;
    }
}
