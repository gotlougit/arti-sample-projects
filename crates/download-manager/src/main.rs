#![warn(clippy::missing_docs_in_private_items)]
//! # download-manager
//! Use Tor to download the Tor Browser Bundle
//!
//! ### Intro
//! This is a project intended to illustrate how Arti can be used to tunnel an HTTPS
//! based project through Tor and also some of the design choices that go into making that
//! happen, most notably, the usage of isolated clients to create different connections
//! which won't lock each other up or run into some Arti shared state issues.
//!
//! ### Usage
//! Simply run the program:
//! `cargo run`
//!
//! The program will then attempt to create new Tor connections and download the Linux version of
//! the Tor Browser Bundle in chunks using [HTTP Range requests](https://developer.mozilla.org/en-US/docs/Web/HTTP/Range_requests)
//! in order to overcome the relatively slow connections that the Tor network provides.
//! It is currently capped to six concurrent connections in order to respect the Tor network's bandwidth
//! The Tor Browser Bundle is saved as `download.tar.xz`
//!
//! ### Disclaimer
//! The download manager showcased is not really meant for production. It is simply an example of how Arti
//! can be utilized. Many features, like resumeable downloads, aren't present. Don't use it for any real
//! usage other than academic
use arti_client::config::pt::ManagedTransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, CfgPath};
use arti_client::{TorClient, TorClientConfig};
use arti_hyper::*;
use futures::future::join_all;
use hyper::{Body, Client, Method, Request, Uri};
use std::error::Error;
use std::fmt::Display;
use std::fs::OpenOptions;
use std::io::Write;
use tls_api::{TlsConnector as TlsConnectorTrait, TlsConnectorBuilder};
use tls_api_native_tls::TlsConnector;
use tor_rtcompat::PreferredRuntime;
use tracing::{debug, error, info, warn};

/// REQSIZE is just the size of each chunk we get from a particular circuit
const REQSIZE: u64 = 1024 * 1024;
/// TORURL is the particular Tor Browser Bundle URL
const TORURL: &str =
    "https://dist.torproject.org/torbrowser/12.5.2/tor-browser-linux64-12.5.2_ALL.tar.xz";
/// Save the TBB with this filename
const DOWNLOAD_FILE_NAME: &str = "download.tar.xz";
/// Number of simultaneous connections that are made
// TODO: make this user configurable
const MAX_CONNECTIONS: usize = 6;
/// Number of retries to make if a particular request failed
const MAX_RETRIES: usize = 6;

#[derive(Debug)]
struct PartialError {
    message: String,
}

impl PartialError {
    fn new() -> Self {
        Self {
            message: "Non partial content status code obtained!".to_string(),
        }
    }
}

impl Display for PartialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for PartialError {}

// TODO: Handle all unwrap() effectively

/// Create a single TorClient which will be used to spawn isolated connections
///
/// This Client is configured to use Snowflake to connect to Tor
///
/// Note that the Snowflake client binary may be present under a different name
/// on your machine and thus will need appropriate modifications
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

/// Create a single TorClient which will be used to spawn isolated connections
///
/// This Client uses the default config with no other changes
async fn create_tor_client() -> TorClient<PreferredRuntime> {
    let config = TorClientConfig::default();
    TorClient::create_bootstrapped(config).await.unwrap()
}

/// Creates a `hyper::Client` for sending HTTPS requests over Tor
///
/// Note that it first creates an isolated circuit from the `TorClient`
/// passed into it, this is generally an Arti best practice
async fn build_tor_hyper_client(
    baseconn: &TorClient<PreferredRuntime>,
) -> Client<ArtiHttpConnector<PreferredRuntime, TlsConnector>> {
    let tor_client = baseconn.isolated_client();
    let tls_connector = TlsConnector::builder().unwrap().build().unwrap();

    let connector = ArtiHttpConnector::new(tor_client, tls_connector);
    hyper::Client::builder().build::<_, Body>(connector)
}

/// Get the size of file to be downloaded so we can prep main loop
async fn get_content_length(url: &'static str, baseconn: &TorClient<PreferredRuntime>) -> u64 {
    let http = build_tor_hyper_client(baseconn).await;
    let uri = Uri::from_static(url);
    debug!("Requesting content length of {} via Tor...", url);
    // Create a new request
    let req = Request::builder()
        .method(Method::HEAD)
        .uri(uri)
        .body(Body::empty())
        .unwrap();

    let resp = http.request(req).await.unwrap();
    // Get Content-Length
    let raw_length = resp.headers().get("Content-Length").unwrap();
    let length = raw_length.to_str().unwrap().parse::<u64>().unwrap();
    debug!("Content-Length of resource: {}", length);
    // Return it after a suitable typecast
    length
}

/// Gets a portion of the file from the server and store it in a Vec if successful
///
/// Note that it returns a Result to denote any network issues that may have arisen from the request
async fn request_range(
    url: &'static str,
    start: usize,
    end: usize,
    http: &Client<ArtiHttpConnector<PreferredRuntime, TlsConnector>>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let uri = Uri::from_static(url);
    let partial_req_value = format!("bytes={}-{}", start, end);
    warn!("Requesting {} via Tor...", url);
    // GET the contents of URL from byte offset "start" to "end"
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("Range", partial_req_value)
        .body(Body::default())?;
    let mut resp = http.request(req).await?;

    // Got partial content, this is good
    if resp.status() == hyper::StatusCode::PARTIAL_CONTENT {
        debug!("Good request, getting partial content...");
        // Get the body of the response
        return match hyper::body::to_bytes(resp.body_mut()).await {
            Ok(bytes) => Ok(bytes.to_vec()),
            Err(e) => Err(Box::new(e)),
        };
    }
    // Got something else, return an Error
    warn!("Non 206 Status code: {}", resp.status());
    Err(Box::new(PartialError::new()))
}

/// Wrapper around [request_range] in order to overcome network issues
///
/// We try a maximum of [MAX_RETRIES] to get the portion of the file we require
///
/// If we are successful, we return the bytes to be later written to disk, else we simply return None
async fn download_segment(
    url: &'static str,
    start: usize,
    end: usize,
    newhttp: Client<ArtiHttpConnector<PreferredRuntime, TlsConnector>>,
) -> Option<Vec<u8>> {
    let base: u64 = 10;
    for trial in 0..MAX_RETRIES as u32 {
        tokio::time::sleep(std::time::Duration::from_millis(base.pow(trial) - 1)).await;
        // request via new Tor connection
        match request_range(url, start, end, &newhttp).await {
            // save to disk
            Ok(body) => {
                return Some(body);
            }
            // retry if we failed
            Err(_) => {
                warn!("Error while trying to get a segment, retrying...");
            }
        }
    }
    None
}

/// Main method which brings it all together
///
/// Summary:
///
/// 1. Create the download file
///
/// 2. Create [MAX_CONNECTIONS] number of connections, these will be all that is used
/// for the main loop of the program
///
/// 3. Get content length of the Tor Browser Bundle so we know how many loops to run
///
/// 4. Create the main loop of the program; it simply cycles through the connections we initialized
/// step 2 and makes a request with them for the bulk of the payload we request from the network
///
/// 5. Request any leftover data
///
/// 6. Write all that data to the disk
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Creating download file");
    let mut fd = OpenOptions::new()
        .write(true)
        .create(true)
        .open(DOWNLOAD_FILE_NAME)
        .unwrap();
    let url = TORURL;
    let baseconn = create_tor_client().await;
    let length = get_content_length(url, &baseconn).await;

    // Initialize the connections we will use for this download
    let mut connections: Vec<Client<_>> = Vec::with_capacity(MAX_CONNECTIONS);
    for _ in 0..MAX_CONNECTIONS {
        let newhttp = build_tor_hyper_client(&baseconn).await;
        connections.push(newhttp);
    }

    // determine the amount of iterations required
    let steps = length / REQSIZE;
    let mut downloadtasks = Vec::with_capacity(steps as usize);
    let mut start = 0;
    for i in 0..steps {
        // the upper bound of what block we need from the server
        let end = start + (REQSIZE as usize) - 1;
        let newhttp = connections
            .get(i as usize % MAX_CONNECTIONS)
            .unwrap()
            .clone();
        downloadtasks.push(tokio::spawn(async move {
            match download_segment(url, start, end, newhttp).await {
                Some(body) => Some((start, body)),
                None => None,
            }
        }));
        start = end + 1;
    }
    let results_options: Vec<Option<(usize, Vec<u8>)>> = join_all(downloadtasks)
        .await
        .into_iter()
        .flatten()
        .collect();
    // if we got None from network operations, that means we don't have entire file
    // thus we delete the partial file and print an error
    let has_none = results_options.iter().any(|result_op| result_op.is_none());
    if has_none {
        error!("Possible missing chunk! Aborting");
        std::fs::remove_file(DOWNLOAD_FILE_NAME).unwrap();
        return;
    }
    let mut results: Vec<(usize, Vec<u8>)> = results_options
        .iter()
        .filter_map(|result| result.to_owned())
        .collect();
    // if last portion of file is left, request it
    if start < length as usize {
        let newhttp = build_tor_hyper_client(&baseconn).await;
        match download_segment(url, start, length as usize, newhttp).await {
            Some(body) => results.push((start, body)),
            None => {}
        };
    }
    results.sort_by(|a, b| a.0.cmp(&b.0));
    // write all chunks to disk, checking along the way if the offsets match our
    // expectations
    let mut start_check = 0;
    for (start, chunk) in results.iter() {
        if *start != start_check {
            error!("Mismatch in expected and observed offset! Aborting");
            std::fs::remove_file(DOWNLOAD_FILE_NAME).unwrap();
            return;
        }
        let end_check = start_check + (REQSIZE as usize) - 1;
        debug!("Saving chunk offset {} to disk...", start);
        fd.write_all(chunk).unwrap();
        start_check = end_check + 1;
    }
}
