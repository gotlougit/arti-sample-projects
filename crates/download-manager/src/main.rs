use arti_client::{TorClient, TorClientConfig};
use arti_hyper::*;
use futures::future::join_all;
use hyper::{Body, Client, Method, Request, Uri};
use std::fs::OpenOptions;
use std::io::{Seek, Write};
use tls_api::{TlsConnector as TlsConnectorTrait, TlsConnectorBuilder};
use tls_api_native_tls::TlsConnector;
use tor_rtcompat::PreferredRuntime;
use tracing::warn;

// REQSIZE is just the size of each chunk we get from a particular circuit
const REQSIZE: u64 = 1024 * 1024;
// TORURL is the particular Tor Browser Bundle URL
const TORURL: &str =
    "https://dist.torproject.org/torbrowser/12.0.7/tor-browser-linux64-12.0.7_ALL.tar.xz";
// Save the TBB with this filename
const DOWNLOAD_FILE_NAME: &str = "download.tar.xz";
// Number of simultaneous connections that are made
// TODO: make this user configurable
const MAX_CONNECTIONS: usize = 6;

// TODO: Handle all unwrap() effectively

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
) -> Vec<u8> {
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
    let body = hyper::body::to_bytes(resp.body_mut())
        .await
        .unwrap()
        .to_vec();
    body
}

// just write the bytes at the right position in the file
fn save_to_file(fname: &'static str, start: usize, body: Vec<u8>) {
    let mut fd = OpenOptions::new()
        .write(true)
        .create(true)
        .open(fname)
        .unwrap();
    fd.seek(std::io::SeekFrom::Start(start as u64)).unwrap();
    fd.write_all(&body).unwrap();
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
    //let url = TESTURL;
    let baseconn = get_tor_client().await;
    let length = get_content_length(url, &baseconn).await;

    // Initialize the connections we will use for this download
    let mut connections: Vec<Client<_>> = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let newhttp = get_new_connection(&baseconn).await;
        connections.push(newhttp);
    }

    // set length of file
    fd.set_len(length).unwrap();
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
        downloadtasks.push(tokio::spawn(async move {
            // request via new Tor connection
            let body = request(url, start, end, &newhttp).await;
            // save to disk
            save_to_file(DOWNLOAD_FILE_NAME, start, body);
        }));
        start = end + 1;
    }
    join_all(downloadtasks).await;
    // if last portion of file is left, request it and write to disk
    if start < length as usize {
        let newhttp = get_new_connection(&baseconn).await;
        let body = request(url, start, length as usize, &newhttp).await;
        save_to_file(DOWNLOAD_FILE_NAME, start, body);
    }
}
