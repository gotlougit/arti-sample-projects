use arti_client::{TorClient, TorClientConfig};
use arti_hyper::*;
use hyper::{Body, Client, Method, Request, Uri};
use std::fs::OpenOptions;
use std::io::{Seek, Write};
use tls_api::{TlsConnector as TlsConnectorTrait, TlsConnectorBuilder};
use tls_api_native_tls::TlsConnector;
use tor_rtcompat::PreferredRuntime;
use tracing::warn;

const REQSIZE: u64 = 1024*1024;
const TORURL: &str =
    "https://dist.torproject.org/torbrowser/12.0.3/tor-browser-linux64-12.0.3_ALL.tar.xz";
const TESTURL: &str = "https://www.gutenberg.org/files/2701/2701-0.txt";
const DOWNLOAD_FILE_NAME : &str = "download.tar.xz";

// TODO: Handle all unwrap() effectively

// Create a single TorClient which will be used to spawn isolated connections
//
// Workaround for https://gitlab.torproject.org/tpo/core/arti/-/issues/779

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
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap();

    let resp = http.request(req).await.unwrap();
    let raw_length = resp.headers().get("Content-Length").unwrap();
    let length = raw_length.to_str().unwrap().parse::<u64>().unwrap();
    warn!("Content-Length of resource: {}", length);
    length
}

// Just get the file from the server and store it in a Vec
async fn request(
    url: &'static str,
    start: usize,
    end: usize,
    http: Client<ArtiHttpConnector<PreferredRuntime, TlsConnector>>,
) -> Vec<u8> {
    //let http = get_new_connection(baseconn).await;
    let uri = Uri::from_static(url);
    let partial_req_value =
        String::from("bytes=") + &start.to_string() + &String::from("-") + &end.to_string();
    warn!("Requesting {} via Tor...", url);
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("Range", partial_req_value)
        .body(Body::default())
        .unwrap();
    let mut resp = http.request(req).await.unwrap();

    if resp.status() == 206 {
        warn!("Good request, getting partial content...");
    } else {
        warn!("Non 206 Status code: {}", resp.status());
    }

    let body = hyper::body::to_bytes(resp.body_mut())
        .await
        .unwrap()
        .to_vec();
    body
}

fn save_to_file(fname: &'static str, start: usize, body: Vec<u8>) {
    let mut fd = OpenOptions::new()
        .write(true)
        .create(true)
        .open(fname)
        .unwrap();
    fd.seek(std::io::SeekFrom::Start(start as u64)).unwrap();
    fd.write_all(&body).unwrap();
}

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
    fd.set_len(length).unwrap();
    let steps = length / REQSIZE;
    let mut start = 0;
    for _ in 0..steps {
        let end = start + (REQSIZE as usize) - 1;
        let newhttp = get_new_connection(&baseconn).await;
        //tokio::task::spawn(async move {
        {
            let body = request(url, start, end, newhttp).await;
            save_to_file(DOWNLOAD_FILE_NAME, start, body);
        }
        //});
        start = end + 1;
    }
    if start < length as usize {
        let newhttp = get_new_connection(&baseconn).await;
        let body = request(url, start, length as usize, newhttp).await;
        save_to_file(DOWNLOAD_FILE_NAME, start, body);
    }
}
