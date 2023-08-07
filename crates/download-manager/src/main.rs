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
use arti_client::{TorClient, TorClientConfig};
use arti_hyper::*;
use futures::future::join_all;
use hyper::{Body, Client, Method, Request, Uri};
use std::error::Error;
use std::fs::{remove_file, OpenOptions};
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

#[derive(thiserror::Error, Debug)]
#[error("Download failed due to unspecified reason")]
struct DownloadError;

// TODO: Handle all unwrap() effectively

/// Create a single TorClient which will be used to spawn isolated connections
///
/// This Client uses the default config with no other changes
async fn create_tor_client() -> Result<TorClient<PreferredRuntime>, arti_client::Error> {
    let config = TorClientConfig::default();
    TorClient::create_bootstrapped(config).await
}

/// Creates a `hyper::Client` for sending HTTPS requests over Tor
///
/// Note that it first creates an isolated circuit from the `TorClient`
/// passed into it, this is generally an Arti best practice
async fn build_tor_hyper_client(
    baseconn: &TorClient<PreferredRuntime>,
) -> anyhow::Result<Client<ArtiHttpConnector<PreferredRuntime, TlsConnector>>> {
    let tor_client = baseconn.isolated_client();
    let tls_connector = TlsConnector::builder()?.build()?;

    let connector = ArtiHttpConnector::new(tor_client, tls_connector);
    Ok(hyper::Client::builder().build::<_, Body>(connector))
}

/// Get the size of file to be downloaded so we can prep main loop
async fn get_content_length(
    url: &'static str,
    baseconn: &TorClient<PreferredRuntime>,
) -> Result<u64, Box<dyn Error>> {
    let http = build_tor_hyper_client(baseconn).await?;
    let uri = Uri::from_static(url);
    debug!("Requesting content length of {} via Tor...", url);
    // Create a new request
    let req = Request::builder()
        .method(Method::HEAD)
        .uri(uri)
        .body(Body::empty())?;

    let resp = http.request(req).await?;
    // Get Content-Length
    match resp.headers().get("Content-Length") {
        Some(raw_length) => {
            let length = raw_length.to_str()?.parse::<u64>()?;
            debug!("Content-Length of resource: {}", length);
            // Return it after a suitable typecast
            Ok(length)
        }
        None => Err(Box::new(DownloadError)),
    }
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
    Err(Box::new(DownloadError))
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
) -> Result<Vec<u8>, DownloadError> {
    let base: u64 = 10;
    for trial in 0..MAX_RETRIES as u32 {
        tokio::time::sleep(std::time::Duration::from_millis(base.pow(trial) - 1)).await;
        // request via new Tor connection
        match request_range(url, start, end, &newhttp).await {
            // save to disk
            Ok(body) => {
                return Ok(body);
            }
            // retry if we failed
            Err(_) => {
                warn!("Error while trying to get a segment, retrying...");
                return Err(DownloadError);
            }
        }
    }
    Err(DownloadError)
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
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    info!("Creating download file");
    let mut fd = OpenOptions::new()
        .write(true)
        .create(true)
        .open(DOWNLOAD_FILE_NAME)?;
    let url = TORURL;
    let baseconn = create_tor_client().await?;
    let length = get_content_length(url, &baseconn).await.unwrap();

    // Initialize the connections we will use for this download
    let mut connections: Vec<Client<_>> = Vec::with_capacity(MAX_CONNECTIONS);
    for _ in 0..MAX_CONNECTIONS {
        let newhttp = build_tor_hyper_client(&baseconn).await?;
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
                Ok(body) => Ok((start, body)),
                Err(e) => Err(e),
            }
        }));
        start = end + 1;
    }
    let results_options: Vec<Result<(usize, Vec<u8>), DownloadError>> = join_all(downloadtasks)
        .await
        .into_iter()
        .flatten()
        .collect();
    // if we got an Error from network operations, that means we don't have entire file
    // thus we delete the partial file and print an error
    let has_err = results_options.iter().any(|result_op| result_op.is_err());
    if has_err {
        error!("Possible missing chunk! Aborting");
        remove_file(DOWNLOAD_FILE_NAME)?;
        return Ok(());
    }
    let mut results: Vec<(usize, Vec<u8>)> = results_options
        .into_iter()
        .filter_map(|result| result.ok())
        .collect();
    // if last portion of file is left, request it
    if start < length as usize {
        let newhttp = build_tor_hyper_client(&baseconn).await?;
        match download_segment(url, start, length as usize, newhttp).await {
            Ok(body) => results.push((start, body)),
            Err(_) => {}
        };
    }
    results.sort_by(|a, b| a.0.cmp(&b.0));
    // write all chunks to disk, checking along the way if the offsets match our
    // expectations
    let mut start_check = 0;
    for (start, chunk) in results.iter() {
        if *start != start_check {
            error!("Mismatch in expected and observed offset! Aborting");
            remove_file(DOWNLOAD_FILE_NAME)?;
            return Ok(());
        }
        let end_check = start_check + (REQSIZE as usize) - 1;
        debug!("Saving chunk offset {} to disk...", start);
        fd.write_all(chunk)?;
        start_check = end_check + 1;
    }
    Ok(())
}
