//! Very very very basic soak test that runs obfs4proxy.

use anyhow::Result;
use fast_socks5::client::Socks5Stream;
use std::io;
use std::str::FromStr;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::Duration;
use tor_chanmgr::transport::proxied::{settings_to_protocol, Protocol};
use tor_linkspec::PtTransportName;
use tor_ptmgr::ipc::{PluggableTransport, PtParameters};
use tor_rtcompat::PreferredRuntime;
use tor_socksproto::SocksAuth;
use tor_socksproto::SocksVersion;

const SERVER_STATE_LOCATION: &str = "/tmp/arti-pt";

fn build_server_config(
    protocol: &str,
    bind_addr: &str,
    forwarding_server_addr: &str,
) -> Result<PtParameters> {
    let bindaddr_formatted = format!("{}-{}", &protocol, bind_addr);
    let orport = forwarding_server_addr.to_string();
    Ok(PtParameters::builder()
        .state_location(SERVER_STATE_LOCATION.into())
        .transports(vec![protocol.parse()?])
        .timeout(Some(Duration::from_secs(1)))
        .server_bindaddr(Some(bindaddr_formatted))
        .server_orport(Some(orport))
        .as_server(true)
        .build()?)
}

fn build_client_config(protocol: &str) -> Result<PtParameters> {
    Ok(PtParameters::builder()
        .state_location("/tmp/arti-pt2".into())
        .transports(vec![protocol.parse()?])
        .timeout(Some(Duration::from_secs(1)))
        .build()?)
}

async fn connect_to_obfs4_client(
    proxy_server: &str,
    bridge_config: &str,
    destination: &str,
    port: u16,
) -> Result<Socks5Stream<TcpStream>> {
    let config = fast_socks5::client::Config::default();
    Ok(Socks5Stream::connect_with_password(
        proxy_server.to_string(),
        destination.to_string(),
        port,
        bridge_config.to_string(),
        '\0'.to_string(),
        config,
    )
    .await?)
}

// TODO: use a low level crate to not generate SOCKS5 messages manually
async fn http_request_over_socks5<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut T,
    http_target: String,
) -> Result<()> {
    // Version identifier/method selection message
    stream.write_all(&[5, 1, 0]).await?;
    let mut response = [0; 2];
    stream.read_exact(&mut response).await?;

    if response[0] != 5 || response[1] != 0 {
        eprintln!("SOCKS5 handshake failed");
        return Ok(());
    }

    // Form a CONNECT request for HTTP endpoint
    let http_request = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", http_target);

    // Prepare SOCKS5 request
    let mut socks_request = Vec::new();
    socks_request.push(5); // SOCKS version
    socks_request.push(1); // CONNECT command
    socks_request.push(0); // Reserved
    socks_request.push(3); // Domain name type
    socks_request.push(http_target.len() as u8); // Domain name length
    socks_request.extend_from_slice(http_target.as_bytes()); // Domain name
    socks_request.extend_from_slice(&(80 as u16).to_be_bytes()); // Port

    // Send the SOCKS5 request
    stream.write_all(&socks_request).await?;

    // Read SOCKS5 response
    let mut socks_response = [0; 10];
    stream.read_exact(&mut socks_response).await?;

    if socks_response[1] != 0 {
        eprintln!("SOCKS5 request failed");
        return Ok(());
    }

    // Send HTTP request through the proxied stream
    stream.write_all(http_request.as_bytes()).await?;

    // Read and print the HTTP response
    let mut http_response = Vec::new();
    stream.read_to_end(&mut http_response).await?;
    println!("{}", String::from_utf8_lossy(&http_response));

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    // TODO: use clap for CLI args for configuring everything
    let cur_runtime = PreferredRuntime::current()?;
    let server_addr = "127.0.0.1:4200";
    let final_socks5_endpoint = "127.0.0.1:9050";
    let obfs4_server_port = 4200;
    // server code
    let server_params = build_server_config("obfs4", &server_addr, &final_socks5_endpoint)?;

    let cr_clone = cur_runtime.clone();
    let mut server_pt = PluggableTransport::new(
        "lyrebird".into(),
        vec![
            "-enableLogging".to_string(),
            "-logLevel".to_string(),
            "DEBUG".to_string(),
            "-unsafeLogging".to_string(),
        ],
        server_params,
    );
    server_pt.launch(cr_clone).await?;
    tokio::spawn(async move {
        while let Ok(_) = server_pt.next_message().await {
            println!("Got a message from a client");
        }
    });

    // Client code

    let client_params = build_client_config("obfs4")?;
    let cr_clone = cur_runtime.clone();
    let mut client_pt = PluggableTransport::new(
        "lyrebird".into(),
        vec![
            "-enableLogging".to_string(),
            "-logLevel".to_string(),
            "DEBUG".to_string(),
            "-unsafeLogging".to_string(),
        ],
        client_params,
    );
    client_pt.launch(cr_clone).await?;
    let client_endpoint = client_pt
        .transport_methods()
        .get(&PtTransportName::from_str("obfs4")?)
        .unwrap()
        .endpoint()
        .to_string();

    // TODO: read this from state directory
    // get the cert from CLI (temp HACK)
    println!("Enter cert and iat-mode in semicolon separated format:");
    let mut obfs4_server_conf = String::new();
    io::stdin().read_line(&mut obfs4_server_conf)?;
    obfs4_server_conf.remove(obfs4_server_conf.len() - 1);

    // TODO: use `settings_to_protocol` to get username and password
    // this way we can deal with all edge cases
    let _settings = settings_to_protocol(SocksVersion::V5, obfs4_server_conf.clone())?;

    println!("Connecting to PT client proxy");
    let dest = String::from("icanhazip.com");
    // TODO: pass password from `settings_to_protocol` in here too
    let mut conn = connect_to_obfs4_client(
        &client_endpoint,
        &obfs4_server_conf,
        "127.0.0.1",
        obfs4_server_port,
    )
    .await?;
    http_request_over_socks5(&mut conn, dest).await?;
    Ok(())
}
