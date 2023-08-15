use anyhow::Result;
use fast_socks5::client::{self, Socks5Stream};
use fast_socks5::server::Socks5Server;
use std::str::FromStr;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Duration;
use tokio_stream::StreamExt;
use tor_chanmgr::transport::proxied::{settings_to_protocol, Protocol};
use tor_linkspec::PtTransportName;
use tor_ptmgr::ipc::{PluggableTransport, PtParameters};
use tor_rtcompat::PreferredRuntime;
use tor_socksproto::SocksAuth;
use tor_socksproto::SocksVersion;

const SERVER_STATE_LOCATION: &str = "/tmp/arti-pt";
const CLIENT_STATE_LOCATION: &str = "/tmp/arti-pt-client";

#[derive(Debug, thiserror::Error)]
#[error("Error while obtaining bridge line data")]
struct BridgeLineParseError;

#[derive(Clone)]
struct ForwardingCreds {
    username: String,
    password: String,
    forward_endpoint: String,
    obfs4_server_ip: String,
    obfs4_server_port: u16,
}

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
        .state_location(CLIENT_STATE_LOCATION.into())
        .transports(vec![protocol.parse()?])
        .timeout(Some(Duration::from_secs(1)))
        .build()?)
}

async fn connect_to_obfs4_client(
    proxy_server: &str,
    username: &str,
    password: &str,
    destination: &str,
    port: u16,
) -> Result<Socks5Stream<TcpStream>> {
    let config = client::Config::default();
    Ok(Socks5Stream::connect_with_password(
        proxy_server.to_string(),
        destination.to_string(),
        port,
        username.to_string(),
        password.to_string(),
        config,
    )
    .await?)
}

fn read_cert_info() -> Result<String> {
    let file_path = format!("{}/obfs4_bridgeline.txt", SERVER_STATE_LOCATION);
    match std::fs::read_to_string(file_path) {
        Ok(contents) => {
            let line = contents
                .lines()
                .find(|line| line.contains("Bridge obfs4"))
                .ok_or(BridgeLineParseError)?;
            let cert = line
                .split_whitespace()
                .find(|part| part.starts_with("cert="))
                .ok_or(BridgeLineParseError)?;
            let iat = line
                .split_whitespace()
                .find(|part| part.starts_with("iat-mode="))
                .ok_or(BridgeLineParseError)?;
            let complete_config = format!("{};{}", cert, iat);
            Ok(complete_config)
        }
        Err(e) => Err(e.into()),
    }
}

async fn run_forwarding_server(endpoint: &str, forward_creds: ForwardingCreds) -> Result<()> {
    let listener = TcpListener::bind(endpoint).await?;
    while let Ok((mut client, _)) = listener.accept().await {
        let forward_creds_clone = forward_creds.clone();
        tokio::spawn(async move {
            if let Ok(mut relay_stream) = connect_to_obfs4_client(
                &forward_creds_clone.forward_endpoint,
                &forward_creds_clone.username,
                &forward_creds_clone.password,
                &forward_creds_clone.obfs4_server_ip,
                forward_creds_clone.obfs4_server_port,
            )
            .await
            {
                if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut relay_stream).await
                {
                    eprintln!("{:#?}", e);
                }
            } else {
                eprintln!("Couldn't connect to obfs4 client, is it running?");
                client
                    .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
            }
        });
    }
    Ok(())
}

async fn run_socks5_server(endpoint: &str) -> Result<()> {
    let listener = Socks5Server::bind(endpoint).await?;
    tokio::spawn(async move {
        while let Some(Ok(socks_socket)) = listener.incoming().next().await {
            tokio::spawn(async move {
                if let Err(e) = socks_socket.upgrade_to_socks5().await {
                    eprintln!("{:#?}", e);
                }
            });
        }
    });
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    // TODO: use clap for CLI args for configuring everything
    let cur_runtime = PreferredRuntime::current()?;
    let entry_ip = "127.0.0.1";
    let entry_socks5_port = 1234;
    let entry_addr = format!("{}:{}", entry_ip, entry_socks5_port);
    let server_ip = "127.0.0.1";
    let obfs4_server_port = 4200;
    let server_addr = format!("{}:{}", server_ip, obfs4_server_port);
    let final_socks5_endpoint = "127.0.0.1:9050";

    // server code
    run_socks5_server(final_socks5_endpoint).await?;
    let server_params = build_server_config("obfs4", &server_addr, final_socks5_endpoint)?;

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

    let obfs4_server_conf = read_cert_info()?;

    let settings = settings_to_protocol(SocksVersion::V5, obfs4_server_conf)?;
    match settings {
        Protocol::Socks(_, auth) => match auth {
            SocksAuth::Username(raw_username, raw_password) => {
                let username = std::str::from_utf8(&raw_username)?;
                let password = match raw_password.is_empty() {
                    true => "\0",
                    false => std::str::from_utf8(&raw_password)?,
                };
                let creds = ForwardingCreds {
                    username: username.to_string(),
                    password: password.to_string(),
                    forward_endpoint: client_endpoint,
                    obfs4_server_ip: String::from("127.0.0.1"),
                    obfs4_server_port,
                };
                run_forwarding_server(&entry_addr, creds).await?;
            }
            _ => eprintln!("Unable to get credentials for obfs4 client process!"),
        },
        _ => eprintln!("Unexpected protocol"),
    }

    Ok(())
}
