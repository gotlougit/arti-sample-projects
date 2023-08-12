//! Very very very basic soak test that runs obfs4proxy.

use anyhow::Result;
use futures_util::io::AsyncWriteExt;
use std::env;
use std::io;
use std::{net::SocketAddrV4, str::FromStr};
use tokio::time::Duration;
use tor_chanmgr::transport::proxied::Protocol;
use tor_chanmgr::transport::proxied::{connect_via_proxy, settings_to_protocol};
use tor_error::ErrorReport;
use tor_linkspec::PtTransportName;
use tor_ptmgr::ipc::{PluggableTransport, PtParameters};
use tor_rtcompat::PreferredRuntime;
use tor_socksproto::SocksAuth;
use tor_socksproto::SocksVersion;

fn build_server_config(protocol: &str, bind_addr: &str) -> Result<PtParameters> {
    let bindaddr_formatted = format!("{}-{}", &protocol, bind_addr);
    let orport = String::from("0.0.0.0:0");
    Ok(PtParameters::builder()
        .state_location("/tmp/arti-pt".into())
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Ok(());
    }
    let cur_runtime = PreferredRuntime::current()?;
    let server_addr = "127.0.0.1:4200";
    if args[1] == "server" {
        let server_params = build_server_config("obfs4", &server_addr)?;

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
        server_pt.launch(cr_clone).await.unwrap();
        while let Ok(_) = server_pt.next_message().await {
            println!("hi");
        }
        return Ok(());
    }

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
        .endpoint();
    println!("{}", client_endpoint.to_string());
    let endpoint = tor_linkspec::PtTargetAddr::IpPort(SocketAddrV4::from_str(server_addr)?.into());
    // get the cert from CLI (temp HACK)
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    input.remove(input.len() - 1);
    let socks_config = settings_to_protocol(SocksVersion::V5, input)?;
    match socks_config {
        Protocol::Socks(_, ref auth) => {
            if let SocksAuth::Username(user, pass) = auth {
                println!("Username: {}", std::str::from_utf8(&user).unwrap());
                println!("Password: {}", std::str::from_utf8(&pass).unwrap());
            }
        }
        _ => {}
    }
    Ok(())
}
