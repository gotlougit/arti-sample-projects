//! Very very very basic soak test that runs obfs4proxy.

use anyhow::Result;
use std::{
    net::{SocketAddr, SocketAddrV4},
    str::FromStr,
};
use tokio::time::Duration;
use tor_chanmgr::transport::proxied::*;
use tor_ptmgr::ipc::{PluggableTransport, PtParameters};
use tor_rtcompat::PreferredRuntime;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let params = PtParameters::builder()
        .state_location("/tmp/arti-pt".into())
        .transports(vec!["obfs4".parse()?])
        .timeout(Some(Duration::from_secs(1)))
        .build()?;
    let cur_runtime = PreferredRuntime::current()?;
    let mut pt = PluggableTransport::new("lyrebird".into(), vec![], params);
    pt.launch(cur_runtime.clone()).await?;
    let endpoint =
        tor_linkspec::PtTargetAddr::IpPort(SocketAddr::V4(SocketAddrV4::from_str("1.1.1.1:1555")?));
    let client_endpoint = SocketAddr::V4(SocketAddrV4::from_str("127.0.0.1:4200")?);
    let socks_config = Protocol::Socks(
        tor_socksproto::SocksVersion::V5,
        tor_socksproto::SocksAuth::NoAuth,
    );
    let conn = connect_via_proxy(&cur_runtime, &client_endpoint, &socks_config, &endpoint).await?;
    Ok(())
}
