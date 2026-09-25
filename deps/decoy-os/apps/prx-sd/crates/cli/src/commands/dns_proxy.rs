//! CLI handler for the `sd dns-proxy` command.

use std::path::Path;

use anyhow::{Context, Result};
use colored::Colorize;

use prx_sd_realtime::dns_proxy::{DnsProxy, DnsProxyConfig};

/// Run the local DNS proxy with adblock + IOC + custom blocklist filtering.
pub async fn run(listen: &str, upstream: &str, log_path: &str, data_dir: &Path) -> Result<()> {
    let listen_addr = listen
        .parse()
        .with_context(|| format!("invalid listen address: {listen}"))?;
    let upstream_addr = upstream
        .parse()
        .with_context(|| format!("invalid upstream address: {upstream}"))?;

    let config = DnsProxyConfig {
        listen_addr,
        upstream_dns: upstream_addr,
        log_path: log_path.into(),
    };

    println!(
        "{} Starting DNS proxy (listen={}, upstream={}, log={})",
        ">>>".cyan().bold(),
        listen,
        upstream,
        log_path,
    );
    println!(
        "{} Filter engines: adblock + dns_blocklist + ioc_domains",
        ">>>".green().bold(),
    );
    println!("{} Press {} to stop.\n", ">>>".green().bold(), "Ctrl+C".bold(),);

    // Construct and run DnsProxy entirely inside a dedicated OS thread.
    // adblock::Engine contains Rc (not Send), so the proxy cannot be
    // moved across threads — it must be created where it runs.
    let data_dir_owned = data_dir.to_path_buf();
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let result = DnsProxy::new(config, &data_dir_owned)
            .context("failed to initialise DNS proxy")
            .and_then(|proxy| proxy.run());
        let _ = tx.send(result);
    });
    rx.await.context("DNS proxy thread terminated unexpectedly")?
}
