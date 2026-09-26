//! JSON-RPC + transport for hos-ethsign.
//!
//! On-device the outbound TCP socket is transparently routed to the LKL network provider by
//! libnshim (the D kernel exposes no userland TCP of its own), and TLS is terminated HERE with
//! rustls because the kernel's TLS is stubbed. `--socks H:P` hops through Tor (SOCKS5, connecting
//! by hostname so DNS resolves at the exit, not locally). Commands: chainid / nonce / gas / call /
//! send / deploy.

use k256::ecdsa::SigningKey;

#[cfg(not(feature = "net"))]
pub fn dispatch(
    cmd: &str,
    _args: &[String],
    _load_key: &dyn Fn(&[String]) -> Result<SigningKey, String>,
) -> Result<(), String> {
    Err(format!("network command '{cmd}' needs the `net` build feature (offline `address`/`sign` still work)"))
}

#[cfg(feature = "net")]
pub use net::dispatch;

#[cfg(feature = "net")]
mod net {
    use super::SigningKey;
    use crate::tx::Eip1559;
    use crate::wallet::{address_checksummed, address_of};
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::sync::Arc;

    fn opt(args: &[String], name: &str) -> Option<String> {
        let pref = format!("--{name}=");
        for (i, a) in args.iter().enumerate() {
            if a == &format!("--{name}") {
                return args.get(i + 1).cloned();
            }
            if let Some(v) = a.strip_prefix(&pref) {
                return Some(v.to_string());
            }
        }
        None
    }
    fn req(args: &[String], name: &str) -> Result<String, String> {
        opt(args, name).ok_or_else(|| format!("missing required --{name}"))
    }

    struct Url<'a> {
        tls: bool,
        host: &'a str,
        port: u16,
        path: &'a str,
    }
    fn parse_url(u: &str) -> Result<Url<'_>, String> {
        let (tls, rest) = if let Some(r) = u.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = u.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(format!("rpc url must be http(s)://: {u}"));
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse().map_err(|_| format!("bad port in {u}"))?),
            None => (authority, if tls { 443 } else { 80 }),
        };
        Ok(Url { tls, host, port, path })
    }

    /// SOCKS5 CONNECT (no auth) to host:port, resolving the hostname at the proxy (ATYP=domain).
    fn socks5_connect(proxy: &str, host: &str, port: u16) -> Result<TcpStream, String> {
        let mut s = TcpStream::connect(proxy).map_err(|e| format!("connect SOCKS {proxy}: {e}"))?;
        s.write_all(&[0x05, 0x01, 0x00]).map_err(|e| format!("socks greet: {e}"))?;
        let mut r = [0u8; 2];
        s.read_exact(&mut r).map_err(|e| format!("socks greet reply: {e}"))?;
        if r != [0x05, 0x00] {
            return Err("SOCKS5 proxy refused (no-auth not accepted)".into());
        }
        if host.len() > 255 {
            return Err("hostname too long for SOCKS5".into());
        }
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req).map_err(|e| format!("socks connect: {e}"))?;
        let mut head = [0u8; 4];
        s.read_exact(&mut head).map_err(|e| format!("socks connect reply: {e}"))?;
        if head[1] != 0x00 {
            return Err(format!("SOCKS5 CONNECT failed (reply code {})", head[1]));
        }
        let skip = match head[3] {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).map_err(|e| format!("socks bnd len: {e}"))?;
                l[0] as usize + 2
            }
            a => return Err(format!("SOCKS5 unknown bound ATYP {a}")),
        };
        let mut junk = vec![0u8; skip];
        s.read_exact(&mut junk).map_err(|e| format!("socks bnd addr: {e}"))?;
        Ok(s)
    }

    fn tcp(url: &Url, socks: Option<&str>) -> Result<TcpStream, String> {
        match socks {
            Some(p) => socks5_connect(p, url.host, url.port),
            None => TcpStream::connect((url.host, url.port))
                .map_err(|e| format!("connect {}:{}: {e}", url.host, url.port)),
        }
    }

    fn http_request(url: &Url, body: &str) -> String {
        format!(
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\nAccept: application/json\r\n\r\n{}",
            url.path,
            url.host,
            body.len(),
            body
        )
    }

    /// Split an HTTP response into the body, honoring chunked transfer-encoding.
    fn http_body(raw: &[u8]) -> Result<Vec<u8>, String> {
        let sep = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or("no HTTP header/body separator")?;
        let headers = String::from_utf8_lossy(&raw[..sep]).to_ascii_lowercase();
        let body = &raw[sep + 4..];
        if headers.contains("transfer-encoding: chunked") {
            let mut out = Vec::new();
            let mut rest = body;
            loop {
                let nl = rest.windows(2).position(|w| w == b"\r\n").ok_or("bad chunk size line")?;
                let size = usize::from_str_radix(
                    String::from_utf8_lossy(&rest[..nl]).trim(),
                    16,
                )
                .map_err(|_| "bad chunk size")?;
                rest = &rest[nl + 2..];
                if size == 0 {
                    break;
                }
                if rest.len() < size {
                    return Err("truncated chunk".into());
                }
                out.extend_from_slice(&rest[..size]);
                rest = &rest[size + 2..]; // skip trailing CRLF
            }
            Ok(out)
        } else {
            Ok(body.to_vec())
        }
    }

    fn send_recv(url: &Url, socks: Option<&str>, body: &str) -> Result<Vec<u8>, String> {
        let sock = tcp(url, socks)?;
        sock.set_read_timeout(Some(std::time::Duration::from_secs(60))).ok();
        sock.set_write_timeout(Some(std::time::Duration::from_secs(60))).ok();
        let request = http_request(url, body);
        let mut raw = Vec::new();
        if url.tls {
            // rustls needs a crypto provider; install ring once (ignore "already installed").
            let _ = rustls::crypto::ring::default_provider().install_default();
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let server = rustls::pki_types::ServerName::try_from(url.host.to_string())
                .map_err(|_| format!("bad TLS server name {}", url.host))?;
            let mut conn = rustls::ClientConnection::new(Arc::new(config), server)
                .map_err(|e| format!("tls setup: {e}"))?;
            let mut sock = sock;
            let mut tls = rustls::Stream::new(&mut conn, &mut sock);
            tls.write_all(request.as_bytes()).map_err(|e| format!("tls write: {e}"))?;
            tls.read_to_end(&mut raw).map_err(|e| format!("tls read: {e}"))?;
        } else {
            let mut sock = sock;
            sock.write_all(request.as_bytes()).map_err(|e| format!("http write: {e}"))?;
            sock.read_to_end(&mut raw).map_err(|e| format!("http read: {e}"))?;
        }
        http_body(&raw)
    }

    /// One JSON-RPC call. `params` is a JSON array string. Returns the `result` value.
    fn rpc(url: &Url, socks: Option<&str>, method: &str, params: &str) -> Result<serde_json::Value, String> {
        let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
        let bytes = send_recv(url, socks, &body)?;
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| format!("rpc {method}: bad JSON reply: {e}"))?;
        if let Some(err) = v.get("error") {
            return Err(format!("rpc {method} error: {err}"));
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| format!("rpc {method}: no result in reply"))
    }

    fn as_hex_str(v: &serde_json::Value) -> Result<String, String> {
        v.as_str().map(|s| s.to_string()).ok_or_else(|| "expected hex string result".into())
    }
    fn hex_to_u128(s: &str) -> Result<u128, String> {
        u128::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| format!("hex u128 {s}: {e}"))
    }
    fn hex_to_u64(s: &str) -> Result<u64, String> {
        u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| format!("hex u64 {s}: {e}"))
    }

    fn get_chainid(url: &Url, socks: Option<&str>) -> Result<u64, String> {
        hex_to_u64(&as_hex_str(&rpc(url, socks, "eth_chainId", "[]")?)?)
    }
    fn get_nonce(url: &Url, socks: Option<&str>, addr: &str) -> Result<u64, String> {
        hex_to_u64(&as_hex_str(&rpc(
            url,
            socks,
            "eth_getTransactionCount",
            &format!(r#"["{addr}","pending"]"#),
        )?)?)
    }
    /// (max_priority_fee, max_fee) suggestion: priority from the node, maxFee = 2*baseFee + priority.
    fn get_fees(url: &Url, socks: Option<&str>) -> Result<(u128, u128), String> {
        let priority = hex_to_u128(&as_hex_str(
            &rpc(url, socks, "eth_maxPriorityFeePerGas", "[]").unwrap_or(serde_json::json!("0x3b9aca00")),
        )?)
        .unwrap_or(1_000_000_000);
        let block = rpc(url, socks, "eth_getBlockByNumber", r#"["latest",false]"#)?;
        let base = block
            .get("baseFeePerGas")
            .and_then(|v| v.as_str())
            .map(|s| hex_to_u128(s).unwrap_or(0))
            .unwrap_or(0);
        Ok((priority, base.saturating_mul(2).saturating_add(priority)))
    }

    pub fn dispatch(
        cmd: &str,
        args: &[String],
        load_key: &dyn Fn(&[String]) -> Result<SigningKey, String>,
    ) -> Result<(), String> {
        let url_s = req(args, "rpc")?;
        let url = parse_url(&url_s)?;
        let socks_owned = opt(args, "socks");
        let socks = socks_owned.as_deref();

        match cmd {
            "chainid" => {
                println!("{}", get_chainid(&url, socks)?);
                Ok(())
            }
            "nonce" => {
                let addr = req(args, "address")?;
                println!("{}", get_nonce(&url, socks, &addr)?);
                Ok(())
            }
            "gas" => {
                let (p, m) = get_fees(&url, socks)?;
                println!("max-priority={p}");
                println!("max-fee={m}");
                Ok(())
            }
            "call" => {
                let to = req(args, "to")?;
                let data = opt(args, "data").unwrap_or_else(|| "0x".into());
                let r = rpc(&url, socks, "eth_call", &format!(r#"[{{"to":"{to}","data":"{data}"}},"latest"]"#))?;
                println!("{}", as_hex_str(&r)?);
                Ok(())
            }
            "send" => {
                let raw = req(args, "raw")?;
                let r = rpc(&url, socks, "eth_sendRawTransaction", &format!(r#"["{raw}"]"#))?;
                println!("tx={}", as_hex_str(&r)?);
                Ok(())
            }
            "deploy" => deploy(&url, socks, args, load_key),
            other => Err(format!("unknown network command '{other}'")),
        }
    }

    fn deploy(
        url: &Url,
        socks: Option<&str>,
        args: &[String],
        load_key: &dyn Fn(&[String]) -> Result<SigningKey, String>,
    ) -> Result<(), String> {
        let bytecode = {
            let s = req(args, "bytecode")?;
            hex::decode(s.trim().trim_start_matches("0x")).map_err(|e| format!("bytecode hex: {e}"))?
        };
        let value: u128 = opt(args, "value").map(|s| s.parse().unwrap_or(0)).unwrap_or(0);
        let sk = load_key(args)?;
        let from = address_checksummed(&address_of(&sk));

        let chain_id = get_chainid(url, socks)?;
        let nonce = get_nonce(url, socks, &from)?;
        let (max_priority_fee, max_fee) = get_fees(url, socks)?;
        // gas: explicit --gas-limit, else eth_estimateGas for the creation.
        let data_hex = format!("0x{}", hex::encode(&bytecode));
        let gas_limit = match opt(args, "gas-limit") {
            Some(s) => s.parse().map_err(|_| "bad --gas-limit".to_string())?,
            None => {
                let est = rpc(
                    url,
                    socks,
                    "eth_estimateGas",
                    &format!(r#"[{{"from":"{from}","data":"{data_hex}"}}]"#),
                )?;
                let g = hex_to_u64(&as_hex_str(&est)?)?;
                g + g / 5 // +20% headroom
            }
        };

        eprintln!("hos-ethsign: deploying from {from} nonce={nonce} chain={chain_id} gas={gas_limit}");
        let txn = Eip1559 {
            chain_id,
            nonce,
            max_priority_fee,
            max_fee,
            gas_limit,
            to: None,
            value,
            data: bytecode,
        };
        let (raw, hash) = txn.sign(&sk);
        let raw_hex = format!("0x{}", hex::encode(&raw));
        let hash_hex = format!("0x{}", hex::encode(hash));

        let sent = rpc(url, socks, "eth_sendRawTransaction", &format!(r#"["{raw_hex}"]"#))?;
        let sent_hash = as_hex_str(&sent).unwrap_or(hash_hex.clone());
        eprintln!("hos-ethsign: broadcast {sent_hash}; waiting for the receipt…");

        // poll for the receipt / contract address (deploys settle in a few blocks)
        for _ in 0..40 {
            std::thread::sleep(std::time::Duration::from_secs(3));
            let rcpt = rpc(url, socks, "eth_getTransactionReceipt", &format!(r#"["{sent_hash}"]"#))?;
            if rcpt.is_null() {
                continue;
            }
            let status = rcpt.get("status").and_then(|v| v.as_str()).unwrap_or("0x1");
            if status == "0x0" {
                return Err(format!("deploy tx {sent_hash} reverted on-chain"));
            }
            if let Some(addr) = rcpt.get("contractAddress").and_then(|v| v.as_str()) {
                println!("contract={addr}");
                println!("tx={sent_hash}");
                return Ok(());
            }
        }
        Err(format!("timed out waiting for receipt of {sent_hash}"))
    }
}
