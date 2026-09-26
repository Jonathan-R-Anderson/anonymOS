//! hos-ethsign — on-device Ethereum transaction signer for anonymOS.
//!
//! The signing toolchain the D kernel/installer lacked (secp256k1 + keccak256 + RLP + EIP-1559),
//! built as a static-musl Linux ELF so it runs under anonymOS's Linux-compat layer like the other
//! hos-* boot tools. Secrets (mnemonic / private key) are read from a file or stdin, NEVER argv.
//!
//! Offline (this file + rlp/wallet/tx): `address`, `sign`.
//! Networked (rpc module): `deploy`, `send`, `nonce`, `gas`, `chainid`, `call` — reach the RPC
//! through a TCP socket (routed to the network by libnshim -> LKL on-device) with optional Tor
//! SOCKS5, using rustls (the kernel's own TLS is stubbed, so TLS is done here in userland).

mod rlp;
mod rpc;
mod tx;
mod wallet;

use std::io::Read;
use std::process::ExitCode;

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
fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == &format!("--{name}"))
}
fn u64opt(args: &[String], name: &str) -> Result<Option<u64>, String> {
    match opt(args, name) {
        None => Ok(None),
        Some(s) => s.parse().map(Some).map_err(|_| format!("--{name}: not a u64: {s}")),
    }
}
fn u128opt(args: &[String], name: &str) -> Result<Option<u128>, String> {
    match opt(args, name) {
        None => Ok(None),
        Some(s) => s.parse().map(Some).map_err(|_| format!("--{name}: not a u128: {s}")),
    }
}

fn parse_addr(s: &str) -> Result<[u8; 20], String> {
    let b = hex::decode(s.trim().trim_start_matches("0x")).map_err(|e| format!("address hex: {e}"))?;
    if b.len() != 20 {
        return Err(format!("address must be 20 bytes, got {}", b.len()));
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&b);
    Ok(a)
}
fn parse_to(args: &[String]) -> Result<Option<[u8; 20]>, String> {
    match opt(args, "to") {
        None => Ok(None),
        Some(s) if s.trim().is_empty() || s.trim() == "0x" => Ok(None), // contract creation
        Some(s) => Ok(Some(parse_addr(&s)?)),
    }
}
fn parse_data(args: &[String]) -> Result<Vec<u8>, String> {
    match opt(args, "data") {
        None => Ok(vec![]),
        Some(s) => hex::decode(s.trim().trim_start_matches("0x")).map_err(|e| format!("data hex: {e}")),
    }
}

/// Load the signing key from --mnemonic-file (+ --index/--mnemonic-passphrase), --key-file (hex),
/// or stdin (a 64-hex private key, else treated as a mnemonic phrase). Never from argv.
fn load_key(args: &[String]) -> Result<k256::ecdsa::SigningKey, String> {
    let index = u64opt(args, "index")?.unwrap_or(0) as u32;
    let pass = opt(args, "mnemonic-passphrase").unwrap_or_default();
    if let Some(f) = opt(args, "mnemonic-file") {
        let content = std::fs::read_to_string(&f).map_err(|e| format!("read {f}: {e}"))?;
        let phrase = content.lines().next().unwrap_or("").trim();
        return wallet::key_from_mnemonic(phrase, &pass, index);
    }
    if let Some(f) = opt(args, "key-file") {
        let content = std::fs::read_to_string(&f).map_err(|e| format!("read {f}: {e}"))?;
        return wallet::key_from_hex(content.trim());
    }
    // stdin
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).map_err(|e| format!("read stdin: {e}"))?;
    let t = s.trim();
    let hexlen = t.trim_start_matches("0x").len();
    if hexlen == 64 && t.trim_start_matches("0x").chars().all(|c| c.is_ascii_hexdigit()) {
        wallet::key_from_hex(t)
    } else if !t.is_empty() {
        wallet::key_from_mnemonic(t, &pass, index)
    } else {
        Err("no key: pass --mnemonic-file / --key-file, or pipe a key/mnemonic on stdin".into())
    }
}

fn usage() -> &'static str {
    "hos-ethsign — on-device Ethereum signer (secrets via --mnemonic-file/--key-file/stdin, never argv)\n\
\n\
  address   [--mnemonic-file F [--index N] | --key-file F]\n\
  sign      --chain-id N --nonce N --gas-limit N (--to 0x..|omit for create) [--value WEI] [--data 0x..]\n\
            EIP-1559 (default): --max-fee WEI --max-priority WEI | legacy: --legacy --gas-price WEI\n\
            + a key source; prints rawtx=0x.. and hash=0x..\n\
  nonce     --rpc URL --address 0x..            [--socks H:P]\n\
  chainid   --rpc URL                           [--socks H:P]\n\
  gas       --rpc URL                           [--socks H:P]   (EIP-1559 fee suggestion)\n\
  call      --rpc URL --to 0x.. --data 0x..     [--socks H:P]\n\
  send      --rpc URL --raw 0x..                [--socks H:P]   (eth_sendRawTransaction)\n\
  deploy    --rpc URL --bytecode 0x.. [--value WEI] [--gas-limit N] + key [--socks H:P]\n\
            builds+signs a create tx, broadcasts it, prints the deployed contract address\n"
}

fn cmd_address(args: &[String]) -> Result<(), String> {
    let sk = load_key(args)?;
    let addr = wallet::address_of(&sk);
    println!("{}", wallet::address_checksummed(&addr));
    Ok(())
}

fn cmd_sign(args: &[String]) -> Result<(), String> {
    let chain_id = u64opt(args, "chain-id")?.ok_or("missing --chain-id")?;
    let nonce = u64opt(args, "nonce")?.ok_or("missing --nonce")?;
    let gas_limit = u64opt(args, "gas-limit")?.ok_or("missing --gas-limit")?;
    let value = u128opt(args, "value")?.unwrap_or(0);
    let to = parse_to(args)?;
    let data = parse_data(args)?;
    let sk = load_key(args)?;

    let (raw, hash) = if flag(args, "legacy") {
        let gas_price = u128opt(args, "gas-price")?.ok_or("legacy needs --gas-price")?;
        tx::Legacy { chain_id, nonce, gas_price, gas_limit, to, value, data }.sign(&sk)
    } else {
        let max_fee = u128opt(args, "max-fee")?.ok_or("EIP-1559 needs --max-fee")?;
        let max_priority_fee = u128opt(args, "max-priority")?.ok_or("EIP-1559 needs --max-priority")?;
        tx::Eip1559 { chain_id, nonce, max_priority_fee, max_fee, gas_limit, to, value, data }.sign(&sk)
    };
    println!("rawtx=0x{}", hex::encode(&raw));
    println!("hash=0x{}", hex::encode(hash));
    Ok(())
}

fn run() -> Result<(), String> {
    let argv: Vec<String> = std::env::args().collect();
    let cmd = argv.get(1).map(|s| s.as_str()).unwrap_or("");
    let rest = &argv[argv.len().min(2)..];
    match cmd {
        "address" => cmd_address(rest),
        "sign" => cmd_sign(rest),
        "nonce" | "chainid" | "gas" | "call" | "send" | "deploy" => rpc::dispatch(cmd, rest, &load_key),
        "-h" | "--help" | "help" | "" => {
            print!("{}", usage());
            Ok(())
        }
        other => Err(format!("unknown command '{other}'\n\n{}", usage())),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hos-ethsign: {e}");
            ExitCode::FAILURE
        }
    }
}
