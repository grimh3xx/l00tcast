//! Helpers mínimos de wire DNS (compartilhado por LLMNR e mDNS).
use std::net::Ipv4Addr;

/// Extrai o nome da primeira question (labels unidos por '.').
pub fn question_name(buf: &[u8]) -> Option<String> {
    if buf.len() < 13 {
        return None;
    }
    let mut i = 12;
    let mut parts = Vec::new();
    while i < buf.len() {
        let len = buf[i] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None; // ponteiro de compressão: ignora
        }
        i += 1;
        if i + len > buf.len() {
            return None;
        }
        parts.push(String::from_utf8_lossy(&buf[i..i + len]).to_string());
        i += len;
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}

/// Fim da seção de question (offset após qname+qtype+qclass).
fn question_end(buf: &[u8]) -> Option<usize> {
    let mut i = 12;
    while i < buf.len() {
        let len = buf[i] as usize;
        if len == 0 {
            i += 1;
            break;
        }
        i += 1 + len;
    }
    let end = i + 4; // qtype + qclass
    if end <= buf.len() {
        Some(end)
    } else {
        None
    }
}

/// Monta resposta A apontando o nome consultado para `ip`.
pub fn build_a_response(query: &[u8], ip: Ipv4Addr) -> Option<Vec<u8>> {
    let qend = question_end(query)?;
    let mut out = Vec::with_capacity(qend + 16);
    // header
    out.extend_from_slice(&query[0..2]); // id
    out.extend_from_slice(&[0x80, 0x00]); // flags: response
    out.extend_from_slice(&[0x00, 0x01]); // qdcount
    out.extend_from_slice(&[0x00, 0x01]); // ancount
    out.extend_from_slice(&[0x00, 0x00]); // nscount
    out.extend_from_slice(&[0x00, 0x00]); // arcount
    // question ecoada
    out.extend_from_slice(&query[12..qend]);
    // answer
    out.extend_from_slice(&[0xC0, 0x0C]); // ponteiro p/ nome
    out.extend_from_slice(&[0x00, 0x01]); // type A
    out.extend_from_slice(&[0x00, 0x01]); // class IN
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x1E]); // ttl 30
    out.extend_from_slice(&[0x00, 0x04]); // rdlength
    out.extend_from_slice(&ip.octets());
    Some(out)
}
