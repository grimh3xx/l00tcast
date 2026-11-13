//! Drives the HTTP NetNTLM capture with a minimal in-process NTLM client over a
//! real socket: Type1 -> (401 + Type2) -> Type3, then asserts the captured
//! hashcat line was written.
use base64::{engine::general_purpose::STANDARD, Engine};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}
fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn build_type3(domain: &str, user: &str, proof: &[u8], blob: &[u8]) -> Vec<u8> {
    let dom = utf16(domain);
    let usr = utf16(user);
    let mut nt = proof.to_vec();
    nt.extend_from_slice(blob);
    let base = 64u32;
    let sb = |len: usize, off: u32| {
        let l = len as u16;
        let mut v = Vec::new();
        v.extend_from_slice(&l.to_le_bytes());
        v.extend_from_slice(&l.to_le_bytes());
        v.extend_from_slice(&off.to_le_bytes());
        v
    };
    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\0");
    m.extend_from_slice(&3u32.to_le_bytes());
    m.extend_from_slice(&sb(0, base));
    m.extend_from_slice(&sb(nt.len(), base + dom.len() as u32 + usr.len() as u32));
    m.extend_from_slice(&sb(dom.len(), base));
    m.extend_from_slice(&sb(usr.len(), base + dom.len() as u32));
    m.extend_from_slice(&sb(0, base));
    m.extend_from_slice(&sb(0, base));
    m.extend_from_slice(&0u32.to_le_bytes());
    m.extend_from_slice(&dom);
    m.extend_from_slice(&usr);
    m.extend_from_slice(&nt);
    m
}

async fn send_req(s: &mut TcpStream, token: &str) -> String {
    let req = format!(
        "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: NTLM {token}\r\nConnection: keep-alive\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = [0u8; 2048];
    let n = s.read(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf[..n]).to_string()
}

#[tokio::test]
async fn captures_netntlm_over_http() {
    let port = 18071u16;
    let loot = std::env::temp_dir().join(format!("l00tcast_loot_{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&loot);
    let loot_s = loot.to_string_lossy().to_string();

    tokio::spawn(l00tcast::http_capture::run(port, Some(loot_s)));

    // wait for the listener
    let mut s = None;
    for _ in 0..40 {
        if let Ok(c) = TcpStream::connect(("127.0.0.1", port)).await {
            s = Some(c);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut s = s.expect("server up");

    // Type1 (negotiate) -> server should answer 401 with a challenge
    let type1 = STANDARD.encode(b"NTLMSSP\0\x01\0\0\0\0\0\0\0");
    let r1 = send_req(&mut s, &type1).await;
    assert!(r1.starts_with("HTTP/1.1 401"), "expected 401, got: {r1}");

    // Type3 (authenticate) with a known NTLMv2 response
    let proof = [0xAAu8; 16];
    let blob: Vec<u8> = (0u8..28).collect();
    let type3 = STANDARD.encode(build_type3("CORP", "jdoe", &proof, &blob));
    let _r2 = send_req(&mut s, &type3).await;

    tokio::time::sleep(Duration::from_millis(100)).await;
    let got = std::fs::read_to_string(&loot).expect("loot file written");
    let want = format!("jdoe::CORP:1122334455667788:{}:{}", hexs(&proof), hexs(&blob));
    assert!(got.contains(&want), "captured '{got}' should contain '{want}'");
    let _ = std::fs::remove_file(&loot);
}
