<img src="docs/banner.svg" alt="l00tcast" width="100%">

[![build](https://img.shields.io/github/actions/workflow/status/grimh3xx/l00tcast/build.yml?branch=main&style=flat-square&labelColor=111826&label=build)](https://github.com/grimh3xx/l00tcast/actions)
[![license](https://img.shields.io/github/license/grimh3xx/l00tcast?style=flat-square&labelColor=111826&color=22D3EE)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-2021-3B82F6?style=flat-square&labelColor=111826)
![platform](https://img.shields.io/badge/Linux-x64-22D3EE?style=flat-square&labelColor=111826)
![authorised use](https://img.shields.io/badge/authorised%20use-only-F87171?style=flat-square&labelColor=111826)


**LLMNR/NBT-NS/mDNS poisoning and NetNTLM capture in Rust**, a lean Responder
alternative for authorised pentests. It answers the LAN's name lookups pointing
them at you and collects the NetNTLMv1/v2 hash already in **hashcat format**.

<p align="center"><img src="docs/demo.svg" alt="l00tcast demo" width="100%"></p>

> ## ⚠️ Authorised use only
> Name-resolution poisoning affects the **whole LAN** and is intrusive. Run
> **only** on networks you own or have **written permission** to test.

## Modules

| flag | what it does |
|---|---|
| `--llmnr` | answer LLMNR (UDP 5355, 224.0.0.252) |
| `--mdns`  | answer mDNS (UDP 5353, 224.0.0.251) |
| `--nbtns` | answer NBT-NS (UDP 137, broadcast) |
| `--http`  | HTTP server that forces NTLM and extracts the NetNTLM hash |

With no flags all are on. The server challenge is fixed to `1122334455667788`
for offline cracking.

## Usage

```sh
sudo l00tcast -I 192.168.1.50                 # all modules
sudo l00tcast -I 192.168.1.50 --llmnr --http  # LLMNR + HTTP capture only
sudo l00tcast -I 192.168.1.50 -o loot.txt     # save hashes
```

Captured lines are hashcat-ready:

```sh
hashcat -m 5600 loot.txt wordlist.txt   # NetNTLMv2
```

## Tests

```sh
cargo test --release
```

- Poisoning: a crafted LLMNR query must be answered with the attacker IP.
- NTLM: a synthetic NTLMv2 Type-3 must parse into the exact hashcat line.
- HTTP capture: an in-process NTLM client (Type1 -> 401 -> Type3) must have its
  hash written to the loot file.

## Roadmap

- NetNTLM capture over **SMB** (rogue server) in addition to HTTP.
- WPAD/proxy and downgrade.

## Build

```sh
cargo build --release
```

## License

MIT. See [LICENSE](LICENSE).
