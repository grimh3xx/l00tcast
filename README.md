# l00tcast

[![build](https://img.shields.io/github/actions/workflow/status/grimh3xx/l00tcast/build.yml?branch=main&style=flat-square&labelColor=111826&label=build)](https://github.com/grimh3xx/l00tcast/actions)
[![license](https://img.shields.io/github/license/grimh3xx/l00tcast?style=flat-square&labelColor=111826&color=22D3EE)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-2021-3B82F6?style=flat-square&labelColor=111826)
![platform](https://img.shields.io/badge/Linux-x64-22D3EE?style=flat-square&labelColor=111826)
![authorised use](https://img.shields.io/badge/authorised%20use-only-F87171?style=flat-square&labelColor=111826)


**Poisoning de LLMNR/NBT-NS/mDNS e captura de NetNTLM em Rust**, alternativa
enxuta ao Responder para pentest autorizado. Responde às buscas de nome da LAN
apontando para você e coleta o hash NetNTLMv1/v2 já em **formato hashcat**.

<p align="center"><img src="docs/demo.svg" alt="l00tcast demo" width="100%"></p>

> ## ⚠️ Uso autorizado apenas
> Poisoning de resolução de nome afeta **toda a LAN** e é intrusivo. Rode
> **somente** em redes que você possui ou tem **permissão escrita** para testar.
> Uso não autorizado é crime; a responsabilidade é sua.

## Módulos

| flag | o que faz |
|---|---|
| `--llmnr` | responde LLMNR (UDP 5355, 224.0.0.252) |
| `--mdns`  | responde mDNS (UDP 5353, 224.0.0.251) |
| `--nbtns` | responde NBT-NS (UDP 137, broadcast) |
| `--http`  | servidor que força NTLM e extrai o NetNTLM |

Sem flags, liga todos. Desafio do servidor fixo em `1122334455667788` para
cracking offline.

## Uso

```sh
sudo l00tcast -I 192.168.1.50                 # todos os módulos
sudo l00tcast -I 192.168.1.50 --llmnr --http  # só LLMNR + captura HTTP
sudo l00tcast -I 192.168.1.50 -o loot.txt     # grava hashes
```

A linha capturada sai pronta pro hashcat:

```sh
hashcat -m 5600 loot.txt wordlist.txt   # NetNTLMv2
```

## Roadmap

- Captura via **SMB** (rogue server) além de HTTP.
- WPAD/proxy e downgrade.

## Build

```sh
cargo build --release
```

## Licença

MIT. Veja [LICENSE](LICENSE).
