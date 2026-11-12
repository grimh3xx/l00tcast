# hashlure

Poisoning de **LLMNR / NBT-NS / mDNS** e **captura de NetNTLM**, alternativa
enxuta ao Responder, para pentest autorizado. Responde às buscas de nome da LAN
apontando para você e coleta o hash NetNTLMv1/v2 em formato **hashcat**.

> ⚠️ **Uso autorizado apenas.** Poisoning afeta toda a LAN — só com escopo e
> permissão explícita. Precisa de privilégio para abrir 137/5353/5355/80.

## Uso
```sh
sudo hashlure -I 192.168.1.50                 # todos os módulos
sudo hashlure -I 192.168.1.50 --llmnr --http  # só LLMNR + captura HTTP
sudo hashlure -I 192.168.1.50 -o loot.txt     # grava hashes
```
A linha capturada vai pro stdout pronta pro hashcat:
```
hashcat -m 5600 loot.txt wordlist.txt   # NetNTLMv2
```

## Módulos
| flag | o que faz |
|------|-----------|
| `--llmnr` | responde LLMNR (UDP 5355, 224.0.0.252) |
| `--mdns`  | responde mDNS (UDP 5353, 224.0.0.251) |
| `--nbtns` | responde NBT-NS (UDP 137, broadcast) |
| `--http`  | servidor que força NTLM e extrai o NetNTLM |

Desafio do servidor fixo em `1122334455667788` para cracking offline.

## Roadmap
- Captura via **SMB** (rogue server) além de HTTP.
- WPAD/proxy e downgrade.

## Build
```sh
cargo build --release
```
