# shell_mon

Monitor de sockets de rede em **tempo real** no terminal (TUI), construído em Rust sobre o comando [`ss`](https://man7.org/linux/man-pages/man8/ss.8.html) do `iproute2`.

Pense num `htop` para conexões de rede: lista TCP/UDP, estados, filas, e qual processo é dono de cada socket — atualizando ao vivo.

```
┌ shell_mon  ·  proto:all  ordem:estado ──────────────────────────────────────┐
│ total 37   tcp 25  udp 12   estab 17  listen 8  time-wait 1                  │
└─────────────────────────────────────────────────────────────────────────────┘
┌ sockets (37) ───────────────────────────────────────────────────────────────┐
│ PROTO  ESTADO   RECV-Q  SEND-Q  LOCAL              REMOTO          PROCESSO   │
│ tcp    ESTAB    0       0       192.168.0.10:22    192.168.0.5:51234  sshd    │
│ tcp    LISTEN   0       0       127.0.0.1:11434    0.0.0.0:*          ollama  │
│ udp    UNCONN   0       0       0.0.0.0:48958      0.0.0.0:*                  │
└─────────────────────────────────────────────────────────────────────────────┘
 q sair · p pausa · / filtro · t proto · s ordem · r refresh · ↑↓ navega
```

## Recursos

- 🔄 **Auto-refresh** configurável (padrão 2s), pausável a qualquer momento
- 🔍 **Filtro ao vivo** por endereço, processo, estado ou PID
- 🎨 **Cores por estado** (ESTAB verde, LISTEN amarelo, TIME-WAIT vermelho) e **destaque de conexões novas** entre refreshes
- 🔀 **Ordenação** alternável (estado, local, remoto, processo, filas) e filtro de protocolo (all / tcp / udp)
- 👮 **Detecção de root** — avisa quando, sem `sudo`, os processos de sockets de outros usuários ficam ocultos
- 📜 **Modo lista** (`--list`) para uso scriptável / one-shot

## Requisitos

- Linux com o comando `ss` disponível (pacote `iproute2`, presente na maioria das distros)
- Rust / Cargo (edição 2021) para compilar

## Instalação

```bash
git clone https://github.com/ecodelearn/shell_mon.git
cd shell_mon
cargo build --release
# binário em ./target/release/shellmon
```

Opcional — instalar no PATH do usuário:

```bash
cargo install --path .
# ou
cp target/release/shellmon ~/.local/bin/
```

## Uso

```bash
# TUI interativa (recomendado rodar com sudo para ver os processos)
sudo shellmon

# Intervalo de refresh de 1 segundo
shellmon --interval 1

# Lista única, scriptável
shellmon --list

# Ajuda
shellmon --help
```

> **Por que `sudo`?** O `ss -p` só revela o processo dono de um socket pertencente a
> *outro* usuário quando executado como root. Sem privilégios você ainda vê todos os
> sockets, mas a coluna PROCESSO/PID fica vazia para os que não são seus.

### Teclas (modo TUI)

| Tecla | Ação |
|---|---|
| `q` / `Esc` / `Ctrl-C` | sair |
| `p` | pausar / retomar auto-refresh |
| `r` | refresh manual |
| `/` | filtrar (endereço, processo, estado, PID) |
| `t` | alternar protocolo (all → tcp → udp) |
| `a` | voltar para todos os protocolos |
| `s` | alternar ordenação |
| `↑`/`↓` ou `k`/`j` | navegar |
| `PgUp` / `PgDn` / `Home` | navegação rápida |

## Como funciona

O `shell_mon` executa `ss -tuanpH` (TCP + UDP, todos os estados, numérico, com
processo, sem cabeçalho), parseia a saída de forma robusta — lidando com IPv6
(`[::1]:631`), interfaces (`192.168.0.1%enp2s0`) e o formato
`users:(("nome",pid=123,fd=5))` — e renderiza tudo com [ratatui](https://ratatui.rs).

```
src/
├── socket.rs   coleta e parsing do `ss` + resumo agregado
├── app.rs      estado: filtros, ordenação, scroll, diffs entre refreshes
├── ui.rs       renderização da TUI (ratatui)
└── main.rs     terminal, loop de eventos, args, detecção de root
```

## Desenvolvimento

```bash
cargo test    # testes do parser
cargo run     # roda em modo debug
```

## Licença

MIT
