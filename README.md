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

- 🔄 **Auto-refresh** em tempo real (padrão 200ms), pausável a qualquer momento
- 🔍 **Filtro ao vivo** por endereço, processo, estado ou PID
- 🎨 **Cores por estado** (ESTAB verde, LISTEN azul, TIME-WAIT magenta) e **destaque de conexões novas** por ~1,5s
- 🏷️ **Nomes dos IPs** (DNS reverso): mostra `→ 140.82.113.25 github` em vez de só o número, resolvido em background sem travar a TUI (`--no-rdns` desativa)
- 🛡️ **Visão defensiva**: zonas de confiança (loopback / **rede local** / **internet**), contadores de **serviços expostos** e **entradas da LAN**, e ⚠ destaque de conexões abertas por **descendentes de navegador**
- 🩺 **Triagem** (`--triage`): relatório humanizado do estado atual (o que está exposto, quem entra da LAN, o que fala com a internet)
- 📝 **Log de eventos**: registra em disco quando listeners/entradas da LAN aparecem e somem, para revisar depois
- 🔔 **Notificações** (`notify-send`): alerta no desktop em eventos de alta severidade (novo serviço exposto, entrada da LAN, DNS suspeito)
- 🧭 **Auditoria de rede** (`--triage`): checa gateway/rotas/DNS e **sinaliza DNS não-padrão empurrado pelo roteador** (sequestro de DNS), lista os dispositivos da LAN e audita o **firewall** (avisa se a entrada não estiver em DROP)
- 🔀 **Ordenação** alternável (estado, local, remoto, processo, filas) e filtro de protocolo (rede / tcp / udp / **unix**)
- 🧦 **UNIX domain sockets** (IPC local): visíveis pela tecla `t` (ficam fora da visão padrão de rede para não inundar), com toda a lógica defensiva aplicada só aos sockets de rede
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
| `t` | alternar protocolo (rede → tcp → udp → unix) |
| `a` | voltar para rede (tcp+udp) |
| `s` | alternar ordenação |
| `↑`/`↓` ou `k`/`j` | navegar |
| `PgUp` / `PgDn` / `Home` | navegação rápida |

## Painel "sempre na tela"

Como o `shellmon` atualiza sozinho (5x/s por padrão), dá para deixá-lo rodando
num canto da tela como um painel passivo — você trabalha em outra coisa e só dá
uma olhada quando quiser. O script `scripts/shellmon-panel.sh` abre a TUI numa
janela [Alacritty](https://alacritty.org) dedicada, com a classe/app-id
`shellmon` (use isso na regra de janela do seu compositor).

Instalação dos utilitários no PATH do usuário:

```bash
cargo build --release
install -m 755 target/release/shellmon       ~/.local/bin/shellmon
install -m 755 scripts/shellmon-panel.sh      ~/.local/bin/shellmon-panel
install -m 644 scripts/shellmon.desktop        ~/.local/share/applications/shellmon.desktop
```

Abrir o painel:

```bash
shellmon-panel                 # janela Alacritty fixa rodando a TUI
SHELLMON_COLS=140 shellmon-panel --interval 0.5   # customizando
```

### Fixar no canto (KDE Plasma / KWin)

1. **Configurações do Sistema → Gerenciamento de Janelas → Regras de Janela → Adicionar Nova**
2. Em *Correspondência de janela*, **Classe de janela (aplicativo)** → `Exatamente igual a` → `shellmon`
3. Adicione as propriedades (cada uma como *Forçar* / *Aplicar inicialmente*):
   - **Flutuante (não no mosaico)**: Sim
   - **Manter acima das outras**: Sim
   - **Em todas as áreas de trabalho**: Sim
   - **Pular barra de tarefas** e **Pular alternador**: Sim
   - **Posição** e **Tamanho**: o canto/dimensão que preferir
4. Aplique. Toda janela aberta via `shellmon-panel` já nasce fixa ali.

### Iniciar junto com a sessão

```bash
cp scripts/shellmon.desktop ~/.config/autostart/   # autostart do Plasma
```

> Em outros compositores Wayland (Hyprland, Sway, river…) a ideia é a mesma:
> uma *window rule* casando o app-id `shellmon` para `float` + `pin`/`above`.

### Painel com root (processo/PID de todos os sockets)

Sem privilégios, a coluna PROCESSO/PID fica vazia para sockets de outros
usuários. Para um painel que mostra tudo — inclusive iniciando junto com a
sessão, sem pedir senha — use o instalador privilegiado:

```bash
cargo build --release
sudo scripts/install-elevation.sh
```

Ele faz isso **com segurança**:

- copia o binário para `/usr/local/bin/shellmon` (`root:root 755`), um local que
  seu usuário **não** pode sobrescrever;
- cria `/etc/sudoers.d/shellmon` com uma regra `NOPASSWD` **restrita exatamente a
  esse caminho** (validada com `visudo -c`).

> Por que `/usr/local/bin` e não `~/.local/bin`? Um `NOPASSWD` apontando para um
> binário que você mesmo pode editar equivaleria a root irrestrito (bastaria
> trocá-lo por um shell). Em local root-only, o `sudo` só consegue rodar *aquele*
> programa, somente-leitura.

Depois, abra o painel elevado:

```bash
shellmon-panel --root
# ou instale a entrada de autostart com root:
cp scripts/shellmon-panel-root.desktop ~/.config/autostart/
```

Para remover a elevação:

```bash
sudo rm -f /etc/sudoers.d/shellmon /usr/local/bin/shellmon
```

## Visão defensiva

O `shell_mon` ajuda a **observar e entender** atividade de rede suspeita. Ele
classifica cada par remoto em **zonas de confiança** e destaca o que costuma
indicar problema:

- **Zonas**: `loopback` (cinza, só a máquina) · `rede local` (ciano) · `internet`
  (amarelo). A coluna REMOTO é colorida por zona.
- **Serviços expostos**: contador no topo de quantos serviços estão escutando
  acessíveis pela rede (não-loopback) — uma porta dos fundos apareceria aqui.
  Inclui **UDP** ligado a `0.0.0.0`/`::` (que fica em estado `UNCONN`, não
  `LISTEN`); para esses há um **debounce** (~1,5s) que ignora sockets UDP
  efêmeros (consultas DNS/QUIC) e só conta serviços que persistem.
- **Entradas da LAN** (`lan-in`): conexões estabelecidas **entrando** de um peer
  da rede local para um serviço seu — fica **vermelho** quando há alguma.
- **⚠ via navegador**: conexões abertas por um processo **descendente de um
  navegador** (Firefox/Chrome/Chromium/Brave) são marcadas, para flagrar ataques
  que escalam a partir da navegação.

### Log de eventos

No modo TUI, o `shell_mon` registra em disco os eventos de **alto sinal** — sem
encher de ruído — para você revisar depois "o que aconteceu enquanto eu não
estava olhando". Fica ligado por padrão (`--no-log` desativa):

```
~/.local/share/shellmon/events.log      # ou $SHELLMON_LOG / $XDG_DATA_HOME
```

São registrados: novos serviços escutando (`LISTEN_NEW`, **HIGH** se exposto),
listeners que somem (`LISTEN_GONE`) e conexões entrando da LAN (`LAN_INBOUND`,
**HIGH**) — cada um com data/hora local, processo/PID e ⚠ se vier de navegador:

```
2026-06-19 16:55:43  [INFO] SESSION_START    monitorando — base: 8 listeners (2 expostos), 0 entradas da LAN
2026-06-19 16:55:45  [HIGH] LISTEN_NEW       tcp 0.0.0.0:4444 (python3, pid 78743) [todas as interfaces]
2026-06-19 16:55:47  [INFO] LISTEN_GONE      tcp 0.0.0.0:4444 (python3, pid 78743) [todas as interfaces]
```

Acompanhe ao vivo com `tail -f ~/.local/share/shellmon/events.log`.

### Notificações de desktop

Eventos de **alta severidade** (novo serviço exposto, entrada da LAN, DNS
suspeito) também disparam uma notificação via `notify-send` — para você ser
avisado na hora, mesmo com o painel fora de vista. Ligado por padrão se
`notify-send` existir; `--no-notify` desativa. Há deduplicação para não repetir
o mesmo alerta em sequência.

As notificações precisam de um **barramento D-Bus de sessão**
(`DBUS_SESSION_BUS_ADDRESS`). Sem ele — por exemplo, rodando via `sudo`, que
limpa o ambiente — elas são silenciosamente desativadas (em vez de cuspir o erro
`dbus-launch --autolaunch`). Para que o **painel root** (`shellmon-panel
--root`) consiga notificar, o launcher repassa o barramento da sua sessão e o
`install-elevation.sh` adiciona `SETENV` à regra sudoers; reexecute-o após
atualizar.

### Auditoria de rede e sequestro de DNS

Um roteador comprometido entrega configuração via DHCP (DNS, gateway, rotas) —
um invasor pode redirecionar todo o seu tráfego **sem invadir a máquina**,
apenas empurrando um servidor DNS malicioso. O `shell_mon` audita isso:

- classifica cada servidor DNS em uso como **conhecido** (Quad9, Cloudflare,
  Google…), **local** (o roteador faz DNS) ou **⚠ não reconhecido**;
- um DNS público não reconhecido vira aviso `DNS_SUSPECT` (log + notificação)
  já na inicialização;
- a `--triage` mostra gateway, rotas, DNS classificados e os dispositivos da LAN.

A `--triage` também **audita o firewall de host** (firewalld/ufw): mostra a zona
padrão e se a política de entrada é `DROP` (bloqueada) ou `ACCEPT` (exposta). Se
o firewall estiver inativo ou aceitando entrada, vira aviso `FIREWALL` no log e
notificação. Exemplo de saída saudável:

```
🧱 FIREWALL
   backend: firewalld (ativo)
   zona padrão: public
   entrada: DROP  → bloqueada por padrão ✅
```

Se um DNS suspeito for sinalizado, **fixe o seu** e impeça o roteador de
empurrar outro:

```bash
sudo nmcli connection modify "Wired connection 1" ipv4.ignore-auto-dns yes \
    ipv4.dns "9.9.9.9 149.112.112.112"
sudo nmcli connection up "Wired connection 1"
```

### Triagem (`--triage`)

Relatório único e humanizado do estado atual — ótimo para uma checagem rápida:

```bash
sudo shellmon --triage     # com root: atribui processo/PID a tudo
shellmon --triage          # sem root: funciona, mas oculta donos de serviços
```

Mostra, em linguagem clara: serviços escutando expostos à rede, conexões
entrando da LAN, conexões ativas com a internet (marcando as que vêm do
navegador) e um resumo no rodapé.

> **Limite importante:** um monitor rodando *na própria máquina* potencialmente
> comprometida tem alcance limitado — um invasor com root pode ocultar rastros.
> Use o `shell_mon` para pegar o óbvio e ganhar visibilidade, mas combine com
> firewall de host, inspeção do roteador e observação a partir de outro
> dispositivo.

## Como funciona

O `shell_mon` executa `ss -tuanpH` (TCP + UDP, todos os estados, numérico, com
processo, sem cabeçalho), parseia a saída de forma robusta — lidando com IPv6
(`[::1]:631`), interfaces (`192.168.0.1%enp2s0`) e o formato
`users:(("nome",pid=123,fd=5))` — e renderiza tudo com [ratatui](https://ratatui.rs).

```
src/
├── socket.rs   coleta e parsing do `ss` + resumo agregado (com contadores de ameaça)
├── analysis.rs zonas de confiança (IP) e linhagem de processos (/proc)
├── app.rs      estado: filtros, ordenação, scroll, diffs, cache de navegador
├── events.rs   log de eventos defensivos em disco (listeners, entradas da LAN)
├── notify.rs   notificações de desktop (notify-send) com deduplicação
├── netcfg.rs   auditoria de rede: gateway/rotas/DNS/vizinhos + DNS suspeito
├── rdns.rs     DNS reverso (PTR) em background → nomes humanos pros IPs
├── triage.rs   relatório defensivo `--triage`
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
