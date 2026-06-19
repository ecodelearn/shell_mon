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
- 🛡️ **Visão defensiva**: zonas de confiança (loopback / **rede local** / **internet**), contadores de **serviços expostos** e **entradas da LAN**, e ⚠ destaque de conexões abertas por **descendentes de navegador**
- 🩺 **Triagem** (`--triage`): relatório humanizado do estado atual (o que está exposto, quem entra da LAN, o que fala com a internet)
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
- **Serviços expostos**: contador no topo de quantos serviços estão em `LISTEN`
  acessíveis pela rede (não-loopback) — uma porta dos fundos apareceria aqui.
- **Entradas da LAN** (`lan-in`): conexões estabelecidas **entrando** de um peer
  da rede local para um serviço seu — fica **vermelho** quando há alguma.
- **⚠ via navegador**: conexões abertas por um processo **descendente de um
  navegador** (Firefox/Chrome/Chromium/Brave) são marcadas, para flagrar ataques
  que escalam a partir da navegação.

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
