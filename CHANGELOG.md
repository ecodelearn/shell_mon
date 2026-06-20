# Changelog

Todas as mudanças notáveis do `shell_mon`. O formato segue
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o projeto adota
[SemVer](https://semver.org/lang/pt-BR/).

## [Não lançado]

### Adicionado
- **Inspeção de processo** (tecla `i` / `Enter`): painel para o socket
  selecionado com linha de comando, árvore de processos e taxas ao vivo de
  **I/O de disco** (leitura/escrita), **CPU** e **memória**, lidas de
  `/proc/<pid>`. CPU/mem aparecem mesmo sem root; o I/O de disco exige root
  (restrição ptrace/yama).

## [0.1.4] — 2026-06-20

### Corrigido
- Coluna **REMOTO** alargada (28% → 36%) para o nome resolvido (DNS reverso)
  não ser cortado em painéis de largura normal (~118 colunas).

## [0.1.3] — 2026-06-20

### Adicionado
- **Cache de DNS reverso em disco** (`~/.cache/shellmon/rdns.tsv`, TTL de 14
  dias): nomes aparecem instantâneos no startup, sem re-resolver.
- **Empacotamento AUR** (`packaging/aur/`): `PKGBUILD` + `.SRCINFO`, validados
  com `makepkg`.

## [0.1.2] — 2026-06-20

### Corrigido
- **Debounce de UDP exposto**: UDP em `UNCONN` ligado a `0.0.0.0`/`::` só conta
  como exposto após persistir ~1,5s, eliminando blips do contador e flood de
  eventos com sockets UDP efêmeros (DNS/QUIC/WebRTC).
- **Notificações D-Bus**: sem barramento de sessão (ex.: via `sudo`), o
  `notify-send` tentava `dbus-launch --autolaunch` e cuspia erro — agora as
  notificações são desativadas em silêncio. O painel root repassa o barramento
  da sessão (`SETENV` no sudoers) para notificar mesmo como root.

## [0.1.1] — 2026-06-20

### Adicionado
- **UNIX domain sockets** (`ss -x`): visíveis pela tecla `t` (fora da visão de
  rede padrão); lógica defensiva permanece restrita aos sockets de rede.
- **DNS reverso (PTR)**: nomes humanos para os IPs (`github`, `google`…),
  resolvidos em background sem travar a TUI.

### Corrigido
- **Detecção de UDP exposto**: sockets UDP "escutando" ficam em `UNCONN` (não
  `LISTEN`) e antes não eram contados — um backdoor UDP em `0.0.0.0` passaria
  despercebido.

## [0.1.0] — 2026-06-19

Primeira versão: monitor de sockets de rede em tempo real (TUI) sobre o comando
`ss`, com foco defensivo.

### Adicionado
- **TUI em tempo real**: auto-refresh de 200ms, pausável; scroll persistente;
  cores por estado; destaque de conexões novas; filtro ao vivo; ordenação;
  filtro de protocolo; modo `--list` scriptável.
- **Visão defensiva**: zonas de confiança (loopback/LAN/internet); ⚠ destaque de
  conexões abertas por descendentes de navegador; contadores de serviços
  expostos e entradas da LAN.
- **Log de eventos** em disco e **notificações** de desktop (`notify-send`) para
  eventos de alta severidade.
- **Triagem** (`--triage`): relatório humanizado cobrindo sockets, auditoria de
  rede (gateway/rotas/DNS com detecção de sequestro de DNS/vizinhos da LAN) e
  auditoria de **firewall** (firewalld/ufw).
- **Operação**: painel "sempre na tela" (launcher Alacritty + `.desktop` +
  regra de janela do KDE/KWin) e **elevação segura** (binário root-only +
  sudoers `NOPASSWD` restrito) para atribuir processo/PID a todos os sockets.
- **CI** (GitHub Actions): `cargo test` + `cargo clippy -D warnings`.

[Não lançado]: https://github.com/ecodelearn/shell_mon/compare/v0.1.4...HEAD
[0.1.4]: https://github.com/ecodelearn/shell_mon/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/ecodelearn/shell_mon/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/ecodelearn/shell_mon/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ecodelearn/shell_mon/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ecodelearn/shell_mon/releases/tag/v0.1.0
