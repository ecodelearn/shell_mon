#!/bin/sh
# Abre a TUI do shell_mon numa janela Alacritty dedicada, pensada para ficar
# fixa num canto da tela como um painel "sempre ligado".
#
# A janela recebe o app-id/classe "shellmon" — use isso para criar uma regra
# de janela (KWin no KDE, ou window rule do seu compositor) que a deixe
# flutuante, sempre acima e em todas as áreas de trabalho.
#
# Uso:   shellmon-panel [--root] [args extras repassados ao shellmon]
# Ex.:   shellmon-panel --interval 0.5
#        shellmon-panel --root          # painel mostrando processo/PID de todos
#
# O modo --root usa `sudo -n /usr/local/bin/shellmon`, que só funciona após
# rodar `scripts/install-elevation.sh` (instala o binário root-only + regra
# sudoers NOPASSWD restrita a ele). Sem isso, use o modo normal (sem root).
#
# Variáveis de ambiente:
#   SHELLMON_BIN   caminho do binário shellmon (padrão: "shellmon" no PATH;
#                  no modo --root, padrão: /usr/local/bin/shellmon)
#   SHELLMON_COLS  largura em colunas (padrão: 118)
#   SHELLMON_ROWS  altura em linhas  (padrão: 30)

set -eu

COLS="${SHELLMON_COLS:-118}"
ROWS="${SHELLMON_ROWS:-30}"

ROOT=0
if [ "${1:-}" = "--root" ]; then
    shift
    ROOT=1
    BIN="${SHELLMON_BIN:-/usr/local/bin/shellmon}"
else
    BIN="${SHELLMON_BIN:-shellmon}"
fi

if ! command -v alacritty >/dev/null 2>&1; then
    echo "shellmon-panel: alacritty não encontrado no PATH" >&2
    exit 1
fi

ALA="alacritty --class shellmon,shellmon --title shell_mon \
    -o window.dimensions.columns=$COLS \
    -o window.dimensions.lines=$ROWS \
    -o window.opacity=0.96 -e"

if [ "$ROOT" = "1" ]; then
    # Repassa o barramento D-Bus da sessão para que as notificações funcionem
    # mesmo rodando como root (precisa de SETENV no sudoers — ver
    # install-elevation.sh). Sem isso, o root simplesmente não notifica.
    # shellcheck disable=SC2086
    exec $ALA sudo -n \
        DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
        XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" \
        "$BIN" "$@"
else
    # shellcheck disable=SC2086
    exec $ALA "$BIN" "$@"
fi
