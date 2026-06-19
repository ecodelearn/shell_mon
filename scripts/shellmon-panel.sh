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

# Modo root: prefixa o comando com `sudo -n` e usa o binário root-only.
ELEVATE=""
if [ "${1:-}" = "--root" ]; then
    shift
    ELEVATE="sudo -n"
    BIN="${SHELLMON_BIN:-/usr/local/bin/shellmon}"
else
    BIN="${SHELLMON_BIN:-shellmon}"
fi

if ! command -v alacritty >/dev/null 2>&1; then
    echo "shellmon-panel: alacritty não encontrado no PATH" >&2
    exit 1
fi

# shellcheck disable=SC2086  # $ELEVATE precisa expandir em palavras (sudo -n)
exec alacritty \
    --class shellmon,shellmon \
    --title "shell_mon" \
    -o "window.dimensions.columns=$COLS" \
    -o "window.dimensions.lines=$ROWS" \
    -o "window.opacity=0.96" \
    -e $ELEVATE "$BIN" "$@"
