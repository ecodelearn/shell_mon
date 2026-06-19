#!/bin/sh
# Abre a TUI do shell_mon numa janela Alacritty dedicada, pensada para ficar
# fixa num canto da tela como um painel "sempre ligado".
#
# A janela recebe o app-id/classe "shellmon" — use isso para criar uma regra
# de janela (KWin no KDE, ou window rule do seu compositor) que a deixe
# flutuante, sempre acima e em todas as áreas de trabalho.
#
# Uso:   shellmon-panel [args extras repassados ao shellmon]
# Ex.:   shellmon-panel --interval 0.5
#
# Variáveis de ambiente:
#   SHELLMON_BIN   caminho do binário shellmon (padrão: "shellmon" no PATH)
#   SHELLMON_COLS  largura em colunas (padrão: 118)
#   SHELLMON_ROWS  altura em linhas  (padrão: 30)

set -eu

BIN="${SHELLMON_BIN:-shellmon}"
COLS="${SHELLMON_COLS:-118}"
ROWS="${SHELLMON_ROWS:-30}"

if ! command -v alacritty >/dev/null 2>&1; then
    echo "shellmon-panel: alacritty não encontrado no PATH" >&2
    exit 1
fi

exec alacritty \
    --class shellmon,shellmon \
    --title "shell_mon" \
    -o "window.dimensions.columns=$COLS" \
    -o "window.dimensions.lines=$ROWS" \
    -o "window.opacity=0.96" \
    -e "$BIN" "$@"
