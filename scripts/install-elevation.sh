#!/bin/sh
# Instala o shellmon de forma privilegiada para o painel "com root", que mostra
# o processo/PID dono de TODOS os sockets (inclusive de outros usuários).
#
# O que faz, com segurança:
#   - copia o binário para /usr/local/bin/shellmon (dono root:root, modo 755),
#     um local que o seu usuário NÃO pode sobrescrever — isso é o que torna o
#     NOPASSWD seguro (senão daria pra trocar o binário por um shell root);
#   - cria uma regra sudoers NOPASSWD restrita EXATAMENTE a esse caminho,
#     validada com `visudo -c` antes de aplicar.
#
# Uso (a partir da raiz do repositório, após `cargo build --release`):
#   sudo scripts/install-elevation.sh
#
# Variáveis:
#   SHELLMON_SRC   caminho do binário a instalar (padrão: target/release/shellmon)

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Rode como root:  sudo $0" >&2
    exit 1
fi

# Usuário que receberá o NOPASSWD (quem chamou o sudo, ou 1º argumento).
TARGET_USER="${SUDO_USER:-${1:-}}"
if [ -z "$TARGET_USER" ]; then
    echo "Não consegui detectar o usuário. Informe:  sudo $0 <usuario>" >&2
    exit 1
fi

SRC="${SHELLMON_SRC:-target/release/shellmon}"
if [ ! -x "$SRC" ]; then
    echo "Binário não encontrado em '$SRC'." >&2
    echo "Rode 'cargo build --release' na raiz do repositório antes." >&2
    exit 1
fi

DEST=/usr/local/bin/shellmon
install -o root -g root -m 755 "$SRC" "$DEST"
echo "✓ instalado: $DEST (root:root 755)"

SUDOERS=/etc/sudoers.d/shellmon
TMP="$(mktemp)"
# SETENV permite repassar DBUS_SESSION_BUS_ADDRESS/XDG_RUNTIME_DIR para que o
# painel root (`shellmon-panel --root`) consiga enviar notificações de desktop.
printf '%s ALL=(root) NOPASSWD:SETENV: %s\n' "$TARGET_USER" "$DEST" > "$TMP"
if visudo -c -f "$TMP" >/dev/null 2>&1; then
    install -o root -g root -m 440 "$TMP" "$SUDOERS"
    rm -f "$TMP"
    echo "✓ instalado: $SUDOERS"
    echo "  ($TARGET_USER pode rodar SOMENTE $DEST como root, sem senha)"
else
    rm -f "$TMP"
    echo "✗ regra sudoers inválida — nada foi alterado" >&2
    exit 1
fi

echo
echo "Pronto. Teste:    sudo -n $DEST --list | head -3"
echo "Painel com root:  shellmon-panel --root"
echo
echo "Para remover depois:"
echo "    sudo rm -f $SUDOERS $DEST"
