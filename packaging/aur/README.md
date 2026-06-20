# Empacotamento AUR

Arquivos para publicar o `shellmon` no [AUR](https://aur.archlinux.org/).

- `PKGBUILD` — compila a partir do tarball do release (`vX.Y.Z`)
- `.SRCINFO` — metadados gerados (regenere ao mudar o PKGBUILD)

## Testar localmente

```bash
# numa cópia destes arquivos (fora de /tmp se ele for noexec):
makepkg -df               # baixa, compila, testa e empacota
makepkg --printsrcinfo > .SRCINFO   # regenera o .SRCINFO
namcap PKGBUILD *.pkg.tar.zst        # (opcional) lint
```

## Publicar no AUR (primeira vez)

Requer conta no AUR com sua **chave SSH** cadastrada.

```bash
git clone ssh://aur@aur.archlinux.org/shellmon.git aur-shellmon
cp PKGBUILD .SRCINFO aur-shellmon/
cd aur-shellmon
git add PKGBUILD .SRCINFO
git commit -m "Initial import: shellmon 0.1.2-1"
git push
```

## Atualizar (a cada novo release)

1. No `PKGBUILD`: atualize `pkgver`, volte `pkgrel=1` e troque o `sha256sums`
   (`updpkgsums` faz isso automaticamente).
2. Regenere o `.SRCINFO`.
3. `git commit` + `git push` no repositório do AUR.

## Variantes possíveis (futuro)

- `shellmon-bin` — usa o binário pré-compilado anexado ao release (sem compilar).
- `shellmon-git` — compila a partir do `main`.

> Após instalar via AUR, o binário fica em `/usr/bin/shellmon`. Para o painel com
> root (processo/PID de todos os sockets), rode o `install-elevation.sh` do repo
> com `SHELLMON_SRC=/usr/bin/shellmon`.
