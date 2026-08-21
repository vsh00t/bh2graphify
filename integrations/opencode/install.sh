#!/usr/bin/env bash
# install.sh — deja bh2graphify operativo en opencode desde donde se haya clonado.
#
# Detecta la ubicación del repo automáticamente (NO quema rutas), la persiste para
# que el command la lea, y enlaza (symlink) el command y el skill. Tras esto,
# `git pull` basta para actualizar todo — los symlinks reflejan los cambios.
#
# Uso:  ./integrations/opencode/install.sh     (o desde cualquier cwd)
set -euo pipefail

# Raíz del repo = dos niveles arriba de este script (integrations/opencode/).
# `cd ... && pwd` lo resuelve a ruta absoluta de forma portable (macOS/Linux).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "[*] Repo detectado: $REPO"

# Verificación mínima de que es el repo correcto.
if [ ! -f "$REPO/analyze_zip.py" ] || [ ! -f "$REPO/skill/graph_q.py" ]; then
    echo "[!] No parece el repo bh2graphify (falta analyze_zip.py o skill/graph_q.py)." >&2
    exit 1
fi

# 1) Persistir la ruta del repo para que el command la lea (sin hardcodear).
CFG="$HOME/.config/bh2graphify"
mkdir -p "$CFG"
printf '%s\n' "$REPO" > "$CFG/repo"
echo "[+] Ruta del repo persistida en $CFG/repo"

# 2) Command /analyze-bh → symlink. opencode escanea commands/ y, según versión,
#    command/ (singular): enlazamos en ambos para no depender de la versión.
CMD_SRC="$REPO/integrations/opencode/commands/analyze-bh.md"
for d in "$HOME/.config/opencode/commands" "$HOME/.config/opencode/command"; do
    mkdir -p "$d"
    ln -sfn "$CMD_SRC" "$d/analyze-bh.md"
    echo "[+] command  → ${d/#$HOME/~}/analyze-bh.md"
done

# 3) Skill graph-pentest-analysis → symlink de la carpeta skill/ del repo.
#    (El nombre de la carpeta = name: del frontmatter, requisito de opencode.)
mkdir -p "$HOME/.agents/skills"
SKILL_DST="$HOME/.agents/skills/graph-pentest-analysis"
rm -rf "$SKILL_DST"
ln -s "$REPO/skill" "$SKILL_DST"
echo "[+] skill    → ${SKILL_DST/#$HOME/~}  ->  $REPO/skill"

# 4) Sanity check: el orquestador arranca.
if python3 "$REPO/analyze_zip.py" --help >/dev/null 2>&1; then
    echo "[+] analyze_zip.py operativo (python3)"
else
    echo "[!] Aviso: 'python3 $REPO/analyze_zip.py --help' falló — revisá tu Python 3.8+." >&2
fi

cat <<EOF

[✓] Instalado.
    Uso en opencode:   /analyze-bh <coleccion_bloodhound.zip>
    Actualizar:        git pull   (los symlinks reflejan los cambios; nada más)
EOF
