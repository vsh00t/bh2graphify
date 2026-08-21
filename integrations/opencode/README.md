# Integración con opencode

Dota a cualquier agente de opencode de una forma **rápida y determinista** de
procesar dumps de BloodHound: el trabajo pesado lo hace `bh2graphify` (2 s), el
modelo solo razona sobre un brief de ~5 KB. Así el agente no se pone a parsear los
JSON crudos (lento, errático, cuelgues).

## Instalación (una sola vez)

Desde donde hayas clonado el repo:

```bash
./integrations/opencode/install.sh
```

El script **detecta solo** dónde está el repo (no hay rutas hardcodeadas), persiste
esa ubicación en `~/.config/bh2graphify/repo`, y crea **symlinks** del command y del
skill hacia el repo. No importa en qué carpeta lo clones.

Después de eso, **actualizar es solo**:

```bash
git pull
```

Los symlinks reflejan los cambios y `analyze_zip.py` re-copia `graph_q.py` junto al
grafo en cada corrida — no hay que reinstalar nada.

## Qué deja instalado

| Symlink | Apunta a |
|---|---|
| `~/.config/opencode/commands/analyze-bh.md` (y `command/`) | `integrations/opencode/commands/analyze-bh.md` |
| `~/.agents/skills/graph-pentest-analysis/` | `skill/` del repo (`SKILL.md` + `graph_q.py`) |

Se enlaza en `commands/` y `command/` porque distintas versiones de opencode usan
uno u otro nombre.

## Uso

```
/analyze-bh coleccion_bloodhound.zip
```

El agente recibe el brief (attack paths + choke points + ADCS + superficie) ya
masticado. Para profundizar en un nodo usa el CLI que queda **junto al grafo**:

```bash
python3 ~/pentest-data/current/graphify-out/graph_q.py controllers "GROUP_0007"
python3 ~/pentest-data/current/graphify-out/graph_q.py paths-to "DOMAIN_ADMINS@DOM_01"
```

Nunca los JSON crudos.

## Notas

- Requiere Python 3.8+ (`python3` en el PATH) y opencode.
- Si preferís no usar symlinks, podés copiar los archivos a mano, pero entonces
  cada `git pull` requiere volver a copiarlos. Los symlinks lo evitan.
- Para apuntar a un repo distinto sin reinstalar, exportá `BH2GRAPHIFY=/otra/ruta`.
