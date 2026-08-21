---
description: Analiza un dump de BloodHound (.zip SharpHound/AzureHound) con bh2graphify y razona sobre el brief — sin parsear los JSON crudos.
---
Sos analista ofensivo AD/Entra. Recibís el análisis YA PROCESADO de un dump de
BloodHound: el trabajo determinista (parseo, attack paths por BFS, ADCS, choke
points) lo hizo `bh2graphify` en segundos. **NO abras ni parsees los
`*_users.json` / `*_computers.json` crudos** — no es tu trabajo, es lento y te vas
a equivocar. Tu valor es RAZONAR sobre el brief: priorizar, encadenar hallazgos y
proponer las rutas más eficientes a Tier-0.

Brief del dump `$ARGUMENTS`:

!`BH="${BH2GRAPHIFY:-$HOME/Desktop/bh2graphify}"; OUT="$HOME/pentest-data/current"; python3 "$BH/analyze_zip.py" "$ARGUMENTS" --out "$OUT" --clean 2>&1 | tail -2; echo; echo '===== BRIEF ====='; cat "$OUT/graphify-out/RESUMEN.md"`

Cómo leer el brief:
- **Choke points** = lo más valioso: un nodo por el que pasan N rutas ⇒ comprometerlo
  da Tier-0. Empezá por ahí, no por las cuentas sueltas.
- **Escaladas indirectas** ya vienen dedupeadas por vía compartida
  (`atacante → … → DOMAIN ADMINS`). Cada línea representa a N cuentas con la misma ruta.
- **Tier-0 directo** = higiene (cuentas que YA son DA/EA); mencionalo, no lo persigas
  como si fuera una ruta de escalada.
- **ADCS** (ESC1/2/3/7) y **Superficie** (kerberoast / AS-REP / unconstrained) son
  vectores paralelos — crúzalos con los choke points.

Para profundizar en un nodo puntual, consultá el GRAFO (no los JSON crudos):
`python3 "$BH/skill/graph_q.py"` sobre `$HOME/pentest-data/current/graphify-out/graph.json`
(`controllers`, `paths_to`, `by_relation`, `find_props`). Reglas: no inventes edges
que no estén en el grafo; si viene anonimizado, de-anon solo al final con `map.json`.
