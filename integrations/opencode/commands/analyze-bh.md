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

!`BH="${BH2GRAPHIFY:-$(cat "$HOME/.config/bh2graphify/repo" 2>/dev/null)}"; OUT="$HOME/pentest-data/current"; python3 "$BH/analyze_zip.py" "$ARGUMENTS" --out "$OUT" --clean 2>&1 | tail -2; echo; echo '===== BRIEF ====='; cat "$OUT/graphify-out/RESUMEN.md"`

Cómo leer el brief:
- **Choke points** = lo más valioso: un nodo por el que pasan N rutas ⇒ comprometerlo
  da Tier-0. Empezá por ahí, no por las cuentas sueltas.
- **Escaladas indirectas** ya vienen dedupeadas por vía compartida
  (`atacante → … → DOMAIN ADMINS`). Cada línea representa a N cuentas con la misma ruta.
- **Tier-0 directo** = higiene (cuentas que YA son DA/EA); mencionalo, no lo persigas
  como si fuera una ruta de escalada.
- **ADCS** (ESC1/2/3/7) y **Superficie** (kerberoast / AS-REP / unconstrained) son
  vectores paralelos — crúzalos con los choke points.

Para profundizar en un nodo, usá el CLI `graph_q.py` que quedó **junto al grafo**
(mismo dir del brief; tiene `--help`). NO abras los JSON crudos, NO adivines rutas:

```
Q="$HOME/pentest-data/current/graphify-out/graph_q.py"
python3 "$Q" --help
python3 "$Q" stats
# Usá los NOMBRES REALES tal como aparecen en el brief — graph_q traduce solo:
python3 "$Q" controllers "SRVR-CRONOS1A.DOMINIO.LOCAL"   # quién controla ese nodo
python3 "$Q" paths-to  "DOMAIN ADMINS@DOMINIO.LOCAL"     # quién llega y cómo
python3 "$Q" find-props hasspn=true                       # kerberoastables
python3 "$Q" by-relation Acl_Addkeycredentiallink         # Shadow Credentials
```

`graph_q.py` acepta el nombre real **o** el alias y devuelve nombres reales (usa el
`map.json` de al lado). Con `--anon` trabaja en aliases (para sacar el grafo fuera
del operador). `--graph`/`--map` ya apuntan por defecto a ese dir. Regla: no
inventes edges que no estén en el grafo.
