# Reglas del workspace — análisis de dumps de BloodHound

Cuando el usuario pida analizar un dump de BloodHound / SharpHound / AzureHound
(un `.zip`, o archivos `*_users.json`, `*_computers.json`, `azurehound.json`):

- **NO** parsees los JSON crudos con Python a mano, **NO** los cargues en contexto,
  **NO** los leas archivo por archivo. Son megabytes y te vas a equivocar (y colgar).
- **SÍ** ejecutá el command `/analyze-bh <ruta-del-zip>`. En 2 s produce un brief con
  attack paths, choke points, ADCS y superficie (el command ya sabe dónde está el repo).
- Razoná sobre el **brief** (`~/pentest-data/current/graphify-out/RESUMEN.md`), no sobre
  el dump. Para consultas puntuales corré el CLI que queda junto al grafo:
  `python3 ~/pentest-data/current/graphify-out/graph_q.py --help` (subcomandos: `stats`,
  `controllers`, `paths-to`, `find-props`, `by-relation`…). Nunca abras los JSON crudos.

El trabajo pesado y determinista lo hace `bh2graphify`. Tu trabajo es razonar sobre
el resultado, no recalcularlo.
