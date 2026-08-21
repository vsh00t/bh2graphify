# Integración con opencode

Dota a cualquier agente de opencode de una forma **rápida y determinista** de
procesar dumps de BloodHound: el trabajo pesado lo hace `bh2graphify` (2 s), el
modelo solo razona sobre un brief de ~5 KB. Así el agente no se pone a parsear los
JSON crudos (lento, errático, cuelgues).

## Qué hay acá

| Archivo | Qué es |
|---|---|
| `commands/analyze-bh.md` | Command `/analyze-bh <zip>`: corre `analyze_zip.py` e inyecta el brief en el prompt |
| `AGENTS.md` | Regla para el workspace: dumps de BloodHound → `/analyze-bh`, nunca parsear a mano |

## Instalación

Asumiendo el repo en `~/Desktop/bh2graphify` (si está en otro lado, exportá
`BH2GRAPHIFY=/ruta/al/repo` en tu entorno, o editá esa variable en el command).

**Command (global, para todos los engagements):**

```bash
mkdir -p ~/.config/opencode/commands && cp ~/Desktop/bh2graphify/integrations/opencode/commands/analyze-bh.md ~/.config/opencode/commands/
```

**AGENTS.md (en el workspace donde trabajás los dumps):**

```bash
cp ~/Desktop/bh2graphify/integrations/opencode/AGENTS.md /ruta/a/tu/workspace/AGENTS.md
```

> Nota: la doc de opencode usa `commands/` (plural). Si tu versión escanea
> `command/` (singular), copiá el `.md` ahí en su lugar.

## Uso

```
/analyze-bh coleccion_bloodhound.zip
```

El agente recibe el brief (attack paths + choke points + ADCS + superficie) ya
masticado y responde/priorizando sobre eso. Para profundizar en un nodo puntual usa
`graph_q.py` sobre `~/pentest-data/current/graphify-out/graph.json` — nunca los JSON
crudos.
