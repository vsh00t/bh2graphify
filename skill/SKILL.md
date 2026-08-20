---
name: graph-pentest-analysis
description: >
  Análisis ofensivo de grafos AD/Entra ya transformados por bh2graphify
  (graph.json, schema graphify node-link). El modelo razona directamente sobre
  el JSON con graph_q.py: attack paths adicionales a los del RESUMEN automático,
  abuso de ACLs, delegación (unconstrained/RBCD), sesiones como captura de
  credenciales, ADCS ESC1-8 (más allá de quickwins), dueños no-admin de apps
  privilegiadas, cadenas MSI Contributor→identidad, escaladas UserAccessAdmin,
  grupos dinámicos manipulables, correlación de identidades. Produce findings
  tipificados con severidad, precondición, evidencia y remediación.
  Triggers — analizar graph.json, análisis de grafo AD, attack paths
  bloodhound sin neo4j, hallazgos desde colección sharphound/azurehound,
  ESC1 ESC4 ESC7, escalada de privilegios AD/Entra sobre grafo.
---

# Graph Pentest Analysis — razonamiento ofensivo sobre graph.json

Eres el analista. Recibes la salida de `bh2graphify`/`analyze_zip.py` y debes
producir hallazgos priorizados. El parsing ya está hecho — tu valor es la
**correlación y el razonamiento que el BFS automático no hace**.

## Input contract

- `graph.json` (o `graph_az.json`) — grafo ANONIMIZADO, schema node-link.
  Nodos `{id, label, type, ...props}`, links `{source, target, relation, ...}`.
  Aliases: `USER_NNNN`, `GROUP_NNNN`, `COMP_NNNN.DOM_NN`, `SP_NNNN`, `KV_NNNN`.
  Well-known preservados: `ADMINISTRATOR`, `DOMAIN_ADMINS@DOM_01`,
  `AUTHENTICATED_USERS`, `Global Administrator` (roles builtin legibles).
- `RESUMEN.md` — hallazgos AUTOMÁTICOS ya generados (top attack paths + ESC
  quickwins). **No los repitas: profundízalos** (validar precondiciones,
  buscar variantes, encadenarlos).
- `map.json` (opcional, CONFIDENCIAL) — reversión alias→real. **Solo se usa al
  final, para el reporte del operador.** El análisis razona sobre aliases.

## Setup

```python
import sys; sys.path.insert(0, "<dir de este skill>/scripts")  # o skill/ según plataforma
from graph_q import GraphQ
g = GraphQ("<path>/graph.json", map_path="<path>/map.json")
g.stats()                       # inventario: tipos, relations top
```

Si `graph_q.py` no está disponible, fallback mínimo:

```python
import json
G = json.load(open("graph.json"))
N = {n["id"]: n for n in G["nodes"]}
IN = {}   # target -> [(source, rel)]
for lk in G["links"]: IN.setdefault(lk["target"], []).append((lk["source"], lk["relation"]))
```

## Semántica del grafo (no negociable)

- `MemberOf`, `AdminTo`, ACLs (`GenericAll/WriteDacl/WriteOwner/Owns/...`),
  `HasRole`, `Owner`, `Contributor`, `Enroll`: **control dirigido** src→target
- `HasSession`/`HasPrivSession`: user con sesión en computer = quien comprometa
  el computer captura las creds del user (edge reversible en ataque)
- `Contains`, `GpLink`: placement, **NO control** — nunca fabricar paths con ellos
- `Trusts`: superficie cross-dominio (revisar `sidfiltering: false` en props del
  link = trust explotable con SID History)
- ACEs con `is_inherited: true` son heredadas — el hallazgo es más débil y el
  corte es en el ancestro, no en el objeto

## Metodología AD (sweeps en orden)

### 1. Validar y profundizar los paths del RESUMEN
```python
g.paths_to("DOMAIN_ADMINS@DOM_01")            # todos los starts, no solo top
g.controllers("GROUP_NNNN")                   # quién más controla cada eslabón
```
Buscar: eslabones alternativos (2+ vías al mismo target = hallazgo más robusto),
y si el path termina en un DC (`DC_NN.DOM_NN`): AdminTo DC = DCSync directo.

### 2. Targets de alto valor no cubiertos por el BFS automático
```python
g.search("KRBTGT")                            # control de KRBTGT = Golden ticket
g.search("DCSYNC", type_="group")             # (nombres preservados si aplican)
for dc in g.search("DC_", type_="computer"):
    print(dc["id"], g.controllers(dc["id"]))
```

### 3. Delegación
```python
g.find_props(unconstraineddelegation=True)    # comprometer el host = cualquier
                                               # user que se autenticó = DCSync
g.by_relation("AllowedToDelegate")            # constrained: revisar SPN target
g.by_relation("AllowedToAct")                 # RBCD: quién puede escribir
                                               # msDS-AllowedToActOnBehalfOf...
```

### 4. Sesiones = matriz de captura de credenciales
```python
for lk in g.by_relation("HasPrivSession"):     # sesiones privilegiadas primero
    print(lk["source"], "→", lk["target"])
```
Cruzar: si un start de attack path tiene `HasPrivSession` en un host que OTRO
start controla con AdminTo → cadena compuesta que el BFS por-target no mostró.

### 5. ADCS más allá de quickwins (ESC4/ESC7/ESC8)
```python
# ESC4: control de ESCRITURA sobre el template (no solo Enroll)
for t in [n for n in g.search("", type_="certtemplate")]:
    ctrl = [c for c in g.controllers(t["id"]) if c[1] in
            ("GenericAll", "WriteDacl", "WriteOwner", "Owns", "GenericWrite")]
    if ctrl: print("ESC4:", t["id"], ctrl)
# ESC7: ManageCA / ManageCertificates sobre la CA
g.by_relation("Acl_Manageca"); g.by_relation("Acl_Managecertificates")
# EnabledTemplate + HostsCA: qué CAs sirven qué templates (impacto por CA)
g.by_relation("EnabledTemplate")
```

### 6. Kerberoast / ASREP / GMSA / LAPS
```python
g.find_props(hasspn=True)                     # kerberoastables (con sesiones = jackpot)
g.find_props(dontreqpreauth=True)             # AS-REP roastable
g.by_relation("ReadGMSAPassword")
g.by_relation("Acl_Readlapspassword")
```

## Metodología AZ

### 1. Holders de roles y sus debilidades
```python
g.paths_to("Global Administrator")
g.paths_to("Privileged Role Administrator")    # quien lo tiene, se da cualquier rol
g.paths_to("Hybrid Identity Administrator")    # controla Entra Connect → on-prem
g.by_relation("HasRole")                       # inventario completo por rol
```

### 2. Apps/SPs: el plano que CA no protege
```python
for lk in g.by_relation("Owns"):               # Owns con target APP/SP
    if g.node_type.get(lk["target"]) in ("app", "sp"):
        print(lk["source"], "→", lk["target"])
```
Owner no-admin de app con `AppRole` privilegiada = consent/credential path.
`g.find_props(haspwdcreds=True, haskeycreds=True)` en SPs = credenciales
activas expuestas.

### 3. Cadenas MSI (Contributor → identidad → permisos)
```python
for lk in g.by_relation("HasManagedIdentity"):
    msi = lk["target"]                          # SP de la identidad
    for other, rel, rev, p in g.neighbors(msi): # qué controla ese SP
        print(msi, rel, other)
```
Contributor/Owner sobre un recurso CON MSI + ese SP con roles útiles = pivote.

### 4. Escaladas ARM
```python
g.by_relation("UserAccessAdmin")              # puede otorgarse cualquier rol en scope
for kv in g.search("KV_", type_="kv"):
    print(kv["id"], g.controllers(kv["id"]))  # Owner/Contributor/KVAccessPolicy
g.find_props(dynamic=True)                    # grupos dinámicos: revisar si la regla
                                               # es manipulable (props de user editables)
```

### 5. Correlación humana
Un mismo `USER_NNNN` con Owns sobre 5 SPs + Owner de un RG + miembro de grupo
dinámico = superusuario de facto sin rol visible. El BFS no lo encuentra —
tú sí:
```python
from collections import Counter
c = Counter(lk["source"] for lk in G["links"]
            if lk["relation"] in ("Owns", "Owner"))
c.most_common(10)
```

## Híbrido (si hay graph.json + graph_az.json)

Cruzar nombres de dominio del tenant AZ (`tenant_domains`) con domains del grafo
AD. Si coinciden: holders de `Directory Synchronization Accounts`, VMs con
nombre de DC en AZ, `Hybrid Identity Administrator` → cadena cloud→on-prem.
Documentar como attack path compuesto aunque no haya edges directos.

## Formato de salida (cada finding)

```
### [SEVERIDAD] AZ-IAM-XX / AD-XXX — título corto
- **Path:** A -[Rel]-> B -[Rel]-> C  (aliases; de-anon al final con map si piden)
- **Precondición:** qué necesita el atacante (ej. "compromiso de USER_0031",
  "sesión válida sin MFA")
- **Evidencia:** la query y su output (reproducible)
- **Impacto:** qué gana el atacante en términos de negocio
- **Remediación:** corte más barato del path (el eslabón más temprano/modificable)
- **Detección:** qué vería el SOC (log/source) si se explota
```

Severidades de referencia — Crítico: path a DA/GA/PRA, ESC1 con Enroll masivo,
KRBTGT control. Alto: ESC4/ESC7, UserAccessAdmin, unconstrained delegation,
Owner de app privilegiada, sin-MFA en admins (cruzar si hay data). Medio:
dynamic group manipulable, RBCD, kerberoastables con sesiones privilegiadas.
Bajo: higiene (SPs con creds viejas, LAPS off).

## Reglas

1. **No inventar edges**: si el path requiere un salto que no está en `links`,
   no es un hallazgo — es una hipótesis (márkala como tal).
2. Análisis sobre aliases; `deanon()` SOLO para el reporte final del operador.
3. Todo hallazgo lleva evidencia = query reproducible, no descripción narrativa.
4. Dedup: el mismo eslabón raíz en N paths = UN hallazgo con N vías.
5. `Contains`/`GpLink` nunca cuentan como paso de ataque.
6. Si el grafo viene de `--no-anon` (no anonymized), NO sacarlo de la máquina
   del operador y omitir la fase de de-anon.
