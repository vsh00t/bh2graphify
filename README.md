# bh2graphify — SharpHound + AzureHound → grafos LLM-native

Transforma colecciones JSON de SharpHound (BloodHound) y AzureHound en
`graph.json` compatible con graphify — plano, legible y apto para análisis
nativo por LLM — con pseudo-anonimización determinista y attack paths.

**100% Python stdlib. Sin dependencias. Sin LLM — parsing determinista.**
Requisito único: Python 3.8+. Portable: copiar la carpeta completa y correr.

## Inicio rápido (zip → análisis completo)

```bash
python3 analyze_zip.py <coleccion.zip> [--out DIR] [--max-hops 6]
```

Detecta el tipo por contenido (SharpHound / AzureHound / híbrido), extrae (con
guarda anti zip-bomb), parsea, verifica leaks y produce en `<out>/graphify-out/`:

- `RESUMEN.md` (600) — attack paths + ADCS (ESC1/2/3 + ESC7) + **correlación
  híbrida AD↔Entra**, con **nombres reales**
- `graph.json` / `graph_az.json` — grafo **anonimizado** (para LLM externo / reporte)
- `map.json` / `map_az.json` (600) — reversión (CONFIDENCIAL, no sale del operador)

Los JSON crudos extraídos (traen nombres reales) quedan en `chmod 600`; con
`--clean` se borran tras el análisis y solo queda `graphify-out/`.

Exit codes: `0` OK · `1` leak duro (revisar antes de usar el grafo) ·
`2` zip sin data reconocible.

## Componentes

| Archivo | Qué es |
|---|---|
| `analyze_zip.py` | Orquestador: zip → análisis automático |
| `bh2graphify.py` | Parser SharpHound v2/v3 → grafo (AD + ADCS) |
| `az2graphify.py` | Parser AzureHound unified → grafo (Entra + ARM RBAC) |
| `az_role_guids.json` | 312 GUIDs de roles ARM builtin (learn.microsoft.com) |
| `schema/graph.schema.json` | Contrato JSON Schema del `graph.json` (node-link) |
| `tests/sample_data/` | Dataset sintético inglés (2 cadenas plantadas) |
| `tests/synthetic_es/` | Suite español: `generar.py` (datasets on-demand) + `validar.py` (30 checks) |

## Uso individual

```bash
# SharpHound
python3 bh2graphify.py <dir_o_jsons> --out graph.json --save-map map.json \
    --attack-paths [--max-hops N] [--no-anon] [--drop-wellknown]

# AzureHound
python3 az2graphify.py azurehound.json --out graph.json --save-map map.json \
    --attack-paths [--max-hops N]
```

### Relations SharpHound (AD)
`MemberOf`, `AdminTo`, `CanRDP`, `CanPSRemote`, `CanDCOM`, `HasSession`,
`HasPrivSession`, ACLs (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`,
`Owns`, `ForceChangePassword`, `AllExtendedRights`, `AddMember`, `AddSelf`,
`ReadGMSAPassword`, `Acl_*`), `DCSync`/`GetChanges*`, delegación
(`AllowedToDelegate`, `AllowedToAct`/RBCD), `SPNTarget`, `HasSIDHistory`,
`Trusts`, `Contains`, `GpLink`, ADCS (`Enroll`, `AutoEnroll`, `EnabledTemplate`,
`HostsCA`, `WritePKI*`).

### Relations AzureHound (Entra + ARM)
`MemberOf`, `Owns` (owners de grupos/apps/SPs/devices), `HasRole` (roles Entra
incl. PIM), `AppRole` (consentimientos), `KVAccessPolicy`, RBAC ARM
(`Owner`, `Contributor`, `Reader`, `UserAccessAdmin`, `VMAdminLogin` y roles
resueltos por GUID; desconocidos → `RBAC_<guid8>`), jerarquía `Contains`
(MG→sub→RG→recursos), `HasManagedIdentity` (MSI de recursos).

### Attack paths (BFS inverso dirigido)
- BFS **inverso desde cada target** (grafo transpuesto): O(targets·(V+E)) en vez de
  un BFS por nodo. Los pasos del path se leen atacante→objetivo.
- AD: hacia Domain Admins / Enterprise Admins / ADMINISTRATOR / DCSync.
  Reversible solo `HasSession`/`HasPrivSession`. Incluye **ADCS**: quick wins de
  template (ESC1/ESC2/ESC3 con quién tiene Enroll) y control sobre la CA
  (ESC7 / takeover: `ManageCA`, `WriteDacl`, `Owns`…).
- AZ: hacia roles de alto valor (Global Administrator, Privileged Role
  Administrator, Application Administrator, Hybrid Identity Administrator...),
  subscriptions, management groups y Key Vaults.

### Vectores de control (edges BloodHound que el BFS no nombra por sí solo)
Basado en el [catálogo de edges de SpecterOps](https://bloodhound.specterops.io/resources/edges/overview);
el brief los computa a partir de los edges ya presentes en el grafo:
- **GPO abuse** — GPO controlado por no-admin → expande `GpLink`/`Contains` y
  cuenta los objetos afectados (+ flag `Enforced`).
- **Shadow Credentials** (`AddKeyCredentialLink`), **ESC4** (escritura sobre
  template), **LAPS** (`ReadLAPSPassword`), **RBCD**, **Kerberoast dirigido**
  (`WriteSPN`).
- **CoerceToTGT** (unconstrained no-DC), **GoldenCert** (AdminTo al host de la CA),
  **ESC9** (`nosecurityextension` + auth), **SpoofSIDHistory** (trust con SID
  filtering off).
- Pendiente por datos de colección: **ESC6/ESC8/ESC10/ESC13** (requieren flags de
  CA / web-enrollment / OID group links que SharpHound no siempre expone en el JSON).

### Híbrido (AD ↔ Entra)
Cuando el zip trae ambos planos, `analyze_zip` correlaciona identidades
sincronizadas por **SID on-prem** (`onPremisesSecurityIdentifier`, cruce fuerte)
o por **UPN** (heurístico), y detecta dominios compartidos AD↔tenant. Se reporta
en `RESUMEN.md` como hallazgo `INFERRED` (no se fabrican edges en el grafo; el
SID on-prem nunca se emite al grafo anonimizado).

## Anonimización

- Alias por categoría: `USER_0001`, `GROUP_0002`, `COMP_0003.DOM_01`,
  `DC_01.DOM_01`, `APP_0001`, `SP_0002`, `KV_0001`, `SUB_0001`...
- Well-known SIDs/RIDs preservados (estructurales, no PII); multi-dominio
  cualifica: `DOMAIN_ADMINS@DOM_01`
- Roles Entra builtin y roles ARM preservados por nombre (estructurales)
- Props whitelist técnica; PII dropeada; scrub case-insensitive longest-first
- Leak-check **hard/soft** post-build con normalización de diacríticos
  (español: á→a, ñ→n); nombres multi-palabra → soft match informativo
- Sin `--save-map` la anonimización es irreversible por diseño

## Validación

```bash
python3 tests/synthetic_es/validar.py     # 30 checks, exit 0 = verde
```

La suite es **hermética**: genera los datasets en un tmpdir (no versiona nada;
`python3 tests/synthetic_es/generar.py` los escribe en disco para inspección).
CI en GitHub Actions corre esto en Python 3.8–3.13 (`.github/workflows/ci.yml`).

Cobertura: separadores (puntos, guiones, espacios, apóstrofes), ñ/acentos/
¿?/Nº/em-dash, dominios con guion, colisiones con schema/roles (user
"target", "Global Administrator", template "Administrator"), Sessions
`Collected:false`, SIDs con prefijo de dominio, appId fantasma, grupos
dinámicos, trusts a dominios no recolectados. **Regresiones nuevas:** GPOChanges
respeta `AffectedComputers` (sin fan-out) y no cruza dominios, clave
`RemoteDesktopUsers`, RIDs Key Admins (526/527), ESC3/ESC7, orden natural del
path (reverse-BFS), merge AZ multi-archivo, correlación híbrida por SID on-prem.

Validado además con: lab ADCS real 3 dominios (31 JSON SH v3, 1450 nodos /
10956 links) y lab Entra real (29800 entradas, 12947 nodos).

## Notas de diseño (lecciones de datos reales)

- Colecciones SH v3 envueltas: `Sessions`/`LocalGroups`/`UserRights` llegan como
  `{Collected, FailureReason, Results}` — iterar `Results`
- SIDs con prefijo de dominio (`DOM-S-1-5-32-544`) → strip antes de matchear
- Well-known RID table verificada (555 ≠ 556)
- Perf: scrub con **Aho-Corasick** O(len) por string + memoización (el mega-regex
  de alternancias es O(nº patrones)/string y colgaba ~30 s en un dominio real de
  3.5K nodos / 65K edges; ahora <2 s, salida byte-idéntica verificada)
- Semántica: `Contains`/`GpLink` NO son control (no reversibles en paths)
- `GPOChanges`: usar `AffectedComputers` (verdad de campo SH v3). Sin ella,
  restringir al MISMO dominio — nunca fan-out a todo el grafo (fabrica AdminTo
  cross-domain). Clave real `RemoteDesktopUsers` (no `RDPUsers`)

## Licencia

**Pendiente de decidir por el propietario.** El repo aún no declara licencia
(sin `LICENSE`); `pyproject.toml` tampoco fija `license`. Sin una licencia
explícita, por defecto **no** hay permiso de uso/redistribución para terceros.
Definir una (MIT/Apache-2.0/GPL-3.0/propietaria) antes de publicar.
