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

Detecta el tipo por contenido (SharpHound / AzureHound / híbrido), extrae,
parsea, verifica leaks y produce en `<out>/graphify-out/`:

- `RESUMEN.md` (600) — attack paths + ADCS quickwins con **nombres reales**
- `graph.json` — grafo **anonimizado** (para LLM externo / reporte)
- `map.json` (600) — reversión (CONFIDENCIAL, no sale del operador)

Exit codes: `0` OK · `1` leak duro (revisar antes de usar el grafo) ·
`2` zip sin data reconocible.

## Componentes

| Archivo | Qué es |
|---|---|
| `analyze_zip.py` | Orquestador: zip → análisis automático |
| `bh2graphify.py` | Parser SharpHound v2/v3 → grafo (AD + ADCS) |
| `az2graphify.py` | Parser AzureHound unified → grafo (Entra + ARM RBAC) |
| `az_role_guids.json` | 312 GUIDs de roles ARM builtin (learn.microsoft.com) |
| `tests/sample_data/` | Dataset sintético inglés (2 cadenas plantadas) |
| `tests/synthetic_es/` | Suite español: 5 datasets + `validar.py` (21 checks) |

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

### Attack paths (BFS dirigido)
- AD: hacia Domain Admins / Enterprise Admins / ADMINISTRATOR / DCSync.
  Reversible solo `HasSession`/`HasPrivSession`. Incluye **ADCS quick wins**
  (templates ESC1/ESC2 con quién tiene Enroll).
- AZ: hacia roles de alto valor (Global Administrator, Privileged Role
  Administrator, Application Administrator, Hybrid Identity Administrator...),
  subscriptions, management groups y Key Vaults.

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
python3 tests/synthetic_es/validar.py     # 21 checks, exit 0 = verde
```

Cobertura: separadores (puntos, guiones, espacios, apóstrofes), ñ/acentos/
¿?/Nº/em-dash, dominios con guion, colisiones con schema/roles (user
"target", "Global Administrator", template "Administrator"), Sessions
`Collected:false`, SIDs con prefijo de dominio, appId fantasma, grupos
dinámicos, trusts a dominios no recolectados.

Validado además con: lab ADCS real 3 dominios (31 JSON SH v3, 1450 nodos /
10956 links) y lab Entra real (29800 entradas, 12947 nodos).

## Notas de diseño (lecciones de datos reales)

- Colecciones SH v3 envueltas: `Sessions`/`LocalGroups`/`UserRights` llegan como
  `{Collected, FailureReason, Results}` — iterar `Results`
- SIDs con prefijo de dominio (`DOM-S-1-5-32-544`) → strip antes de matchear
- Well-known RID table verificada (555 ≠ 556)
- Perf: scrub con regex alternante único precompilado (~300x vs re.sub por
  entrada) — 13K nodos en segundos
- Semántica: `Contains`/`GpLink` NO son control (no reversibles en paths)
