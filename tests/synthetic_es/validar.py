#!/usr/bin/env python3
"""
validar.py — Suite de regression con data sintética en ESPAÑOL.

Corre bh2graphify (ds1-ds3) y az2graphify (ds4-ds5) en dos modos por dataset:
  1. --no-anon  → verifica CADENAS DE ATAQUE PLANTADAS (el análisis funciona)
  2. anon       → verifica leak-check limpio, soft matches y no-crash

Exit 0 = todo PASS. Exit 1 = al menos un FAIL.
"""
import json
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).parent.parent.parent   # ~/tools/bh2graphify
sys.path.insert(0, str(HERE))

import bh2graphify as bh                      # noqa: E402
import az2graphify as az                      # noqa: E402

SYN = Path(__file__).parent
RESULTS = []


def check(case: str, name: str, fn):
    try:
        ok, detail = fn()
    except Exception:
        ok, detail = False, traceback.format_exc(limit=2)
    RESULTS.append((case, name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + ("" if ok else f"\n         → {detail}"))
    return ok


# ── runners ─────────────────────────────────────────────────────────────────
def run_bh(d: Path):
    g = bh.BHGraph()
    for f in sorted(d.glob("*.json")):
        g.parse_file(f)
    plain = bh.build_graph(g, None)
    paths = bh.attack_paths(plain, 6, top=50)
    anon = bh.Anonymizer()
    agr = bh.build_graph(g, anon)
    leaks, soft = bh.leakage_check(agr, anon.map)
    return plain, paths, agr, leaks, soft


def run_az(f: Path):
    g = az.AZGraph()
    g.parse(f)
    plain = az.build_graph(g, None)
    paths = az.attack_paths(plain, 5, top=50)
    anon = az.AZAnonymizer()
    agr = az.build_graph(g, anon)
    leaks, soft = az.leakage_check(agr, anon.map)
    return plain, paths, agr, leaks, soft, g


def has_edge(graph, rel, src_sub=None, dst_sub=None):
    for lk in graph["links"]:
        if lk["relation"] != rel:
            continue
        if src_sub and src_sub.upper() not in lk["source"].upper():
            continue
        if dst_sub and dst_sub.upper() not in lk["target"].upper():
            continue
        return True
    return False


def path_hit(paths, frm, *rels, target=None):
    for r in paths:
        if frm.upper() not in r["from"].upper():
            continue
        if target and target.upper() not in r["target"].upper():
            continue
        if all(rel in r["path"] for rel in rels):
            return r
    return None


# ── casos ───────────────────────────────────────────────────────────────────
def caso_ds1():
    print("\n== DS1 corp-hispana (puntos/guiones bajos, Sessions Collected:false) ==")
    plain, paths, agr, leaks, soft = run_bh(SYN / "ds1_corp_hispana")

    def e1():
        # target válido A: DC01 con DCSync rights (2h — el DC ES el objetivo)
        # target válido B: domain obj (4h — path completo con GetChangesAll)
        r = path_hit(paths, "soporte.nomina", "WriteDacl", "AdminTo", target="DC01") \
            or path_hit(paths, "soporte.nomina", "WriteDacl", "AdminTo", "GetChangesAll",
                        target="EMPRESA.COM.EC")
        return (bool(r), f"recuperado: {r['path'][:120]}" if r else
                "cadena WriteDacl→AdminTo→DC→GetChangesAll NO recuperada")
    check("ds1", "cadena plantada soporte.nomina → DCSync (DC o dominio)", e1)

    def e2():
        return has_edge(plain, "HasSession", "jimenez", "srv-contabilidad"), "—"
    check("ds1", "edge HasSession desde Sessions.Results", e2)

    def e3():
        return (leaks == [], f"leaks={leaks[:5]}")
    check("ds1", "leak-check anon limpio (descripción con nombre real)", e3)


def caso_ds2():
    print("\n== DS2 financiera (espacios/apóstrofes, ñ, HasSession reversible, ESC1) ==")
    plain, paths, agr, leaks, soft = run_bh(SYN / "ds2_financiera")

    def e1():
        r = path_hit(paths, "auditor.interno", "AdminTo", "HasPrivSession↩", "MemberOf",
                     target="DOMAIN ADMINS")
        return (bool(r), f"recuperado: {r['path'][:130]}" if r else
                "cadena AdminTo→HasPrivSession↩→MemberOf→DA NO recuperada")
    check("ds2", "cadena reversible HasPrivSession → DOMAIN ADMINS", e1)

    def e2():
        # quickwins sobre el grafo ANON: los well-known tienen su alias ahí, y
        # el template es TPL_NNNN (no su nombre real)
        wins = bh.adcs_quickwins(agr)
        q = next((w for w in wins
                  if any("AUTHENTICATED_USERS" in x for x in w["enroll"] + w["wk_enroll"])), None)
        ok = q is not None and "ESC1" in q["esc"]
        return ok, f"quickwins={[(w['esc'], w['wk_enroll']) for w in wins]}"
    check("ds2", "ADCS quickwin ESC1 con Enroll AUTHENTICATED_USERS", e2)

    def e3():
        return has_edge(plain, "HasPrivSession", "director financiero",
                        "servidor auditoría"), "—"
    check("ds2", "edge HasPrivSession (nombres con espacios/acentos)", e3)

    def e4():
        return (leaks == [], f"leaks={leaks[:5]}")
    check("ds2", "leak-check anon limpio (ñ y apóstrofes)", e4)


def caso_ds3():
    print("\n== DS3 sector-público (¿?, Nº, em-dash, colisiones target/user/Administrator) ==")
    plain, paths, agr, leaks, soft = run_bh(SYN / "ds3_sector_publico")

    def e1():
        r = path_hit(paths, "niño.perez", "MemberOf", "AddMember", target="DOMAIN ADMINS")
        return (bool(r), f"recuperado: {r['path'][:120]}" if r else "cadena NO recuperada")
    check("ds3", "cadena MemberOf→AddMember→DOMAIN ADMINS", e1)

    def e2():
        return (leaks == [], f"leaks={leaks[:5]} — colisiones esperadas ignoradas")
    check("ds3", "leak-check limpio pese a colisiones (TARGET/USER/template Administrator)", e2)

    def e3():
        return any(n["type"] == "domain" and "SOCIEDAD-EXTERNA" in n["id"]
                   for n in plain["nodes"]), "—"
    check("ds3", "trust a dominio no recolectado → nodo domain fantasma", e3)

    def e4():
        return has_edge(plain, "GenericAll") and \
               any("SERVIDOR Nº7" in n["id"] or "SERVIDOR Nº7" in n.get("label", "")
                   for n in plain["nodes"]), "—"
    check("ds3", "ACE con SID prefijo-dominio y computer 'SERVIDOR Nº7 — CONTABILIDAD'", e4)


def caso_ds4():
    print("\n== DS4 AZ corporativo (español, dynamic group, MSI, KeyVault, MG→sub→RG) ==")
    plain, paths, agr, leaks, soft, g = run_az(SYN / "ds4_az_corporativo" / "azurehound.json")

    def e1():
        r = path_hit(paths, "Ana lucía", "MemberOf", "HasRole", target="Global Administrator")
        return (bool(r), f"recuperado: {r['from']} → {r['target']}" if r else
                "cadena user→grupo→Global Administrator NO recuperada")
    check("ds4", "cadena Ana lucía Torres → Equipo de Dirección → Global Administrator", e1)

    def e2():
        r = path_hit(paths, "María José", "Owner", target="Suscripción Producción")
        return (bool(r) and r["hops"] == 1, f"r={r}")
    check("ds4", "cadena María José Gómez -Owner→ Suscripción Producción (1h)", e2)

    def e3():
        return has_edge(plain, "KVAccessPolicy", "pérez", "bóveda"), "—"
    check("ds4", "KeyVault access policy (acentos en ambos extremos)", e3)

    def e4():
        return (leaks == [], f"leaks={leaks[:5]} soft={soft[:5]}")
    check("ds4", "leak-check anon limpio (nombres multi-palabra ES)", e4)

    def e5():
        dyn = [n for n in agr["nodes"] if n.get("dynamic")]
        return (len(dyn) >= 1, f"dynamic={len(dyn)}")
    check("ds4", "grupo dinámico 'Administradores de TI' marcado", e5)


def caso_ds5():
    print("\n== DS5 AZ edge (user 'Global Administrator', 'USER 001', appId fantasma) ==")
    plain, paths, agr, leaks, soft, g = run_az(SYN / "ds5_az_edge" / "azurehound.json")

    def e1():
        r = path_hit(paths, "Sincronizador", "HasRole", target="Privileged Role Administrator")
        return (bool(r), f"r={r}")
    check("ds5", "cadena SP con credenciales → Privileged Role Administrator", e1)

    def e2():
        return (g.unresolved.get("appOwner", 0) == 1, f"unresolved={dict(g.unresolved)}")
    check("ds5", "appId fantasma → unresolved (no crash)", e2)

    def e3():
        return (leaks == [], f"leaks={leaks[:5]}")
    check("ds5", "leak-check limpio pese a colisiones (USER 001 / Global Administrator)", e3)

    def e4():
        customs = [(m["alias"], m["real"]) for m in az_anon_map(g).values()
                   if m.get("kind") == "role"]
        ok = any("Rol Interno de Auditoría" == r for _, r in customs)
        return ok, f"custom roles={customs}"
    check("ds5", "rol custom ES anonimizado (no preservado)", e4)

    def e5():
        return has_edge(plain, "Contributor", "Sincronizador", "Backdoor"), "—"
    check("ds5", "RBAC Contributor resuelto por GUID → FunctionApp", e5)


# helper para ds5 e4: reconstruir el map (el runner no lo devuelve)
_anon_map_cache = {}
def az_anon_map(g):
    key = id(g)
    if key not in _anon_map_cache:
        anon = az.AZAnonymizer()
        az.build_graph(g, anon)
        _anon_map_cache[key] = anon.map
    return _anon_map_cache[key]


if __name__ == "__main__":
    print("[*] Suite sintética ES — bh2graphify + az2graphify")
    print("[*] Generando datasets…")
    sys.path.insert(0, str(SYN))
    from generar import ds1, ds2, ds3, ds4, ds5
    ds1(); ds2(); ds3(); ds4(); ds5()

    for fn in (caso_ds1, caso_ds2, caso_ds3, caso_ds4, caso_ds5):
        fn()

    npass = sum(1 for *_, ok, _ in RESULTS if ok)
    print(f"\n[*] RESULTADO: {npass}/{len(RESULTS)} PASS")
    if npass != len(RESULTS):
        for case, name, ok, det in RESULTS:
            if not ok:
                print(f"  FAIL {case}: {name}")
        sys.exit(1)
    print("[+] TODO VERDE")
