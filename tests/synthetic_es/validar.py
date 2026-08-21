#!/usr/bin/env python3
"""
validar.py — Suite de regression con data sintética en ESPAÑOL.

Corre bh2graphify (ds1-ds3) y az2graphify (ds4-ds5) en dos modos por dataset:
  1. --no-anon  → verifica CADENAS DE ATAQUE PLANTADAS (el análisis funciona)
  2. anon       → verifica leak-check limpio, soft matches y no-crash

Exit 0 = todo PASS. Exit 1 = al menos un FAIL.
"""
import json
import os
import sys
import tempfile
import traceback
from pathlib import Path

HERE = Path(__file__).parent.parent.parent   # ~/tools/bh2graphify
sys.path.insert(0, str(HERE))

import bh2graphify as bh                      # noqa: E402
import az2graphify as az                      # noqa: E402

# Suite hermética: los datasets se generan en un tmpdir (no se toca nada
# versionado). Fijar la env var ANTES de importar/usar generar.py.
os.environ.setdefault("BH2G_SYNTH_OUT", tempfile.mkdtemp(prefix="bh2g_synth_"))
SYN = Path(os.environ["BH2G_SYNTH_OUT"])
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


def caso_mejoras():
    print("\n== MEJORAS (GPO scoping, RIDs, ESC3/ESC7, reverse-BFS, híbrido) ==")
    import analyze_zip as azip

    def e_gpo_affected():
        # GPOChanges con AffectedComputers → AdminTo SOLO al equipo afectado
        DOM = "S-1-5-21-10-20-30"
        g = bh.BHGraph()
        g.add_node(f"{DOM}-1000", "computer", "PC-AFECTADO")
        g.add_node(f"{DOM}-2000", "computer", "PC-OTRO")
        g._parse_domain({"ObjectIdentifier": DOM, "Properties": {"name": "A.LOCAL"},
            "GPOChanges": {"LocalAdmins": [{"ObjectIdentifier": f"{DOM}-1101", "ObjectType": "User"}],
                           "AffectedComputers": [{"ObjectIdentifier": f"{DOM}-1000", "ObjectType": "Computer"}]}}, "domain")
        adm = [(e["src"], e["dst"]) for e in g.edges if e["rel"] == "AdminTo"]
        return (adm == [(f"{DOM}-1101", f"{DOM}-1000")],
                f"AdminTo={adm} (debe ir solo a PC-AFECTADO)")
    check("mej", "GPOChanges respeta AffectedComputers (no fan-out)", e_gpo_affected)

    def e_gpo_xdom():
        # domain-level sin AffectedComputers NO debe cruzar dominios
        DA, DB = "S-1-5-21-1-2-3", "S-1-5-21-9-9-9"
        g = bh.BHGraph()
        g.add_node(f"{DA}-1000", "computer", "PC-A")
        g.add_node(f"{DB}-1000", "computer", "PC-B")
        g._parse_domain({"ObjectIdentifier": DA, "Properties": {"name": "A.LOCAL"},
            "GPOChanges": {"LocalAdmins": [{"ObjectIdentifier": f"{DA}-1101", "ObjectType": "User"}]}}, "domain")
        dsts = {e["dst"] for e in g.edges if e["rel"] == "AdminTo"}
        return (dsts == {f"{DA}-1000"}, f"AdminTo dsts={dsts} (nunca PC-B de dom B)")
    check("mej", "GPOChanges domain-level no cruza dominios", e_gpo_xdom)

    def e_gpo_rdp():
        # clave real de SharpHound: RemoteDesktopUsers (no 'RDPUsers') → CanRDP
        DOM = "S-1-5-21-5-5-5"
        g = bh.BHGraph()
        g.add_node(f"{DOM}-1000", "computer", "PC")
        g._parse_domain({"ObjectIdentifier": DOM, "Properties": {"name": "R.LOCAL"},
            "GPOChanges": {"RemoteDesktopUsers": [{"ObjectIdentifier": f"{DOM}-1200", "ObjectType": "User"}],
                           "AffectedComputers": [{"ObjectIdentifier": f"{DOM}-1000", "ObjectType": "Computer"}]}}, "domain")
        return (any(e["rel"] == "CanRDP" for e in g.edges),
                f"rels={[e['rel'] for e in g.edges]}")
    check("mej", "GPOChanges reconoce RemoteDesktopUsers → CanRDP", e_gpo_rdp)

    def e_rids():
        anon = bh.Anonymizer()
        S = "S-1-5-21-1-2-3-"
        a526 = anon.alias(S + "526", "group", "KEY ADMINS")
        a527 = anon.alias(S + "527", "group", "ENTERPRISE KEY ADMINS")
        return (a526 == "KEY_ADMINS" and a527 == "ENTERPRISE_KEY_ADMINS",
                f"526→{a526} 527→{a527}")
    check("mej", "RIDs well-known nuevos (Key Admins 526/527) preservados", e_rids)

    def e_esc3():
        gr = {"nodes": [{"id": "TPL_X", "type": "certtemplate",
                         "ekus": ["Certificate Request Agent"], "requiresmanagerapproval": False}],
              "links": [{"source": "USER_1", "target": "TPL_X", "relation": "Enroll"}]}
        wins = bh.adcs_quickwins(gr)
        return (any("ESC3" in w["esc"] for w in wins), f"wins={wins}")
    check("mej", "ADCS ESC3 (Certificate Request Agent) detectado", e_esc3)

    def e_esc7():
        gr = {"nodes": [{"id": "ECA_1", "type": "enterpriseca"}],
              "links": [{"source": "USER_9", "target": "ECA_1", "relation": "Acl_Manageca"}]}
        f = bh.adcs_ca_findings(gr)
        return (bool(f) and f[0]["controllers"][0]["esc"] == "ESC7", f"ca_findings={f}")
    check("mej", "ADCS ESC7 (ManageCA sobre la CA) detectado", e_esc7)

    def e_path_order():
        # el path debe leerse atacante→objetivo (start primero)
        plain, paths, *_ = run_bh(SYN / "ds1_corp_hispana")
        r = path_hit(paths, "soporte.nomina", "WriteDacl")
        first = r["path"].split(" | ")[0] if r else ""
        return ("SOPORTE.NOMINA" in first.split(" -[")[0].upper(),
                f"primer paso: {first}")
    check("mej", "reverse-BFS: path en orden natural (start primero)", e_path_order)

    def e_az_merge():
        # parse_many une 2 archivos: nodo en uno, edge en otro
        import tempfile as _t
        d = Path(_t.mkdtemp())
        (d / "a.json").write_text(json.dumps({"data": [
            {"kind": "AZUser", "data": {"id": "u1", "displayName": "Alpha"}},
            {"kind": "AZRole", "data": {"id": "r1", "displayName": "Global Administrator", "isBuiltIn": True}}]}))
        (d / "b.json").write_text(json.dumps({"data": [
            {"kind": "AZRoleAssignment", "data": {"roleAssignments": [
                {"id": "ra", "roleDefinitionId": "r1", "principalId": "u1", "directoryScopeId": "/"}]}}]}))
        g = az.AZGraph()
        g.parse_many([d / "a.json", d / "b.json"])
        return (any(e["rel"] == "HasRole" and e["src"] == "u1" for e in g.edges),
                f"edges={[(e['src'], e['rel'], e['dst']) for e in g.edges]}")
    check("mej", "AZ merge multi-archivo (edge cruza archivos)", e_az_merge)

    def e_hybrid():
        # correlación por SID on-prem
        bg = bh.BHGraph()
        SID = "S-1-5-21-7-7-7-1104"
        bg.add_node("S-1-5-21-7-7-7", "domain", "corp.local")
        bg.add_node(SID, "user", "JSMITH@CORP.LOCAL")
        ag = az.AZGraph()
        ag.tenant_domains = {"corp.local"}
        ag.nodes["az1"] = {"kind": "user", "name": "John Smith", "props": {}}
        ag.hybrid["az1"] = {"onprem_sid": SID, "upn": "jsmith@corp.local"}
        corr = azip.hybrid_correlation(bg, ag)
        ok = (corr["common_domains"] == ["corp.local"] and
              corr["identities"] and corr["identities"][0]["via"] == "SID on-prem")
        return (ok, f"corr={corr}")
    check("mej", "correlación híbrida cloud↔on-prem por SID on-prem", e_hybrid)

    def e_scrub_ac():
        # el scrub Aho-Corasick debe ser byte-idéntico al regex de alternancias
        # (oracle) — un fallo aquí = fuga de PII. Casos: solapamiento longest-first,
        # acentos (upper), separadores de FQDN/SPN, substring embebido.
        import re as _re
        mapping = {"ADMINISTRADOR DE NOMINA": "GROUP_0001", "ADMIN": "USER_0009",
                   "HOST-01": "COMP_0002", "CORP.LOCAL": "DOM_01",
                   "NÓMINA".upper(): "GROUP_0007", "MARÍA".upper(): "USER_0003"}
        pats = sorted(mapping, key=len, reverse=True)
        rx = _re.compile("|".join(_re.escape(p) for p in pats), flags=_re.IGNORECASE)
        ref = lambda s: rx.sub(lambda m: mapping.get(m.group(0).upper(), m.group(0)), s)
        ac = bh._ScrubAutomaton(mapping)
        corpus = ["TERMSRV/HOST-01.CORP.LOCAL", "admin del ADMINISTRADOR DE NOMINA",
                  "contacto maría en nómina", "sin coincidencias 123",
                  "ADMINistradorDeNomina pegado", ""]
        diffs = [(s, ref(s), ac.replace(s)) for s in corpus if ref(s) != ac.replace(s)]
        return (not diffs, f"diffs={diffs[:2]}")
    check("mej", "scrub Aho-Corasick idéntico al regex de referencia", e_scrub_ac)

    def e_no_contains():
        # Contains es placement, no control: user→CN=Users→(Contains)→DA NO es path
        gr = {"nodes": [{"id": "U", "type": "user"},
                        {"id": "CN=USERS", "type": "container"},
                        {"id": "DOMAIN ADMINS@D", "type": "group"}],
              "links": [{"source": "U", "target": "CN=USERS", "relation": "MemberOf"},
                        {"source": "CN=USERS", "target": "DOMAIN ADMINS@D", "relation": "Contains"}]}
        reach = [p for p in bh.attack_paths(gr, max_hops=6, top=50) if p["from"] == "U"]
        return (not reach, f"U no debe escalar por Contains: {reach}")
    check("mej", "attack_paths no atraviesa Contains (sin falsos DA)", e_no_contains)

    def e_brief():
        # brief ejecutivo: choke points + escaladas dedupeadas (2 cuentas, 1 vía)
        real = {"nodes": [{"id": "U1", "type": "user"}, {"id": "U2", "type": "user"},
                          {"id": "CHOKE", "type": "computer"}, {"id": "DA1", "type": "user"},
                          {"id": "DOMAIN ADMINS@D", "type": "group"}],
                "links": [{"source": "U1", "target": "CHOKE", "relation": "AdminTo"},
                          {"source": "U2", "target": "CHOKE", "relation": "AdminTo"},
                          {"source": "DA1", "target": "CHOKE", "relation": "HasSession"},
                          {"source": "DA1", "target": "DOMAIN ADMINS@D", "relation": "MemberOf"}]}
        brief = "\n".join(azip.build_ad_brief(real, real, 6))
        ok = ("Choke points" in brief and "`CHOKE`" in brief
              and "Escaladas indirectas" in brief and "(+1 cuenta" in brief)
        return (ok, f"brief={brief[:120]!r}")
    check("mej", "brief ejecutivo: choke points + escaladas dedupeadas", e_brief)

    def e_graphq_cli():
        import importlib.util
        import tempfile
        spec = importlib.util.spec_from_file_location("graph_q", HERE / "skill" / "graph_q.py")
        gq = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gq)
        gr = {"directed": True, "multigraph": True, "graph": {},
              "nodes": [{"id": "U", "label": "U", "type": "user"},
                        {"id": "CN", "label": "CN", "type": "container"},
                        {"id": "DA", "label": "DA", "type": "group"}],
              "links": [{"source": "U", "target": "CN", "relation": "MemberOf"},
                        {"source": "CN", "target": "DA", "relation": "Contains"}]}
        f = Path(tempfile.mkdtemp()) / "graph.json"
        f.write_text(json.dumps(gr))
        g = gq.GraphQ(str(f))
        p = g.path("U", "DA")   # no debe existir (solo via Contains)
        return (p is None and hasattr(gq, "main"),
                f"path={p} tiene_main={hasattr(gq, 'main')}")
    check("mej", "graph_q: CLI presente + path no atraviesa Contains", e_graphq_cli)

    def e_deanon():
        import importlib.util
        import tempfile
        d = Path(tempfile.mkdtemp())
        graph = {"directed": True, "multigraph": True, "graph": {"anonymized": True},
                 "nodes": [{"id": "USER_0001", "label": "USER_0001", "type": "user"},
                           {"id": "DOMAIN_ADMINS@DOM_01", "label": "x", "type": "group"}],
                 "links": [{"source": "USER_0001", "target": "DOMAIN_ADMINS@DOM_01",
                            "relation": "MemberOf"}]}
        mp = {"mapping": {"s1": {"alias": "USER_0001", "real": "JPEREZ@CORP.LOCAL", "kind": "user"},
                          "s2": {"alias": "DOMAIN_ADMINS@DOM_01",
                                 "real": "DOMAIN ADMINS@CORP.LOCAL", "kind": "group"}}}
        (d / "graph.json").write_text(json.dumps(graph))
        (d / "map.json").write_text(json.dumps(mp))
        spec = importlib.util.spec_from_file_location("graph_q_d", HERE / "skill" / "graph_q.py")
        gq = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gq)
        g = gq.GraphQ(str(d / "graph.json"), map_path=str(d / "map.json"))
        alias = g.to_alias("JPEREZ@CORP.LOCAL")   # nombre real (del RESUMEN) → alias
        deanon = g.deanon_path("USER_0001 -[MemberOf]-> DOMAIN_ADMINS@DOM_01")
        ok = (alias == "USER_0001" and "JPEREZ@CORP.LOCAL" in deanon
              and "DOMAIN ADMINS@CORP.LOCAL" in deanon)
        return (ok, f"alias={alias} deanon={deanon}")
    check("mej", "graph_q: consulta por nombre real + de-anon de salida", e_deanon)

    def e_control_vectors():
        graph = {"nodes": [{"id": "U1", "type": "user"}, {"id": "GPO_X", "type": "gpo"},
                           {"id": "OU_1", "type": "ou"}, {"id": "PC1", "type": "computer"},
                           {"id": "PC2", "type": "computer"}, {"id": "TPL_1", "type": "certtemplate"},
                           {"id": "PC3", "type": "computer"}, {"id": "DOMAIN_ADMINS@D", "type": "group"}],
                 "links": [{"source": "U1", "target": "GPO_X", "relation": "GenericAll"},
                           {"source": "DOMAIN_ADMINS@D", "target": "GPO_X", "relation": "GenericAll"},
                           {"source": "GPO_X", "target": "OU_1", "relation": "GpLink", "enforced": True},
                           {"source": "OU_1", "target": "PC1", "relation": "Contains"},
                           {"source": "OU_1", "target": "PC2", "relation": "Contains"},
                           {"source": "U1", "target": "PC3", "relation": "Acl_Addkeycredentiallink"},
                           {"source": "U1", "target": "PC1", "relation": "Acl_Readlapspassword"},
                           {"source": "U1", "target": "TPL_1", "relation": "WriteDacl"},
                           {"source": "U1", "target": "PC2", "relation": "AllowedToAct"}]}
        cv = bh.control_vectors(graph)
        ok = (cv["gpo"] and cv["gpo"][0]["affected"] == 2 and cv["gpo"][0]["enforced"]
              and len(cv["gpo"][0]["controllers"]) == 1   # DA well-known filtrado
              and cv["shadow"] == [("U1", "PC3")] and cv["esc4"]
              and cv["laps"] == [("U1", "PC1")] and cv["rbcd"] == [("U1", "PC2")])
        return (bool(ok), f"cv={cv}")
    check("mej", "control_vectors: GPO abuse + Shadow/LAPS/ESC4/RBCD", e_control_vectors)

    def e_scrub_perf():
        # anti-regresión: el scrub escala O(len), no O(nº patrones). Con el
        # mega-regex viejo esto tardaba >30 s; margen amplio para no ser flaky.
        import time as _tm
        mapping = {f"NOMBREREAL{i:05d}": f"USER_{i:04d}" for i in range(2000)}
        ac = bh._ScrubAutomaton(mapping)
        corpus = [f"texto con NOMBREREAL{i:05d} embebido" for i in range(2000)]
        s = _tm.time()
        for x in corpus:
            ac.replace(x)
        dt = _tm.time() - s
        return (dt < 5.0, f"{len(corpus)} scrubs / {len(mapping)} patrones en {dt:.2f}s")
    check("mej", "scrub escala O(len) no O(patrones) (anti-regresión)", e_scrub_perf)


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

    for fn in (caso_ds1, caso_ds2, caso_ds3, caso_ds4, caso_ds5, caso_mejoras):
        fn()

    npass = sum(1 for *_, ok, _ in RESULTS if ok)
    print(f"\n[*] RESULTADO: {npass}/{len(RESULTS)} PASS")
    if npass != len(RESULTS):
        for case, name, ok, det in RESULTS:
            if not ok:
                print(f"  FAIL {case}: {name}")
        sys.exit(1)
    print("[+] TODO VERDE")
