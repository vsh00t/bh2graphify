#!/usr/bin/env python3
"""
analyze_zip.py — Zip SharpHound/AzureHound → análisis automático completo.

Un solo paso: extrae, detecta el tipo, corre el parser, verifica leaks y
emite el resumen DECODIFICADO para el operador (nombres reales).

Uso:
    python3 analyze_zip.py <zip.zip> [--out DIR] [--max-hops 6]

Salidas (en <out>/graphify-out/):
    graph.json   — grafo ANONIMIZADO (para LLM externo / reporte)
    map.json     — reversión (chmod 600, CONFIDENCIAL, no sale del operador)
    RESUMEN.md   — hallazgos decodificados (nombres reales, 600)

Tipos detectados:
    - SharpHound: *_users.json/_groups.json/... (meta.type o patrón timestamp)
    - AzureHound: {"data":[{"kind":"AZ..."}}] (unified format)
    - Híbrido: ambos → corre ambos parsers y lo indica

Exit codes: 0 OK · 1 leak duro · 2 zip sin data reconocible
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import stat
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import bh2graphify as bh   # noqa: E402
import az2graphify as az   # noqa: E402

SH_KINDS = set(bh.NODE_KINDS) | {"aiacas", "certtemplates", "enterprisecas",
                                 "rootcas", "ntauthstores"}


def classify(files: list[Path]) -> tuple[list[Path], list[Path]]:
    sh, azf = [], []
    for p in files:
        if "__MACOSX" in p.name or p.suffix != ".json":
            continue
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                doc = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        if isinstance(doc, dict) and isinstance(doc.get("data"), list) and doc["data"] \
                and isinstance(doc["data"][0], dict) and \
                str(doc["data"][0].get("kind", "")).startswith("AZ"):
            azf.append(p)
        elif isinstance(doc, dict) and (doc.get("meta") or {}).get("type", "") in SH_KINDS \
                or re.match(r"^\d{14}_\w+\.json$", p.name):
            sh.append(p)
    return sh, azf


def _save_deliverables(gdir: Path, suffix: str, agr: dict, amap: dict):
    (gdir / f"graph{suffix}.json").write_text(
        json.dumps(agr, ensure_ascii=False, indent=1))
    mp = gdir / f"map{suffix}.json"
    mp.write_text(json.dumps({"_warning": "CONFIDENCIAL — reversión de nombres",
                              "mapping": amap}, ensure_ascii=False, indent=1))
    mp.chmod(stat.S_IRUSR | stat.S_IWUSR)


def analyze_sh(files: list[Path], gdir: Path, max_hops: int):
    g = bh.BHGraph()
    for f in sorted(files):
        g.parse_file(f)

    anon = bh.Anonymizer()
    agr = bh.build_graph(g, anon)
    hard, soft = bh.leakage_check(agr, anon.map)
    _save_deliverables(gdir, "", agr, anon.map)

    real = bh.build_graph(g, None)
    lines = build_ad_brief(real, agr, max_hops)
    return "\n".join(lines), hard, soft, g, real


def build_ad_brief(real: dict, agr: dict, max_hops: int) -> list[str]:
    """Brief EJECUTIVO priorizado (no un volcado de DA directos). El modelo lee
    esto — no los JSON crudos: Tier-0 directo resumido, choke points, escaladas
    indirectas dedupeadas por vía compartida, ADCS y superficie."""
    paths = bh.attack_paths(real, max_hops, top=400)
    direct = [p for p in paths if p["hops"] == 1 and "member of" in p["why"]]
    indirect = [p for p in paths if p["hops"] >= 2]
    # una cuenta puede ser DA y EA a la vez → dedup para no contarla dos veces
    direct_accts = list(dict.fromkeys(sorted(p["from"] for p in direct)))
    ntype = {n["id"]: n.get("type") for n in real["nodes"]}

    # choke points: nodos intermedios por los que pasan más rutas de escalada
    choke = Counter()
    for p in indirect:
        for n in p["nodes"][1:-1]:
            choke[n] += 1

    # escaladas dedupeadas: colapsar todos los starts que comparten la misma cola
    tails: dict = defaultdict(list)
    for p in indirect:
        tails[tuple(p["nodes"][1:])].append(p["from"])
    grouped = sorted(tails.items(), key=lambda kv: len(kv[1]), reverse=True)

    kerb = [n["id"] for n in real["nodes"] if n.get("type") == "user" and n.get("kerberoastable")]
    asrep = [n["id"] for n in real["nodes"] if n.get("dontreqpreauth")]
    uncon = [n["id"] for n in real["nodes"] if n.get("unconstraineddelegation")]
    quick = bh.adcs_quickwins(real)
    ca_findings = bh.adcs_ca_findings(real)
    cv = bh.control_vectors(real)
    starts_ind = {p["from"] for p in indirect}

    L = [f"**Nodos:** {len(agr['nodes'])} | **links:** {len(agr['links'])}", "",
         "## Resumen ejecutivo", "",
         f"- **Tier-0 directo:** {len(direct_accts)} cuentas ya son DA/EA/Administrator "
         f"(higiene, no son rutas).",
         f"- **Escaladas a Tier-0:** {len(indirect)} rutas de 2+ hops desde "
         f"{len(starts_ind)} cuentas no-admin."]
    if choke:
        L.append("- **Choke points:** " + ", ".join(f"`{c}`" for c, _ in choke.most_common(3))
                 + " (comprometerlos ⇒ Tier-0).")
    L.append(f"- **Superficie:** {len(kerb)} kerberoastables · {len(asrep)} AS-REP · "
             f"{len(uncon)} unconstrained delegation.")
    L.append("")

    if choke:
        L += ["## Choke points — comprometer el nodo ⇒ camino a Tier-0", ""]
        for c, n in choke.most_common(8):
            L.append(f"- `{c}` ({ntype.get(c, '?')}) — en **{n}** rutas de escalada")
        L.append("")

    L += ["## Escaladas indirectas (dedupeadas por vía compartida)", ""]
    if grouped:
        for tail, starts in grouped[:12]:
            ej = sorted(starts)[0]
            more = f" (+{len(starts) - 1} cuentas)" if len(starts) > 1 else ""
            L.append(f"- **[{len(tail)}h]** `{ej}`{more} → " + " → ".join(f"`{x}`" for x in tail))
    else:
        L.append("- (sin escaladas indirectas dentro del límite de hops)")
    L.append("")

    if direct_accts:
        L += [f"## Tier-0 directo ({len(direct_accts)} cuentas — revisar necesidad de cada una)", ""]
        L.append(", ".join(f"`{x}`" for x in direct_accts[:24])
                 + (f" …y {len(direct_accts) - 24} más." if len(direct_accts) > 24 else ""))
        L.append("")

    if quick:
        L += ["## ADCS quick wins (ESC1/ESC2/ESC3)", ""]
        for q in quick[:15]:
            en = q["enroll"] or q["wk_enroll"]
            who = ", ".join(en[:6]) if en else "(sin Enroll directo)"
            L.append(f"- **[{q['esc']}]** `{q['template']}` — Enroll: {who}")
        L.append("")
    if ca_findings:
        L += ["## ADCS — control sobre CA (ESC7 / takeover)", ""]
        for c in ca_findings[:10]:
            for ctrl in c["controllers"][:8]:
                wk = " (well-known)" if ctrl["wellknown"] else ""
                L.append(f"- **[{ctrl['esc']}]** `{ctrl['who']}`{wk} -[{ctrl['rel']}]-> `{c['ca']}`")
        L.append("")

    if any(cv.values()):
        L += ["## Vectores de control (edges BloodHound)", ""]
        def _pairs(lst, n=6):
            return ", ".join(f"`{s}`→`{t}`" for s, t in lst[:n]) + (
                f" …(+{len(lst) - n})" if len(lst) > n else "")
        if cv["gpo"]:
            L.append(f"- **GPO abuse** — {len(cv['gpo'])} GPO controlados por no-admin "
                     "(control ⇒ código en los equipos de las OU linkeadas):")
            for gp in cv["gpo"][:6]:
                who = ", ".join(f"`{s}`" for s, _ in gp["controllers"][:3])
                enf = " **[ENFORCED]**" if gp["enforced"] else ""
                L.append(f"  - `{gp['gpo']}`{enf} → **{gp['affected']}** objetos afectados · "
                         f"controlan: {who}")
        if cv["shadow"]:
            L.append(f"- **Shadow Credentials** (AddKeyCredentialLink, {len(cv['shadow'])}): "
                     + _pairs(cv["shadow"]))
        if cv["esc4"]:
            L.append(f"- **ADCS ESC4** (escritura sobre el template, {len(cv['esc4'])}): "
                     + ", ".join(f"`{e['template']}`" for e in cv["esc4"][:8]))
        if cv["laps"]:
            L.append(f"- **LAPS readers** (ReadLAPSPassword, {len(cv['laps'])}): "
                     + _pairs(cv["laps"]))
        if cv["rbcd"]:
            L.append(f"- **RBCD** (AllowedToAct / WriteAccountRestrictions, {len(cv['rbcd'])}): "
                     + _pairs(cv["rbcd"]))
        if cv["targeted_kerberoast"]:
            L.append(f"- **Kerberoast dirigido** (WriteSPN, {len(cv['targeted_kerberoast'])}): "
                     + _pairs(cv["targeted_kerberoast"]))
        L.append("")

    if uncon or kerb or asrep:
        L += ["## Superficie de ataque", ""]
        if uncon:
            L.append(f"- **Unconstrained delegation** ({len(uncon)}): "
                     + ", ".join(f"`{x}`" for x in uncon[:8]))
        if kerb:
            L.append(f"- **Kerberoastables** ({len(kerb)}): "
                     + ", ".join(f"`{x}`" for x in sorted(kerb)[:8]))
        if asrep:
            L.append(f"- **AS-REP roastables** ({len(asrep)}): "
                     + ", ".join(f"`{x}`" for x in sorted(asrep)[:8]))
    return L


def analyze_az(files: list[Path], gdir: Path, max_hops: int):
    g = az.AZGraph()
    g.parse_many(sorted(files))

    anon = az.AZAnonymizer()
    agr = az.build_graph(g, anon)
    hard, soft = az.leakage_check(agr, anon.map)
    _save_deliverables(gdir, "_az", agr, anon.map)

    real = az.build_graph(g, None)
    paths = az.attack_paths(real, max_hops, top=15)

    lines = [f"**Nodos:** {len(agr['nodes'])} | **links:** {len(agr['links'])}"]
    if g.unresolved:
        lines.append(f"**Refs sin resolver:** {dict(g.unresolved)}")
    lines += ["", "## Attack paths (nombres reales)", ""]
    if paths:
        for r in paths:
            lines.append(f"- **[{r['hops']}h]** `{r['from']}` → `{r['target']}` — {r['why']}")
            lines.append(f"  - `{r['path']}`")
    else:
        lines.append("- (sin paths a roles/subs/MGs/KVs)")
    return "\n".join(lines), hard, soft, g


def hybrid_correlation(bh_graph, azg) -> dict:
    """Cruza el plano cloud (AzureHound) con el on-prem (SharpHound) sobre datos
    REALES (plano de-anon del operador). No fabrica edges en el grafo: correlaciona
    identidades sincronizadas por SID on-prem (fuerte) o UPN (heurístico) y detecta
    dominios compartidos AD↔tenant. Marcar los hallazgos como INFERRED."""
    by_sid = bh_graph.nodes
    by_name: dict[str, str] = {}
    for sid, n in bh_graph.nodes.items():
        nm = (n.get("name") or "").lower()
        if nm:
            by_name.setdefault(nm, sid)
            by_name.setdefault(nm.split("@")[0], sid)
    sh_domains = {(n.get("name") or "").lower()
                  for n in bh_graph.nodes.values() if n["kind"] == "domain"}
    common = sorted(d for d in azg.tenant_domains if d and d in sh_domains)

    identities = []
    for oid, h in azg.hybrid.items():
        sid, hit = h.get("onprem_sid"), None
        if sid and sid in by_sid:
            hit = ("SID on-prem", sid)
        elif h.get("upn"):
            upn = h["upn"]
            cand = by_name.get(upn) or by_name.get(upn.split("@")[0])
            if cand:
                hit = ("UPN", cand)
        if hit:
            identities.append({
                "az": azg.nodes.get(oid, {}).get("name", oid),
                "ad": by_sid[hit[1]].get("name", hit[1]), "via": hit[0]})
    return {"common_domains": common, "identities": identities}


def _protect_raw(names: list[str], out: Path, clean: bool):
    """Los JSON crudos (SharpHound/AzureHound) traen los NOMBRES REALES — son el
    activo más sensible. Tras generar entregables, borrarlos (--clean) o al menos
    restringir sus permisos a 600, igual que map.json/RESUMEN.md."""
    for name in names:
        p = (out / name)
        if not p.is_file() or "graphify-out" in Path(name).parts:
            continue
        try:
            if clean:
                p.unlink()
            else:
                p.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    if clean:
        # limpiar directorios vacíos que dejó la extracción
        for d in sorted((q for q in out.rglob("*") if q.is_dir()),
                        key=lambda q: len(q.parts), reverse=True):
            if d.name != "graphify-out" and not any(d.iterdir()):
                try:
                    d.rmdir()
                except OSError:
                    pass


def main():
    ap = argparse.ArgumentParser(prog="analyze_zip")
    ap.add_argument("zip_path")
    ap.add_argument("--out", default=None, help="dir destino (default ~/pentest-data/<zip>/)")
    ap.add_argument("--max-hops", type=int, default=6)
    ap.add_argument("--clean", action="store_true",
                    help="borrar los JSON crudos extraídos tras el análisis (deja solo graphify-out)")
    ap.add_argument("--max-uncompressed", type=int, default=4 * 1024**3,
                    help="límite de bytes descomprimidos (guarda anti zip-bomb; default 4 GiB)")
    ap.add_argument("--max-files", type=int, default=100_000,
                    help="máximo de entradas en el zip (guarda anti zip-bomb)")
    args = ap.parse_args()

    zp = Path(args.zip_path).expanduser().resolve()
    if not zp.is_file():
        sys.exit(f"[!] no existe: {zp}")
    out = Path(args.out).expanduser() if args.out else \
        Path.home() / "pentest-data" / zp.stem.lower()
    out.mkdir(parents=True, exist_ok=True)
    try:  # dir del operador: solo el dueño (contiene nombres reales + map)
        out.chmod(stat.S_IRWXU)
    except OSError:
        pass

    with zipfile.ZipFile(zp) as z:
        infos = z.infolist()
        total = sum(i.file_size for i in infos)
        if len(infos) > args.max_files:
            sys.exit(f"[!] {zp.name}: demasiadas entradas ({len(infos)} > {args.max_files}) — "
                     "posible zip-bomb (subir con --max-files si es legítimo)")
        if total > args.max_uncompressed:
            sys.exit(f"[!] {zp.name}: descompresión {total/1e6:.0f} MB excede el límite "
                     f"{args.max_uncompressed/1e6:.0f} MB (subir con --max-uncompressed)")
        names = z.namelist()
        z.extractall(out)     # zipfile (Py>=3.6.2) sanea rutas absolutas y '..'
    files = [p for p in out.rglob("*.json") if p.is_file()]
    sh, azf = classify(files)
    if not sh and not azf:
        sys.exit(f"[!] {zp.name}: sin JSONs SharpHound/AzureHound reconocibles (exit 2)")
    print(f"[*] {zp.name} → {out}")
    print(f"    SharpHound: {len(sh)} files | AzureHound: {len(azf)} files")

    gdir = out / "graphify-out"
    gdir.mkdir(exist_ok=True)
    # copiar el CLI de consultas junto al grafo → el agente lo corre por ruta
    # predecible (python3 <gdir>/graph_q.py stats), sin adivinar dónde está.
    try:
        shutil.copy(HERE / "skill" / "graph_q.py", gdir / "graph_q.py")
    except OSError:
        pass
    sections, hard_all, soft_all = [], [], []
    bh_graph = azg = None

    if sh:
        print("[*] Corriendo bh2graphify…")
        summary, hard, soft, bh_graph, _real = analyze_sh(sh, gdir, args.max_hops)
        sections.append(("Active Directory (SharpHound)", summary))
        hard_all, soft_all = hard_all + hard, soft_all + soft

    if azf:
        print("[*] Corriendo az2graphify…")
        summary, hard, soft, azg = analyze_az(azf, gdir, args.max_hops)
        sections.append(("Entra ID / Azure (AzureHound)", summary))
        hard_all, soft_all = hard_all + hard, soft_all + soft

    if sh and azf:
        corr = hybrid_correlation(bh_graph, azg)
        hy = ["Correlación cloud ↔ on-prem sobre datos reales (INFERRED — no son "
              "edges del grafo; validar a mano).", ""]
        if corr["common_domains"]:
            hy.append(f"- **Dominios compartidos AD↔tenant:** {', '.join(corr['common_domains'])}")
        if corr["identities"]:
            hy.append("- **Identidades sincronizadas (misma cuenta en ambos planos):**")
            for m in corr["identities"][:20]:
                hy.append(f"  - `{m['az']}` (cloud) ≈ `{m['ad']}` (on-prem) — vía {m['via']}")
            hy += ["", "  → Un compromiso on-prem de estas cuentas se hereda en Entra "
                   "(y viceversa). Cruzar con holders de *Hybrid Identity Administrator* "
                   "y *Directory Synchronization Accounts*."]
        if not corr["common_domains"] and not corr["identities"]:
            hy.append("- (sin dominios ni identidades correlacionables entre ambos planos)")
        sections.append(("Híbrido (AD ↔ Entra)", "\n".join(hy)))

    hdr = [f"# Análisis automático — {zp.name}", ""]
    if hard_all:
        hdr += ["> ⚠️ **LEAK DURO — NO usar el grafo anon hacia fuera** hasta revisar:",
                "> " + "; ".join(hard_all[:10]), ""]
    else:
        hdr += ["> ✅ Leak-check OK — grafo anonimizado apto para LLM externo/reportes", ""]
    if soft_all:
        hdr += ["> ℹ️ Soft matches multi-palabra (revisar a mano): "
                + "; ".join(soft_all[:6]), ""]
    body = "\n\n".join(f"## {t}\n\n{s}" for t, s in sections)
    report = "\n".join(hdr) + body + "\n"
    rp = gdir / "RESUMEN.md"
    rp.write_text(report, encoding="utf-8")
    rp.chmod(stat.S_IRUSR | stat.S_IWUSR)

    _protect_raw(names, out, args.clean)

    print()
    print(report)
    print(f"[+] Entregables: {gdir}/  (graph*.json anon · map*.json 600 · RESUMEN.md 600)")
    if args.clean:
        print("[+] JSON crudos extraídos: BORRADOS (--clean)")
    else:
        print("[i] JSON crudos extraídos: chmod 600 (traen nombres reales; usa --clean para borrarlos)")
    sys.exit(1 if hard_all else 0)


if __name__ == "__main__":
    main()
