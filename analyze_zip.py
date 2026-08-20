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
import stat
import sys
import zipfile
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


def analyze_sh(files: list[Path], gdir: Path, max_hops: int) -> tuple[str, list[str], list[str]]:
    g = bh.BHGraph()
    for f in sorted(files):
        g.parse_file(f)

    anon = bh.Anonymizer()
    agr = bh.build_graph(g, anon)
    hard, soft = bh.leakage_check(agr, anon.map)
    _save_deliverables(gdir, "", agr, anon.map)

    real = bh.build_graph(g, None)
    paths = bh.attack_paths(real, max_hops, top=15)
    quick = bh.adcs_quickwins(real)

    lines = [f"**Nodos:** {len(agr['nodes'])} | **links:** {len(agr['links'])}", "",
             "## Attack paths (nombres reales)", ""]
    if paths:
        for r in paths:
            lines.append(f"- **[{r['hops']}h]** `{r['from']}` → `{r['target']}` — {r['why']}")
            lines.append(f"  - `{r['path']}`")
    else:
        lines.append("- (sin paths a DA/DCSync dentro del límite de hops)")
    if quick:
        lines += ["", "## ADCS quick wins (ESC1/ESC2)", ""]
        for q in quick[:15]:
            en = q["enroll"] or q["wk_enroll"]
            who = ", ".join(en[:6]) if en else "(sin Enroll directo)"
            lines.append(f"- **[{q['esc']}]** `{q['template']}` — Enroll: {who}")
    return "\n".join(lines), hard, soft


def analyze_az(f: Path, gdir: Path, max_hops: int) -> tuple[str, list[str], list[str]]:
    g = az.AZGraph()
    g.parse(f)

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
    return "\n".join(lines), hard, soft


def main():
    ap = argparse.ArgumentParser(prog="analyze_zip")
    ap.add_argument("zip_path")
    ap.add_argument("--out", default=None, help="dir destino (default ~/pentest-data/<zip>/)")
    ap.add_argument("--max-hops", type=int, default=6)
    args = ap.parse_args()

    zp = Path(args.zip_path).expanduser().resolve()
    if not zp.is_file():
        sys.exit(f"[!] no existe: {zp}")
    out = Path(args.out).expanduser() if args.out else \
        Path.home() / "pentest-data" / zp.stem.lower()
    out.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zp) as z:
        z.extractall(out)
    files = [p for p in out.rglob("*.json") if p.is_file()]
    sh, azf = classify(files)
    if not sh and not azf:
        sys.exit(f"[!] {zp.name}: sin JSONs SharpHound/AzureHound reconocibles (exit 2)")
    print(f"[*] {zp.name} → {out}")
    print(f"    SharpHound: {len(sh)} files | AzureHound: {len(azf)} files")

    gdir = out / "graphify-out"
    gdir.mkdir(exist_ok=True)
    sections, hard_all, soft_all = [], [], []

    if sh:
        print("[*] Corriendo bh2graphify…")
        summary, hard, soft = analyze_sh(sh, gdir, args.max_hops)
        sections.append(("Active Directory (SharpHound)", summary))
        hard_all, soft_all = hard_all + hard, soft_all + soft

    if azf:
        print("[*] Corriendo az2graphify…")
        summary, hard, soft = analyze_az(azf[0], gdir, args.max_hops)
        sections.append(("Entra ID / Azure (AzureHound)", summary))
        hard_all, soft_all = hard_all + hard, soft_all + soft

    if sh and azf:
        sections.append(("Nota", "Dataset **híbrido** detectado. Grafos generados por "
                       "separado (merge cross-plane AD↔AZ pendiente — ver skill)."))

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

    print()
    print(report)
    print(f"[+] Entregables: {gdir}/  (graph*.json anon · map*.json 600 · RESUMEN.md 600)")
    sys.exit(1 if hard_all else 0)


if __name__ == "__main__":
    main()
