#!/usr/bin/env python3
"""
graph_q.py — Query helper para análisis de grafos bh2graphify (graph.json).

Zero dependencias (stdlib). Uso típico desde Python:

    from graph_q import GraphQ
    g = GraphQ("graphify-out/graph.json", map_path="graphify-out/map.json")
    g.stats()
    g.paths_to("DOMAIN_ADMINS@DOM_01")           # quién llega y cómo
    g.controllers("KV_0001")                      # quién controla X
    g.by_relation("HasSession")                   # todas las sesiones
    g.find_props(hasspn=True)                     # kerberoastables
    g.deanon("USER_0007")                         # nombre real (si hay map)
"""
from __future__ import annotations

import json
from collections import defaultdict, deque
from pathlib import Path

# relations que significan CONTROL (para controllers() y scoring)
CONTROL_RELS = {
    "MemberOf", "AdminTo", "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
    "WriteProperty", "Owns", "AllExtendedRights", "AddMember", "AddSelf",
    "ForceChangePassword", "DCSync", "GetChanges", "GetChangesAll",
    "AllowedToAct", "ReadGMSAPassword", "HasRole", "Owner", "Contributor",
    "UserAccessAdmin", "VMAdminLogin", "Enroll", "AutoEnroll",
    "WritePKINameFlag", "WritePKIEnrollmentFlag", "Acl_Addkeycredentiallink",
    "Acl_Manageca", "Acl_Managecertificates", "Acl_Writeaccountrestrictions",
    "Acl_Addallowedtoact", "Acl_Readlapspassword", "KVAccessPolicy",
}
# edges reversibles en semántica de ataque (sesión = control de creds del user)
REVERSIBLE = {"HasSession", "HasPrivSession"}
# containment/placement — NO son control
NON_ATTACK = {"Contains", "GpLink", "Trusts"}


class GraphQ:
    def __init__(self, graph_path: str, map_path: str | None = None):
        with open(graph_path, encoding="utf-8") as f:
            self.graph = json.load(f)
        self.nodes = {n["id"]: n for n in self.graph["nodes"]}
        self.node_type = {n["id"]: n.get("type", "") for n in self.graph["nodes"]}
        self._map = {}
        if map_path and Path(map_path).is_file():
            with open(map_path, encoding="utf-8") as f:
                self._map = json.load(f).get("mapping", {})
            self._by_alias = {e["alias"]: e for e in self._map.values()}
        else:
            self._by_alias = {}
        # adyacencia: node -> [(other, rel, reversed_flag, props)]
        self.adj: dict[str, list] = defaultdict(list)
        for lk in self.graph["links"]:
            p = {k: v for k, v in lk.items()
                 if k not in ("source", "target", "relation", "weight", "confidence")}
            self.adj[lk["source"]].append((lk["target"], lk["relation"], False, p))
            if lk["relation"] in REVERSIBLE:
                self.adj[lk["target"]].append((lk["source"], lk["relation"], True, p))

    # — info básica —
    def stats(self) -> dict:
        by_type, by_rel = defaultdict(int), defaultdict(int)
        for n in self.graph["nodes"]:
            by_type[n.get("type", "?")] += 1
        for lk in self.graph["links"]:
            by_rel[lk["relation"]] += 1
        return {"nodes": len(self.graph["nodes"]),
                "links": len(self.graph["links"]),
                "by_type": dict(by_type),
                "top_relations": dict(sorted(by_rel.items(), key=lambda x: -x[1])[:15]),
                "anonymized": self.graph.get("graph", {}).get("anonymized", False)}

    def node(self, nid: str) -> dict | None:
        return self.nodes.get(nid)

    def search(self, substr: str, type_: str | None = None) -> list[dict]:
        s = substr.upper()
        return [n for n in self.graph["nodes"]
                if s in n["id"].upper() and (type_ is None or n.get("type") == type_)]

    # — queries de relación —
    def neighbors(self, nid: str, rel: str | None = None,
                  direction: str = "out") -> list[tuple]:
        """[(other, rel, reversed_flag, props)] — direction: out|in|both."""
        out = []
        for other, r, rev, p in self.adj.get(nid, []):
            if rev:  # edge entrante almacenado como reversible
                if direction in ("in", "both") and (rel is None or r == rel):
                    out.append((other, r, True, p))
            elif direction in ("out", "both") and (rel is None or r == rel):
                out.append((other, r, False, p))
        return out

    def by_relation(self, rel: str, limit: int = 0) -> list[dict]:
        links = [lk for lk in self.graph["links"] if lk["relation"] == rel]
        return links[:limit] if limit else links

    def controllers(self, nid: str) -> list[tuple]:
        """Quién tiene edges de CONTROL hacia nid (sin seguir MemberOf anidado)."""
        seen = {}
        for lk in self.graph["links"]:
            if lk["target"] == nid and lk["relation"] in CONTROL_RELS:
                seen[lk["source"]] = (lk["source"], lk["relation"],
                                      {k: v for k, v in lk.items()
                                       if k not in ("source", "target", "relation",
                                                    "weight", "confidence")})
        return list(seen.values())

    # — paths —
    def path(self, src: str, dst: str, max_hops: int = 6) -> list[str] | None:
        """Shortest attack path src→dst como lista de pasos legibles (None si no hay)."""
        if src not in self.nodes or dst not in self.nodes:
            return None
        prev: dict[str, tuple] = {}
        dist = {src: 0}
        q = deque([src])
        while q:
            cur = q.popleft()
            if cur == dst:
                break
            if dist[cur] >= max_hops:
                continue
            for other, r, rev, p in self.adj[cur]:
                if r in NON_ATTACK or other in dist:  # Contains/GpLink/Trusts = placement
                    continue
                dist[other] = dist[cur] + 1
                prev[other] = (cur, r, rev)
                q.append(other)
        if dst not in dist:
            return None
        steps, cur = [], dst
        while cur != src:
            p, r, rev = prev[cur]
            steps.append(f"{p} -[{r}{'↩' if rev else ''}]-> {cur}")
            cur = p
        return list(reversed(steps))

    def paths_to(self, target: str, max_hops: int = 6, limit: int = 10) -> list[dict]:
        """Todos los starts (user/group/sp) con path a target, ordenados por hops."""
        results = []
        for nid, ntype in self.node_type.items():
            if ntype not in ("user", "group", "sp") or nid == target:
                continue
            p = self.path(nid, target, max_hops)
            if p:
                results.append({"from": nid, "hops": len(p), "path": p})
        results.sort(key=lambda r: r["hops"])
        return results[:limit]

    # — props —
    def find_props(self, **props) -> list[dict]:
        """Nodos cuyas props matchean exactamente (ej: find_props(hasspn=True))."""
        out = []
        for n in self.graph["nodes"]:
            if all(n.get(k) == v for k, v in props.items()):
                out.append(n)
        return out

    # — de-anonimización (solo operador) —
    def deanon(self, alias: str) -> str:
        e = self._by_alias.get(alias)
        return e["real"] if e else "(sin mapa o alias desconocido)"

    def deanon_path(self, path_str: str) -> str:
        """De-anonimiza un path string (reemplaza alias por nombres reales)."""
        import re as _re
        def _sub(m):
            tok = m.group(0)
            real = self._by_alias.get(tok, {}).get("real")
            return f"{real} [{tok}]" if real else tok
        return _re.sub(r"[A-Z]+_[A-Z0-9_.@\-]+", _sub, path_str)


# ──────────────────────────────────────────────────────────────────────────────
# CLI — para consultas rápidas sin escribir Python. `analyze_zip` copia este
# script junto al grafo, así el agente lo corre por ruta predecible:
#   python3 <out>/graphify-out/graph_q.py stats
#   python3 <out>/graphify-out/graph_q.py controllers "GROUP_0007"
#   python3 <out>/graphify-out/graph_q.py paths-to "DOMAIN_ADMINS@DOM_01"
# ──────────────────────────────────────────────────────────────────────────────
def main():
    import argparse
    import sys
    argv = sys.argv[1:]
    # tolerar lo que suele tipear un modelo: `help` (en vez de --help) y sin-args → ayuda
    argv = ["-h" if a.lower() in ("help", "-help", "--h") else a for a in argv]
    if not argv:
        argv = ["-h"]
    here = Path(__file__).parent
    ap = argparse.ArgumentParser(
        prog="graph_q",
        description="Consultas sobre el graph.json de bh2graphify (sin neo4j).")
    ap.add_argument("--graph", default=str(here / "graph.json"),
                    help="ruta a graph.json (default: junto a este script)")
    ap.add_argument("--map", default=str(here / "map.json"),
                    help="ruta a map.json para de-anon (opcional)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("stats", help="inventario: tipos y relations top")
    sp = sub.add_parser("controllers", help="quién tiene control directo sobre un nodo")
    sp.add_argument("node")
    sp = sub.add_parser("paths-to", aliases=["paths_to"],
                        help="starts (user/group/sp) con path a un target")
    sp.add_argument("target"); sp.add_argument("--max-hops", type=int, default=6)
    sp.add_argument("--limit", type=int, default=15)
    sp = sub.add_parser("path", help="shortest attack path src -> dst")
    sp.add_argument("src"); sp.add_argument("dst"); sp.add_argument("--max-hops", type=int, default=6)
    sp = sub.add_parser("by-relation", aliases=["by_relation"],
                        help="todos los links de una relation")
    sp.add_argument("relation"); sp.add_argument("--limit", type=int, default=40)
    sp = sub.add_parser("find-props", aliases=["find_props"],
                        help="nodos por props (K=V, ej: hasspn=true)")
    sp.add_argument("kv", nargs="+")
    sp = sub.add_parser("search", help="nodos cuyo id contiene SUBSTR")
    sp.add_argument("substr"); sp.add_argument("--type", default=None)
    sp = sub.add_parser("neighbors", help="vecinos de un nodo")
    sp.add_argument("node"); sp.add_argument("--rel", default=None)
    sp.add_argument("--direction", default="out", choices=["out", "in", "both"])
    sp = sub.add_parser("deanon", help="alias -> nombre real (requiere --map)")
    sp.add_argument("alias")
    args = ap.parse_args(argv)
    cmd = (args.cmd or "").replace("_", "-")  # aceptar paths_to / by_relation / find_props

    mp = args.map if Path(args.map).is_file() else None
    g = GraphQ(args.graph, map_path=mp)

    if cmd == "stats":
        s = g.stats()
        print(f"nodos={s['nodes']} links={s['links']} anonymized={s['anonymized']}")
        print("por tipo: " + ", ".join(f"{k}={v}" for k, v in sorted(s["by_type"].items())))
        print("relations top:")
        for r, c in s["top_relations"].items():
            print(f"  {r:26s} {c}")
    elif cmd == "controllers":
        rows = g.controllers(args.node)
        if not rows:
            print("(sin controladores directos)")
        for src, rel, p in rows:
            extra = "  (" + ", ".join(f"{k}={v}" for k, v in p.items()) + ")" if p else ""
            print(f"  {src} -[{rel}]-> {args.node}{extra}")
    elif cmd == "paths-to":
        res = g.paths_to(args.target, max_hops=args.max_hops, limit=args.limit)
        if not res:
            print("(sin paths a ese target)")
        for r in res:
            print(f"[{r['hops']}h] {r['from']}")
            print("   " + " | ".join(r["path"]))
    elif cmd == "path":
        p = g.path(args.src, args.dst, max_hops=args.max_hops)
        print(" | ".join(p) if p else "(sin path)")
    elif cmd == "by-relation":
        links = g.by_relation(args.relation, limit=args.limit)
        if not links:
            print("(ningún link con esa relation)")
        for lk in links:
            print(f"  {lk['source']} -[{lk['relation']}]-> {lk['target']}")
    elif cmd == "find-props":
        props = {}
        for kv in args.kv:
            if "=" not in kv:
                ap.error(f"prop inválida (usar K=V): {kv}")
            k, v = kv.split("=", 1)
            vv = {"true": True, "false": False}.get(v.lower(), v)
            if isinstance(vv, str) and vv.lstrip("-").isdigit():
                vv = int(vv)
            props[k] = vv
        rows = g.find_props(**props)
        print(f"{len(rows)} nodo(s):")
        for n in rows[:60]:
            print(f"  {n['id']} ({n.get('type')})")
    elif cmd == "search":
        rows = g.search(args.substr, type_=args.type)
        print(f"{len(rows)} nodo(s):")
        for n in rows[:60]:
            print(f"  {n['id']} ({n.get('type')})")
    elif cmd == "neighbors":
        rows = g.neighbors(args.node, rel=args.rel, direction=args.direction)
        if not rows:
            print("(sin vecinos)")
        for other, rel, rev, _p in rows:
            print(f"  {args.node} {'<-' if rev else '->'}[{rel}] {other}")
    elif cmd == "deanon":
        print(g.deanon(args.alias))


if __name__ == "__main__":
    main()
