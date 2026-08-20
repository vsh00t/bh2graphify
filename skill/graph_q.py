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
                if other in dist:
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
