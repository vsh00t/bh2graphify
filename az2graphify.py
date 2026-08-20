#!/usr/bin/env python3
"""
az2graphify — AzureHound JSON → graphify-compatible graph.json (LLM-native)
+ pseudo-anonimización determinista + attack paths Entra/ARM.

Complemento de bh2graphify (mismo schema, mismo Anonymizer). Uso:

    python3 az2graphify.py azurehound_output.json \
        --out graphify-out/graph.json --save-map graphify-out/map.json \
        --attack-paths [--max-hops N]

Formato de entrada: AzureHound (unified): {"data": [{"kind": "AZUser", "data": {...}}, ...]}
"""
from __future__ import annotations

import argparse
import json
import re
import stat
import sys
from collections import defaultdict, deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from bh2graphify import Anonymizer  # noqa: E402  (scrub machinery validada)

# ──────────────────────────────────────────────────────────────────────────────
# Mapeos
# ──────────────────────────────────────────────────────────────────────────────
NODE_KIND = {
    "AZTenant": "tenant", "AZUser": "user", "AZGroup": "group", "AZApp": "app",
    "AZServicePrincipal": "sp", "AZDevice": "device", "AZRole": "role",
    "AZManagementGroup": "mg", "AZSubscription": "sub", "AZResourceGroup": "rg",
    "AZVM": "vm", "AZVMScaleSet": "vmss", "AZKeyVault": "kv",
    "AZAutomationAccount": "automation", "AZFunctionApp": "function",
    "AZLogicApp": "logic", "AZManagedCluster": "aks",
    "AZContainerRegistry": "acr", "AZWebApp": "web",
}
# ARM resources: id es el ARM path completo; el kind graphify agrupa el tipo
RESOURCE_KINDS = {"vm", "vmss", "kv", "automation", "function", "logic", "aks", "acr", "web"}

# props seguras (no PII) por tipo
SAFE_PROPS = {
    "accountenabled", "usertype", "onpremsynced", "securityenabled", "dynamic",
    "signinaudience", "sptype", "haskeycreds", "haspwdcreds", "operatingsystem",
    "operatingsystemversion", "trusttype", "isbuiltin", "state", "location",
    "msitype", "enabledfordeployment", "enabledfordiskencryption",
    "enabledfortemplatedeployment", "enablesoftdelete", "purgeprotection",
}

# Roles Entra de alto valor (targets de attack paths)
HIGH_VALUE_ROLES = {
    "Global Administrator", "Privileged Role Administrator",
    "Privileged Authentication Administrator", "Application Administrator",
    "Hybrid Identity Administrator", "Exchange Administrator",
    "Cloud Application Administrator", "Security Administrator",
    "Directory Synchronization Accounts",
}

# GUIDs ARM RBAC conocidos; el resto se resuelve desde az_role_guids.json
# (extraído de learn.microsoft.com built-in-roles — 312 GUIDs, Ago'26)
ARM_GUID_NAMES = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "UserAccessAdmin",
}
try:
    with open(Path(__file__).parent / "az_role_guids.json") as _f:
        ARM_GUID_NAMES.update({k.lower(): v for k, v in json.load(_f).items()})
except OSError:
    pass

# kind edge → (campo lista, campo target, relation fija | None=resolver GUID)
ARM_RBAC_KINDS = {
    "AZVMOwner": ("owners", "virtualMachineId", "Owner"),
    "AZVMContributor": ("contributors", "virtualMachineId", "Contributor"),
    "AZVMAdminLogin": ("adminLogins", "virtualMachineId", "VMAdminLogin"),
    "AZVMUserAccessAdmin": ("userAccessAdmins", "virtualMachineId", "UserAccessAdmin"),
    "AZVMAvereContributor": ("avereContributors", "virtualMachineId", "AvereContributor"),
    "AZSubscriptionOwner": ("owners", "subscriptionId", "Owner"),
    "AZSubscriptionUserAccessAdmin": ("userAccessAdmins", "subscriptionId", "UserAccessAdmin"),
    "AZResourceGroupOwner": ("owners", "resourceGroupId", "Owner"),
    "AZResourceGroupUserAccessAdmin": ("userAccessAdmins", "resourceGroupId", "UserAccessAdmin"),
    "AZManagementGroupOwner": ("owners", "managementGroupId", "Owner"),
    "AZManagementGroupUserAccessAdmin": ("userAccessAdmins", "managementGroupId", "UserAccessAdmin"),
    "AZKeyVaultOwner": ("owners", "keyVaultId", "Owner"),
    "AZKeyVaultContributor": ("contributors", "keyVaultId", "Contributor"),
    "AZKeyVaultKVContributor": ("kvContributors", "keyVaultId", "KVContributor"),
    "AZKeyVaultUserAccessAdmin": ("userAccessAdmins", "keyVaultId", "UserAccessAdmin"),
    "AZVMScaleSetRoleAssignment": ("assignees", "objectId", None),
    "AZContainerRegistryRoleAssignment": ("assignees", "objectId", None),
    "AZWebAppRoleAssignment": ("assignees", "objectId", None),
    "AZLogicAppRoleAssignment": ("assignees", "objectId", None),
    "AZFunctionAppRoleAssignment": ("assignees", "objectId", None),
    "AZAutomationAccountRoleAssignment": ("assignees", "objectId", None),
    "AZManagedClusterRoleAssignment": ("assignees", "objectId", None),
}
# nombres de campo del objeto interno según el nombre de la lista
INNER_KEY = {
    "owners": "owner", "contributors": "contributor", "adminLogins": "adminLogin",
    "userAccessAdmins": "userAccessAdmin", "avereContributors": "avereContributor",
    "kvContributors": "kvContributor", "assignees": "assignee",
    "members": "member",
}

ODATA_KIND = {"#microsoft.graph.user": "user", "#microsoft.graph.serviceprincipal": "sp",
              "#microsoft.graph.group": "group", "#microsoft.graph.device": "device"}


# ──────────────────────────────────────────────────────────────────────────────
# Parsing AzureHound
# ──────────────────────────────────────────────────────────────────────────────
class AZGraph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []
        self._edge_seen: set = set()
        self.tenant_domains: set[str] = set()
        self.appidx: dict[str, str] = {}        # appId (client) → objectId
        self.stats: dict[str, int] = defaultdict(int)
        self.unresolved: dict[str, int] = defaultdict(int)

    def add_node(self, nid: str, kind: str, name: str | None = None, props: dict | None = None):
        if not nid:
            return
        n = self.nodes.setdefault(nid, {"kind": kind, "name": name or nid, "props": {}})
        if name and (not n["name"] or n["name"] == nid):
            n["name"] = name
        if props:
            n["props"].update({k: v for k, v in props.items() if k in SAFE_PROPS})

    def add_edge(self, src: str, dst: str, rel: str, props: dict | None = None):
        if not src or not dst or src == dst:
            return
        key = (src, dst, rel)
        if key in self._edge_seen:
            return
        self._edge_seen.add(key)
        self.edges.append({"src": src, "dst": dst, "rel": rel, "props": props or {}})

    # — helpers —
    def _odata_node(self, obj: dict):
        """Nodo desde un objeto Graph embebido ({@odata.type, id, displayName})."""
        if not isinstance(obj, dict):
            return None
        kind = ODATA_KIND.get(obj.get("@odata.type") or "", "user")
        self.add_node(obj.get("id"), kind, obj.get("displayName"))
        return obj.get("id")

    def _arm_role_edge(self, inner: dict, target: str, fixed_rel: str | None, entry: dict):
        """Edge RBAC desde un objeto ARM roleAssignment embebido."""
        if not isinstance(inner, dict):
            return
        props = inner.get("properties") or {}
        pid = props.get("principalId") or inner.get("principalId")
        if not pid:
            return
        ptype = (props.get("principalType") or "").lower()
        kind = {"user": "user", "group": "group", "serviceprincipal": "sp"}.get(ptype, "user")
        self.add_node(pid, kind)
        rel = fixed_rel
        if rel is None:
            rd = (entry.get("roleDefinitionId") or
                  str(props.get("roleDefinitionId") or "")).split("/")[-1]
            rel = ARM_GUID_NAMES.get(rd.lower(), f"RBAC_{rd[:8]}")
        self.add_edge(pid, target, rel)

    # — parseo —
    def parse(self, path: Path):
        with open(path, encoding="utf-8", errors="replace") as f:
            doc = json.load(f)
        entries = doc.get("data") if isinstance(doc, dict) else doc
        if not isinstance(entries, list):
            sys.exit("[!] formato AzureHound inesperado")
        print(f"[*] {len(entries)} entradas AzureHound")
        # pasada 1: nodos + índices (appId→objId)
        for e in entries:
            k = e.get("kind", "")
            d = e.get("data") or {}
            if not isinstance(d, dict):
                continue
            self.stats[k] += 1
            self._parse_node(k, d)
        # pasada 2: edges (necesita índices completos)
        for e in entries:
            k = e.get("kind", "")
            d = e.get("data") or {}
            if not isinstance(d, dict):
                continue
            self._parse_edge(k, d)
        print(f"[*] Nodos: {len(self.nodes)} | edges: {len(self.edges)}")

    def _parse_node(self, k: str, d: dict):
        if k == "AZTenant":
            self.add_node(d.get("tenantId"), "tenant", d.get("displayName"))
            for dom in ([d.get("defaultDomain")] + (d.get("domains") or [])):
                if dom:
                    self.tenant_domains.add(str(dom).lower())
        elif k == "AZUser":
            props = {"accountenabled": d.get("accountEnabled"), "usertype": d.get("userType"),
                     "onpremsynced": bool(d.get("onPremisesImmutableId"))}
            self.add_node(d.get("id"), "user", d.get("displayName"), props)
        elif k == "AZGroup":
            props = {"securityenabled": d.get("securityEnabled"),
                     "dynamic": bool(d.get("membershipRule"))}
            self.add_node(d.get("id"), "group", d.get("displayName"), props)
        elif k == "AZApp":
            if d.get("id") and d.get("appId"):
                self.appidx[str(d["appId"]).lower()] = d["id"]
            props = {"signinaudience": d.get("signInAudience")}
            self.add_node(d.get("id"), "app", d.get("displayName"), props)
        elif k == "AZServicePrincipal":
            if d.get("id") and d.get("appId"):
                self.appidx.setdefault(str(d["appId"]).lower(), d["id"])
            props = {"accountenabled": d.get("accountEnabled"),
                     "sptype": d.get("servicePrincipalType"),
                     "haskeycreds": bool(d.get("keyCredentials")),
                     "haspwdcreds": bool(d.get("passwordCredentials"))}
            self.add_node(d.get("id"), "sp", d.get("displayName") or d.get("appDisplayName"), props)
        elif k == "AZDevice":
            props = {"accountenabled": d.get("accountEnabled"),
                     "operatingsystem": d.get("operatingSystem"),
                     "operatingsystemversion": d.get("operatingSystemVersion"),
                     "trusttype": d.get("trustType")}
            self.add_node(d.get("id"), "device", d.get("displayName"), props)
        elif k == "AZRole":
            props = {"isbuiltin": d.get("isBuiltIn")}
            # builtin → kind 'builtinrole' (nombre preservado)
            kind = "builtinrole" if d.get("isBuiltIn") else "role"
            self.add_node(d.get("id"), kind, d.get("displayName"), props)
        elif k == "AZSubscription":
            sid = d.get("id") or (f"/subscriptions/{d.get('subscriptionId')}" if d.get("subscriptionId") else None)
            self.add_node(sid, "sub", d.get("displayName"), {"state": d.get("state")})
        elif k == "AZManagementGroup":
            self.add_node(d.get("id"), "mg", d.get("name"))
        elif k == "AZResourceGroup":
            self.add_node(d.get("id"), "rg", d.get("name"), {"location": d.get("location")})
        elif k in NODE_KIND:
            kind = NODE_KIND[k]
            props = {"location": d.get("location")}
            if kind == "kv":
                pr = d.get("properties") or {}
                props.update({"enablesoftdelete": pr.get("enableSoftDelete"),
                              "purgeprotection": pr.get("enablePurgeProtection")})
            ident = d.get("identity") or {}
            if ident.get("principalId"):
                props["msitype"] = ident.get("type")
            self.add_node(d.get("id"), kind, d.get("name"), props)

    def _parse_edge(self, k: str, d: dict):
        # — Entra plane —
        if k == "AZGroupMember":
            gid = d.get("groupId")
            for m in d.get("members") or []:
                mid = self._odata_node((m or {}).get("member") or {})
                if mid:
                    self.add_edge(mid, gid, "MemberOf")
        elif k in ("AZGroupOwner", "AZAppOwner", "AZServicePrincipalOwner", "AZDeviceOwner"):
            fld, tid = {"AZGroupOwner": ("owners", d.get("groupId")),
                        "AZAppOwner": ("owners", d.get("appId")),
                        "AZServicePrincipalOwner": ("owners", d.get("servicePrincipalId")),
                        "AZDeviceOwner": ("owners", d.get("deviceId"))}[k]
            # AZAppOwner viene con appId (client) — resolver a objectId
            if k == "AZAppOwner" and tid:
                tid = self.appidx.get(str(tid).lower(), tid)
                if str(tid) not in self.nodes:
                    self.unresolved["appOwner"] += 1
            for o in d.get(fld) or []:
                oid = self._odata_node((o or {}).get("owner") or {})
                if oid:
                    self.add_edge(oid, tid, "Owns")
        elif k == "AZRoleAssignment":
            for ra in d.get("roleAssignments") or []:
                pid, rid = ra.get("principalId"), ra.get("roleDefinitionId")
                if pid and rid:
                    self.add_node(pid, "user")
                    self.add_node(rid, "builtinrole", rid and self._rolename(rid))
                    self.add_edge(pid, rid, "HasRole")
        elif k == "AZAppRoleAssignment":
            pid, rid = d.get("principalId"), d.get("resourceId")
            if pid and rid:
                ptype = (d.get("principalType") or "").lower()
                kind = {"user": "user", "group": "group",
                        "serviceprincipal": "sp"}.get(ptype, "user")
                self.add_node(pid, kind, d.get("principalDisplayName"))
                self.add_node(rid, "sp", d.get("resourceDisplayName"))
                props = {}
                arid = d.get("appRoleId") or ""
                if arid and not set(arid) <= {"0", "-"}:  # no default-access
                    props["app_role_id"] = arid[:8]
                self.add_edge(pid, rid, "AppRole", props)
        elif k == "AZKeyVaultAccessPolicy":
            oid, kvid = d.get("objectId"), d.get("keyVaultId")
            if oid and kvid:
                perms = d.get("permissions") or {}
                summ = []
                for area in ("keys", "secrets", "certificates"):
                    acts = perms.get(area) or []
                    if acts:
                        summ.append(f"{area}:{','.join(acts[:4])}")
                self.add_node(oid, "user")
                self.add_edge(oid, kvid, "KVAccessPolicy",
                              {"permissions": "; ".join(summ)} if summ else None)
        # — ARM RBAC —
        elif k in ARM_RBAC_KINDS:
            fld, tfld, fixed = ARM_RBAC_KINDS[k]
            target = d.get(tfld)
            if not target:
                return
            for item in d.get(fld) or []:
                inner = item.get(INNER_KEY.get(fld, "")) if isinstance(item, dict) else None
                if inner:
                    self._arm_role_edge(inner, target, fixed, item)
                elif isinstance(item, str):
                    self.add_node(item, "user")
                    self.add_edge(item, target, fixed or "RBAC")
        # — jerarquía ARM (desde nodos) —
        elif k == "AZManagementGroup":
            mgid = d.get("id")
            props = d.get("properties") or {}
            for ch in props.get("children") or []:
                cid = (ch or {}).get("id")
                if cid:
                    kind = "sub" if "/subscriptions/" in cid else "mg"
                    self.add_node(cid, kind, (ch or {}).get("name"))
                    self.add_edge(mgid, cid, "Contains")
        elif k == "AZResourceGroup":
            rgid, sid = d.get("id"), d.get("subscriptionId")
            if rgid and sid:
                self.add_node(sid, "sub")
                self.add_edge(sid, rgid, "Contains")
        elif k in NODE_KIND and NODE_KIND[k] in RESOURCE_KINDS:
            rid = d.get("id")
            rgid = d.get("resourceGroupId") or d.get("resourceGroup")
            if rid and rgid:
                self.add_node(rgid, "rg")
                self.add_edge(rgid, rid, "Contains")
            # managed identity → SP
            ident = d.get("identity") or {}
            msi = ident.get("principalId")
            if msi:
                self.add_node(msi, "sp")
                self.add_edge(rid, msi, "HasManagedIdentity")

    def _rolename(self, rid: str) -> str:
        n = self.nodes.get(rid)
        return n["name"] if n and n.get("name") != rid else rid


# ──────────────────────────────────────────────────────────────────────────────
# Anonimizador AZ (reutiliza scrub de bh2graphify)
# ──────────────────────────────────────────────────────────────────────────────
class AZAnonymizer(Anonymizer):
    PREFIXES = {"tenant": "TENANT", "user": "USER", "group": "GROUP", "app": "APP",
                "sp": "SP", "device": "DEV", "role": "ROLE", "builtinrole": "ROLE_KEEP",
                "mg": "MG", "sub": "SUB", "rg": "RG", "vm": "VM", "vmss": "VMSS",
                "kv": "KV", "automation": "AUTO", "function": "FUNC", "logic": "LOGIC",
                "aks": "AKS", "acr": "ACR", "web": "WEB", "object": "OBJ"}

    def alias(self, sid: str, kind: str, real_name: str) -> str:
        if sid in self.map:
            return self.map[sid]["alias"]
        if kind == "builtinrole":
            # nombre estructural (Global Administrator) — preservado
            a = real_name or sid
            self.map[sid] = {"alias": a, "kind": kind, "real": real_name}
            return a
        # registrar dominios del tenant para el scrub
        prefix = self.PREFIXES.get(kind, "OBJ")
        self.counters[prefix] += 1
        a = f"{prefix}_{self.counters[prefix]:04d}"
        self.map[sid] = {"alias": a, "kind": kind, "real": real_name}
        return a

    def register_domains(self, domains: set[str]):
        for dom in domains:
            self._domain_alias(dom)


# ──────────────────────────────────────────────────────────────────────────────
# Build graph (schema node-link graphify)
# ──────────────────────────────────────────────────────────────────────────────
def build_graph(az: AZGraph, anon: AZAnonymizer | None) -> dict:
    def node_id(sid):
        n = az.nodes[sid]
        if anon:
            return anon.alias(sid, n["kind"], n["name"])
        return n["name"] or sid

    if anon:
        anon.register_domains(az.tenant_domains)
        for sid, n in az.nodes.items():
            node_id(sid)
        anon._build_scrub_map()

    id_by_sid = {sid: node_id(sid) for sid in az.nodes}

    nodes, seen = [], set()
    for sid, n in az.nodes.items():
        nid = id_by_sid[sid]
        if nid in seen:
            continue
        seen.add(nid)
        props = {k: v for k, v in n["props"].items()
                 if v is not None and not (isinstance(v, str) and len(v) > 200)}
        if anon:
            props = anon.scrub_props(props)
        node = {"id": nid, "label": nid, "type": n["kind"]}
        node.update(props)
        nodes.append(node)

    links, lseen = [], set()
    for e in az.edges:
        if e["src"] not in az.nodes or e["dst"] not in az.nodes:
            continue
        link = {"source": id_by_sid[e["src"]], "target": id_by_sid[e["dst"]],
                "relation": e["rel"], "weight": 1.0, "confidence": "EXTRACTED"}
        eprops = {k: v for k, v in e["props"].items() if v not in (None, False)}
        if anon:
            eprops = anon.scrub_props(eprops)
        link.update(eprops)
        k = (link["source"], link["target"], link["relation"])
        if k not in lseen:
            lseen.add(k)
            links.append(link)

    return {"directed": True, "multigraph": True,
            "graph": {"source": "azurehound", "anonymized": anon is not None,
                      "node_count": len(nodes), "edge_count": len(links)},
            "nodes": nodes, "links": links}


# ──────────────────────────────────────────────────────────────────────────────
# Attack paths Entra/ARM
# ──────────────────────────────────────────────────────────────────────────────
def attack_paths(graph: dict, max_hops: int = 5, top: int = 15) -> list[dict]:
    adj: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for lk in graph["links"]:
        adj[lk["source"]].append((lk["target"], lk["relation"]))

    node_types = {n["id"]: n.get("type") for n in graph["nodes"]}
    targets = {}
    for n in graph["nodes"]:
        if n.get("type") == "builtinrole" and n["id"] in HIGH_VALUE_ROLES:
            targets[n["id"]] = f"holds {n['id']}"
        elif n.get("type") == "sub":
            targets[n["id"]] = "subscription (Owner/UA-admin control)"
        elif n.get("type") == "mg":
            targets[n["id"]] = "management group (Owner/UA-admin control)"
        elif n.get("type") == "kv":
            targets[n["id"]] = "key vault (access policy/RBAC)"

    results = []
    for start, stype in node_types.items():
        if stype not in ("user", "sp", "group"):
            continue
        dist = {start: 0}
        prev: dict[str, tuple[str, str]] = {}
        q = deque([start])
        while q:
            cur = q.popleft()
            if dist[cur] >= max_hops:
                continue
            for nxt, rel in adj[cur]:
                if nxt in dist:
                    continue
                dist[nxt] = dist[cur] + 1
                prev[nxt] = (cur, rel)
                q.append(nxt)
        hit = sorted(((dist[t], t) for t in targets if t in dist and t != start))
        if not hit:
            continue
        for d, t in hit[:1]:
            hops, cur = [], t
            while cur != start:
                p, rel = prev[cur]
                hops.append(f"{p} -[{rel}]-> {cur}")
                cur = p
            results.append({"from": start, "target": t, "why": targets[t], "hops": d,
                            "path": " | ".join(hops)})
    results.sort(key=lambda r: (r["hops"], r["from"]))
    return results[:top]


# ──────────────────────────────────────────────────────────────────────────────
# Leak check (token-exact; reglas de bh2graphify + roles preservados AZ)
# ──────────────────────────────────────────────────────────────────────────────
def _norm_latin(s: str) -> str:
    from unicodedata import normalize, category
    return "".join(c for c in normalize("NFD", s) if category(c) != "Mn")


def leakage_check(graph: dict, mapping: dict) -> tuple[list[str], list[str]]:
    """Devuelve (hard, soft). Hard = token exacto; soft = multi-palabra.
    Nombres reales que colisionan con roles builtin preservados (p.ej. un user
    llamado "Global Administrator") se ignoran: el token que aparece en el
    grafo es el del rol, no del user. Diacríticos normalizados (español)."""
    blob = _norm_latin(json.dumps(graph, ensure_ascii=False).upper())
    blob = re.sub(r'"[A-Z0-9_\-]+"\s*:', ",", blob)
    # roles builtin preservados por diseño — sus NOMBRES se remueven del blob
    # antes de tokenizar: un grupo llamado "Simulation" no es leak aunque el
    # rol "Attack Simulation Administrator" contenga ese token
    preserved_names = sorted({_norm_latin((m.get("real") or "").strip().upper())
                              for m in mapping.values() if m.get("kind") == "builtinrole"
                              and m.get("real")}, key=len, reverse=True)
    for pn in preserved_names:
        if len(pn) >= 4:
            blob = blob.replace(pn, ",")
    graph_tokens = set(re.split(r"[^A-Z0-9_\-]+", blob))
    for lk in graph.get("links") or []:
        rel = (lk.get("relation") or "").upper()
        graph_tokens.discard(rel)
        # palabras componentes de relations (nombres de roles usados como
        # relation) — un SP llamado "Quota" no es leak por "Quota Request
        # Operator"
        for w in re.split(r"[^A-Z0-9_]+", rel):
            if len(w) >= 4:
                graph_tokens.discard(w)
    graph_tokens -= {"AZUREHOUND", "EXTRACTED", "INFERRED", "TRUE", "FALSE"}
    graph_tokens -= {"USER", "GROUP", "COMPUTER", "DOMAIN", "GPO", "OU", "CONTAINER",
                     "CERTTEMPLATE", "ENTERPRISECA", "ROOTCA", "AICA", "NTAUTHSTORE",
                     "OBJECT", "APP", "SP", "DEVICE", "TENANT", "SUB", "MG", "RG", "VM",
                     "KV", "ACR", "AKS", "WEB", "FUNC", "LOGIC", "AUTO", "VMSS", "ROLE"}
    # valores de operatingsystem (prop técnica genérica, no PII): un device
    # llamado literalmente "Windows" colisiona con el OS string
    graph_tokens -= {"WINDOWS", "MACOS", "LINUX", "ANDROID", "IOS", "IPADOS", "DARWIN"}
    # roles builtin preservados por diseño — sus nombres PUEDE que aparezcan
    preserved_names = {_norm_latin((m.get("real") or "").strip().upper())
                       for m in mapping.values() if m.get("kind") == "builtinrole"}
    graph_tokens = {t for t in graph_tokens if t not in preserved_names}
    leaks, soft = [], []
    for sid, m in mapping.items():
        if m.get("kind") == "builtinrole":
            continue
        alias, real = (m.get("alias") or ""), _norm_latin((m.get("real") or "").strip().upper())
        if not real or real == _norm_latin(sid.upper()) or real == alias.upper():
            continue  # preservado por diseño (builtin roles)
        if real in preserved_names:
            continue  # colisión con nombre de rol builtin — el token es del rol
        base = real.split("@")[0].split("\\")[-1]
        for cand in {base, real}:
            if len(cand) >= 4 and cand in graph_tokens:
                leaks.append(f"{cand} (de {alias})")
        words = [w for w in re.split(r"[\s.]+", base) if len(w) >= 4]
        if len(words) >= 2 and all(w in graph_tokens for w in words) \
                and base not in graph_tokens:
            soft.append(f"{base} (de {alias})")
    return sorted(set(leaks)), sorted(set(soft))


# ──────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(prog="az2graphify")
    ap.add_argument("input", help="archivo JSON AzureHound")
    ap.add_argument("--out", default="graphify-out/graph.json")
    ap.add_argument("--no-anon", action="store_true")
    ap.add_argument("--save-map", metavar="PATH")
    ap.add_argument("--attack-paths", action="store_true")
    ap.add_argument("--max-hops", type=int, default=5)
    args = ap.parse_args()

    az = AZGraph()
    az.parse(Path(args.input))

    anon = None if args.no_anon else AZAnonymizer()
    graph = build_graph(az, anon)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump(graph, f, indent=1, ensure_ascii=False)
    print(f"[+] Escrito {out} ({len(graph['nodes'])} nodos, {len(graph['links'])} links)")

    if anon:
        leaks, soft = leakage_check(graph, anon.map)
        print("[!] POSIBLE LEAK: " + ", ".join(leaks[:10]) if leaks
              else "[+] Leak check OK: ningún nombre real en el grafo")
        if soft:
            print(f"[i] Soft matches multi-palabra (revisar a mano): {soft[:10]}")
        if args.save_map:
            mp = Path(args.save_map)
            with open(mp, "w") as f:
                json.dump({"_warning": "MAPEAR NOMBRES REALES — confidencial",
                           "mapping": anon.map}, f, indent=1)
            mp.chmod(stat.S_IRUSR | stat.S_IWUSR)
            print(f"[+] Mapa de reversión: {mp} (chmod 600)")

    if az.unresolved:
        print(f"[i] Unresolved refs: {dict(az.unresolved)}")

    by_rel = defaultdict(int)
    for lk in graph["links"]:
        by_rel[lk["relation"]] += 1
    print("[*] Edges por relation:")
    for rel, c in sorted(by_rel.items(), key=lambda x: -x[1]):
        print(f"      {rel:22s} {c}")

    if args.attack_paths:
        print("\n[*] Attack paths (targets: roles high-value / subs / MGs / KVs):")
        for r in attack_paths(graph, args.max_hops):
            print(f"  [{r['hops']}h] {r['from']} → {r['target']} ({r['why']})")
            print(f"        {r['path']}")


if __name__ == "__main__":
    main()
