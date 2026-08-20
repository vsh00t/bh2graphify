#!/usr/bin/env python3
"""
bh2graphify — SharpHound JSON → graphify-compatible graph.json (LLM-native) + pseudo-anonimización.

Uso:
    python3 bh2graphify.py INPUT... [opciones]

INPUT: uno o más archivos SharpHound JSON (_users.json, _groups.json, ...) o
       un directorio (se procesan todos los *.json válidos dentro).

Opciones clave:
    --out PATH            output graph.json (default: graphify-out/graph.json)
    --anon                pseudo-anonimizar (default: ON salvo --no-anon)
    --no-anon             mantener nombres reales
    --keep-wellknown      preservar nombres well-known RID (default ON; --drop-wellknown para off)
    --save-map PATH       guardar mapa de reversión (chmod 600)
    --attack-paths        calcular shortest paths hacia DA / ADMINISTRATOR / DCSync
    --max-hops N          límite BFS attack paths (default 6)
"""
from __future__ import annotations

import argparse
import json
import stat
import sys
from collections import defaultdict, deque
from pathlib import Path

# ──────────────────────────────────────────────────────────────────────────────
# Well-known RIDs (estructurales, no PII — preservarlos mantiene el análisis)
# ──────────────────────────────────────────────────────────────────────────────
WELLKNOWN_RIDS = {
    498: "ENTERPRISE_READ_ONLY_DOMAIN_CONTROLLERS",
    500: "ADMINISTRATOR",
    501: "GUEST",
    502: "KRBTGT",
    512: "DOMAIN_ADMINS",
    513: "DOMAIN_USERS",
    514: "DOMAIN_GUESTS",
    515: "DOMAIN_COMPUTERS",
    516: "DOMAIN_CONTROLLERS",
    517: "CERT_PUBLISHERS",
    518: "SCHEMA_ADMINS",
    519: "ENTERPRISE_ADMINS",
    520: "GROUP_POLICY_CREATOR_OWNERS",
    521: "READ_ONLY_DOMAIN_CONTROLLERS",
    522: "CLONEABLE_DOMAIN_CONTROLLERS",
    525: "PROTECTED_USERS",
    526: "KEY_ADMINS",             # Shadow Credentials (msDS-KeyCredentialLink)
    527: "ENTERPRISE_KEY_ADMINS",  # idem, forest-wide
    553: "RAS_SERVERS",
}
WELLKNOWN_SIDS = {
    "S-1-5-11": "AUTHENTICATED_USERS",
    "S-1-5-7": "ANONYMOUS",
    "S-1-1-0": "EVERYONE",
    "S-1-5-32-544": "BUILTIN_ADMINISTRATORS",
    "S-1-5-32-545": "BUILTIN_USERS",
    "S-1-5-32-548": "ACCOUNT_OPERATORS",
    "S-1-5-32-549": "SERVER_OPERATORS",
    "S-1-5-32-550": "PRINT_OPERATORS",
    "S-1-5-32-551": "BACKUP_OPERATORS",
    "S-1-5-32-555": "REMOTE_DESKTOP_USERS",
    "S-1-5-32-556": "NETWORK_CONFIGURATION_OPERATORS",
    "S-1-5-32-557": "DHCP_ADMINISTRATORS",
    "S-1-5-32-573": "EVENT_LOG_READERS",
}
# builtin con prefijo de dominio (S-1-5-21-...-1000+ son RIDs de dominio; builtin son S-1-5-32-*)
BUILTIN_PREFIX = "S-1-5-32"

NODE_KINDS = {"users": "user", "groups": "group", "computers": "computer",
              "domains": "domain", "gpos": "gpo", "ous": "ou",
              "containers": "container",
              "certtemplates": "certtemplate", "enterprisecas": "enterpriseca",
              "rootcas": "rootca", "aiacas": "aiaca", "ntauthstores": "ntauthstore"}

# RightName → relation canónica
ACL_MAP = {
    "genericall": "GenericAll",
    "genericwrite": "GenericWrite",
    "writeowner": "WriteOwner",
    "writedacl": "WriteDacl",
    "writeproperty": "WriteProperty",
    "forcechangepassword": "ForceChangePassword",
    "allextendedrights": "AllExtendedRights",
    "addmember": "AddMember",
    "addself": "AddSelf",
    "enroll": "Enroll",
    "autoenroll": "AutoEnroll",
    "writepkinameflag": "WritePKINameFlag",
    "writepkienrollmentflag": "WritePKIEnrollmentFlag",
    "readgmsapassword": "ReadGMSAPassword",
    "owner": "Owns",
    "owns": "Owns",
    "dcsync": "DCSync",
    "getchanges": "GetChanges",
    "getchangesall": "GetChangesAll",
    "allextendedrights-dcsync": "DCSync",
}
# (RightName contiene alguna de estas + AceType Extended) → DCSync en domain
DCSYNC_RIGHTS = {"getchanges", "getchangesall", "getchangesinfilteredset"}

# Properties seguras por tipo (whitelist técnico; el resto se dropea por PII)
SAFE_PROPS = {
    "enabled", "unconstraineddelegation", "constraineddelegation", "transitivedelegation",
    "dontreqpreauth", "passwordneverexpires", "sensitive", "admincount", "highvalue",
    "haslaps", "trustedtoauth", "resourcebasedconstraineddelegation", "owned",
    "functionallevel", "domainsid", "description_special", "serviceprincipalnames",
    "sam", "domain", "operatingsystem", "osversion", "isdc", "allowdelegation",
    "pwdlastset_epoch", "lastlogon_epoch", "lastlogontimestamp_epoch", "membercount",
    "issecuritygroup", "isaclprotected",
    # ADCS (ESC-relevant)
    "authenticationenabled", "enrolleesuppliessubject", "requiresmanagerapproval",
    "authorizedsignatures", "certificatenameflag", "applicationpolicies",
    "certificateapplicationpolicy", "enrollmentflag", "validityperiod",
    "renewalperiod", "schemaversion", "nosecurityextension", "hasspn", "ekus",
}
EPOCH_PROPS = {"pwdlastset", "lastlogon", "lastlogontimestamp"}


# ──────────────────────────────────────────────────────────────────────────────
# Parsing SharpHound
# ──────────────────────────────────────────────────────────────────────────────
class BHGraph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}          # sid -> {"kind", "name", "props"}
        self.edges: list[dict] = []               # {"src","dst","rel","props"}
        self._edge_seen: set = set()

    def add_node(self, sid: str, kind: str, name: str | None = None, props: dict | None = None):
        if not sid:
            return
        n = self.nodes.setdefault(sid, {"kind": kind, "name": name or sid, "props": {}})
        if kind in ("domain", "gpo", "ou", "container") and n["kind"] == "object":
            n["kind"] = kind
        if name:
            # preferir nombre canónico FQDN (SH v3: "USER@DOM") sobre nombres de sesión
            if not n["name"] or n["name"] == sid or \
               ("@" in name and "@" not in n["name"]):
                n["name"] = name
        if props:
            n["props"].update({k: v for k, v in props.items() if k in SAFE_PROPS})

    def add_edge(self, src: str, dst: str, rel: str, props: dict | None = None):
        if not src or not dst or src == dst:
            return
        key = (src, dst, rel, props.get("is_inherited") if props else None)
        if key in self._edge_seen:
            return
        self._edge_seen.add(key)
        self.edges.append({"src": src, "dst": dst, "rel": rel, "props": props or {}})

    def _resolve(self, ref: dict | str) -> tuple[str | None, str | None]:
        """Extrae (sid, nombre) de una referencia SH (dict o string)."""
        if isinstance(ref, str):
            return ref, None
        if isinstance(ref, dict):
            sid = ref.get("ObjectIdentifier") or ref.get("SID") or ref.get("ObjectID")
            name = ref.get("Name") or ref.get("name") or ref.get("MemberName")
            return sid, name
        return None, None

    def parse_file(self, path: Path):
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                doc = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"  [skip] {path.name}: {e}", file=sys.stderr)
            return
        meta_type = ""
        if isinstance(doc, dict):
            meta_type = (doc.get("meta") or {}).get("type", "")
            items = doc.get("data") or []
        elif isinstance(doc, list):  # algunos zips viejos
            items = doc
        else:
            return
        if not isinstance(items, list):
            return
        kind = NODE_KINDS.get(meta_type, "object")
        fn = getattr(self, f"_parse_{kind}", None) or self._parse_generic
        for item in items:
            if isinstance(item, dict):
                fn(item, kind)
        print(f"  [ok]   {path.name}: {len(items)} items ({meta_type or 'untyped'})")

    # — helpers comunes —
    def _base(self, item: dict, kind: str):
        sid = item.get("ObjectIdentifier") or item.get("ObjectID")
        props = item.get("Properties") or {}
        name = (props.get("name") or props.get("sam") or
                item.get("Name") or sid)
        safe = dict(props)
        for ep in EPOCH_PROPS:
            v = props.get(ep)
            if isinstance(v, (int, float)) and v > 10**12:  # filetime → epoch
                safe[ep + "_epoch"] = int((v - 116444736000000000) / 1e7)
            safe.pop(ep, None)
        self.add_node(sid, kind, name, safe)
        self._parse_aces(item, sid)
        return sid, name

    def _parse_aces(self, item: dict, owner_sid: str):
        for ace in item.get("Aces") or []:
            psid, pname = self._resolve(ace.get("PrincipalSID") or ace)
            if not psid:
                continue
            ptype = (ace.get("PrincipalType") or "").lower()
            self.add_node(psid, "user" if ptype == "user" else "group", pname)
            right = str(ace.get("RightName") or ace.get("Right") or "").strip()
            rl = right.lower().replace(" ", "")
            if rl in ACL_MAP:
                rel = ACL_MAP[rl]
            elif any(d in rl for d in DCSYNC_RIGHTS):
                rel = "DCSync"
            elif rl:
                rel = "Acl_" + rl.title().replace("_", "")
            else:
                continue
            self.add_edge(psid, owner_sid, rel, {
                "is_inherited": bool(ace.get("IsInherited")),
                "ace_type": ace.get("AceType") or "All",
            })

    # — por tipo —
    def _parse_user(self, item, kind):
        sid, _ = self._base(item, "user")
        if not sid:
            return
        pg = item.get("PrimaryGroupSID")
        if pg:
            self.add_node(pg, "group")
            self.add_edge(sid, pg, "MemberOf", {"primary": True})
        # delegación (user → computer)
        for ref in item.get("AllowedToDelegate") or []:
            tsid, tname = self._resolve(ref)
            if tsid:
                self.add_node(tsid, "computer", tname)
                self.add_edge(sid, tsid, "AllowedToDelegate")
        # kerberoastable: SPNTargets o serviceprincipalnames en props
        if item.get("SPNTargets") or (item.get("Properties") or {}).get("serviceprincipalnames"):
            self.nodes[sid]["props"]["hasspn"] = True
        # SPN targets (kerberoastable → servicio)
        for spn in item.get("SPNTargets") or []:
            csid = spn.get("ComputerSID") or spn.get("ComputerId")
            if csid:
                self.add_node(csid, "computer")
                self.add_edge(sid, csid, "SPNTarget",
                              {"service": spn.get("Service"), "port": spn.get("Port")})
        for sh in item.get("HasSIDHistory") or []:
            ssid, sname = self._resolve(sh)
            if ssid:
                self.add_node(ssid, "user", sname)
                self.add_edge(sid, ssid, "HasSIDHistory")

    def _parse_group(self, item, kind):
        sid, _ = self._base(item, "group")
        if not sid:
            return
        pg = item.get("PrimaryGroupSID")
        if pg:
            self.add_edge(sid, pg, "MemberOf", {"primary": True})
        for m in item.get("Members") or []:
            msid, mname = self._resolve(m)
            if not msid:
                continue
            mk = {"user": "user", "computer": "computer", "group": "group",
                  "localgroup": "group"}.get(
                (m.get("ObjectType") or "").lower() if isinstance(m, dict) else "", "user")
            self.add_node(msid, mk, mname)
            self.add_edge(msid, sid, "MemberOf")

    @staticmethod
    def _results_list(v):
        """SH v3 envuelve colecciones como {Collected, FailureReason, Results}."""
        if isinstance(v, dict):
            return v.get("Results") or []
        return v or []

    # GPOChanges: (clave SharpHound v3, alias legacy, relation)
    _GPO_CATS = (("LocalAdmins", None, "AdminTo"),
                 ("RemoteDesktopUsers", "RDPUsers", "CanRDP"),
                 ("PSRemoteUsers", None, "CanPSRemote"),
                 ("DcomUsers", None, "CanDCOM"))

    @staticmethod
    def _dom_prefix(sid: str) -> str:
        """S-1-5-21-A-B-C de un SID de dominio (para agrupar/filtrar por dominio)."""
        if not sid:
            return ""
        base = sid[sid.rfind("S-1-"):] if "S-1-" in sid else sid
        parts = base.split("-")
        return "-".join(parts[:7]) if len(parts) >= 8 and \
            parts[:4] == ["S", "1", "5", "21"] else base

    def _gpo_affected(self, gpc: dict) -> list[str] | None:
        """SIDs de las computadoras afectadas si SharpHound las trae (v3);
        None si el objeto GPOChanges no incluye AffectedComputers."""
        aff = gpc.get("AffectedComputers")
        if aff is None:
            return None
        out = []
        for c in aff:
            csid, cname = self._resolve(c)
            if csid:
                self.add_node(csid, "computer", cname)
                out.append(csid)
        return out

    def _apply_gpochanges(self, gpc: dict, targets, via: str):
        """Enlaza principals de GPOChanges (LocalAdmins/RDP/PSRemote/DCOM) a los
        `targets` (SIDs de computadoras; lista o callable perezoso) con la relation
        correspondiente. Acepta la clave real de SharpHound y el alias legacy."""
        if not gpc:
            return
        for key, legacy, rel in self._GPO_CATS:
            refs = gpc.get(key) or (gpc.get(legacy) if legacy else None)
            for ref in refs or []:
                psid, pname = self._resolve(ref)
                if not psid:
                    continue
                self.add_node(psid, "user", pname)
                tlist = targets() if callable(targets) else targets
                for nid in tlist:
                    if self.nodes.get(nid, {}).get("kind") == "computer":
                        self.add_edge(psid, nid, rel, {"via": via})

    def _parse_computer(self, item, kind):
        sid, name = self._base(item, "computer")
        if not sid:
            return
        pg = item.get("PrimaryGroupSID")
        if pg:
            self.add_node(pg, "group")
            self.add_edge(sid, pg, "MemberOf", {"primary": True})
        # sesiones (SH v3: dict {Collected, FailureReason, Results})
        for sess_key, rel in (("Sessions", "HasSession"), ("PrivilegedSessions", "HasPrivSession")):
            for s in self._results_list(item.get(sess_key)):
                usid = s.get("UserID") or s.get("UserSID")
                if not usid and s.get("User"):
                    usid = self._fuzzy_add_user(s["User"])
                if usid:
                    self.add_node(usid, "user", s.get("User"))
                    self.add_edge(usid, sid, rel)
        # grupos locales → AdminTo / CanRDP / CanPSRemote / CanDCOM
        for lg in item.get("LocalGroups") or []:
            gname = str(lg.get("Name") or "").upper()
            rel = None
            if "ADMINISTRATOR" in gname:
                rel = "AdminTo"
            elif "REMOTE DESKTOP" in gname or gname == "RDP":
                rel = "CanRDP"
            elif "REMOTE MANAGEMENT" in gname or "WINRM" in gname:
                rel = "CanPSRemote"
            elif "DISTRIBUTED COM" in gname or "DCOM" in gname:
                rel = "CanDCOM"
            if not rel:
                continue
            for m in (lg.get("Results") or lg.get("Members") or []):
                msid, mname = self._resolve(m)
                if msid:
                    mk = {"user": "user", "computer": "computer", "group": "group",
                          "localgroup": "group"}.get(
                        (m.get("ObjectType") or "").lower() if isinstance(m, dict) else "", "user")
                    self.add_node(msid, mk, mname)
                    self.add_edge(msid, sid, rel, {"via": lg.get("Name")})
        # delegación y RBCD
        for ref in item.get("AllowedToDelegate") or []:
            tsid, tname = self._resolve(ref)
            if tsid:
                self.add_node(tsid, "computer", tname)
                self.add_edge(sid, tsid, "AllowedToDelegate")
        for ref in item.get("AllowedToAct") or []:
            tsid, tname = self._resolve(ref)
            if tsid:
                self.add_node(tsid, "user", tname)
                self.add_edge(tsid, sid, "AllowedToAct")

    def _parse_domain(self, item, kind):
        sid, name = self._base(item, "domain")
        if not sid:
            return
        for t in item.get("Trusts") or []:
            tsid = t.get("TargetDomainSid") or t.get("TargetDomainSID")
            tname = t.get("TargetDomainName")
            if not tsid and tname:
                tsid = "TRUST::" + str(tname).upper()
            if tsid:
                self.add_node(tsid, "domain", tname)
                self.add_edge(sid, tsid, "Trusts", {
                    "direction": t.get("TrustDirection"),
                    "transitive": t.get("IsTransitive"),
                    "sidfiltering": t.get("SidFilteringEnabled"),
                })
        for c in item.get("ChildObjects") or []:
            csid, cname = self._resolve(c)
            if csid:
                ck = {"User": "user", "Group": "group", "Computer": "computer",
                      "OU": "ou", "GPO": "gpo", "Container": "container"}.get(
                    (c.get("ObjectType") or "") if isinstance(c, dict) else "", "object")
                self.add_node(csid, ck, cname)
                self.add_edge(sid, csid, "Contains")
        # GPOChanges a nivel de dominio. SharpHound v3 trae AffectedComputers:
        # úsala (verdad de campo). Si no está, restringir al MISMO dominio —
        # nunca a computers de otros dominios de la colección, o se fabrican
        # AdminTo cross-domain (falsos positivos en attack paths multi-dominio).
        gpc = item.get("GPOChanges") or {}
        affected = self._gpo_affected(gpc)
        if affected is not None:
            self._apply_gpochanges(gpc, affected, "GPOChanges")
        elif gpc:
            dom = self._dom_prefix(sid)
            self._apply_gpochanges(
                gpc, lambda: [nid for nid, n in self.nodes.items()
                              if n["kind"] == "computer" and self._dom_prefix(nid) == dom],
                "GPOChanges(domain)")

    def _parse_certtemplate(self, item, kind):
        self._base(item, "certtemplate")

    def _parse_enterpriseca(self, item, kind):
        sid, _ = self._base(item, "enterpriseca")
        if not sid:
            return
        h = item.get("HostingComputer")
        if isinstance(h, dict):
            hsid, hname = self._resolve(h)
            if hsid:
                self.add_node(hsid, "computer", hname)
                self.add_edge(hsid, sid, "HostsCA")
        for t in item.get("EnabledCertTemplates") or []:
            tsid, _ = self._resolve(t)
            if tsid:
                self.add_node(tsid, "certtemplate")
                self.add_edge(sid, tsid, "EnabledTemplate")

    def _parse_gpo(self, item, kind):
        sid, _ = self._base(item, "gpo")
        if not sid:
            return
        for ao in item.get("AffectedObjects") or []:
            asid, aname = self._resolve(ao)
            if asid:
                self.add_edge(sid, asid, "GpLink")

    def _parse_ou(self, item, kind):
        return self._parse_container(item, "ou")

    def _parse_container(self, item, kind):
        sid, _ = self._base(item, kind)
        if not sid:
            return
        for key in ("ChildObjects", "Contains"):
            for c in item.get(key) or []:
                csid, cname = self._resolve(c)
                if csid:
                    self.add_edge(sid, csid, "Contains")
        for lk in item.get("Links") or []:
            gsid = lk.get("GUID") or lk.get("ObjectIdentifier")
            if gsid:
                self.add_node(gsid, "gpo")
                self.add_edge(gsid, sid, "GpLink", {"enforced": bool(lk.get("IsEnforced"))})
        self._parse_gpochanges_direct(item)

    def _parse_gpochanges_direct(self, item):
        gpc = item.get("GPOChanges") or {}
        ou_sid = item.get("ObjectIdentifier")
        if not gpc or not ou_sid:
            return
        # AffectedComputers (v3) es la verdad de campo; si no está, caer a los
        # computers descendientes de esta OU (nunca a todo el grafo).
        affected = self._gpo_affected(gpc)
        targets = affected if affected is not None else \
            (lambda: [nid for nid in self._descendants(ou_sid)
                      if self.nodes.get(nid, {}).get("kind") == "computer"])
        self._apply_gpochanges(gpc, targets, "GPOChanges(OU)")

    def _descendants(self, sid: str, depth: int = 3) -> list[str]:
        out, frontier, _d = [], [sid], 0
        while frontier and _d < depth:
            nxt = []
            for e in self.edges:
                if e["src"] in frontier and e["rel"] == "Contains":
                    nxt.append(e["dst"])
            out.extend(nxt)
            frontier, _d = nxt, _d + 1
        return out

    def _parse_generic(self, item, kind):
        self._base(item, kind)

    _fuzzy_users: dict[str, str] = defaultdict(lambda: None)

    def _fuzzy_add_user(self, username: str) -> str:
        """Usuarios vistos solo por nombre en Sessions — id sintético."""
        if username not in self._fuzzy_users:
            self._fuzzy_users[username] = "NAME::" + username.upper()
        self.add_node(self._fuzzy_users[username], "user", username)
        return self._fuzzy_users[username]


# ──────────────────────────────────────────────────────────────────────────────
# Pseudo-anonimización
# ──────────────────────────────────────────────────────────────────────────────
WELLKNOWN_DOMAIN_PARTS = {"USERS", "COMPUTERS", "DOMAIN CONTROLLERS", "ADMINSDROP",
                          "SYSTEM", "MICROSOFT", "PROGRAM DATA", "LOSTANDFOUND"}

class Anonymizer:
    def __init__(self, keep_wellknown: bool = True):
        self.keep_wellknown = keep_wellknown
        self.counters: dict[str, int] = defaultdict(int)
        self.map: dict[str, dict] = {}          # sid -> {"alias","kind","real"}
        self.name_map: dict[str, str] = {}      # nombre real -> alias
        self._scrub_map: dict[str, str] = {}
        self._dom_alias_by_sid: dict[str, str] = {}
        self._scrub_re = None

    def alias(self, sid: str, kind: str, real_name: str) -> str:
        if sid in self.map:
            return self.map[sid]["alias"]
        # SH v3: SIDs con prefijo de dominio ("PHANTOM.CORP-S-1-5-32-544") → SID puro
        base = sid
        if not base.startswith("S-1-") and "S-1-" in base:
            base = base[base.rfind("S-1-"):]
        # well-known SIDs absolutos
        if base in WELLKNOWN_SIDS:
            a = WELLKNOWN_SIDS[base]
            self.map[sid] = {"alias": a, "kind": kind, "real": real_name}
            return a
        # well-known RIDs de dominio (S-1-5-21-x-y-z-<RID>)
        parts = base.split("-")
        if len(parts) == 8 and parts[:4] == ["S", "1", "5", "21"] and parts[7].isdigit():
            rid = int(parts[7]) if int(parts[7]) < 1000 else None
        else:
            rid = None
        if rid is not None and rid in WELLKNOWN_RIDS and self.keep_wellknown:
            a = WELLKNOWN_RIDS[rid]
            # multi-dominio: cualificar con el alias del dominio para no colapsar
            # los DOMAIN_ADMINS/ADMINISTRATOR de dominios distintos en un nodo
            dom_alias = self._dom_alias_by_sid.get("-".join(parts[:7]))
            if dom_alias:
                a = f"{a}@{dom_alias}"
            self.map[sid] = {"alias": a, "kind": kind, "real": real_name}
            return a
        # dominios: derivar alias del FQDN completo (DOM_01, DOM_02...)
        if kind == "domain":
            key = ("domain", (real_name or sid).lower()) if real_name else ("domain", sid.lower())
            if key not in self.name_map:
                self.counters["domain"] += 1
                self.name_map[key] = f"DOM_{self.counters['domain']:02d}"
            a = self.name_map[key]
            self._dom_alias_by_sid[sid] = a
            self.map[sid] = {"alias": a, "kind": kind, "real": real_name}
            return a
        # genérico por categoría
        prefix = {"user": "USER", "group": "GROUP", "computer": "COMP",
                  "gpo": "GPO", "ou": "OU", "container": "CN", "domain": "DOM",
                  "certtemplate": "TPL", "enterpriseca": "ECA", "rootca": "RCA",
                  "aiaca": "AICA", "ntauthstore": "NTAUTH",
                  "object": "OBJ"}.get(kind, "OBJ")
        # DCs marcados como tales (útil para análisis, no PII)
        if kind == "computer" and real_name and real_name.upper().startswith(("DC", "SRV-DC")):
            self.counters["dc"] += 1
            a = f"DC_{self.counters['dc']:02d}"
        else:
            self.counters[prefix] += 1
            a = f"{prefix}_{self.counters[prefix]:04d}"
        # computadoras: preservar el dominio anonimizado como sufijo
        if kind == "computer" and real_name and "." in real_name:
            dom_real = real_name.split(".", 1)[1]
            dom_alias = self._domain_alias(dom_real)
            a = f"{a}.{dom_alias}"
        self.map[sid] = {"alias": a, "kind": kind, "real": real_name}
        return a

    def _domain_alias(self, dom_real: str) -> str:
        key = ("domain", dom_real.lower())
        if key not in self.name_map:
            self.counters["domain"] += 1
            self.name_map[key] = f"DOM_{self.counters['domain']:02d}"
        return self.name_map[key]


    def scrub(self, value):
        """Reemplaza nombres reales por alias dentro de strings de props (case-insensitive).
        Un solo regex alternante precompilado (longest-first) — O(1) pasadas por string,
        no O(n) re.sub por entrada del mapa."""
        if not isinstance(value, str):
            return value
        if self._scrub_re is not None:
            return self._scrub_re.sub(
                lambda m: self._scrub_map.get(m.group(0).upper(), m.group(0)), value)
        return value

    def _build_scrub_map(self):
        # real_name (upper) → alias; orden de aplicación: más largo primero
        m = {}
        for sid, entry in self.map.items():
            real = (entry.get("real") or "").strip()
            if not real or real == sid or len(real) < 4:
                continue
            up = real.upper()
            m[up] = entry["alias"]
            # FQDN estilo nombre@DOMINIO o nombre.DOMINIO
            base = up.split("@")[0].split(".")[0]
            if base and base not in m:
                m[base] = entry["alias"].split(".")[0]
            # sufijo de dominio completo (CORP.LOCAL → DOM_01)
            if "@" in up or "." in up:
                suffix = up.split("@")[-1] if "@" in up else ".".join(up.split(".")[1:])
                if suffix and suffix not in m:
                    m[suffix] = self._domain_alias(suffix)
        self._scrub_map = m
        # regex alternante único (longest-first preserva "match más largo gana")
        import re
        pats = sorted(m, key=len, reverse=True)
        self._scrub_re = re.compile("|".join(re.escape(p) for p in pats),
                                    flags=re.IGNORECASE) if pats else None

    def scrub_props(self, props: dict) -> dict:
        out = {}
        for k, v in props.items():
            if isinstance(v, str):
                out[k] = self.scrub(v)
            elif isinstance(v, list):
                out[k] = [self.scrub(x) for x in v]
            else:
                out[k] = v
        return out


def build_graph(bh: BHGraph, anon: Anonymizer | None) -> dict:
    def node_id(sid: str) -> str:
        n = bh.nodes[sid]
        if anon:
            return anon.alias(sid, n["kind"], n["name"])
        return n["name"] or sid

    # 1ª pasada: alias de dominios PRIMERO (RIDs well-known se cualifican con
    # DOM_NN; sin esto, multi-dominio colapsa los DA de N dominios en 1 nodo)
    if anon:
        for sid, n in bh.nodes.items():
            if n["kind"] == "domain":
                anon.alias(sid, n["kind"], n["name"])
    id_by_sid = {sid: node_id(sid) for sid in bh.nodes}
    if anon:
        anon._build_scrub_map()

    nodes = []
    for sid, n in bh.nodes.items():
        nid = id_by_sid[sid]
        props = {k: v for k, v in n["props"].items()
                 if v is not None and not (isinstance(v, str) and len(v) > 200)}
        if anon:
            props = anon.scrub_props(props)
            props.pop("sam", None)  # derivada del nombre real; el alias la reemplaza
        node = {"id": nid, "label": nid, "type": n["kind"]}
        if n["kind"] == "user":
            node["kerberoastable"] = bool(n["props"].get("serviceprincipalnames"))
        node.update(props)
        nodes.append(node)

    # dedup por id (alias colisionan solo si el mismo objeto aparece 2 veces)
    seen, final_nodes = set(), []
    for nd in nodes:
        if nd["id"] not in seen:
            seen.add(nd["id"])
            final_nodes.append(nd)

    links = []
    for e in bh.edges:
        if e["src"] not in bh.nodes or e["dst"] not in bh.nodes:
            continue
        link = {"source": id_by_sid[e["src"]], "target": id_by_sid[e["dst"]],
                "relation": e["rel"], "weight": 1.0, "confidence": "EXTRACTED"}
        eprops = {k: v for k, v in e["props"].items() if v not in (None, False)}
        if anon:
            eprops = anon.scrub_props(eprops)  # via/service pueden llevar nombres reales
        link.update(eprops)
        links.append(link)

    # dedup (alias pueden colapsar multi-edges del mismo par+rel)
    lseen, final_links = set(), []
    for lk in links:
        k = (lk["source"], lk["target"], lk["relation"])
        if k not in lseen:
            lseen.add(k)
            final_links.append(lk)

    return {
        "directed": True,
        "multigraph": True,
        "graph": {"source": "sharphound", "anonymized": anon is not None,
                  "node_count": len(final_nodes), "edge_count": len(final_links)},
        "nodes": final_nodes,
        "links": final_links,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Attack paths (BFS dirigido; HasSession/Contains/GpLink reversibles)
# ──────────────────────────────────────────────────────────────────────────────
REVERSIBLE = {"HasSession", "HasPrivSession"}

def attack_paths(graph: dict, max_hops: int = 6, top: int = 12) -> list[dict]:
    # Grafo transpuesto (predecesores). Un solo BFS inverso por target — O(T·(V+E))
    # en vez de un BFS forward por nodo — O(V·(V+E)). Misma salida: shortest paths
    # dirigidos, con edges reversibles (HasSession/HasPrivSession) expandidos igual.
    radj: dict[str, list[tuple[str, str, bool]]] = defaultdict(list)
    for lk in graph["links"]:
        radj[lk["target"]].append((lk["source"], lk["relation"], False))
        if lk["relation"] in REVERSIBLE:
            radj[lk["source"]].append((lk["target"], lk["relation"], True))

    node_types = {n["id"]: n.get("type") for n in graph["nodes"]}
    # targets de alto valor
    targets = {}
    for n in graph["nodes"]:
        nid_u = n["id"].upper()
        if any(x in nid_u for x in ("DOMAIN_ADMINS", "DOMAIN ADMINS",
                                    "ENTERPRISE_ADMINS", "ENTERPRISE ADMINS")):
            targets[n["id"]] = f"member of {n['id']}"
        elif n["id"] == "ADMINISTRATOR" or nid_u.startswith("ADMINISTRATOR@"):
            targets[n["id"]] = "built-in Administrator (RID 500)"
        elif n.get("type") == "domain":
            targets[n["id"]] = "domain obj (DCSync potential)"
    # dcsync directo: AllExtendedRights/GetChanges* hacia dominio
    for lk in graph["links"]:
        if lk["relation"] in ("DCSync", "GetChangesAll", "AllExtendedRights") \
                and node_types.get(lk["target"]) == "domain":
            targets[lk["source"]] = "DCSync rights on domain"

    # BFS inverso desde cada target: dist_by_t[t][n] = coste del shortest path n→t;
    # prev_by_t[t][n] = (siguiente nodo hacia t, rel, rev) → paso forward n -[rel]-> nxt
    dist_by_t: dict[str, dict[str, int]] = {}
    prev_by_t: dict[str, dict[str, tuple[str, str, bool]]] = {}
    for t in targets:
        dist = {t: 0}
        prev: dict[str, tuple[str, str, bool]] = {}
        q = deque([t])
        while q:
            cur = q.popleft()
            if dist[cur] >= max_hops:
                continue
            for pnode, rel, rev in radj.get(cur, ()):  # pnode -[rel]-> cur (forward)
                if pnode in dist:
                    continue
                dist[pnode] = dist[cur] + 1
                prev[pnode] = (cur, rel, rev)
                q.append(pnode)
        dist_by_t[t] = dist
        prev_by_t[t] = prev

    wk_names = set(WELLKNOWN_RIDS.values()) | set(WELLKNOWN_SIDS.values())
    results = []
    for start in node_types:
        if node_types.get(start) not in ("user", "group"):
            continue
        if start in targets and "member of" in targets[start]:
            continue  # ya es DA — path trivial
        # starts estructurales (DA/EA/DC/BUILTIN/KRBTGT/ADMINISTRATOR/...): triviales
        if start.upper() in wk_names or start.upper().split("@")[0] in wk_names:
            continue
        hit = sorted((dist_by_t[t][start], t) for t in targets
                     if start in dist_by_t[t] and t != start)
        if not hit:
            continue
        best_d = hit[0][0]
        for d, t in hit[:2]:  # hasta 2 targets al mismo coste mínimo
            if d > best_d:
                break
            hops, cur = [], start
            while cur != t:
                nxt, rel, rev = prev_by_t[t][cur]
                hops.append(f"{cur} -[{rel}{'↩' if rev else ''}]-> {nxt}" if rev
                            else f"{cur} -[{rel}]-> {nxt}")
                cur = nxt
            results.append({"from": start, "target": t,
                            "why": targets[t], "hops": d,
                            "path": " | ".join(hops)})
    results.sort(key=lambda r: (r["hops"], r["from"]))
    return results[:top]


# ──────────────────────────────────────────────────────────────────────────────
# Leakage check: ningún nombre real debe aparecer en el grafo anonimizado
# ──────────────────────────────────────────────────────────────────────────────
def _norm_latin(s: str) -> str:
    """Strip diacríticos (á→a, ñ→n) para comparar tokens con data en español."""
    import unicodedata
    return "".join(c for c in unicodedata.normalize("NFD", s)
                   if unicodedata.category(c) != "Mn")


def leakage_check(graph: dict, mapping: dict) -> tuple[list[str], list[str]]:
    """Detección de tokens exactos: nombre base completo del objeto real
    (ej SERVER_ADMINS, HELPDESK1) apareciendo como token en el grafo.

    Devuelve (leaks_hard, leaks_soft):
    - hard: nombre completo como token exacto (falla el build)
    - soft: nombres multi-palabra donde TODAS las palabras (len>=4) aparecen
      como tokens — puede ser coincidencia, revisar a mano (data en español
      trae nombres tipo "María José Gómez" que jamás matchean como un token)

    Falsos positivos eliminados (lecciones de datos reales):
    - keys JSON (TARGET/SOURCE/RELATION son nombres de campo, no contenido)
    - nombres de relations (un user real llamado "addself" colisiona con la
      relation AddSelf y no es leak)
    - graph.source ("sharphound") — metadata, no contenido
    - tokens preservados (ADMINISTRATOR...) — by-design aunque un template
      built-in se llame literalmente "Administrator"
    - diacríticos: blob y candidatos se normalizan sin acentos para que
      "MARÍA" sea comparable con "MARIA"
    """
    import re
    blob = _norm_latin(json.dumps(graph, ensure_ascii=False).upper())
    blob = re.sub(r'"[A-Z0-9_\-]+"\s*:', ",", blob)  # quitar keys JSON
    graph_tokens = set(re.split(r"[^A-Z0-9_\-]+", blob))
    for lk in graph.get("links") or []:
        graph_tokens.discard((lk.get("relation") or "").upper())
    graph_tokens -= {"SHARPHOUND", "EXTRACTED", "INFERRED", "TRUE", "FALSE"}
    # valores schema: type de nodo ("user"/"group"/...) son valores de campo, no PII
    graph_tokens -= {"USER", "GROUP", "COMPUTER", "DOMAIN", "GPO", "OU", "CONTAINER",
                     "CERTTEMPLATE", "ENTERPRISECA", "ROOTCA", "AICA", "NTAUTHSTORE", "OBJECT"}
    preserved = set(WELLKNOWN_RIDS.values()) | set(WELLKNOWN_SIDS.values())
    # cualquier token cuyo base sea well-known preservado es by-design
    graph_tokens = {t for t in graph_tokens if t.split("@")[0] not in preserved}
    leaks, soft = [], []
    for sid, m in mapping.items():
        alias = m.get("alias") or ""
        if alias in preserved or alias.split("@")[0] in preserved:
            continue  # nombres preservados por diseño (posiblemente cualificados)
        real = _norm_latin((m.get("real") or "").strip().upper())
        if not real or real == _norm_latin(sid.upper()):
            continue
        # nombre base: sin dominio, sin DN — token exacto
        base = real.split("@")[0].split("\\")[-1]
        for cand in {base, real}:
            if len(cand) >= 4 and cand in graph_tokens:
                leaks.append(f"{cand} (de {m['alias']})")
        # soft: multi-palabra, todas las palabras >=4 chars presentes
        words = [w for w in re.split(r"[\s.]+", base) if len(w) >= 4]
        if len(words) >= 2 and all(w in graph_tokens for w in words) \
                and base not in graph_tokens:
            soft.append(f"{base} (de {m['alias']})")
    return sorted(set(leaks)), sorted(set(soft))


# ──────────────────────────────────────────────────────────────────────────────
# ADCS quick wins: certtemplates ESC1/ESC2 con Enroll de principals
# ──────────────────────────────────────────────────────────────────────────────
def adcs_quickwins(graph: dict) -> list[dict]:
    enroll: dict[str, set] = defaultdict(set)
    for lk in graph.get("links") or []:
        if lk.get("relation") in ("Enroll", "AutoEnroll"):
            enroll[lk["target"]].add(lk["source"])
    wk_names = set(WELLKNOWN_RIDS.values()) | set(WELLKNOWN_SIDS.values())
    out = []
    for n in graph.get("nodes") or []:
        if n.get("type") != "certtemplate":
            continue
        def _blob(*keys):
            parts = []
            for k in keys:
                v = n.get(k)
                parts += v if isinstance(v, list) else [str(v or "")]
            return " ".join(parts).upper()
        pols = _blob("applicationpolicies")
        eku_blob = _blob("applicationpolicies", "certificateapplicationpolicy", "ekus")
        esc1 = (bool(n.get("enrolleesuppliessubject")) and n.get("authenticationenabled")
                and not n.get("requiresmanagerapproval") and not n.get("authorizedsignatures"))
        esc2 = ("ANY PURPOSE" in pols and n.get("authenticationenabled")
                and not n.get("requiresmanagerapproval"))
        # ESC3: Certificate Request Agent (enrollment agent) sin aprobación
        esc3 = (("CERTIFICATE REQUEST AGENT" in eku_blob
                 or "1.3.6.1.4.1.311.20.2.1" in eku_blob)
                and not n.get("requiresmanagerapproval"))
        if not (esc1 or esc2 or esc3):
            continue
        who = sorted(w for w in enroll.get(n["id"], [])
                     if w.upper().split("@")[0] not in wk_names)
        wk_who = sorted(w for w in enroll.get(n["id"], [])
                        if w.upper().split("@")[0] in wk_names)
        tag = "+".join(t for t, ok in (("ESC1", esc1), ("ESC2", esc2), ("ESC3", esc3)) if ok)
        out.append({"template": n["id"], "esc": tag, "enroll": who, "wk_enroll": wk_who})
    out.sort(key=lambda r: (-len(r["enroll"]), r["template"]))
    return out


# CA con control de escritura/gestión = ESC7 (ManageCA/ManageCertificates) o
# toma directa del objeto CA (GenericAll/WriteDacl/WriteOwner/Owns).
ESC7_RELS = {"Acl_Manageca", "Acl_Managecertificates", "GenericAll",
             "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "WritePKIEnrollmentFlag",
             "WritePKINameFlag"}


def adcs_ca_findings(graph: dict) -> list[dict]:
    ca_ids = {n["id"] for n in graph.get("nodes") or []
              if n.get("type") in ("enterpriseca", "rootca")}
    wk_names = set(WELLKNOWN_RIDS.values()) | set(WELLKNOWN_SIDS.values())
    by_ca: dict[str, list] = defaultdict(list)
    for lk in graph.get("links") or []:
        if lk.get("target") in ca_ids and lk.get("relation") in ESC7_RELS:
            src = lk["source"]
            tag = "ESC7" if lk["relation"].lower() in (
                "acl_manageca", "acl_managecertificates") else "CA-takeover"
            by_ca[lk["target"]].append({
                "who": src, "rel": lk["relation"], "esc": tag,
                "wellknown": src.upper().split("@")[0] in wk_names})
    return [{"ca": ca, "controllers": ctrl} for ca, ctrl in sorted(by_ca.items())]


def re_split(name: str) -> list[str]:
    import re
    raw = name.replace("@", ".").replace(",", ".").replace("=", ".")
    return [p for p in re.split(r"[.\-_\s\\]+", raw) if p]


# ──────────────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(prog="bh2graphify")
    ap.add_argument("inputs", nargs="+", help="archivos JSON SharpHound o directorios")
    ap.add_argument("--out", default="graphify-out/graph.json")
    ap.add_argument("--no-anon", action="store_true", help="sin anonimización")
    ap.add_argument("--drop-wellknown", action="store_true",
                    help="anonimizar también well-known RIDs")
    ap.add_argument("--save-map", metavar="PATH", help="guardar mapa reversión (600)")
    ap.add_argument("--attack-paths", action="store_true")
    ap.add_argument("--max-hops", type=int, default=6)
    args = ap.parse_args()

    files: list[Path] = []
    for i in args.inputs:
        p = Path(i)
        if p.is_dir():
            files += sorted(p.glob("*.json"))
        elif p.is_file():
            files.append(p)
        else:
            print(f"[!] no existe: {i}", file=sys.stderr)
    if not files:
        sys.exit("[!] sin archivos de entrada")

    print(f"[*] Parseando {len(files)} archivo(s) SharpHound…")
    bh = BHGraph()
    for f in files:
        bh.parse_file(f)
    print(f"[*] Nodos: {len(bh.nodes)} | edges: {len(bh.edges)}")

    anon = None
    if not args.no_anon:
        anon = Anonymizer(keep_wellknown=not args.drop_wellknown)

    graph = build_graph(bh, anon)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        json.dump(graph, f, indent=1, ensure_ascii=False)
    print(f"[+] Escrito {out} ({len(graph['nodes'])} nodos, {len(graph['links'])} links)")

    if anon:
        leaks, soft = leakage_check(graph, anon.map)
        if leaks:
            print(f"[!] POSIBLE LEAK de nombres reales: {leaks[:10]}")
        else:
            print("[+] Leak check OK: ningún nombre real en el grafo")
        if soft:
            print(f"[i] Soft matches multi-palabra (revisar a mano): {soft[:10]}")
        if args.save_map:
            mp = Path(args.save_map)
            with open(mp, "w") as f:
                json.dump({"_warning": "MAPEAR NOMBRES REALES — tratar como confidencial",
                           "mapping": anon.map}, f, indent=1)
            mp.chmod(stat.S_IRUSR | stat.S_IWUSR)
            print(f"[+] Mapa de reversión: {mp} (chmod 600)")
        else:
            print("[i] Mapa de reversión NO guardado (usa --save-map si lo necesitas)")

    # resumen por relation
    by_rel = defaultdict(int)
    for lk in graph["links"]:
        by_rel[lk["relation"]] += 1
    print("[*] Edges por relation:")
    for rel, c in sorted(by_rel.items(), key=lambda x: -x[1]):
        print(f"      {rel:24s} {c}")

    if args.attack_paths:
        print("\n[*] Attack paths (shortest, top):")
        for r in attack_paths(graph, args.max_hops):
            print(f"  [{r['hops']}h] {r['from']} → {r['target']} ({r['why']})")
            print(f"        {r['path']}")
        adcs = adcs_quickwins(graph)
        if adcs:
            print(f"\n[*] ADCS quick wins ({len(adcs)} templates ESC1/ESC2):")
            for a in adcs[:15]:
                print(f"  [{a['esc']}] {a['template']}")
                if a["enroll"]:
                    print(f"        Enroll: {', '.join(a['enroll'][:8])}")
                elif a["wk_enroll"]:
                    print(f"        Enroll (well-known): {', '.join(a['wk_enroll'][:8])}")


if __name__ == "__main__":
    main()
