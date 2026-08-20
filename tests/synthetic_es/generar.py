#!/usr/bin/env python3
"""
generar.py — Datasets sintéticos en ESPAÑOL para regression de bh2graphify/az2graphify.

5 casos, cada uno con estilos de naming distintos (como se ve con data real de
clientes hispanohablantes) y edge cases de data real:

  ds1_corp_hispana    AD  — separadores: puntos y guiones bajos (jperez, m.jimenez_lopez)
  ds2_financiera      AD  — separadores: espacios y apóstrofes ("María Fernanda López",
                            "Juan José O'Connor"); cadena vía HasSession reversible; ADCS ESC1
  ds3_sector_publico  AD  — extremos: ñ, ¿?, Nº, em-dash, dominio con guion, colisiones
                            (user "target", "user", grupo "Administrator", template "Administrator")
  ds4_az_corporativo  AZ  — tenant español normal, dynamic groups, MSI, KeyVault, jerarquía MG→sub→RG
  ds5_az_edge         AZ  — colisiones ("USER 001", user "Global Administrator"), SP sin nombre,
                            appId fantasma (unresolved), rol custom, credenciales en SP

Cada dataset planta CADENAS DE ATAQUE CONOCIDAS (pitfall #12: "corre sin crash"
no es validación). Las expectativas viven en validar.py.

Uso:  python3 generar.py   (escribe ds_*/ dentro de este directorio)
"""
import json
import os
from pathlib import Path

# Destino configurable: validar.py fija BH2G_SYNTH_OUT a un tmpdir para que la
# suite sea hermética (no sobrescribe nada versionado). Sin la env var, escribe
# junto a este archivo (uso manual: `python3 generar.py`).
OUT = Path(os.environ.get("BH2G_SYNTH_OUT") or Path(__file__).parent)

def write(path: Path, meta_type: str, items: list):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"meta": {"type": meta_type, "count": len(items)}, "data": items},
                  f, ensure_ascii=False, indent=1)

def ace(psid, ptype, right, inherited=False):
    return {"PrincipalSID": psid, "PrincipalType": ptype, "RightName": right,
            "IsInherited": inherited, "AceType": "All"}


# ═════════════════════════════════════════════════════════════════════════════
# DS1 — CORP HISPANA (puntos y guiones bajos)
# Dominio EMPRESA.COM.EC · cadena: soporte.nomina -WriteDacl→ ADMINISTRADORES DE
# NÓMINA -AdminTo→ DC01 -GetChangesAll→ dominio (4 hops)
# ═════════════════════════════════════════════════════════════════════════════
def ds1():
    D = "20260101100000"
    base = Path(OUT, "ds1_corp_hispana")
    DOM = "EMPRESA.COM.EC"
    SID = "S-1-5-21-1111111111-2222222222-3333333333"
    s = lambda r: f"{SID}-{r}"
    users = [
        {"ObjectIdentifier": s(500), "Properties": {"name": "ADMINISTRATOR@"+DOM, "domain": DOM,
          "samaccountname": "administrator", "enabled": True, "pwdlastset": 132999000000000000},
         "PrimaryGroupSID": s(513), "Aces": []},
        {"ObjectIdentifier": s(1101), "Properties": {"name": "SOPORTE.NOMINA@"+DOM, "domain": DOM,
          "samaccountname": "soporte.nomina", "enabled": True,
          "description": "Cuenta de soporte para nómina — contacto: soporte.nomina@empresa.com.ec"},
         "PrimaryGroupSID": s(513), "Aces": []},
        {"ObjectIdentifier": s(1103), "Properties": {"name": "M.JIMENEZ_LOPEZ@"+DOM, "domain": DOM,
          "samaccountname": "m.jimenez_lopez", "enabled": True, "dontreqpreauth": True},
         "PrimaryGroupSID": s(513), "Aces": []},
    ]
    groups = [
        {"ObjectIdentifier": s(512), "Properties": {"name": "DOMAIN ADMINS@"+DOM, "domain": DOM,
          "admincount": True}, "Members": [{"ObjectIdentifier": s(500), "ObjectType": "User"}], "Aces": []},
        {"ObjectIdentifier": s(1102), "Properties": {"name": "ADMINISTRADORES DE NÓMINA@"+DOM,
          "domain": DOM, "description": "Gestión de sistemas de nómina"},
         "Members": [], "Aces": [ace(s(1101), "User", "WriteDacl")]},
        # colisión: grupo llamado como una relation
        {"ObjectIdentifier": s(1104), "Properties": {"name": "ADDSELF@"+DOM, "domain": DOM},
         "Members": [], "Aces": []},
        # colisión: grupo llamado como token de schema
        {"ObjectIdentifier": s(1105), "Properties": {"name": "USUARIO@"+DOM, "domain": DOM},
         "Members": [], "Aces": []},
    ]
    computers = [
        {"ObjectIdentifier": s(1100), "Properties": {"name": "DC01."+DOM.lower(), "domain": DOM,
          "enabled": True, "haslaps": True, "operatingsystem": "Windows Server 2022 Datacenter"},
         "PrimaryGroupSID": s(516),
         "Sessions": {"Collected": False, "FailureReason": "Puerto RPC no accesible", "Results": []},
         "PrivilegedSessions": {"Collected": True, "FailureReason": None, "Results": []},
         "LocalGroups": [{"Name": "ADMINISTRATORS@DC01."+DOM.lower(),
                          "ObjectIdentifier": s(1100)+"-lg1", "Collected": True,
                          "Results": [{"ObjectIdentifier": s(1102), "ObjectType": "Group"}]}],
         "Aces": []},
        {"ObjectIdentifier": s(1106), "Properties": {"name": "SRV-CONTABILIDAD."+DOM.lower(),
          "domain": DOM, "enabled": True, "haslaps": False},
         "PrimaryGroupSID": s(513),
         "Sessions": {"Collected": True, "FailureReason": None,
                      "Results": [{"UserSID": s(1103), "ComputerSID": s(1106)}]},
         "PrivilegedSessions": {"Collected": False, "FailureReason": "sin privilegios", "Results": []},
         "LocalGroups": [], "Aces": []},
    ]
    domains = [{"ObjectIdentifier": SID, "Properties": {"name": DOM, "functionallevel": 2016,
        "domainsid": SID},
        "Trusts": [], "ChildObjects": [],
        "Aces": [ace(s(1100), "Computer", "GetChangesAll")]}]
    write(base/f"{D}_users.json", "users", users)
    write(base/f"{D}_groups.json", "groups", groups)
    write(base/f"{D}_computers.json", "computers", computers)
    write(base/f"{D}_domains.json", "domains", domains)


# ═════════════════════════════════════════════════════════════════════════════
# DS2 — FINANCIERA (espacios y apóstrofes)
# Cadena vía HasSession reversible: AUDITOR.INTERNO -AdminTo→ "SERVIDOR AUDITORÍA"
# -(HasSession↩)→ "DIRECTOR FINANCIERO" -MemberOf→ DOMAIN ADMINS
# + ADCS: template ESC1 con Enroll a AUTHENTICATED USERS
# ═════════════════════════════════════════════════════════════════════════════
def ds2():
    D = "20260101110000"
    base = Path(OUT, "ds2_financiera")
    DOM = "FINANCIERA.LOCAL"
    SID = "S-1-5-21-4444444444-5555555555-6666666666"
    s = lambda r: f"{SID}-{r}"
    users = [
        {"ObjectIdentifier": s(1201), "Properties": {"name": "AUDITOR.INTERNO@"+DOM,
          "domain": DOM, "samaccountname": "auditor.interno", "enabled": True},
         "PrimaryGroupSID": s(513), "Aces": []},
        {"ObjectIdentifier": s(1203), "Properties": {"name": "DIRECTOR FINANCIERO@"+DOM,
          "domain": DOM, "samaccountname": "director.financiero", "enabled": True, "admincount": True},
         "PrimaryGroupSID": s(512), "Aces": []},
        {"ObjectIdentifier": s(1204), "Properties": {"name": "JUAN JOSÉ O'CONNOR@"+DOM,
          "domain": DOM, "samaccountname": "jjose.oconnor", "enabled": True},
         "PrimaryGroupSID": s(513), "Aces": []},
    ]
    groups = [
        {"ObjectIdentifier": s(512), "Properties": {"name": "DOMAIN ADMINS@"+DOM, "domain": DOM,
          "admincount": True},
         "Members": [{"ObjectIdentifier": s(1203), "ObjectType": "User"}], "Aces": []},
        {"ObjectIdentifier": s(1205), "Properties": {"name": "PROTECCIÓN DE DATOS@"+DOM,
          "domain": DOM}, "Members": [], "Aces": []},
    ]
    computers = [
        {"ObjectIdentifier": s(1202), "Properties": {"name": "SERVIDOR AUDITORÍA."+DOM.lower(),
          "domain": DOM, "enabled": True, "haslaps": True},
         "PrimaryGroupSID": s(513),
         "Sessions": {"Collected": True, "FailureReason": None, "Results": []},
         "PrivilegedSessions": {"Collected": True, "FailureReason": None,
                                "Results": [{"UserSID": s(1203), "ComputerSID": s(1202)}]},
         "LocalGroups": [{"Name": "ADMINISTRATORS@SERVIDOR AUDITORÍA."+DOM.lower(),
                          "ObjectIdentifier": s(1202)+"-lg1", "Collected": True,
                          "Results": [{"ObjectIdentifier": s(1201), "ObjectType": "User"}]}],
         "Aces": []},
    ]
    ous = [{"ObjectIdentifier": "11111111-aaaa-bbbb-cccc-000000000001",
            "Properties": {"name": "Dirección General", "domain": DOM},
            "ChildObjects": [{"ObjectIdentifier": s(1202), "ObjectType": "Computer"}],
            "Links": [{"GUID": "22222222-aaaa-bbbb-cccc-000000000002", "IsEnforced": False}],
            "GPOChanges": {"LocalAdmins": [{"ObjectIdentifier": s(1204), "ObjectType": "User"}],
                           "RemoteDesktopUsers": [], "PSRemoteUsers": [], "DcomUsers": [],
                           "AffectedComputers": [{"ObjectIdentifier": s(1202), "ObjectType": "Computer"}]},
            "Aces": [ace("FINANCIERA.LOCAL-S-1-5-32-544", "Group", "GenericAll", inherited=True)]}]
    gpos = [{"ObjectIdentifier": "22222222-aaaa-bbbb-cccc-000000000002",
             "Properties": {"name": "Directiva de Contraseñas", "domain": DOM,
                            "gpcpath": "\\\\financiera.local\\sysvol"},
             "Aces": []}]
    templates = [{"ObjectIdentifier": "33333333-aaaa-bbbb-cccc-000000000003",
        "Properties": {"name": "PLANTILLAUSUARIOAUTENTICADO@"+DOM, "domain": DOM,
                       "enrolleesuppliessubject": True, "authenticationenabled": True,
                       "requiresmanagerapproval": False, "authorizedsignatures": 0,
                       "certificatenameflag": "ENROLLEE_SUPPLIES_SUBJECT",
                       "applicationpolicies": [], "ekus": ["Client Authentication"]},
        "ContainedBy": {"ObjectIdentifier": "44444444-aaaa-bbbb-cccc-000000000004", "ObjectType": "Container"},
        "Aces": [ace("S-1-5-11", "Group", "Enroll")]}]
    cas = [{"ObjectIdentifier": "55555555-aaaa-bbbb-cccc-000000000005",
        "Properties": {"name": "ENTIDAD CERTIFICADORA RAÍZ@"+DOM, "domain": DOM,
                       "caname": "Entidad Certificadora Raíz",
                       "dnshostname": "srv-ca.financiera.local", "whencreated": 1678886000},
        "HostingComputer": {"ObjectIdentifier": s(1206), "ObjectType": "Computer"},
        "EnabledCertTemplates": [{"ObjectIdentifier": "33333333-aaaa-bbbb-cccc-000000000003",
                                  "ObjectType": "CertTemplate"}],
        "Aces": [ace(s(1204), "User", "Acl_ManageCa" if False else "Owns")]}]
    domains = [{"ObjectIdentifier": SID, "Properties": {"name": DOM, "functionallevel": 2016,
        "domainsid": SID},
        "Trusts": [{"TargetDomainSid": "S-1-5-21-1212121212-1313131313-1414141414",
                    "TargetDomainName": "BANCO-ALIADO.COM", "TrustDirection": "Bidirectional",
                    "TrustType": "External", "IsTransitive": True, "SidFilteringEnabled": False}],
        "ChildObjects": [], "Aces": []}]
    write(base/f"{D}_users.json", "users", users)
    write(base/f"{D}_groups.json", "groups", groups)
    write(base/f"{D}_computers.json", "computers", computers)
    write(base/f"{D}_domains.json", "domains", domains)
    write(base/f"{D}_ous.json", "ous", ous)
    write(base/f"{D}_gpos.json", "gpos", gpos)
    write(base/f"{D}_certtemplates.json", "certtemplates", templates)
    write(base/f"{D}_enterprisecas.json", "enterprisecas", cas)


# ═════════════════════════════════════════════════════════════════════════════
# DS3 — SECTOR PÚBLICO (extremos: ñ, ¿?, Nº, em-dash, guiones en dominio, colisiones)
# Cadena: NIÑO.PEREZ -MemberOf→ GRUPO DE APOYO TÉCNICO -AddMember→ DOMAIN ADMINS
# ═════════════════════════════════════════════════════════════════════════════
def ds3():
    D = "20260101120000"
    base = Path(OUT, "ds3_sector_publico")
    DOM = "SECT-OR.GOB.EC"        # dominio con guion (data real de gov.ec)
    SID = "S-1-5-21-7777777777-8888888888-9999999999"
    s = lambda r: f"{SID}-{r}"
    users = [
        {"ObjectIdentifier": s(1301), "Properties": {"name": "NIÑO.PEREZ@"+DOM, "domain": DOM,
          "samaccountname": "niño.perez", "enabled": True,
          "description": "Contacto: niño.perez@sect-or.gob.ec — Teléf. 0999999999",
          "email": "niño.perez@sect-or.gob.ec"},
         "PrimaryGroupSID": s(513), "Aces": []},
        {"ObjectIdentifier": s(1302), "Properties": {"name": "SEÑOR.ÑOÑEZ@"+DOM, "domain": DOM,
          "samaccountname": "señor.ñonez", "enabled": True},
         "PrimaryGroupSID": s(513), "Aces": []},
        # colisiones con keys JSON / type values
        {"ObjectIdentifier": s(1303), "Properties": {"name": "TARGET@"+DOM, "domain": DOM,
          "samaccountname": "target", "enabled": True}, "PrimaryGroupSID": s(513), "Aces": []},
        {"ObjectIdentifier": s(1304), "Properties": {"name": "USER@"+DOM, "domain": DOM,
          "samaccountname": "user", "enabled": True}, "PrimaryGroupSID": s(513), "Aces": []},
    ]
    groups = [
        {"ObjectIdentifier": s(512), "Properties": {"name": "DOMAIN ADMINS@"+DOM, "domain": DOM,
          "admincount": True},
         "Members": [],
         "Aces": [ace(s(1305), "Group", "AddMember")]},   # cadena plantada
        {"ObjectIdentifier": s(1305), "Properties": {"name": "GRUPO DE APOYO TÉCNICO@"+DOM,
          "domain": DOM},
         "Members": [{"ObjectIdentifier": s(1301), "ObjectType": "User"},
                     {"ObjectIdentifier": s(1302), "ObjectType": "User"}], "Aces": []},
        # colisión parcial con well-known
        {"ObjectIdentifier": s(1307), "Properties": {"name": "ADMINISTRADOR DE SISTEMAS@"+DOM,
          "domain": DOM}, "Members": [], "Aces": []},
        # grupo con Members vacíos y ContainedBy null (reconcile-style)
        {"ObjectIdentifier": DOM+"-S-1-5-32-556", "Properties": {"name": "NETWORK CONFIGURATION "
          "OPERATORS@"+DOM, "domain": DOM, "reconcile": False}, "Members": [],
         "ContainedBy": None, "Aces": []},
    ]
    computers = [
        {"ObjectIdentifier": s(1306), "Properties": {"name": "SERVIDOR Nº7 — CONTABILIDAD."+DOM.lower(),
          "domain": DOM, "enabled": True, "operatingsystem": "Windows Server 2019 Standard"},
         "PrimaryGroupSID": s(513),
         "Sessions": {"Collected": True, "FailureReason": None, "Results": []},
         "PrivilegedSessions": {"Collected": True, "FailureReason": None, "Results": []},
         "LocalGroups": [], "Aces": []},
    ]
    # template que colisiona EXACTO con well-known ADMINISTRATOR
    templates = [{"ObjectIdentifier": "66666666-aaaa-bbbb-cccc-000000000006",
        "Properties": {"name": "ADMINISTRATOR@"+DOM, "domain": DOM,
                       "enrolleesuppliessubject": False, "authenticationenabled": False},
        "Aces": [ace("S-1-5-11", "Group", "Enroll")]}]
    # ACE con SID prefijo-de-dominio sobre una OU
    ous = [{"ObjectIdentifier": "77777777-aaaa-bbbb-cccc-000000000007",
            "Properties": {"name": "Subsecretaría de Tecnologías", "domain": DOM},
            "ChildObjects": [{"ObjectIdentifier": s(1306), "ObjectType": "Computer"}],
            "Aces": [ace(DOM+"-S-1-5-32-544", "Group", "GenericAll")]}]
    domains = [{"ObjectIdentifier": SID, "Properties": {"name": DOM, "functionallevel": 2016,
        "domainsid": SID},
        "Trusts": [{"TargetDomainSid": "S-1-5-21-1515151515-1616161616-1717171717",
                    "TargetDomainName": "SOCIEDAD-EXTERNA.COM", "TrustDirection": "Inbound",
                    "TrustType": "External", "IsTransitive": False, "SidFilteringEnabled": True}],
        "ChildObjects": [], "Aces": []}]
    write(base/f"{D}_users.json", "users", users)
    write(base/f"{D}_groups.json", "groups", groups)
    write(base/f"{D}_computers.json", "computers", computers)
    write(base/f"{D}_domains.json", "domains", domains)
    write(base/f"{D}_ous.json", "ous", ous)
    write(base/f"{D}_certtemplates.json", "certtemplates", templates)


# ═════════════════════════════════════════════════════════════════════════════
# DS4 — AZ CORPORATIVO (español normal)
# Cadenas: "Ana lucía Torres" -MemberOf→ "Equipo de Dirección" -HasRole→ Global Administrator
#          "María José Gómez" -Owner→ "Suscripción Producción"
# ═════════════════════════════════════════════════════════════════════════════
def _az_user(uid, disp, upn, extra=None):
    d = {"id": uid, "displayName": disp, "userPrincipalName": upn,
         "accountEnabled": True, "userType": "Member"}
    if extra:
        d.update(extra)
    return d

def _graph_user(uid, disp):
    return {"@odata.type": "#microsoft.graph.user", "id": uid,
            "displayName": disp, "accountEnabled": True}

def ds4():
    base = Path(OUT, "ds4_az_corporativo")
    TID = "6a2b3c4d-0000-4000-8000-aaaaaaaaaaa1"
    SUB = "/subscriptions/bbbbbbbb-1111-2222-3333-cccccccccccc"
    entries = [
        {"kind": "AZTenant", "data": {"tenantId": TID, "displayName": "Grupo Comercial del Sur S.A.",
          "defaultDomain": "grupocomercialsur.onmicrosoft.com",
          "domains": ["grupocomercialsur.onmicrosoft.com", "grupocomercialsur.com"],
          "id": f"/tenants/{TID}"}},
        {"kind": "AZUser", "data": _az_user("u1", "María José Gómez", "m.gomez@grupocomercialsur.com")},
        {"kind": "AZUser", "data": _az_user("u2", "Ana lucía Torres", "a.torres@grupocomercialsur.com")},
        {"kind": "AZUser", "data": _az_user("u3", "Juan Pérez-López", "j.perez@grupocomercialsur.com")},
        {"kind": "AZUser", "data": _az_user("u4", "Alicia Ñúñez", "a.nunez@grupocomercialsur.com")},
        {"kind": "AZRole", "data": {"id": "62e90394-69f5-4237-9190-012177145e10",
          "displayName": "Global Administrator", "isBuiltIn": True, "isEnabled": True,
          "tenantId": TID}},
        {"kind": "AZGroup", "data": {"id": "g1", "displayName": "Equipo de Dirección",
          "securityEnabled": True, "tenantId": TID}},
        {"kind": "AZGroup", "data": {"id": "g2", "displayName": "Administradores de TI",
          "securityEnabled": True, "membershipRule": "user.city -eq \"Quito\"",
          "membershipRuleProcessingState": "On", "tenantId": TID}},
        {"kind": "AZGroupMember", "data": {"groupId": "g1",
          "members": [{"member": _graph_user("u2", "Ana lucía Torres")}]}},
        {"kind": "AZGroupMember", "data": {"groupId": "g2",
          "members": [{"member": _graph_user("u4", "Alicia Ñúñez")}]}},
        {"kind": "AZRoleAssignment", "data": {"tenantId": TID, "roleAssignments": [{
          "id": "ra1", "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
          "principalId": "g1", "directoryScopeId": "/"}]}},
        {"kind": "AZManagementGroup", "data": {"id": "/providers/Microsoft.Management/managementGroups/mg1",
          "name": "Grupo Comercial", "tenantId": TID,
          "properties": {"children": [{"id": SUB, "type": "/subscriptions", "name": "Suscripción Producción"}]}}},
        {"kind": "AZSubscription", "data": {"id": SUB, "subscriptionId": SUB.split("/")[-1],
          "displayName": "Suscripción Producción", "state": "Enabled", "tenantId": TID}},
        {"kind": "AZSubscriptionOwner", "data": {"subscriptionId": SUB, "owners": [{
          "owner": {"id": SUB + "/providers/Microsoft.Authorization/roleAssigngments/ra2",
                    "properties": {"principalId": "u1", "principalType": "User",
                                   "roleDefinitionId": SUB + "/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                                   "scope": SUB}}}],
          "userAccessAdmins": []}},
        {"kind": "AZResourceGroup", "data": {"id": SUB + "/resourceGroups/RG-Produccion",
          "name": "RG-Produccion", "location": "eastus", "subscriptionId": SUB, "tenantId": TID}},
        {"kind": "AZKeyVault", "data": {"id": SUB + "/resourceGroups/RG-Produccion/providers/Microsoft.KeyVault/vaults/vaulta-claves",
          "name": "Bóveda de Claves", "location": "eastus",
          "properties": {"enableSoftDelete": True, "enablePurgeProtection": False},
          "resourceGroup": SUB + "/resourceGroups/RG-Produccion", "tenantId": TID}},
        {"kind": "AZKeyVaultAccessPolicy", "data": {"objectId": "u3",
          "keyVaultId": SUB + "/resourceGroups/RG-Produccion/providers/Microsoft.KeyVault/vaults/vaulta-claves",
          "permissions": {"secrets": ["Get", "List"]}}},
        {"kind": "AZVM", "data": {"id": SUB + "/resourceGroups/RG-Produccion/providers/Microsoft.Compute/virtualMachines/srv-contabilidad",
          "name": "Servidor-Contabilidad", "location": "eastus",
          "identity": {"principalId": "msi1", "tenantId": TID, "type": "SystemAssigned"},
          "resourceGroupId": SUB + "/resourceGroups/RG-Produccion", "tenantId": TID}},
        {"kind": "AZApp", "data": {"id": "objapp1", "appId": "client1",
          "displayName": "Aplicación de Nómina",
          "signInAudience": "AzureADMyOrg", "publisherDomain": "grupocomercialsur.com"}},
        {"kind": "AZServicePrincipal", "data": {"id": "sp1", "appId": "client1",
          "appDisplayName": "Aplicación de Nómina", "accountEnabled": True,
          "servicePrincipalType": "Application", "passwordCredentials": [],
          "keyCredentials": [], "tenantId": TID}},
        {"kind": "AZServicePrincipalOwner", "data": {"servicePrincipalId": "sp1",
          "owners": [{"owner": _graph_user("u3", "Juan Pérez-López")}]}},
        {"kind": "AZAppRoleAssignment", "data": {"principalId": "u4", "principalType": "User",
          "principalDisplayName": "Alicia Ñúñez", "resourceId": "sp1",
          "resourceDisplayName": "Aplicación de Nómina",
          "appRoleId": "00000000-0000-0000-0000-000000000000"}},
        {"kind": "AZDevice", "data": {"id": "dev1", "displayName": "Equipo de María",
          "accountEnabled": True, "operatingSystem": "Windows", "trustType": "AzureAd"}},
        {"kind": "AZDeviceOwner", "data": {"deviceId": "dev1",
          "owners": [{"owner": _graph_user("u1", "María José Gómez")}]}},
    ]
    base.mkdir(parents=True, exist_ok=True)
    with open(base / "azurehound.json", "w", encoding="utf-8") as f:
        json.dump({"data": entries}, f, ensure_ascii=False, indent=1)


# ═════════════════════════════════════════════════════════════════════════════
# DS5 — AZ EDGE (colisiones y adversarial)
# Cadena: SP "Sincronizador de Identidades" -HasRole→ Privileged Role Administrator
# Edge: user llamado "Global Administrator", "USER 001", SP sin nombre, appId fantasma
# ═════════════════════════════════════════════════════════════════════════════
def ds5():
    base = Path(OUT, "ds5_az_edge")
    TID = "6a2b3c4d-0000-4000-8000-aaaaaaaaaaa2"
    SUB = "/subscriptions/dddddddd-1111-2222-3333-eeeeeeeeeeee"
    PRA = "e8611ab8-c5d4-4ea4-9d92-d06f3b55b6f4"   # Privileged Role Administrator
    entries = [
        {"kind": "AZTenant", "data": {"tenantId": TID, "displayName": "Ñandú Servicios S.L.",
          "defaultDomain": "nanduservicios.onmicrosoft.com",
          "domains": ["nanduservicios.onmicrosoft.com"], "id": f"/tenants/{TID}"}},
        # colisiones deliberadas
        {"kind": "AZUser", "data": _az_user("ux1", "USER 001", "user001@nanduservicios.onmicrosoft.com")},
        {"kind": "AZUser", "data": _az_user("ux2", "Global Administrator", "ga.shadow@nanduservicios.onmicrosoft.com")},
        # sin displayName — name debe caer a id sin romper
        {"kind": "AZUser", "data": {"id": "ux3", "userPrincipalName": "sin.nombre@nanduservicios.onmicrosoft.com",
          "accountEnabled": True}},
        {"kind": "AZUser", "data": _az_user("ux4", "¿Pruebas y Seguridad?", "pruebas@nanduservicios.onmicrosoft.com")},
        {"kind": "AZRole", "data": {"id": PRA, "displayName": "Privileged Role Administrator",
          "isBuiltIn": True, "isEnabled": True, "tenantId": TID}},
        # rol custom (no builtin) — debe anonimizarse como ROLE_NNNN
        {"kind": "AZRole", "data": {"id": "dddddddd-1111-2222-3333-role-custom01",
          "displayName": "Rol Interno de Auditoría", "isBuiltIn": False, "isEnabled": True,
          "tenantId": TID}},
        {"kind": "AZRoleAssignment", "data": {"tenantId": TID, "roleAssignments": [
            {"id": "ra1", "roleDefinitionId": PRA, "principalId": "sp_sync", "directoryScopeId": "/"},
            {"id": "ra2", "roleDefinitionId": "dddddddd-1111-2222-3333-role-custom01",
             "principalId": "ux4", "directoryScopeId": "/"}]}},
        {"kind": "AZServicePrincipal", "data": {"id": "sp_sync", "appId": "clientsync",
          "appDisplayName": "Sincronizador de Identidades", "accountEnabled": True,
          "servicePrincipalType": "Application",
          "passwordCredentials": [{"keyId": "k1", "hint": "Xz!"}],
          "keyCredentials": [{"keyId": "k2", "usage": "Sign"}], "tenantId": TID}},
        # app sin displayName + owner con appId fantasma (unresolved — no crash)
        {"kind": "AZApp", "data": {"id": "objapp9", "appId": "client9",
          "signInAudience": "AzureADMyOrg"}},
        {"kind": "AZAppOwner", "data": {"appId": "00000000-dead-beef-0000-000000000000",
          "owners": [{"owner": _graph_user("ux1", "USER 001")}]}},
        # grupo anidado (grupo dentro de grupo)
        {"kind": "AZGroup", "data": {"id": "gx1", "displayName": "Grupo Anidado Padre",
          "securityEnabled": True, "tenantId": TID}},
        {"kind": "AZGroup", "data": {"id": "gx2", "displayName": "Hijo con Acentós",
          "securityEnabled": True, "tenantId": TID}},
        {"kind": "AZGroupMember", "data": {"groupId": "gx1", "members": [
            {"member": {"@odata.type": "#microsoft.graph.group", "id": "gx2",
                        "displayName": "Hijo con Acentós", "securityEnabled": True}}]}},
        {"kind": "AZSubscription", "data": {"id": SUB, "subscriptionId": SUB.split("/")[-1],
          "displayName": "Suscripción de Desarrollo", "state": "Enabled", "tenantId": TID}},
        {"kind": "AZFunctionApp", "data": {"id": SUB + "/resourceGroups/rg-edge/providers/Microsoft.Web/sites/fn-backdoor",
          "name": "Backdoor-Función", "kind": "functionapp", "location": "centralus",
          "identity": {"principalId": "msi2", "tenantId": TID, "type": "SystemAssigned"},
          "resourceGroupId": SUB + "/resourceGroups/rg-edge", "tenantId": TID}},
        {"kind": "AZFunctionAppRoleAssignment", "data": {
          "objectId": SUB + "/resourceGroups/rg-edge/providers/Microsoft.Web/sites/fn-backdoor",
          "assignees": [{"assignee": {"id": "x", "properties": {
              "principalId": "sp_sync", "principalType": "ServicePrincipal",
              "roleDefinitionId": SUB + "/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c",
              "scope": SUB}}, "objectId": "fn1",
            "roleDefinitionId": "b24988ac-6180-42a0-ab88-20f7382dd24c"}]}},
        {"kind": "AZDevice", "data": {"id": "dev2", "displayName": "Equipo de María 2",
          "accountEnabled": False, "operatingSystem": "macOS", "trustType": "AzureAd"}},
    ]
    base.mkdir(parents=True, exist_ok=True)
    with open(base / "azurehound.json", "w", encoding="utf-8") as f:
        json.dump({"data": entries}, f, ensure_ascii=False, indent=1)


if __name__ == "__main__":
    ds1(); ds2(); ds3(); ds4(); ds5()
    print("[+] Datasets escritos en", OUT)
