#!/usr/bin/env python3
"""Migration check: vaultwarden -> Workers (driven by tests/import_check.sh).

  import_check.py seed   BASE OUT.json   fill a real vaultwarden with data, record what it returns
  import_check.py verify BASE OUT.json   after importing its db.sqlite3, the Worker must return
                                         the same vault (and the same file bytes)

Python 3 stdlib only; both servers must be on loopback. Dummy encrypted strings, as in smoke.py.
"""
import base64
import json
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import smoke  # noqa: E402
from smoke import check, eq, login_payload, multipart, section, totp, now_step  # noqa: E402

ORG_KEY = "4.org-key-for-member"


def use(base):
    smoke.BASE = base.rstrip("/")


def login(email, password, **extra):
    _, r = smoke.login(email, password, **extra)
    return r.json["access_token"]


def user_id(token):
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["sub"]


def api(token, method, path, **kw):
    # vaultwarden 1.37 requires `encryptedFor` (the encrypting user) on every cipher body.
    body = kw.get("body")
    if isinstance(body, dict) and "type" in body and "name" in body and method in ("POST", "PUT"):
        kw["body"] = body | {"encryptedFor": user_id(token)}
    elif isinstance(body, dict) and isinstance(body.get("cipher"), dict):
        kw["body"] = body | {"cipher": body["cipher"] | {"encryptedFor": user_id(token)}}
    return smoke.call(method, path, token=token, **kw)


def register(label):
    email = f"import-{label}-{smoke.RUN}@example.com"
    password = smoke.client_hash(f"import-{label}-{smoke.RUN}")
    # vaultwarden 1.37 only has the two-step registration; without mail the token comes back directly.
    token = smoke.call(
        "POST", "/identity/accounts/register/send-verification-email", body={"email": email, "name": f"Import {label}"}
    ).body.decode().strip().strip('"')
    smoke.call(
        "POST",
        "/identity/accounts/register/finish",
        body={
            "email": email,
            "emailVerificationToken": token,
            "masterPasswordHash": password,
            "masterPasswordHint": None,
            "userSymmetricKey": smoke.USER_KEY,
            "kdf": 0,
            "kdfIterations": smoke.KDF_ITER,
            "userAsymmetricKeys": {"publicKey": smoke.PUBLIC_KEY, "encryptedPrivateKey": smoke.PRIVATE_KEY},
        },
    )
    return {"email": email, "password": password}


def norm_date(v):
    # vaultwarden: microseconds; Worker: milliseconds. Compare to the millisecond.
    return v[:23] if isinstance(v, str) and len(v) >= 23 and v[10] == "T" else v


def snapshot(token):
    """The parts of /api/sync a migrated client depends on, normalized for comparison."""
    s = api(token, "GET", "/api/sync").json
    ciphers = {}
    for c in s["ciphers"]:
        ciphers[c["id"]] = {
            "type": c["type"],
            "name": c["name"],
            "notes": c.get("notes"),
            "key": c.get("key"),
            "folderId": c.get("folderId"),
            "organizationId": c.get("organizationId"),
            "collectionIds": sorted(c.get("collectionIds") or []),
            "favorite": c.get("favorite"),
            "reprompt": c.get("reprompt"),
            "edit": c.get("edit"),
            "viewPassword": c.get("viewPassword"),
            "login": {k: (c.get("login") or {}).get(k) for k in ("username", "password", "totp")},
            "fields": c.get("fields"),
            "passwordHistory": [
                {"password": h.get("password"), "lastUsedDate": norm_date(h.get("lastUsedDate"))}
                for h in (c.get("passwordHistory") or [])
            ],
            "deletedDate": norm_date(c.get("deletedDate")),
            "revisionDate": norm_date(c.get("revisionDate")),
            "attachments": sorted(
                [(a["id"], a["fileName"], a["key"], str(a["size"])) for a in (c.get("attachments") or [])]
            ),
        }
    p = s["profile"]
    return {
        "profile": {
            "id": p["id"],
            "email": p["email"],
            "name": p["name"],
            "key": p["key"],
            "privateKey": p["privateKey"],
            "twoFactorEnabled": p["twoFactorEnabled"],
            "securityStamp": p["securityStamp"],
            "organizations": sorted(
                [(o["id"], o["name"], o["type"], o["status"], o.get("key")) for o in p["organizations"]]
            ),
        },
        "folders": sorted([(f["id"], f["name"]) for f in s["folders"]]),
        "collections": sorted([(c["id"], c["name"], c["readOnly"], c["hidePasswords"]) for c in s["collections"]]),
        "ciphers": ciphers,
        "sends": sorted(
            [(x["id"], x["accessId"], x["type"], x["name"], norm_date(x["deletionDate"])) for x in s["sends"]]
        ),
        "policies": sorted([(x["id"], x["type"], x["enabled"]) for x in (s.get("policies") or [])]),
        "domains": (s.get("domains") or {}).get("equivalentDomains"),
    }


def seed(out):
    section("seed vaultwarden")
    owner, member = register("owner"), register("member")
    t_owner = login(owner["email"], owner["password"])
    t_member = login(member["email"], member["password"])

    fid = api(t_owner, "POST", "/api/folders", body={"name": "2.folder|iv|mac"}).json["id"]
    personal = api(t_owner, "POST", "/api/ciphers", body=login_payload("p1", folderId=fid, favorite=True)).json["id"]
    note = api(
        t_owner,
        "POST",
        "/api/ciphers",
        body={"type": 2, "name": "2.note|iv|mac", "notes": "2.n|iv|mac", "secureNote": {"type": 0}},
    ).json["id"]
    trashed = api(t_owner, "POST", "/api/ciphers", body=login_payload("trash")).json["id"]
    api(t_owner, "PUT", f"/api/ciphers/{trashed}/delete")
    api(t_owner, "PUT", "/api/settings/domains", body={"equivalentDomains": [["example.com", "example.net"]], "excludedGlobalEquivalentDomains": []})

    # Attachment (v2 flow, multipart upload as vaultwarden expects).
    content = os.urandom(3000)
    r = api(
        t_owner,
        "POST",
        f"/api/ciphers/{personal}/attachment/v2",
        body={"key": "2.attkey|iv|mac", "fileName": "2.file|iv|mac", "fileSize": len(content)},
    ).json
    hdrs, mp = multipart([("data", "file.bin", content)])
    api(t_owner, "POST", f"/api/ciphers/{personal}/attachment/{r['attachmentId']}", raw=mp, headers=hdrs)

    # File Send.
    blob = os.urandom(700)
    body = {
        "type": 1,
        "key": "2.sendkey|iv|mac",
        "name": "2.sendname|iv|mac",
        "notes": None,
        "file": {"fileName": "2.fn|iv|mac"},
        "fileLength": len(blob),
        "deletionDate": smoke.future(5),
        "disabled": False,
        "hideEmail": False,
        "password": None,
    }
    r = api(t_owner, "POST", "/api/sends/file/v2", body=body).json
    send = r["sendResponse"]
    hdrs, mp = multipart([("data", "2.fn|iv|mac", blob)])
    api(t_owner, "POST", f"/api/sends/{send['id']}/file/{send['file']['id']}", raw=mp, headers=hdrs)
    text_send = api(t_owner, "POST", "/api/sends", body=smoke.text_send()).json["id"]

    # Organization, collection, confirmed member with read-only access, org item, policy, group.
    org = api(
        t_owner,
        "POST",
        "/api/organizations",
        body={
            "name": "Import Org",
            "billingEmail": owner["email"],
            "key": "4.org-key-owner",
            "keys": {"publicKey": "org-pub", "encryptedPrivateKey": "2.org-priv|iv|mac"},
            "collectionName": "2.col|iv|mac",
            "planType": 0,
        },
    ).json
    org_id = org["id"]
    col = api(t_owner, "GET", f"/api/organizations/{org_id}/collections").json["data"][0]["id"]
    api(
        t_owner,
        "POST",
        f"/api/organizations/{org_id}/users/invite",
        body={
            "emails": [member["email"]],
            "type": 2,
            "collections": [{"id": col, "readOnly": True, "hidePasswords": False, "manage": False}],
            "groups": [],
            "accessAll": False,
            "permissions": {},
        },
    )
    users = api(t_owner, "GET", f"/api/organizations/{org_id}/users").json["data"]
    mid = [u for u in users if u["email"] == member["email"]][0]["id"]
    api(t_owner, "POST", f"/api/organizations/{org_id}/users/{mid}/confirm", body={"key": ORG_KEY})
    shared = api(
        t_owner,
        "POST",
        "/api/ciphers/create",
        body={"cipher": login_payload("org", organizationId=org_id), "collectionIds": [col]},
    ).json["id"]
    api(t_owner, "PUT", f"/api/organizations/{org_id}/policies/1", body={"policy": {"enabled": True, "data": None}})
    api(
        t_owner,
        "POST",
        f"/api/organizations/{org_id}/groups",
        body={"name": "Import Group", "accessAll": False, "collections": [], "users": [mid]},
    )

    # Member enables TOTP: 2FA must survive the move.
    r = api(t_member, "POST", "/api/two-factor/get-authenticator", body={"masterPasswordHash": member["password"]}).json
    # vaultwarden 1.37 (#7563): {authenticator: {key}, userVerificationToken}.
    secret = r["authenticator"]["key"]
    api(
        t_member,
        "POST",
        "/api/two-factor/authenticator",
        body={"key": secret, "token": totp(secret, now_step()), "userVerificationToken": r["userVerificationToken"]},
    )
    member["totp"] = secret

    expect = {
        "owner": owner,
        "member": member,
        "ids": {"personal": personal, "note": note, "trashed": trashed, "shared": shared, "org": org_id, "col": col,
                "send": send["id"], "send_access": send["accessId"], "send_file": send["file"]["id"], "text_send": text_send},
        "attachment": {"cipher": personal, "id": r and None, "b64": base64.b64encode(content).decode()},
        "send_b64": base64.b64encode(blob).decode(),
        "owner_view": snapshot(t_owner),
        "member_view": snapshot(t_member),
        "groups": [(g["name"]) for g in api(t_owner, "GET", f"/api/organizations/{org_id}/groups").json["data"]],
    }
    expect["attachment"]["id"] = expect["owner_view"]["ciphers"][personal]["attachments"][0][0]
    check(expect["member_view"]["ciphers"].get(shared), "member sees the shared item in vaultwarden")
    with open(out, "w") as f:
        json.dump(expect, f, indent=1)
    print(f"seeded: {len(expect['owner_view']['ciphers'])} owner ciphers, org {org_id}")


def diff(a, b, path=""):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            diff(a.get(k), b.get(k), f"{path}.{k}")
    elif a != b:
        raise smoke.Failure(f"{path}: vaultwarden {a!r} != worker {b!r}")


def verify(out):
    with open(out) as f:
        exp = json.load(f)
    owner, member, ids = exp["owner"], exp["member"], exp["ids"]

    section("verify: owner logs in with the same master password")
    t_owner = login(owner["email"], owner["password"])
    diff(json.loads(json.dumps(exp["owner_view"])), json.loads(json.dumps(snapshot(t_owner))), "owner")

    section("verify: member needs the migrated TOTP")
    _, r = smoke.login(member["email"], member["password"], expect=400)
    eq(r.json["TwoFactorProviders"], ["0"], "member 2FA providers")
    # Use the next step: the seed may have spent the current one (vaultwarden stores last_used).
    t_member = login(
        member["email"], member["password"], twoFactorToken=totp(member["totp"], now_step() + 1), twoFactorProvider="0"
    )
    diff(json.loads(json.dumps(exp["member_view"])), json.loads(json.dumps(snapshot(t_member))), "member")

    section("verify: files moved to R2")
    a = exp["attachment"]
    info = api(t_owner, "GET", f"/api/ciphers/{a['cipher']}/attachment/{a['id']}").json
    eq(smoke.call("GET", info["url"]).body, base64.b64decode(a["b64"]), "attachment bytes")
    smoke.call("POST", f"/api/sends/access/{ids['send_access']}", body={})
    dl = smoke.call("POST", f"/api/sends/{ids['send']}/access/file/{ids['send_file']}", body={}).json
    eq(smoke.call("GET", dl["url"]).body, base64.b64decode(exp["send_b64"]), "send file bytes")

    section("verify: org admin data")
    eq(
        [g["name"] for g in api(t_owner, "GET", f"/api/organizations/{ids['org']}/groups").json["data"]],
        exp["groups"],
        "groups",
    )
    members = api(t_owner, "GET", f"/api/organizations/{ids['org']}/users").json["data"]
    eq(sorted((m["email"], m["status"]) for m in members), sorted([(owner["email"], 2), (member["email"], 2)]), "members")
    # Read-only member can't edit the shared item; owner can, and the member is told.
    api(t_member, "PUT", f"/api/ciphers/{ids['shared']}", body=login_payload("x", organizationId=ids["org"]), expect=(400, 401, 403, 404))
    api(t_owner, "PUT", f"/api/ciphers/{ids['shared']}", body=login_payload("edited", organizationId=ids["org"], collectionIds=[ids["col"]]))
    eq(snapshot(t_member)["ciphers"][ids["shared"]]["name"], "2.name-edited|iv|mac", "edit visible to member")
    print("import verified")


if __name__ == "__main__":
    mode, base, out = sys.argv[1:4]
    use(base)
    start = time.time()
    try:
        {"seed": seed, "verify": verify}[mode](out)
    except Exception as e:  # noqa: BLE001 - any error fails the check
        print(f"FAIL: {type(e).__name__}: {e}")
        sys.exit(1)
    print(f"OK import {mode} ({time.time() - start:.0f}s)")
