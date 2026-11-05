#!/usr/bin/env python3
"""End-to-end HTTP regression test for the Workers API (Python 3 stdlib only).

Talks to a local `wrangler dev` at http://127.0.0.1:8787 (override with SMOKE_BASE_URL, loopback
only) and exits non-zero on the first failure. The server never decrypts vault data, so dummy
encrypted strings are enough. Every request is forced to the local server, including URLs the API
hands back (attachment and Send upload/download), so a stray BASE_URL can't reach production.

The final "witness" user is left in the database on purpose, so tests/storage_check.py can inspect
the rows the worker actually wrote.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE = os.environ.get("SMOKE_BASE_URL", "http://127.0.0.1:8787").rstrip("/")
RUN = uuid.uuid4().hex[:10]

API_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
PROFILE_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

KDF_ITER = 600000
PUBLIC_KEY = "public-key-b64"
PRIVATE_KEY = "2.private|key|enc"
USER_KEY = "2.user|key|enc"

assert urllib.parse.urlparse(BASE).hostname in ("127.0.0.1", "localhost"), "smoke test is local only"


class Failure(Exception):
    pass


def check(cond, msg):
    if not cond:
        raise Failure(msg)


def eq(actual, expected, what):
    if actual != expected:
        raise Failure(f"{what}: expected {expected!r}, got {actual!r}")


def is_api_date(value, what):
    check(isinstance(value, str) and API_DATE.match(value), f"{what}: bad API date {value!r}")


def section(title):
    print(f"== {title}", flush=True)


class Resp:
    def __init__(self, status, body):
        self.status = status
        self.body = body

    @property
    def json(self):
        return json.loads(self.body) if self.body else None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def local_url(path_or_url):
    """Force any URL to the local server, keeping only its path and query."""
    if path_or_url.startswith("/"):
        return BASE + path_or_url
    parsed = urllib.parse.urlparse(path_or_url)
    return BASE + parsed.path + (f"?{parsed.query}" if parsed.query else "")


def call(method, path, *, body=None, form=None, raw=None, token=None, headers=None, expect=200):
    """Send a request, waiting out rate limits. `expect` may be a status, a tuple, or None (any)."""
    url = local_url(path)
    hdrs = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    elif raw is not None:
        data = raw
    if token:
        hdrs["Authorization"] = f"Bearer {token}"

    deadline = time.time() + 180
    while True:
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with OPENER.open(req, timeout=120) as r:
                resp = Resp(r.status, r.read())
        except urllib.error.HTTPError as e:
            resp = Resp(e.code, e.read())
        if resp.status == 429 and time.time() < deadline:
            print("   (rate limited, waiting 15s)", flush=True)
            time.sleep(15)
            continue
        break

    expected = (expect,) if isinstance(expect, int) else expect
    if expected is not None and resp.status not in expected:
        raise Failure(f"{method} {path}: expected {expected}, got {resp.status}: {resp.body[:600]!r}")
    return resp


def multipart(fields):
    """fields: list of (name, filename-or-None, bytes). Returns (headers, body)."""
    boundary = uuid.uuid4().hex
    out = b""
    for name, filename, value in fields:
        disp = f'form-data; name="{name}"'
        if filename:
            disp += f'; filename="{filename}"'
        out += f"--{boundary}\r\nContent-Disposition: {disp}\r\n\r\n".encode() + value + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return {"Content-Type": f"multipart/form-data; boundary={boundary}"}, out


# ── Accounts ─────────────────────────────────────────────────────────


def client_hash(label):
    return base64.b64encode(hashlib.sha256(label.encode()).digest()).decode()


def new_email(label):
    return f"smoke-{label}-{RUN}@example.com"


def register(email, password, *, name="Smoke User", hint=None, kdf=0, iters=KDF_ITER, mem=None, par=None):
    body = {
        "email": email,
        "name": name,
        "masterPasswordHash": password,
        "masterPasswordHint": hint,
        "key": USER_KEY,
        "kdf": kdf,
        "kdfIterations": iters,
        "kdfMemory": mem,
        "kdfParallelism": par,
        "userAsymmetricKeys": {"publicKey": PUBLIC_KEY, "encryptedPrivateKey": PRIVATE_KEY},
    }
    eq(call("POST", "/identity/accounts/register", body=body).json, {}, "register response")


def token_form(email, password, device, **extra):
    form = {
        "grant_type": "password",
        "username": email,
        "password": password,
        "scope": "api offline_access",
        "client_id": "web",
        "device_type": "9",
        "device_identifier": device,
        "device_name": "smoke-device",
    }
    form.update(extra)
    return form


def login(email, password, device=None, expect=200, **extra):
    device = device or str(uuid.uuid4())
    return device, call("POST", "/identity/connect/token", form=token_form(email, password, device, **extra), expect=expect)


class User:
    def __init__(self, label, **kwargs):
        self.email = new_email(label)
        self.password = client_hash(f"{label}-{RUN}")
        register(self.email, self.password, **kwargs)
        self.relogin()

    def relogin(self):
        self.device, r = login(self.email, self.password)
        self.tokens = r.json
        self.token = r.json["access_token"]
        return r.json

    def api(self, method, path, **kwargs):
        return call(method, path, token=self.token, **kwargs)

    @property
    def auth(self):
        return {"masterPasswordHash": self.password}


# ── Cipher helpers ───────────────────────────────────────────────────


def login_payload(tag="a", **overrides):
    payload = {
        "type": 1,
        "name": f"2.name-{tag}|iv|mac",
        "notes": f"2.notes-{tag}|iv|mac",
        "favorite": False,
        "folderId": None,
        "organizationId": None,
        "reprompt": 1,
        "key": f"2.key-{tag}|iv|mac",
        "login": {
            "username": f"2.user-{tag}|iv|mac",
            "password": f"2.pass-{tag}|iv|mac",
            "totp": f"2.totp-{tag}|iv|mac",
            "passwordRevisionDate": "2026-02-03T04:05:06.000Z",
            "uris": [{"uri": f"2.uri-{tag}|iv|mac", "uriChecksum": "2.sum|iv|mac", "match": 2}],
            "fido2Credentials": [],
            "autofillOnPageLoad": True,
        },
        "fields": [
            {"name": f"2.fname-{tag}|iv|mac", "value": "2.fval|iv|mac", "type": 1, "linkedId": None},
            {"name": "2.fname2|iv|mac", "value": None, "type": 3, "linkedId": 100},
        ],
        "passwordHistory": [
            {"password": f"2.old-{tag}|iv|mac", "lastUsedDate": "2026-01-02T03:04:05.000Z"},
        ],
    }
    payload.update(overrides)
    return payload


TYPE_KEYS = {
    1: "login",
    2: "secureNote",
    3: "card",
    4: "identity",
    5: "sshKey",
    6: "bankAccount",
    7: "driversLicense",
    8: "passport",
}


def assert_cipher(c, sent, *, what, folder=None, favorite=False, user=None):
    """Every field the client sent must come back unchanged."""
    eq(c["type"], sent["type"], f"{what}.type")
    eq(c["name"], sent["name"], f"{what}.name")
    eq(c["notes"], sent.get("notes"), f"{what}.notes")
    eq(c["fields"], sent.get("fields") or [], f"{what}.fields")
    eq(c["passwordHistory"], sent.get("passwordHistory") or [], f"{what}.passwordHistory")
    eq(c["reprompt"], sent.get("reprompt") or 0, f"{what}.reprompt")
    eq(c["key"], sent.get("key"), f"{what}.key")
    eq(c["folderId"], folder, f"{what}.folderId")
    eq(c["favorite"], favorite, f"{what}.favorite")
    for t, key in TYPE_KEYS.items():
        expected = sent.get(key) if t == sent["type"] else None
        eq(c[key], expected, f"{what}.{key}")
    eq(c["organizationId"], None, f"{what}.organizationId")
    eq(c["edit"], True, f"{what}.edit")
    eq(c["viewPassword"], True, f"{what}.viewPassword")
    eq(c["organizationUseTotp"], False, f"{what}.organizationUseTotp")
    eq(c["collectionIds"], [], f"{what}.collectionIds")
    eq(c["permissions"], {"delete": True, "restore": True}, f"{what}.permissions")
    check(c["object"] in ("cipher", "cipherDetails"), f"{what}.object: {c['object']}")
    is_api_date(c["revisionDate"], f"{what}.revisionDate")
    is_api_date(c["creationDate"], f"{what}.creationDate")
    if user:
        eq(c["userId"], user, f"{what}.userId")


def list_ciphers(u):
    r = u.api("GET", "/api/ciphers").json
    eq(r["object"], "list", "list object")
    eq(r["continuationToken"], None, "list continuationToken")
    return {c["id"]: c for c in r["data"]}


def sync(u, query=""):
    r = u.api("GET", f"/api/sync{query}").json
    eq(r["object"], "sync", "sync object")
    return r


def sync_ciphers(u):
    return {c["id"]: c for c in sync(u)["ciphers"]}


def get_cipher(u, cid):
    return u.api("GET", f"/api/ciphers/{cid}").json


def assert_everywhere(u, cid, sent, *, what, folder=None, favorite=False):
    """The Rust path (get/details) and the SQL JSON path (list/sync) must agree."""
    profile_id = u.api("GET", "/api/accounts/profile").json["id"]
    got = get_cipher(u, cid)
    assert_cipher(got, sent, what=f"{what}/get", folder=folder, favorite=favorite, user=profile_id)
    details = u.api("GET", f"/api/ciphers/{cid}/details").json
    assert_cipher(details, sent, what=f"{what}/details", folder=folder, favorite=favorite, user=profile_id)
    listed = list_ciphers(u)[cid]
    assert_cipher(listed, sent, what=f"{what}/list", folder=folder, favorite=favorite, user=profile_id)
    synced = sync_ciphers(u)[cid]
    assert_cipher(synced, sent, what=f"{what}/sync", folder=folder, favorite=favorite, user=profile_id)
    for other, name in ((listed, "list"), (synced, "sync"), (details, "details")):
        eq(other["revisionDate"], got["revisionDate"], f"{what}: {name}.revisionDate matches get")
        eq(other["creationDate"], got["creationDate"], f"{what}: {name}.creationDate matches get")
    return got


# ── TOTP ─────────────────────────────────────────────────────────────


def totp(secret, step):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0xF
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"


def now_step():
    return int(time.time()) // 30


# ── Sections ─────────────────────────────────────────────────────────


def test_meta():
    section("meta endpoints")
    is_api_date(call("GET", "/api/alive").json, "alive")
    is_api_date(call("GET", "/api/now").json, "now")
    check(call("GET", "/api/config").json, "config body")
    call("GET", "/api/ciphers", expect=401)


def test_accounts():
    section("register / prelogin / token / refresh")
    u = User("acct", hint="my hint")

    p = call("POST", "/identity/accounts/prelogin", body={"email": u.email}).json
    eq(p["kdf"], 0, "prelogin.kdf")
    eq(p["kdfIterations"], KDF_ITER, "prelogin.kdfIterations")
    eq(p["kdfMemory"], None, "prelogin.kdfMemory")
    eq(p["kdfParallelism"], None, "prelogin.kdfParallelism")
    eq(p["kdfSettings"]["iterations"], KDF_ITER, "prelogin.kdfSettings.iterations")
    p = call("POST", "/identity/accounts/prelogin", body={"email": new_email("missing")}).json
    eq(p["kdf"], 0, "prelogin(unknown).kdf")
    eq(p["kdfIterations"], KDF_ITER, "prelogin(unknown).kdfIterations")

    t = u.tokens
    eq(t["token_type"], "Bearer", "token_type")
    eq(t["Key"], USER_KEY, "token.Key")
    eq(t["PrivateKey"], PRIVATE_KEY, "token.PrivateKey")
    eq(t["Kdf"], 0, "token.Kdf")
    eq(t["KdfIterations"], KDF_ITER, "token.KdfIterations")
    eq(t["KdfMemory"], None, "token.KdfMemory")
    eq(t["KdfParallelism"], None, "token.KdfParallelism")
    eq(t["scope"], "api offline_access", "token.scope")
    eq(t["UserDecryptionOptions"]["HasMasterPassword"], True, "HasMasterPassword")
    unlock = t["UserDecryptionOptions"]["MasterPasswordUnlock"]
    eq(unlock["Salt"], u.email, "unlock.Salt")
    eq(unlock["MasterKeyWrappedUserKey"], USER_KEY, "unlock.MasterKeyWrappedUserKey")
    eq(unlock["MasterKeyEncryptedUserKey"], USER_KEY, "unlock.MasterKeyEncryptedUserKey")
    eq(unlock["Kdf"]["KdfType"], 0, "unlock.Kdf.KdfType")
    eq(unlock["Kdf"]["Iterations"], KDF_ITER, "unlock.Kdf.Iterations")
    keys = t["AccountKeys"]["publicKeyEncryptionKeyPair"]
    eq(keys["publicKey"], PUBLIC_KEY, "AccountKeys.publicKey")
    eq(keys["wrappedPrivateKey"], PRIVATE_KEY, "AccountKeys.wrappedPrivateKey")
    check(t["access_token"] and t["refresh_token"], "tokens present")

    login(u.email, client_hash("wrong"), expect=401)
    login(new_email("nobody"), u.password, expect=401)
    # Email is case-insensitive at login.
    _, r = login(u.email.upper(), u.password, device=u.device)
    eq(r.json["Key"], USER_KEY, "uppercase login Key")

    r = call(
        "POST",
        "/identity/connect/token",
        form={"grant_type": "refresh_token", "refresh_token": t["refresh_token"], "client_id": "web"},
    ).json
    eq(r["Key"], USER_KEY, "refresh.Key")
    eq(r["Kdf"], 0, "refresh.Kdf")
    check(r["access_token"], "refresh.access_token")
    eq(call("GET", "/api/accounts/profile", token=r["access_token"]).json["email"], u.email, "refreshed token works")
    call(
        "POST",
        "/identity/connect/token",
        form={"grant_type": "refresh_token", "refresh_token": "not-a-token"},
        expect=400,
    )

    section("register variants")
    # Current client format (2026.5+): /register/finish with auth + unlock objects.
    email = new_email("finish")
    kdf = {"kdfType": 0, "iterations": KDF_ITER}
    body = {
        "email": email,
        "name": "Finish User",
        "userAsymmetricKeys": {"publicKey": PUBLIC_KEY, "encryptedPrivateKey": PRIVATE_KEY},
        "masterPasswordAuthentication": {
            "kdf": kdf,
            "salt": email,
            "masterPasswordAuthenticationHash": client_hash("finish"),
        },
        "masterPasswordUnlock": {"kdf": kdf, "salt": email, "masterKeyWrappedUserKey": USER_KEY},
    }
    eq(call("POST", "/identity/accounts/register/finish", body=body).json, {}, "register/finish")
    _, r = login(email, client_hash("finish"))
    eq(r.json["Key"], USER_KEY, "register/finish login")

    # Argon2id settings are stored and echoed; memory/parallelism are dropped for PBKDF2.
    email = new_email("argon")
    register(email, client_hash("argon"), kdf=1, iters=3, mem=64, par=4)
    p = call("POST", "/identity/accounts/prelogin", body={"email": email}).json
    eq((p["kdf"], p["kdfIterations"], p["kdfMemory"], p["kdfParallelism"]), (1, 3, 64, 4), "argon2 prelogin")
    email = new_email("pbkdf")
    register(email, client_hash("pbkdf"), mem=64, par=4)
    p = call("POST", "/identity/accounts/prelogin", body={"email": email}).json
    eq((p["kdfMemory"], p["kdfParallelism"]), (None, None), "pbkdf2 clears argon params")

    # Name is optional at registration; the profile then has no name.
    email = new_email("noname")
    register(email, client_hash("noname"), name=None)
    _, r = login(email, client_hash("noname"))
    prof = call("GET", "/api/accounts/profile", token=r.json["access_token"]).json
    check(not prof.get("name"), f"nameless profile has no name: {prof.get('name')!r}")

    # Duplicate email must not create a second account.
    dup = dict(body, name="Dup")
    call("POST", "/identity/accounts/register/finish", body=dup, expect=500)

    section("profile / revision date / hint / avatar / domains")
    prof = u.api("GET", "/api/accounts/profile").json
    eq(prof["email"], u.email, "profile.email")
    eq(prof["name"], "Smoke User", "profile.name")
    eq(prof["key"], USER_KEY, "profile.key")
    eq(prof["privateKey"], PRIVATE_KEY, "profile.privateKey")
    eq(prof["object"], "profile", "profile.object")
    eq(prof["emailVerified"], True, "profile.emailVerified")
    eq(prof["twoFactorEnabled"], False, "profile.twoFactorEnabled")
    eq(prof["premium"], True, "profile.premium")
    eq(prof["avatarColor"], None, "profile.avatarColor")
    eq(
        prof["accountKeys"]["publicKeyEncryptionKeyPair"]["publicKey"],
        PUBLIC_KEY,
        "profile.accountKeys.publicKey",
    )
    check(prof["securityStamp"], "profile.securityStamp")
    check(PROFILE_DATE.match(prof["creationDate"]), f"profile.creationDate {prof['creationDate']!r}")

    rev1 = u.api("GET", "/api/accounts/revision-date").json
    check(isinstance(rev1, int), "revision-date is an int")
    check(abs(rev1 - time.time() * 1000) < 900_000, f"revision-date near now: {rev1}")
    time.sleep(0.05)

    eq(u.api("PUT", "/api/accounts/profile", body={"name": "Renamed"}).json["name"], "Renamed", "PUT profile")
    eq(u.api("POST", "/api/accounts/profile", body={"name": "Renamed2"}).json["name"], "Renamed2", "POST profile")
    eq(u.api("GET", "/api/accounts/profile").json["name"], "Renamed2", "GET profile after update")
    u.api("PUT", "/api/accounts/profile", body={"name": "x" * 51}, expect=400)
    rev2 = u.api("GET", "/api/accounts/revision-date").json
    eq(rev2 > rev1, True, "profile update bumps revision date")
    time.sleep(0.05)

    eq(u.api("PUT", "/api/accounts/avatar", body={"avatarColor": "#112233"}).json["avatarColor"], "#112233", "avatar")
    eq(u.api("GET", "/api/accounts/profile").json["avatarColor"], "#112233", "avatar persisted")
    u.api("PUT", "/api/accounts/avatar", body={"avatarColor": "#12"}, expect=400)

    r = call("POST", "/api/accounts/password-hint", body={"email": u.email}, expect=400).json
    check("my hint" in r["error"], f"hint returned: {r}")
    r = call("POST", "/api/accounts/password-hint", body={"email": new_email("nohint")}, expect=400).json
    check("no password hint" in r["error"], f"no hint: {r}")

    eq(u.api("GET", "/api/tasks").json["data"], [], "tasks")

    d = u.api("GET", "/api/settings/domains").json
    eq(d["object"], "domains", "domains.object")
    eq(d["equivalentDomains"], [], "domains.equivalentDomains default")
    u.api(
        "PUT",
        "/api/settings/domains",
        body={"equivalentDomains": [["a.example", "b.example"]], "excludedGlobalEquivalentDomains": [1]},
    )
    d = u.api("GET", "/api/settings/domains").json
    eq(d["equivalentDomains"], [["a.example", "b.example"]], "domains persisted")
    s = sync(u)
    eq(s["domains"]["equivalentDomains"], [["a.example", "b.example"]], "sync.domains.equivalentDomains")
    eq(sync(u, "?excludeDomains=true")["domains"], None, "sync excludeDomains")

    return u


def test_folders(u):
    section("folders CRUD")
    created = u.api("POST", "/api/folders", body={"name": "2.folder|iv|mac"}).json
    eq(created["name"], "2.folder|iv|mac", "folder.name")
    eq(created["object"], "folder", "folder.object")
    is_api_date(created["revisionDate"], "folder.revisionDate")
    fid = created["id"]
    eq(u.api("GET", f"/api/folders/{fid}").json, created, "GET folder")
    listed = u.api("GET", "/api/folders").json
    eq(listed["object"], "list", "folders.object")
    check(created in listed["data"], "folder listed")
    check(created in sync(u)["folders"], "folder in sync")

    time.sleep(0.01)
    updated = u.api("PUT", f"/api/folders/{fid}", body={"name": "2.renamed|iv|mac"}).json
    eq(updated["name"], "2.renamed|iv|mac", "folder rename")
    check(updated["revisionDate"] > created["revisionDate"], "folder revisionDate advances")
    eq(u.api("GET", f"/api/folders/{fid}").json["name"], "2.renamed|iv|mac", "folder rename persisted")

    other = u.api("POST", "/api/folders", body={"name": "2.tmp|iv|mac"}).json["id"]
    u.api("DELETE", f"/api/folders/{other}")
    u.api("GET", f"/api/folders/{other}", expect=400)
    gone = u.api("POST", "/api/folders", body={"name": "2.tmp2|iv|mac"}).json["id"]
    u.api("POST", f"/api/folders/{gone}/delete")
    u.api("GET", f"/api/folders/{gone}", expect=400)
    u.api("PUT", f"/api/folders/{gone}", body={"name": "x"}, expect=404)
    return fid


def test_ciphers(u, fid):
    section("cipher create / get / list / sync round trip")
    sent = login_payload("create", favorite=True, folderId=fid)
    created = u.api("POST", "/api/ciphers", body=sent).json
    profile_id = u.api("GET", "/api/accounts/profile").json["id"]
    assert_cipher(created, sent, what="create", folder=fid, favorite=True, user=profile_id)
    eq(created["deletedDate"], None, "create.deletedDate")
    eq(created["archivedDate"], None, "create.archivedDate")
    eq(created["attachments"], None, "create.attachments")
    cid = created["id"]
    got = assert_everywhere(u, cid, sent, what="create", folder=fid, favorite=True)
    eq(got["id"], cid, "get.id")

    section("cipher variants")
    wrapped = login_payload("wrapped", folderId=fid)
    r = u.api("POST", "/api/ciphers/create", body={"cipher": wrapped, "collectionIds": []}).json
    assert_cipher(r, wrapped, what="create-wrapped", folder=fid)
    assert_everywhere(u, r["id"], wrapped, what="create-wrapped", folder=fid)
    u.api("DELETE", f"/api/ciphers/{r['id']}")

    minimal = {"type": 1, "name": "2.min|iv|mac", "login": {"username": None, "password": None}}
    r = u.api("POST", "/api/ciphers", body=minimal).json
    assert_everywhere(u, r["id"], minimal, what="minimal")
    u.api("DELETE", f"/api/ciphers/{r['id']}")

    for sent_other in (
        {"type": 2, "name": "2.note|iv|mac", "secureNote": {"type": 0}},
        {"type": 3, "name": "2.card|iv|mac", "card": {"cardholderName": "2.ch|iv|mac", "brand": None, "number": "2.n|iv|mac"}},
        {"type": 4, "name": "2.id|iv|mac", "identity": {"firstName": "2.f|iv|mac", "ssn": None}},
        {"type": 5, "name": "2.ssh|iv|mac", "sshKey": {"privateKey": "2.p|iv|mac", "publicKey": "2.q|iv|mac", "keyFingerprint": "2.k|iv|mac"}},
    ):
        r = u.api("POST", "/api/ciphers", body=sent_other).json
        assert_everywhere(u, r["id"], sent_other, what=f"type{sent_other['type']}")
        u.api("DELETE", f"/api/ciphers/{r['id']}")

    u.api("POST", "/api/ciphers", body=dict(login_payload("bad"), type=99), expect=(400, 422))

    # Empty folder id means no folder; a malformed history entry is dropped.
    odd = login_payload("odd", folderId="")
    odd["passwordHistory"] = [{"password": "2.keep|iv|mac", "lastUsedDate": None}, {"lastUsedDate": "x"}, {"password": None}]
    r = u.api("POST", "/api/ciphers", body=odd).json
    eq(r["folderId"], None, "empty folderId")
    expected = [{"password": "2.keep|iv|mac", "lastUsedDate": None}]
    eq(r["passwordHistory"], expected, "password history normalized")
    eq(sync_ciphers(u)[r["id"]]["passwordHistory"], expected, "password history normalized in sync")
    u.api("DELETE", f"/api/ciphers/{r['id']}")

    u.api("POST", "/api/ciphers", body=login_payload("nf", folderId=str(uuid.uuid4())), expect=400)

    section("cipher update")
    fid2 = u.api("POST", "/api/folders", body={"name": "2.second|iv|mac"}).json["id"]
    time.sleep(0.01)
    upd = login_payload("update", folderId=fid2, favorite=False, reprompt=0, key=None, notes=None)
    upd["fields"] = [{"name": "2.only|iv|mac", "value": "2.v|iv|mac", "type": 0, "linkedId": None}]
    upd["passwordHistory"] = [
        {"password": "2.h1|iv|mac", "lastUsedDate": "2026-03-01T00:00:00.000Z"},
        {"password": "2.h2|iv|mac", "lastUsedDate": "2026-03-02T00:00:00.000Z"},
    ]
    r = u.api("PUT", f"/api/ciphers/{cid}", body=upd).json
    assert_cipher(r, upd, what="update", folder=fid2)
    eq(r["creationDate"], created["creationDate"], "update keeps creationDate")
    check(r["revisionDate"] > created["revisionDate"], "update advances revisionDate")
    assert_everywhere(u, cid, upd, what="update", folder=fid2)

    r2 = u.api("POST", f"/api/ciphers/{cid}", body=upd).json
    assert_cipher(r2, upd, what="update(POST)", folder=fid2)

    # Stale-client protection compares against the stored revision date.
    u.api("PUT", f"/api/ciphers/{cid}", body=dict(upd, lastKnownRevisionDate="2020-01-01T00:00:00.000Z"), expect=400)
    current = get_cipher(u, cid)["revisionDate"]
    u.api("PUT", f"/api/ciphers/{cid}", body=dict(upd, lastKnownRevisionDate=current))
    u.api("PUT", f"/api/ciphers/{str(uuid.uuid4())}", body=upd, expect=404)
    u.api("PUT", f"/api/ciphers/{cid}", body=dict(upd, folderId=str(uuid.uuid4())), expect=400)

    # Clearing the folder and the optional arrays on update.
    cleared = {"type": 1, "name": "2.cleared|iv|mac", "login": {"username": "2.u|iv|mac"}}
    r = u.api("PUT", f"/api/ciphers/{cid}", body=cleared).json
    assert_cipher(r, cleared, what="update-clear")
    assert_everywhere(u, cid, cleared, what="update-clear")
    u.api("PUT", f"/api/ciphers/{cid}", body=upd)

    section("favorite toggle / partial")
    r = u.api("PUT", f"/api/ciphers/{cid}/partial", body={"folderId": fid2, "favorite": True}).json
    eq((r["favorite"], r["folderId"]), (True, fid2), "partial favorite on")
    assert_everywhere(u, cid, upd, what="favorite-on", folder=fid2, favorite=True)
    # Repeating is idempotent.
    r = u.api("POST", f"/api/ciphers/{cid}/partial", body={"folderId": fid2, "favorite": True}).json
    eq(r["favorite"], True, "partial favorite repeat")
    r = u.api("PUT", f"/api/ciphers/{cid}/partial", body={"folderId": None, "favorite": False}).json
    eq((r["favorite"], r["folderId"]), (False, None), "partial clears both")
    assert_everywhere(u, cid, upd, what="favorite-off")
    r = u.api("PUT", f"/api/ciphers/{cid}/partial", body={"folderId": "", "favorite": True}).json
    eq((r["favorite"], r["folderId"]), (True, None), "partial empty folder")
    u.api("PUT", f"/api/ciphers/{cid}/partial", body={"folderId": str(uuid.uuid4()), "favorite": True}, expect=400)
    u.api("PUT", f"/api/ciphers/{str(uuid.uuid4())}/partial", body={"favorite": True}, expect=404)
    # Update takes favorite from the payload.
    r = u.api("PUT", f"/api/ciphers/{cid}", body=dict(upd, favorite=False)).json
    eq(r["favorite"], False, "update clears favorite")
    assert_everywhere(u, cid, upd, what="update-favorite-off", folder=fid2)

    section("move to folder")
    u.api("POST", "/api/ciphers/move", body={"folderId": fid, "ids": [cid]})
    eq(get_cipher(u, cid)["folderId"], fid, "POST move")
    eq(sync_ciphers(u)[cid]["folderId"], fid, "POST move in sync")
    second = u.api("POST", "/api/ciphers", body=login_payload("second", folderId=fid2)).json["id"]
    u.api("PUT", "/api/ciphers/move", body={"folderId": fid2, "ids": [cid, second]})
    eq(get_cipher(u, cid)["folderId"], fid2, "PUT move (a)")
    eq(get_cipher(u, second)["folderId"], fid2, "PUT move (b)")
    u.api("POST", "/api/ciphers/move", body={"folderId": str(uuid.uuid4()), "ids": [cid]}, expect=400)
    eq(get_cipher(u, cid)["folderId"], fid2, "failed move leaves folder")
    u.api("POST", "/api/ciphers/move", body={"folderId": "", "ids": [second]})
    eq(get_cipher(u, second)["folderId"], None, "move empty string clears")
    u.api("POST", "/api/ciphers/move", body={"ids": [cid]})
    eq(get_cipher(u, cid)["folderId"], None, "move without folderId clears")
    u.api("POST", "/api/ciphers/move", body={"folderId": fid2, "ids": [cid]})
    u.api("POST", "/api/ciphers/move", raw=b"{bad", headers={"Content-Type": "application/json"}, expect=400)

    section("deleting a folder unlinks its ciphers")
    r = u.api("DELETE", f"/api/folders/{fid2}")
    eq(get_cipher(u, cid)["folderId"], None, "cipher unlinked from deleted folder")
    eq(sync_ciphers(u)[cid]["folderId"], None, "unlinked in sync")

    section("archive / unarchive")
    r = u.api("PUT", f"/api/ciphers/{cid}/archive").json
    is_api_date(r["archivedDate"], "archive.archivedDate")
    archived_date = r["archivedDate"]
    eq(get_cipher(u, cid)["archivedDate"], archived_date, "archive get")
    eq(list_ciphers(u)[cid]["archivedDate"], archived_date, "archive list")
    eq(sync_ciphers(u)[cid]["archivedDate"], archived_date, "archive sync")
    r = u.api("PUT", f"/api/ciphers/{cid}", body=upd | {"folderId": fid}).json
    eq(r["archivedDate"], archived_date, "update keeps archivedDate")
    eq(get_cipher(u, cid)["archivedDate"], archived_date, "update keeps archivedDate (get)")
    r = u.api("PUT", f"/api/ciphers/{cid}/unarchive").json
    eq(r["archivedDate"], None, "unarchive")
    eq(sync_ciphers(u)[cid]["archivedDate"], None, "unarchive sync")
    u.api("PUT", f"/api/ciphers/{str(uuid.uuid4())}/archive", expect=400)
    u.api("PUT", f"/api/ciphers/{str(uuid.uuid4())}/unarchive", expect=400)

    r = u.api("PUT", "/api/ciphers/archive", body={"ids": [cid, second]}).json
    eq(r["object"], "list", "bulk archive object")
    eq({c["id"] for c in r["data"]}, {cid, second}, "bulk archive ids")
    for c in r["data"]:
        is_api_date(c["archivedDate"], "bulk archive.archivedDate")
    r = u.api("PUT", "/api/ciphers/unarchive", body={"ids": [cid, second]}).json
    for c in r["data"]:
        eq(c["archivedDate"], None, "bulk unarchive")
    u.api("PUT", "/api/ciphers/archive", raw=b"{bad", headers={"Content-Type": "application/json"}, expect=400)

    section("soft delete / restore")
    u.api("PUT", f"/api/ciphers/{cid}/delete")
    c = get_cipher(u, cid)
    is_api_date(c["deletedDate"], "soft delete.deletedDate")
    check(cid not in list_ciphers(u), "soft-deleted cipher hidden from list")
    eq(sync_ciphers(u)[cid]["deletedDate"], c["deletedDate"], "soft delete visible in sync")
    r = u.api("PUT", f"/api/ciphers/{cid}/restore").json
    eq(r["deletedDate"], None, "restore response")
    eq(get_cipher(u, cid)["deletedDate"], None, "restore persisted")
    check(cid in list_ciphers(u), "restored cipher listed")
    u.api("PUT", f"/api/ciphers/{str(uuid.uuid4())}/delete", expect=404)
    u.api("PUT", f"/api/ciphers/{str(uuid.uuid4())}/restore", expect=404)

    u.api("PUT", "/api/ciphers/delete", body={"ids": [cid, second]})
    check(not ({cid, second} & set(list_ciphers(u))), "bulk soft delete")
    r = u.api("PUT", "/api/ciphers/restore", body={"ids": [cid, second]}).json
    eq(r["object"], "list", "bulk restore object")
    eq({c["id"] for c in r["data"]}, {cid, second}, "bulk restore ids")
    for c in r["data"]:
        eq(c["deletedDate"], None, "bulk restore deletedDate")
    check({cid, second} <= set(list_ciphers(u)), "bulk restore listed")

    section("hard delete with favorites, folder, and archive attached")
    full = u.api("POST", "/api/ciphers", body=login_payload("hard", favorite=True, folderId=fid)).json["id"]
    u.api("PUT", f"/api/ciphers/{full}/archive")
    u.api("DELETE", f"/api/ciphers/{full}")
    u.api("GET", f"/api/ciphers/{full}", expect=404)
    u.api("DELETE", f"/api/ciphers/{full}", expect=404)
    check(full not in sync_ciphers(u), "hard-deleted cipher gone from sync")

    full = u.api("POST", "/api/ciphers", body=login_payload("hard2", favorite=True, folderId=fid)).json["id"]
    u.api("POST", f"/api/ciphers/{full}/delete")
    u.api("GET", f"/api/ciphers/{full}", expect=404)

    section("bulk hard delete")
    a = u.api("POST", "/api/ciphers", body=login_payload("bulk-a", favorite=True, folderId=fid)).json["id"]
    b = u.api("POST", "/api/ciphers", body=login_payload("bulk-b")).json["id"]
    c = u.api("POST", "/api/ciphers", body=login_payload("bulk-c", favorite=True)).json["id"]
    d = u.api("POST", "/api/ciphers", body=login_payload("bulk-d")).json["id"]
    u.api("PUT", f"/api/ciphers/{a}/archive")
    u.api("POST", "/api/ciphers/delete", body={"ids": [a, b]})
    u.api("DELETE", "/api/ciphers", body={"ids": [c]})
    current = list_ciphers(u)
    check(not ({a, b, c} & set(current)), "bulk delete removed ciphers")
    check(d in current, "bulk delete spares other ciphers")
    u.api("POST", "/api/ciphers/delete", raw=b"{bad", headers={"Content-Type": "application/json"}, expect=400)
    u.api("DELETE", f"/api/ciphers/{d}")
    u.api("DELETE", f"/api/ciphers/{second}")
    return cid


def test_isolation(u, fid, cid):
    section("user isolation")
    other = User("isolation")
    theirs = other.api("POST", "/api/folders", body={"name": "2.theirs|iv|mac"}).json["id"]
    other.api("GET", f"/api/ciphers/{cid}", expect=404)
    other.api("PUT", f"/api/ciphers/{cid}", body=login_payload("hijack"), expect=404)
    other.api("PUT", f"/api/ciphers/{cid}/partial", body={"favorite": True}, expect=404)
    other.api("PUT", f"/api/ciphers/{cid}/delete", expect=404)
    other.api("PUT", f"/api/ciphers/{cid}/archive", expect=400)
    other.api("DELETE", f"/api/ciphers/{cid}", expect=404)
    other.api("GET", f"/api/folders/{fid}", expect=400)
    other.api("PUT", f"/api/folders/{fid}", body={"name": "x"}, expect=404)

    # Bulk endpoints take ids from the body; ids owned by someone else must be left alone.
    before = get_cipher(u, cid)
    other.api("POST", "/api/ciphers/delete", body={"ids": [cid]})
    other.api("PUT", "/api/ciphers/delete", body={"ids": [cid]})
    other.api("PUT", "/api/ciphers/archive", body={"ids": [cid]})
    other.api("POST", "/api/ciphers/move", body={"folderId": theirs, "ids": [cid]})
    other.api("DELETE", f"/api/folders/{fid}")
    after = get_cipher(u, cid)
    eq(after, before, "other user's bulk calls don't touch the cipher")
    u.api("GET", f"/api/folders/{fid}")

    # Folder ownership is enforced on every path that assigns one.
    u.api("POST", "/api/ciphers", body=login_payload("x", folderId=theirs), expect=400)
    u.api("PUT", f"/api/ciphers/{cid}", body=login_payload("x", folderId=theirs), expect=400)
    u.api("PUT", f"/api/ciphers/{cid}/partial", body={"folderId": theirs, "favorite": False}, expect=400)
    u.api("POST", "/api/ciphers/move", body={"folderId": theirs, "ids": [cid]}, expect=400)
    return other


def test_import(u):
    section("import with folders and relationships")
    p0 = login_payload("imp0", favorite=True)
    p1 = login_payload("imp1")
    p2 = {"type": 2, "name": "2.impnote|iv|mac", "notes": "2.n|iv|mac", "secureNote": {"type": 0}, "favorite": False}
    existing = u.api("POST", "/api/folders", body={"name": "2.existing|iv|mac"}).json["id"]
    preset_id = str(uuid.uuid4())
    body = {
        "ciphers": [p0, p1, p2],
        "folders": [
            {"name": "2.imp-a|iv|mac"},
            {"id": existing, "name": "2.ignored|iv|mac"},
            {"id": preset_id, "name": "2.imp-c|iv|mac"},
        ],
        "folderRelationships": [{"key": 0, "value": 0}, {"key": 1, "value": 1}, {"key": 2, "value": 2}],
    }
    before = set(sync_ciphers(u))
    u.api("POST", "/api/ciphers/import", body=body)
    s = sync(u)
    folders = {f["name"]: f["id"] for f in s["folders"]}
    check("2.imp-a|iv|mac" in folders, "imported folder created")
    eq(folders.get("2.existing|iv|mac"), existing, "existing folder reused and not renamed")
    check("2.ignored|iv|mac" not in folders, "existing folder keeps its name")
    eq(folders.get("2.imp-c|iv|mac"), preset_id, "imported folder keeps the provided id")

    new = [c for c in s["ciphers"] if c["id"] not in before]
    eq(len(new), 3, "imported cipher count")
    by_name = {c["name"]: c for c in new}
    assert_cipher(by_name[p0["name"]], p0, what="import[0]", folder=folders["2.imp-a|iv|mac"], favorite=True)
    assert_cipher(by_name[p1["name"]], p1, what="import[1]", folder=existing)
    assert_cipher(by_name[p2["name"]], p2, what="import[2]", folder=preset_id)
    assert_everywhere(u, by_name[p0["name"]]["id"], p0, what="import[0]", folder=folders["2.imp-a|iv|mac"], favorite=True)

    # Without relationships nothing lands in a folder.
    p3 = login_payload("imp3")
    u.api("POST", "/api/ciphers/import", body={"ciphers": [p3], "folders": []})
    c = [c for c in sync(u)["ciphers"] if c["name"] == p3["name"]][0]
    eq(c["folderId"], None, "import without relationship")
    # A relationship pointing past the folder list is ignored.
    p4 = login_payload("imp4")
    u.api("POST", "/api/ciphers/import", body={"ciphers": [p4], "folders": [], "folderRelationships": [{"key": 0, "value": 9}]})
    c = [c for c in sync(u)["ciphers"] if c["name"] == p4["name"]][0]
    eq(c["folderId"], None, "import with out-of-range relationship")


def test_attachments(u, fid):
    section("attachments v2")
    cid = u.api("POST", "/api/ciphers", body=login_payload("att", favorite=True, folderId=fid)).json["id"]
    content = os.urandom(2345)
    r = u.api(
        "POST",
        f"/api/ciphers/{cid}/attachment/v2",
        body={"key": "2.attkey|iv|mac", "fileName": "2.file|iv|mac", "fileSize": len(content)},
    ).json
    eq(r["object"], "attachment-fileUpload", "attachment.object")
    eq(r["fileUploadType"], 1, "attachment.fileUploadType")
    aid = r["attachmentId"]
    pending = [a for a in r["cipherResponse"]["attachments"] if a["id"] == aid]
    eq(len(pending), 1, "pending attachment in cipherResponse")
    eq(pending[0]["fileName"], "2.file|iv|mac", "pending.fileName")
    eq(pending[0]["key"], "2.attkey|iv|mac", "pending.key")
    # Not visible until the upload finishes.
    eq(get_cipher(u, cid)["attachments"], None, "pending attachment hidden")

    call("PUT", r["url"], raw=content, headers={"Content-Length": str(len(content))}, expect=201)

    c = get_cipher(u, cid)
    eq(len(c["attachments"]), 1, "one attachment after upload")
    a = c["attachments"][0]
    eq(a["id"], aid, "attachment.id")
    eq(a["fileName"], "2.file|iv|mac", "attachment.fileName")
    eq(a["key"], "2.attkey|iv|mac", "attachment.key")
    eq(a["size"], str(len(content)), "attachment.size")
    eq(a["object"], "attachment", "attachment.object")
    check(a["sizeName"], "attachment.sizeName")
    synced = sync_ciphers(u)[cid]["attachments"]
    eq(len(synced), 1, "attachment in sync")
    eq(
        (synced[0]["id"], synced[0]["fileName"], synced[0]["key"], synced[0]["size"], synced[0]["url"]),
        (aid, "2.file|iv|mac", "2.attkey|iv|mac", str(len(content)), None),
        "attachment fields in sync",
    )
    eq(len(list_ciphers(u)[cid]["attachments"]), 1, "attachment in list")

    info = u.api("GET", f"/api/ciphers/{cid}/attachment/{aid}").json
    eq(call("GET", info["url"]).body, content, "attachment bytes round trip")

    # A size mismatch is rejected and leaves no attachment behind.
    r = u.api(
        "POST",
        f"/api/ciphers/{cid}/attachment/v2",
        body={"key": "2.k|iv|mac", "fileName": "2.bad|iv|mac", "fileSize": 10},
    ).json
    call("PUT", r["url"], raw=b"short", headers={"Content-Length": "5"}, expect=400)
    eq(len(get_cipher(u, cid)["attachments"]), 1, "bad upload not finalized")

    u.api("POST", f"/api/ciphers/{cid}/attachment/v2", body={"key": "k", "fileName": "f", "fileSize": 0}, expect=400)
    u.api(
        "POST",
        f"/api/ciphers/{str(uuid.uuid4())}/attachment/v2",
        body={"key": "k", "fileName": "f", "fileSize": 1},
        expect=404,
    )

    section("attachments via multipart")
    blob = os.urandom(777)
    r = u.api(
        "POST",
        f"/api/ciphers/{cid}/attachment/v2",
        body={"key": "2.mp|iv|mac", "fileName": "2.mp|iv|mac", "fileSize": len(blob)},
    ).json
    hdrs, body = multipart([("key", None, b"2.mp2|iv|mac"), ("data", "x.bin", blob)])
    u.api("POST", f"/api/ciphers/{cid}/attachment/{r['attachmentId']}", raw=body, headers=hdrs)
    c = get_cipher(u, cid)
    mp = [a for a in c["attachments"] if a["id"] == r["attachmentId"]][0]
    eq(mp["key"], "2.mp2|iv|mac", "multipart key override")
    info = u.api("GET", f"/api/ciphers/{cid}/attachment/{mp['id']}").json
    eq(call("GET", info["url"]).body, blob, "multipart bytes round trip")

    legacy = os.urandom(99)
    hdrs, body = multipart([("key", None, b"2.leg|iv|mac"), ("data", "legacy.bin", legacy)])
    r = u.api("POST", f"/api/ciphers/{cid}/attachment", raw=body, headers=hdrs).json
    leg = [a for a in r["attachments"] if a["fileName"] == "legacy.bin"][0]
    eq(leg["key"], "2.leg|iv|mac", "legacy.key")
    info = u.api("GET", f"/api/ciphers/{cid}/attachment/{leg['id']}").json
    eq(call("GET", info["url"]).body, legacy, "legacy bytes round trip")

    section("attachment delete")
    r = u.api("DELETE", f"/api/ciphers/{cid}/attachment/{leg['id']}").json
    check(leg["id"] not in [a["id"] for a in r["cipher"]["attachments"]], "legacy attachment gone")
    r = u.api("POST", f"/api/ciphers/{cid}/attachment/{mp['id']}/delete").json
    eq([a["id"] for a in r["cipher"]["attachments"]], [aid], "only the first attachment remains")
    u.api("GET", f"/api/ciphers/{cid}/attachment/{mp['id']}", expect=404)

    section("hard delete a cipher that has attachments and a pending upload")
    u.api("POST", f"/api/ciphers/{cid}/attachment/v2", body={"key": "k", "fileName": "f", "fileSize": 5})
    u.api("DELETE", f"/api/ciphers/{cid}")
    u.api("GET", f"/api/ciphers/{cid}", expect=404)

    # Same through the bulk route.
    cid = u.api("POST", "/api/ciphers", body=login_payload("att2")).json["id"]
    r = u.api("POST", f"/api/ciphers/{cid}/attachment/v2", body={"key": "k", "fileName": "f", "fileSize": 3}).json
    call("PUT", r["url"], raw=b"abc", headers={"Content-Length": "3"}, expect=201)
    u.api("POST", "/api/ciphers/delete", body={"ids": [cid]})
    u.api("GET", f"/api/ciphers/{cid}", expect=404)


def future(days):
    return time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(time.time() + days * 86400))


def text_send(**over):
    body = {
        "type": 0,
        "key": "2.sendkey|iv|mac",
        "name": "2.sendname|iv|mac",
        "notes": "2.sendnotes|iv|mac",
        "text": {"text": "2.secret|iv|mac", "hidden": True},
        "file": None,
        "maxAccessCount": None,
        "expirationDate": None,
        "deletionDate": future(3),
        "disabled": False,
        "hideEmail": False,
        "password": None,
    }
    body.update(over)
    return body


def test_sends(u):
    section("text send create / list / get / access")
    sent = text_send(expirationDate=future(2), maxAccessCount=5)
    s = u.api("POST", "/api/sends", body=sent).json
    eq(s["object"], "send", "send.object")
    eq(s["type"], 0, "send.type")
    eq(s["name"], sent["name"], "send.name")
    eq(s["notes"], sent["notes"], "send.notes")
    eq(s["key"], sent["key"], "send.key")
    eq(s["text"], sent["text"], "send.text")
    eq(s["file"], None, "send.file")
    eq(s["maxAccessCount"], 5, "send.maxAccessCount")
    eq(s["accessCount"], 0, "send.accessCount")
    eq(s["disabled"], False, "send.disabled")
    eq(s["hideEmail"], False, "send.hideEmail")
    eq(s["password"], None, "send.password")
    eq(s["authType"], 2, "send.authType")
    is_api_date(s["revisionDate"], "send.revisionDate")
    is_api_date(s["deletionDate"], "send.deletionDate")
    is_api_date(s["expirationDate"], "send.expirationDate")
    eq(s["deletionDate"], sent["deletionDate"], "send.deletionDate preserved")
    eq(s["expirationDate"], sent["expirationDate"], "send.expirationDate preserved")
    sid = s["id"]
    eq(u.api("GET", f"/api/sends/{sid}").json, s, "GET send")
    listed = u.api("GET", "/api/sends").json
    eq(listed["object"], "list", "sends.object")
    check(s in listed["data"], "send listed")
    check(s in sync(u)["sends"], "send in sync")

    a = call("POST", f"/api/sends/access/{s['accessId']}", body={}).json
    eq(a["object"], "send-access", "access.object")
    eq(a["id"], sid, "access.id")
    eq(a["name"], sent["name"], "access.name")
    eq(a["text"], sent["text"], "access.text")
    eq(a["creatorIdentifier"], u.email, "access.creatorIdentifier")
    eq(a["expirationDate"], sent["expirationDate"], "access.expirationDate")
    eq(u.api("GET", f"/api/sends/{sid}").json["accessCount"], 1, "access count incremented")
    call("POST", f"/api/sends/access/{'A' * 22}", body={}, expect=404)

    section("send access token flow")
    r = call(
        "POST",
        "/identity/connect/token",
        form={"grant_type": "send_access", "client_id": "send", "send_id": s["accessId"]},
    ).json
    eq(r["scope"], "api.send.access", "send token scope")
    a = call("POST", "/api/sends/access", body={}, token=r["access_token"]).json
    eq(a["id"], sid, "token access.id")

    section("send update / limits")
    upd = text_send(name="2.sendname2|iv|mac", text={"text": "2.secret2|iv|mac", "hidden": False}, disabled=False, maxAccessCount=99)
    r = u.api("PUT", f"/api/sends/{sid}", body=upd).json
    eq(r["name"], upd["name"], "send update name")
    eq(r["text"], upd["text"], "send update text")
    eq(r["maxAccessCount"], 99, "send update maxAccessCount")
    eq(r["expirationDate"], None, "send update clears expiration")
    eq(u.api("GET", f"/api/sends/{sid}").json["text"], upd["text"], "send update persisted")
    u.api("PUT", f"/api/sends/{sid}", body=upd | {"type": 1}, expect=400)
    u.api("GET", f"/api/sends/{str(uuid.uuid4())}", expect=400)

    u.api("POST", "/api/sends", body=text_send(deletionDate="2020-01-01T00:00:00.000Z"), expect=400)
    u.api("POST", "/api/sends", body=text_send(deletionDate=future(40)), expect=400)
    u.api("POST", "/api/sends", body=text_send(expirationDate="2020-01-01T00:00:00.000Z"), expect=400)
    u.api("POST", "/api/sends", body=text_send(deletionDate="not-a-date"), expect=400)

    limited = u.api("POST", "/api/sends", body=text_send(maxAccessCount=1)).json
    call("POST", f"/api/sends/access/{limited['accessId']}", body={})
    call("POST", f"/api/sends/access/{limited['accessId']}", body={}, expect=404)

    disabled = u.api("POST", "/api/sends", body=text_send(disabled=True)).json
    eq(disabled["disabled"], True, "send.disabled stored")
    call("POST", f"/api/sends/access/{disabled['accessId']}", body={}, expect=404)

    hidden = u.api("POST", "/api/sends", body=text_send(hideEmail=True)).json
    eq(hidden["hideEmail"], True, "send.hideEmail stored")
    eq(call("POST", f"/api/sends/access/{hidden['accessId']}", body={}).json["creatorIdentifier"], None, "hidden creator")

    section("send password")
    pw = u.api("POST", "/api/sends", body=text_send(password="send-pass-hash")).json
    eq(pw["authType"], 1, "password send authType")
    check(isinstance(pw["password"], str) and len(pw["password"]) == 43, f"send.password is base64url: {pw['password']!r}")
    check(re.fullmatch(r"[A-Za-z0-9_-]+", pw["password"]), f"send.password is base64url: {pw['password']!r}")
    call("POST", f"/api/sends/access/{pw['accessId']}", body={}, expect=401)
    call("POST", f"/api/sends/access/{pw['accessId']}", body={"password": "wrong"}, expect=400)
    a = call("POST", f"/api/sends/access/{pw['accessId']}", body={"password": "send-pass-hash"}).json
    eq(a["text"], text_send()["text"], "password send access")
    eq(u.api("GET", f"/api/sends/{pw['id']}").json["password"], pw["password"], "stored send password stable")

    # password_hash_b64 is checked by the same PBKDF2 routine.
    form = {"grant_type": "send_access", "client_id": "send", "send_id": pw["accessId"]}
    call("POST", "/identity/connect/token", form=form, expect=400)
    call("POST", "/identity/connect/token", form=form | {"password_hash_b64": "wrong"}, expect=404)
    r = call("POST", "/identity/connect/token", form=form | {"password_hash_b64": "send-pass-hash"}).json
    check(r["access_token"], "password send token")

    # Updating with a new password replaces it; updating without one keeps it.
    r = u.api("PUT", f"/api/sends/{pw['id']}", body=text_send(password="new-pass-hash")).json
    check(r["password"] != pw["password"], "send password changed")
    call("POST", f"/api/sends/access/{pw['accessId']}", body={"password": "send-pass-hash"}, expect=400)
    call("POST", f"/api/sends/access/{pw['accessId']}", body={"password": "new-pass-hash"})
    r = u.api("PUT", f"/api/sends/{pw['id']}", body=text_send()).json
    eq(r["authType"], 1, "send password kept when not provided")
    r = u.api("PUT", f"/api/sends/{pw['id']}/remove-password").json
    eq((r["password"], r["authType"]), (None, 2), "remove-password")
    call("POST", f"/api/sends/access/{pw['accessId']}", body={})

    section("file send")
    content = os.urandom(1500)
    body = {
        "type": 1,
        "key": "2.fkey|iv|mac",
        "name": "2.fname|iv|mac",
        "file": {"fileName": "2.fn|iv|mac"},
        "fileLength": len(content),
        "deletionDate": future(2),
        "disabled": False,
    }
    r = u.api("POST", "/api/sends/file/v2", body=body).json
    eq(r["object"], "send-fileUpload", "file send object")
    fs = r["sendResponse"]
    fsid = fs["id"]
    eq(fs["file"]["fileName"], "2.fn|iv|mac", "file send fileName")
    eq(fs["file"]["size"], str(len(content)), "file send size")
    check(fs["file"]["sizeName"], "file send sizeName")
    fid = fs["file"]["id"]
    # Pending until uploaded.
    u.api("GET", f"/api/sends/{fsid}", expect=400)
    call("PUT", r["url"], raw=content, headers={"Content-Length": str(len(content))}, expect=201)
    got = u.api("GET", f"/api/sends/{fsid}").json
    eq(got["file"]["id"], fid, "finalized file id")
    is_api_date(got["revisionDate"], "file send revisionDate")
    a = call("POST", f"/api/sends/access/{fs['accessId']}", body={}).json
    eq(a["file"]["id"], fid, "file send access file id")
    dl = call("POST", f"/api/sends/{fsid}/access/file/{fid}", body={}).json
    eq(dl["object"], "send-fileDownload", "file download object")
    eq(call("GET", dl["url"]).body, content, "file send bytes round trip")
    eq(u.api("GET", f"/api/sends/{fsid}").json["accessCount"], 1, "file send access count")

    # A pending file send uploaded through the multipart route.
    blob = os.urandom(300)
    r = u.api("POST", "/api/sends/file/v2", body=body | {"fileLength": len(blob)}).json
    pend = r["sendResponse"]
    hdrs, mp = multipart([("data", "x.bin", blob)])
    u.api("POST", f"/api/sends/{pend['id']}/file/{pend['file']['id']}", raw=mp, headers=hdrs)
    eq(u.api("GET", f"/api/sends/{pend['id']}").json["file"]["id"], pend["file"]["id"], "multipart file send")

    # Legacy creation: the file arrives with the model.
    legacy = os.urandom(50)
    hdrs, mp = multipart(
        [
            ("model", None, json.dumps({k: v for k, v in body.items() if k != "fileLength"}).encode()),
            ("data", "legacy.bin", legacy),
        ]
    )
    r = u.api("POST", "/api/sends/file", raw=mp, headers=hdrs).json
    eq(r["file"]["size"], str(len(legacy)), "legacy file send size")
    dl = call("POST", f"/api/sends/{r['id']}/access/file/{r['file']['id']}", body={}).json
    eq(call("GET", dl["url"]).body, legacy, "legacy file send bytes")

    # A pending send left behind should not block account deletion later.
    u.api("POST", "/api/sends/file/v2", body=body | {"fileLength": 10})

    section("send delete")
    u.api("DELETE", f"/api/sends/{sid}")
    u.api("GET", f"/api/sends/{sid}", expect=400)
    u.api("DELETE", f"/api/sends/{fsid}")
    u.api("GET", f"/api/sends/{fsid}", expect=400)


def test_devices(u):
    section("devices")
    r = u.api("GET", "/api/devices").json
    eq(r["object"], "list", "devices.object")
    mine = [d for d in r["data"] if d["identifier"] == u.device]
    eq(len(mine), 1, "current device listed")
    d = mine[0]
    eq(d["id"], u.device, "device.id")
    eq(d["name"], "smoke-device", "device.name")
    eq(d["type"], 9, "device.type")
    eq(d["object"], "device", "device.object")
    eq(d["devicePendingAuthRequest"], None, "device.devicePendingAuthRequest")
    is_api_date(d["creationDate"], "device.creationDate")
    one = u.api("GET", f"/api/devices/identifier/{u.device}").json
    eq(one["identifier"], u.device, "GET device")
    u.api("GET", f"/api/devices/identifier/{uuid.uuid4()}", expect=(400, 404))

    email_b64 = base64.urlsafe_b64encode(u.email.encode()).decode().rstrip("=")
    known = call("GET", "/api/devices/knowndevice", headers={"X-Request-Email": email_b64, "X-Device-Identifier": u.device})
    eq(known.json, True, "known device")
    unknown = call("GET", "/api/devices/knowndevice", headers={"X-Request-Email": email_b64, "X-Device-Identifier": "nope"})
    eq(unknown.json, False, "unknown device")

    # Logging in again from the same device with a new name updates that one row.
    _, r = login(u.email, u.password, device=u.device, device_name="renamed", device_type="8")
    same = [x for x in u.api("GET", "/api/devices").json["data"] if x["identifier"] == u.device]
    eq(len(same), 1, "same device reused")
    eq((same[0]["name"], same[0]["type"]), ("renamed", 8), "device rename on login")
    login(u.email, u.password, device=u.device)

    u.api("PUT", f"/api/devices/identifier/{u.device}/token", body={"pushToken": "push-token"})
    u.api("POST", f"/api/devices/identifier/{u.device}/token", body={"pushToken": "push-token-2"})
    u.api("PUT", f"/api/devices/identifier/{u.device}/clear-token")
    u.api("POST", f"/api/devices/identifier/{u.device}/clear-token")
    u.api("PUT", f"/api/devices/identifier/{uuid.uuid4()}/token", body={"pushToken": "x"}, expect=401)


def test_auth_requests(u):
    section("auth requests (login with device)")
    hdrs = {"device-type": "9"}
    code = "access-code-" + RUN
    body = {"email": u.email, "publicKey": "2.pub|iv|mac", "deviceIdentifier": u.device, "accessCode": code, "type": 0}
    ar = call("POST", "/api/auth-requests", body=body, headers=hdrs).json
    eq(ar["object"], "auth-request", "auth-request.object")
    eq(ar["publicKey"], "2.pub|iv|mac", "auth-request.publicKey")
    eq(ar["requestApproved"], False, "auth-request.requestApproved")
    eq(ar["key"], None, "auth-request.key")
    eq(ar["responseDate"], None, "auth-request.responseDate")
    is_api_date(ar["creationDate"], "auth-request.creationDate")
    rid = ar["id"]

    call("POST", "/api/auth-requests", body=body | {"deviceIdentifier": "unknown"}, headers=hdrs, expect=400)

    pending = u.api("GET", "/api/auth-requests/pending").json["data"]
    check(rid in [p["id"] for p in pending], "auth request pending")
    check(rid in [p["id"] for p in u.api("GET", "/api/auth-requests").json["data"]], "auth request listed")
    eq(u.api("GET", f"/api/auth-requests/{rid}").json["id"], rid, "GET auth request")
    dev = [d for d in u.api("GET", "/api/devices").json["data"] if d["identifier"] == u.device][0]
    eq(dev["devicePendingAuthRequest"]["id"], rid, "device shows pending auth request")
    is_api_date(dev["devicePendingAuthRequest"]["creationDate"], "pending.creationDate")

    resp = call("GET", f"/api/auth-requests/{rid}/response?code={code}", headers=hdrs).json
    eq(resp["requestApproved"], False, "response before approval")
    call("GET", f"/api/auth-requests/{rid}/response?code=wrong", headers=hdrs, expect=400)

    # Not approved yet, so the auth request cannot be used to log in.
    login(u.email, code, device=u.device, authrequest=rid, expect=400)

    approve = {"deviceIdentifier": u.device, "key": "2.enc|iv|mac", "masterPasswordHash": "2.mph|iv|mac", "requestApproved": True}
    r = u.api("PUT", f"/api/auth-requests/{rid}", body=approve).json
    eq(r["requestApproved"], True, "approved")
    eq(r["key"], "2.enc|iv|mac", "approved.key")
    eq(r["masterPasswordHash"], "2.mph|iv|mac", "approved.masterPasswordHash")
    is_api_date(r["responseDate"], "approved.responseDate")
    resp = call("GET", f"/api/auth-requests/{rid}/response?code={code}", headers=hdrs).json
    eq((resp["requestApproved"], resp["key"]), (True, "2.enc|iv|mac"), "response after approval")
    u.api("PUT", f"/api/auth-requests/{rid}", body=approve, expect=400)
    check(rid not in [p["id"] for p in u.api("GET", "/api/auth-requests/pending").json["data"]], "no longer pending")

    _, r = login(u.email, code, device=u.device, authrequest=rid)
    eq(r.json["Key"], USER_KEY, "login with approved auth request")
    login(u.email, "bad-code", device=u.device, authrequest=rid, expect=400)

    # Denying removes the request.
    ar2 = call("POST", "/api/auth-requests", body=body, headers=hdrs).json
    u.api("PUT", f"/api/auth-requests/{ar2['id']}", body=approve | {"requestApproved": False})
    u.api("GET", f"/api/auth-requests/{ar2['id']}", expect=400)

    # Left pending on purpose: account deletion has to clean it up.
    call("POST", "/api/auth-requests", body=body, headers=hdrs)


def test_twofactor():
    section("two-factor authenticator")
    u = User("totp")
    eq(u.api("GET", "/api/two-factor").json["data"], [], "no providers")
    u.api("POST", "/api/two-factor/get-authenticator", body={"masterPasswordHash": "wrong"}, expect=401)
    r = u.api("POST", "/api/two-factor/get-authenticator", body=u.auth).json
    eq(r["enabled"], False, "authenticator not enabled")
    eq(r["object"], "twoFactorAuthenticator", "authenticator.object")
    secret = r["key"]

    u.api(
        "POST",
        "/api/two-factor/authenticator",
        body=u.auth | {"key": secret, "token": "000000" if totp(secret, now_step()) != "000000" else "111111"},
        expect=401,
    )
    r = u.api("POST", "/api/two-factor/authenticator", body=u.auth | {"key": secret, "token": totp(secret, now_step())}).json
    eq((r["enabled"], r["key"]), (True, secret), "authenticator enabled")
    providers = u.api("GET", "/api/two-factor").json["data"]
    eq(providers, [{"enabled": True, "type": 0, "object": "twoFactorProvider"}], "providers")
    eq(u.api("GET", "/api/accounts/profile").json["twoFactorEnabled"], True, "profile.twoFactorEnabled")
    eq(sync(u)["profile"]["twoFactorEnabled"], True, "sync.profile.twoFactorEnabled")
    r = u.api("POST", "/api/two-factor/get-authenticator", body=u.auth).json
    eq((r["enabled"], r["key"]), (True, secret), "get-authenticator after enabling")

    section("login with TOTP")
    _, r = login(u.email, u.password, expect=400)
    eq(r.json["error_description"], "Two factor required.", "2FA challenge")
    eq(r.json["TwoFactorProviders"], ["0"], "2FA providers")
    login(u.email, u.password, twoFactorToken="12345", twoFactorProvider="0", expect=400)

    # The activation code is spent; the drift window accepts the next step's code.
    next_code = totp(secret, now_step() + 1)
    device, r = login(u.email, u.password, twoFactorToken=next_code, twoFactorProvider="0", twoFactorRemember="1")
    eq(r.json["Key"], USER_KEY, "TOTP login")
    remember = r.json["TwoFactorToken"]
    check(remember, "remember token issued")
    u.token = r.json["access_token"]
    u.device = device
    # Replay of the same step is rejected.
    login(u.email, u.password, twoFactorToken=next_code, twoFactorProvider="0", expect=401)

    section("remember device token")
    _, r = login(u.email, u.password, device=device, twoFactorToken=remember, twoFactorProvider="5")
    eq(r.json["Key"], USER_KEY, "remember login")
    _, r = login(u.email, u.password, device=str(uuid.uuid4()), twoFactorToken=remember, twoFactorProvider="5", expect=400)
    check("TwoFactorProviders" in r.json, "remember token is bound to its device")

    section("recovery code")
    r = u.api("POST", "/api/two-factor/get-recover", body=u.auth).json
    eq(r["object"], "twoFactorRecover", "recover.object")
    code = r["code"]
    check(code, "recovery code present")
    login(u.email, u.password, twoFactorToken="WRONG", twoFactorProvider="8", expect=400)
    _, r = login(u.email, u.password, device=device, twoFactorToken=code.lower(), twoFactorProvider="8")
    u.token = r.json["access_token"]
    eq(u.api("GET", "/api/two-factor").json["data"], [], "recovery removes 2FA")
    eq(u.api("POST", "/api/two-factor/get-recover", body=u.auth).json["code"], None, "recovery code spent")
    _, r = login(u.email, u.password, device=device, twoFactorToken=remember, twoFactorProvider="5")

    section("disable authenticator")
    u.api("POST", "/api/two-factor/authenticator", body=u.auth | {"key": secret, "token": totp(secret, now_step())})
    u.api("DELETE", "/api/two-factor/authenticator", body=u.auth | {"key": "AAAA", "type": 0}, expect=400)
    r = u.api("DELETE", "/api/two-factor/authenticator", body=u.auth | {"key": secret.lower(), "type": 0}).json
    eq((r["enabled"], r["type"]), (False, 0), "DELETE authenticator")
    eq(u.api("GET", "/api/two-factor").json["data"], [], "authenticator gone")
    eq(u.api("POST", "/api/two-factor/get-recover", body=u.auth).json["code"], None, "recovery code cleared")
    r = u.api("POST", "/api/two-factor/get-authenticator", body=u.auth).json
    secret2 = r["key"]
    u.api("PUT", "/api/two-factor/authenticator", body=u.auth | {"key": secret2, "token": totp(secret2, now_step())})
    r = u.api("POST", "/api/two-factor/disable", body=u.auth | {"type": 0}).json
    eq((r["enabled"], r["type"]), (False, 0), "POST two-factor/disable")
    _, r = login(u.email, u.password, device=device)
    eq(r.json["Key"], USER_KEY, "login without 2FA again")
    u.token = r.json["access_token"]

    section("delete an account that still has 2FA enabled")
    secret3 = u.api("POST", "/api/two-factor/get-authenticator", body=u.auth).json["key"]
    u.api("POST", "/api/two-factor/authenticator", body=u.auth | {"key": secret3, "token": totp(secret3, now_step())})
    u.api("DELETE", "/api/accounts", body=u.auth)
    login(u.email, u.password, expect=401)


def test_credentials():
    section("change password")
    u = User("cred")
    old_token = u.token
    new_pw = client_hash(f"new-{RUN}")
    u.api(
        "POST",
        "/api/accounts/password",
        body={"masterPasswordHash": "wrong", "newMasterPasswordHash": new_pw, "masterPasswordHint": None, "key": "2.k2|iv|mac"},
        expect=401,
    )
    u.api(
        "POST",
        "/api/accounts/password",
        body={"masterPasswordHash": u.password, "newMasterPasswordHash": new_pw, "masterPasswordHint": "newhint", "key": "2.k2|iv|mac"},
    )
    call("GET", "/api/accounts/profile", token=old_token, expect=401)
    login(u.email, u.password, expect=401)
    u.password = new_pw
    t = u.relogin()
    eq(t["Key"], "2.k2|iv|mac", "new user key after password change")
    r = call("POST", "/api/accounts/password-hint", body={"email": u.email}, expect=400).json
    check("newhint" in r["error"], f"new hint: {r}")

    section("change KDF")
    new_pw2 = client_hash(f"kdf-{RUN}")
    argon = {"kdf": 1, "kdfIterations": 4, "kdfMemory": 128, "kdfParallelism": 2}
    body = {
        "masterPasswordHash": u.password,
        "authenticationData": {"salt": u.email, "kdf": argon, "masterPasswordAuthenticationHash": new_pw2},
        "unlockData": {"salt": u.email, "kdf": argon, "masterKeyWrappedUserKey": "2.k3|iv|mac"},
    }
    u.api("POST", "/api/accounts/kdf", body=body | {"masterPasswordHash": "wrong"}, expect=401)
    u.api("POST", "/api/accounts/kdf", body=body)
    p = call("POST", "/identity/accounts/prelogin", body={"email": u.email}).json
    eq((p["kdf"], p["kdfIterations"], p["kdfMemory"], p["kdfParallelism"]), (1, 4, 128, 2), "KDF change prelogin")
    login(u.email, u.password, expect=401)
    u.password = new_pw2
    t = u.relogin()
    eq((t["Kdf"], t["KdfIterations"], t["KdfMemory"], t["KdfParallelism"]), (1, 4, 128, 2), "KDF change token")
    eq(t["Key"], "2.k3|iv|mac", "KDF change key")
    unlock = sync(u)["userDecryption"]["masterPasswordUnlock"]
    eq(unlock["kdf"], {"kdfType": 1, "iterations": 4, "memory": 128, "parallelism": 2}, "sync.userDecryption.kdf")
    eq(unlock["masterKeyWrappedUserKey"], "2.k3|iv|mac", "sync.userDecryption key")

    section("key rotation")
    fid = u.api("POST", "/api/folders", body={"name": "2.rot|iv|mac"}).json["id"]
    fid2 = u.api("POST", "/api/folders", body={"name": "2.rot2|iv|mac"}).json["id"]
    cipher = u.api("POST", "/api/ciphers", body=login_payload("rot", favorite=True, folderId=fid)).json
    cid = cipher["id"]
    r = u.api("POST", f"/api/ciphers/{cid}/attachment/v2", body={"key": "2.oldatt|iv|mac", "fileName": "2.oldfile|iv|mac", "fileSize": 4}).json
    call("PUT", r["url"], raw=b"data", headers={"Content-Length": "4"}, expect=201)
    aid = r["attachmentId"]
    send = u.api("POST", "/api/sends", body=text_send()).json

    rotated = login_payload("rotated", favorite=False, folderId=fid2, id=cid)
    rotated["attachments2"] = {aid: {"fileName": "2.newfile|iv|mac", "key": "2.newatt|iv|mac"}}
    new_pw3 = client_hash(f"rot-{RUN}")
    rot_body = {
        "oldMasterKeyAuthenticationHash": u.password,
        "accountUnlockData": {
            "masterPasswordUnlockData": {
                "kdfType": 1,
                "kdfIterations": 4,
                "kdfMemory": 128,
                "kdfParallelism": 2,
                "email": u.email,
                "masterKeyAuthenticationHash": new_pw3,
                "masterKeyEncryptedUserKey": "2.k4|iv|mac",
            }
        },
        "accountKeys": {"userKeyEncryptedAccountPrivateKey": "2.priv2|iv|mac", "accountPublicKey": PUBLIC_KEY},
        "accountData": {
            "ciphers": [rotated],
            "folders": [{"id": fid, "name": "2.rotn|iv|mac"}, {"id": fid2, "name": "2.rotn2|iv|mac"}],
            "sends": [
                {
                    "id": send["id"],
                    "type": 0,
                    "key": "2.sk2|iv|mac",
                    "name": "2.sn2|iv|mac",
                    "notes": None,
                    "text": {"text": "2.st2|iv|mac", "hidden": False},
                    "deletionDate": send["deletionDate"],
                }
            ],
        },
    }
    path = "/api/accounts/key-management/rotate-user-account-keys"
    u.api("POST", path, body=rot_body | {"oldMasterKeyAuthenticationHash": "wrong"}, expect=401)
    u.api("POST", path, body=rot_body | {"accountData": rot_body["accountData"] | {"ciphers": []}}, expect=400)
    u.api("POST", path, body=rot_body | {"accountData": rot_body["accountData"] | {"folders": []}}, expect=400)
    swapped = dict(rotated, id=str(uuid.uuid4()))
    u.api("POST", path, body=rot_body | {"accountData": rot_body["accountData"] | {"ciphers": [swapped]}}, expect=400)
    u.api("POST", path, body=rot_body | {"accountKeys": rot_body["accountKeys"] | {"accountPublicKey": "other"}}, expect=400)
    # Rejected attempts change nothing.
    eq(get_cipher(u, cid)["name"], cipher["name"], "rejected rotation keeps cipher")

    u.api("POST", path, body=rot_body)
    login(u.email, u.password, expect=401)
    u.password = new_pw3
    t = u.relogin()
    eq(t["Key"], "2.k4|iv|mac", "rotation key")
    eq(t["PrivateKey"], "2.priv2|iv|mac", "rotation private key")
    expected = {k: v for k, v in rotated.items() if k not in ("id", "attachments2")}
    assert_everywhere(u, cid, expected, what="rotated", folder=fid2)
    c = get_cipher(u, cid)
    eq((c["attachments"][0]["fileName"], c["attachments"][0]["key"]), ("2.newfile|iv|mac", "2.newatt|iv|mac"), "rotated attachment")
    names = {f["id"]: f["name"] for f in u.api("GET", "/api/folders").json["data"]}
    eq(names, {fid: "2.rotn|iv|mac", fid2: "2.rotn2|iv|mac"}, "rotated folders")
    s = u.api("GET", f"/api/sends/{send['id']}").json
    eq((s["name"], s["key"], s["text"]), ("2.sn2|iv|mac", "2.sk2|iv|mac", {"text": "2.st2|iv|mac", "hidden": False}), "rotated send")

    section("security stamp")
    stamp = u.api("GET", "/api/accounts/profile").json["securityStamp"]
    old_token, old_refresh = u.token, u.tokens["refresh_token"]
    u.api("POST", "/api/accounts/security-stamp", body={"masterPasswordHash": "wrong"}, expect=401)
    u.api("POST", "/api/accounts/security-stamp", body=u.auth)
    call("GET", "/api/accounts/profile", token=old_token, expect=401)
    call("POST", "/identity/connect/token", form={"grant_type": "refresh_token", "refresh_token": old_refresh}, expect=400)
    u.relogin()
    check(u.api("GET", "/api/accounts/profile").json["securityStamp"] != stamp, "security stamp rotated")
    eq(len(u.api("GET", "/api/devices").json["data"]), 1, "other devices removed")

    section("purge vault")
    u.api("POST", "/api/ciphers/purge", body={"masterPasswordHash": "wrong"}, expect=401)
    gone = u.api("POST", "/api/ciphers", body=login_payload("purged", favorite=True, folderId=fid)).json["id"]
    u.api("PUT", f"/api/ciphers/{gone}/archive")
    soft = u.api("POST", "/api/ciphers", body=login_payload("purged2")).json["id"]
    u.api("PUT", f"/api/ciphers/{soft}/delete")
    u.api("POST", "/api/ciphers/purge", body=u.auth)
    s = sync(u)
    eq((s["ciphers"], s["folders"]), ([], []), "purge removes ciphers and folders")
    check(s["sends"], "purge keeps sends")
    # Vault is usable afterwards.
    fid3 = u.api("POST", "/api/folders", body={"name": "2.again|iv|mac"}).json["id"]
    cid3 = u.api("POST", "/api/ciphers", body=login_payload("again", folderId=fid3)).json["id"]
    eq(get_cipher(u, cid3)["folderId"], fid3, "vault usable after purge")
    u.api("DELETE", "/api/accounts", body={"masterPasswordHash": "wrong"}, expect=401)
    u.api("POST", "/api/accounts/delete", body=u.auth)
    login(u.email, u.password, expect=401)


def test_scheduled(u):
    section("scheduled purge leaves recent data alone")
    soft = u.api("POST", "/api/ciphers", body=login_payload("recent-trash")).json["id"]
    u.api("PUT", f"/api/ciphers/{soft}/delete")
    send = u.api("POST", "/api/sends", body=text_send()).json["id"]
    pend = u.api(
        "POST",
        "/api/sends/file/v2",
        body={"type": 1, "key": "k", "name": "n", "file": {"fileName": "f"}, "fileLength": 5, "deletionDate": future(2)},
    ).json["url"]
    cid = u.api("POST", "/api/ciphers", body=login_payload("pending-att")).json["id"]
    att = u.api("POST", f"/api/ciphers/{cid}/attachment/v2", body={"key": "k", "fileName": "f", "fileSize": 2}).json["url"]

    call("GET", "/cdn-cgi/handler/scheduled?cron=0+3+*+*+*")
    time.sleep(1)

    check(get_cipher(u, soft)["deletedDate"], "recently trashed cipher kept")
    u.api("GET", f"/api/sends/{send}")
    call("PUT", pend, raw=b"12345", headers={"Content-Length": "5"}, expect=201)
    call("PUT", att, raw=b"ab", headers={"Content-Length": "2"}, expect=201)


def test_delete_account(u):
    section("delete account with everything attached")
    fid = u.api("POST", "/api/folders", body={"name": "2.last|iv|mac"}).json["id"]
    cid = u.api("POST", "/api/ciphers", body=login_payload("last", favorite=True, folderId=fid)).json["id"]
    u.api("PUT", f"/api/ciphers/{cid}/archive")
    r = u.api("POST", f"/api/ciphers/{cid}/attachment/v2", body={"key": "k", "fileName": "f", "fileSize": 2}).json
    call("PUT", r["url"], raw=b"ab", headers={"Content-Length": "2"}, expect=201)
    u.api("POST", f"/api/ciphers/{cid}/attachment/v2", body={"key": "k", "fileName": "f", "fileSize": 2})
    u.api("POST", "/api/sends", body=text_send(password="pw"))
    token = u.token

    u.api("DELETE", "/api/accounts", body={"masterPasswordHash": "wrong"}, expect=401)
    eq(u.api("DELETE", "/api/accounts", body=u.auth).json, {}, "delete account response")
    call("GET", "/api/accounts/profile", token=token, expect=401)
    login(u.email, u.password, expect=401)
    # The email can be registered again.
    register(u.email, u.password)
    fresh = login(u.email, u.password)[1].json
    eq(fresh["Key"], USER_KEY, "re-registered account")


def make_witness():
    """A fully populated user that stays behind for tests/storage_check.py."""
    section("witness user")
    u = User("witness", hint="witness hint")
    u.api("PUT", "/api/accounts/avatar", body={"avatarColor": "#abcdef"})
    fid = u.api("POST", "/api/folders", body={"name": "2.wfolder|iv|mac"}).json["id"]
    sent = login_payload("witness", favorite=True, folderId=fid)
    cid = u.api("POST", "/api/ciphers", body=sent).json["id"]
    u.api("PUT", f"/api/ciphers/{cid}/archive")
    content = b"witness-attachment"
    r = u.api(
        "POST",
        f"/api/ciphers/{cid}/attachment/v2",
        body={"key": "2.wkey|iv|mac", "fileName": "2.wfile|iv|mac", "fileSize": len(content)},
    ).json
    call("PUT", r["url"], raw=content, headers={"Content-Length": str(len(content))}, expect=201)
    trash = u.api("POST", "/api/ciphers", body=login_payload("witness-trash")).json["id"]
    u.api("PUT", f"/api/ciphers/{trash}/delete")
    u.api("POST", "/api/sends", body=text_send(password="witness-send-pass", expirationDate=future(2)))
    secret = u.api("POST", "/api/two-factor/get-authenticator", body=u.auth).json["key"]
    u.api("POST", "/api/two-factor/authenticator", body=u.auth | {"key": secret, "token": totp(secret, now_step())})
    call(
        "POST",
        "/api/auth-requests",
        body={"email": u.email, "publicKey": "2.pub|iv|mac", "deviceIdentifier": u.device, "accessCode": "witness", "type": 0},
        headers={"device-type": "9"},
    )
    assert_cipher(get_cipher(u, cid), sent, what="witness", folder=fid, favorite=True)
    return u.email, cid, u.password


def main():
    started = time.time()
    try:
        test_meta()
        u = test_accounts()
        fid = test_folders(u)
        cid = test_ciphers(u, fid)
        test_isolation(u, fid, cid)
        test_import(u)
        test_attachments(u, fid)
        test_sends(u)
        test_devices(u)
        test_auth_requests(u)
        test_twofactor()
        test_credentials()
        test_scheduled(u)
        test_delete_account(u)
        email, witness_cid, password = make_witness()
    except Failure as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print(f"WITNESS email={email} cipher={witness_cid} password={password}")
    print(f"OK ({time.time() - started:.0f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
