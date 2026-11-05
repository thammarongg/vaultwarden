#!/usr/bin/env python3
"""End-to-end test for the admin page (phase 4). Needs the server started with
`--var ADMIN_TOKEN:local-admin-token` (tests/run_local.sh does). Stdlib only, local only.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(__file__))

from smoke import BASE, OPENER, RUN, Failure, User, check, client_hash, eq, login, now_step, register, section, totp  # noqa: E402
from smoke_orgs import org_payload  # noqa: E402

TOKEN = os.environ.get("ADMIN_TOKEN", "local-admin-token")


def req(method, path, *, form=None, cookie=None, origin=BASE):
    headers = {}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if cookie:
        headers["Cookie"] = cookie
    if origin and method == "POST":
        headers["Origin"] = origin
    r = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with OPENER.open(r, timeout=60) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode()


def admin_session():
    section("admin: login")
    status, _, body = req("GET", "/admin")
    check(status == 200 and 'name="token"' in body, "login form")
    status, _, _ = req("POST", "/admin", form={"token": "wrong"})
    eq(status, 401, "wrong token")
    status, headers, _ = req("POST", "/admin", form={"token": TOKEN})
    eq(status, 303, "login redirects")
    cookie = headers.get("set-cookie", "")
    check(cookie.startswith("VW_ADMIN=") and "HttpOnly" in cookie and "SameSite=Strict" in cookie, f"session cookie: {cookie}")
    cookie = cookie.split(";", 1)[0]
    status, _, body = req("GET", "/admin", cookie=cookie)
    check(status == 200 and "Settings" in body and "ALLOWED_EMAILS" in body, "settings page")
    check("local-test" not in body, "secret values are not shown")
    status, _, body = req("GET", "/admin/diagnostics", cookie=cookie)
    check(status == 200 and "<dt>users</dt>" in body, "diagnostics")
    # Without a session every admin route shows the login form.
    status, _, body = req("GET", "/admin/users", cookie="VW_ADMIN=forged")
    check('name="token"' in body, "forged session refused")
    return cookie


def admin_users(cookie):
    status, _, body = req("GET", "/admin/users", cookie=cookie)
    eq(status, 200, "users json")
    return {u["email"]: u for u in json.loads(body)}


def act(cookie, path, origin=BASE):
    status, headers, _ = req("POST", path, cookie=cookie, origin=origin)
    return status, urllib.parse.unquote(headers.get("location", ""))


def test_users(cookie):
    section("admin: users (disable / deauth / remove 2FA / delete)")
    u = User("admin-target")
    info = admin_users(cookie)[u.email]
    eq((info["userEnabled"], info["invited"], info["cipherCount"]), (True, False, 0), "user row")
    uid = info["id"]
    status, _ = act(cookie, f"/admin/users/{uid}/disable", origin="https://evil.example")
    eq(status, 400, "foreign origin refused")
    status, loc = act(cookie, f"/admin/users/{uid}/disable")
    check(status == 303 and "disabled" in loc, f"disabled: {loc}")
    u.api("GET", "/api/sync", expect=401)
    _, r = login(u.email, u.password, expect=400)
    check("disabled" in r.json.get("error", "") + json.dumps(r.json), "login refused while disabled")
    status, html_ = req("GET", "/admin/users/overview", cookie=cookie)[0::2]
    check(status == 200 and u.email in html_ and "disabled" in html_, "overview shows disabled user")
    act(cookie, f"/admin/users/{uid}/enable")
    u.relogin()
    act(cookie, f"/admin/users/{uid}/deauth")
    u.api("GET", "/api/sync", expect=401)
    u.relogin()

    r = u.api("POST", "/api/two-factor/get-authenticator", body=u.auth).json
    u.api("POST", "/api/two-factor/authenticator", body={"key": r["key"], "token": totp(r["key"], now_step()), "userVerificationToken": r["userVerificationToken"]})
    login(u.email, u.password, expect=400)
    eq(admin_users(cookie)[u.email]["twoFactorEnabled"], True, "2FA shown")
    act(cookie, f"/admin/users/{uid}/remove-2fa")
    login(u.email, u.password)

    status, loc = act(cookie, f"/admin/users/{uid}/delete")
    check("deleted" in loc, f"deleted: {loc}")
    check(u.email not in admin_users(cookie), "user gone")
    login(u.email, u.password, expect=(400, 401))


def test_invite(cookie):
    section("admin: invite an email outside ALLOWED_EMAILS")
    email = f"invited-{RUN}@outside.test"
    password = client_hash(f"invited-{RUN}")
    status, loc = act_invite(cookie, email)
    check("invited" in loc, f"invite: {loc}")
    eq(admin_users(cookie)[email]["invited"], True, "placeholder listed as invited")
    register(email, password)
    login(email, password)
    eq(admin_users(cookie)[email]["invited"], False, "registered")
    other = f"stranger-{RUN}@outside.test"
    from smoke import call
    call("POST", "/identity/accounts/register", body={
        "email": other, "name": "x", "masterPasswordHash": password, "masterPasswordHint": None,
        "key": "2.k|i|m", "kdf": 0, "kdfIterations": 600000, "kdfMemory": None, "kdfParallelism": None,
        "userAsymmetricKeys": {"publicKey": "p", "encryptedPrivateKey": "2.p|i|m"},
    }, expect=401)


def act_invite(cookie, email):
    status, headers, _ = req("POST", "/admin/invite", form={"email": email}, cookie=cookie)
    return status, urllib.parse.unquote(headers.get("location", ""))


def test_orgs(cookie):
    section("admin: organizations")
    owner = User("admin-orgowner")
    org = owner.api("POST", "/api/organizations", body=org_payload("Admin Org")).json["id"]
    status, _, body = req("GET", "/admin/organizations/overview", cookie=cookie)
    check(status == 200 and "Admin Org" in body and org in body, "org listed")
    status, loc = act(cookie, f"/admin/organizations/{org}/delete")
    check("deleted" in loc, f"org deleted: {loc}")
    owner.api("GET", f"/api/organizations/{org}", expect=(400, 401, 403, 404))
    status, headers, _ = req("GET", "/admin/logout", cookie=cookie)
    check("Max-Age=0" in headers.get("set-cookie", ""), "logout clears the cookie")


def main():
    started = time.time()
    try:
        cookie = admin_session()
        test_users(cookie)
        test_invite(cookie)
        test_orgs(cookie)
    except Failure as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print(f"OK admin ({time.time() - started:.0f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
