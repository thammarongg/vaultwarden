#!/usr/bin/env python3
"""End-to-end HTTP test for emergency access (phase 4), mail off.

Same rules as tests/smoke.py (local server only, stdlib only). The wait-time expiry is
simulated by moving `recovery_initiated_at` back in the local D1 database with
`wrangler d1 execute --local` (SMOKE_PERSIST_TO selects a non-default state dir).
"""

import os
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(__file__))

from smoke import (  # noqa: E402
    USER_KEY,
    Failure,
    User,
    call,
    check,
    client_hash,
    eq,
    login,
    login_payload,
    new_email,
    register,
    section,
)
from smoke_orgs import DENIED, org_payload  # noqa: E402

WORKERS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def local_sql(sql):
    cmd = ["npx", "-y", "wrangler", "d1", "execute", "vaultwarden-cf", "--local", "--command", sql]
    if os.environ.get("SMOKE_PERSIST_TO"):
        cmd += ["--persist-to", os.environ["SMOKE_PERSIST_TO"]]
    subprocess.run(cmd, cwd=WORKERS, check=True, capture_output=True, timeout=120)


def trusted(u):
    return {e["email"]: e for e in u.api("GET", "/api/emergency-access/trusted").json["data"]}


def granted(u):
    return {e["email"]: e for e in u.api("GET", "/api/emergency-access/granted").json["data"]}


def invite(grantor, email, atype, days=1, expect=200):
    return grantor.api(
        "POST",
        "/api/emergency-access/invite",
        body={"email": email, "type": atype, "waitTimeDays": days},
        expect=expect,
    )


def test_invite_confirm(grantor, takeover):
    section("emergency access: invite / accept (no mail) / confirm")
    invite(grantor, grantor.email, 1, expect=400)
    invite(grantor, takeover.email, 1, days=0, expect=400)
    invite(grantor, takeover.email, 5, expect=400)
    invite(grantor, takeover.email, 1)
    invite(grantor, takeover.email, 1, expect=400)  # duplicate
    e = trusted(grantor)[takeover.email]
    eq((e["status"], e["type"], e["waitTimeDays"], e["object"]), (1, 1, 1, "emergencyAccessGranteeDetails"), "accepted at once")
    eid = e["id"]
    g = granted(takeover)[grantor.email]
    eq((g["id"], g["status"], g["object"]), (eid, 1, "emergencyAccessGrantorDetails"), "grantee view")
    eq(grantor.api("GET", f"/api/emergency-access/{eid}").json["granteeId"], e["granteeId"], "get one")
    takeover.api("GET", f"/api/emergency-access/{eid}", expect=DENIED)
    # Only confirmed contacts can start a recovery.
    takeover.api("POST", f"/api/emergency-access/{eid}/initiate", expect=400)
    takeover.api("POST", f"/api/emergency-access/{eid}/confirm", body={"key": "4.ea-key"}, expect=400)
    r = grantor.api("POST", f"/api/emergency-access/{eid}/confirm", body={"key": "4.ea-key"}).json
    eq((r["status"], r["object"]), (2, "emergencyAccess"), "confirmed")
    r = grantor.api("PUT", f"/api/emergency-access/{eid}", body={"type": 1, "waitTimeDays": 7, "keyEncrypted": None}).json
    eq(r["waitTimeDays"], 7, "wait time updated")
    grantor.api("POST", f"/api/emergency-access/{eid}", body={"type": "Takeover", "waitTimeDays": 1})
    return eid


def test_recovery(grantor, takeover, eid):
    section("emergency access: initiate / reject / approve / takeover")
    takeover.api("POST", f"/api/emergency-access/{eid}/takeover", expect=400)
    eq(takeover.api("POST", f"/api/emergency-access/{eid}/initiate").json["status"], 3, "initiated")
    grantor.api("POST", f"/api/emergency-access/{eid}/initiate", expect=400)
    takeover.api("POST", f"/api/emergency-access/{eid}/approve", expect=400)
    eq(grantor.api("POST", f"/api/emergency-access/{eid}/reject").json["status"], 2, "rejected")
    takeover.api("POST", f"/api/emergency-access/{eid}/initiate")
    eq(grantor.api("POST", f"/api/emergency-access/{eid}/approve").json["status"], 4, "approved")
    # Takeover access can't be used to view.
    takeover.api("POST", f"/api/emergency-access/{eid}/view", expect=400)
    t = takeover.api("POST", f"/api/emergency-access/{eid}/takeover").json
    eq(
        (t["kdf"], t["kdfIterations"], t["keyEncrypted"], t["salt"], t["object"]),
        (0, 600000, "4.ea-key", grantor.email, "emergencyAccessTakeover"),
        "takeover data",
    )
    eq(takeover.api("GET", f"/api/emergency-access/{eid}/policies").json["object"], "list", "policies")

    # The grantor is a plain member of someone else's org: takeover drops that membership.
    org_owner = User("ea-orgowner")
    org = org_owner.api("POST", "/api/organizations", body=org_payload("EA Org")).json["id"]
    org_owner.api(
        "POST",
        f"/api/organizations/{org}/users/invite",
        body={"emails": [grantor.email], "type": 2, "collections": [], "groups": [], "accessAll": False, "permissions": {}},
    )
    users = org_owner.api("GET", f"/api/organizations/{org}/users").json["data"]
    mid = [m for m in users if m["email"] == grantor.email][0]["id"]
    org_owner.api("POST", f"/api/organizations/{org}/users/{mid}/confirm", body={"key": "4.org-key"})
    eq(len(grantor.api("GET", "/api/sync").json["profile"]["organizations"]), 1, "grantor in the org")

    new_hash = client_hash(f"ea-new-{uuid.uuid4()}")
    takeover.api("POST", f"/api/emergency-access/{eid}/password", body={"newMasterPasswordHash": "x"}, expect=400)
    takeover.api(
        "POST",
        f"/api/emergency-access/{eid}/password",
        body={"newMasterPasswordHash": new_hash, "key": "2.new-user-key|iv|mac"},
    )
    login(grantor.email, grantor.password, expect=(400, 401))
    _, r = login(grantor.email, new_hash)
    eq(r.json["Key"], "2.new-user-key|iv|mac", "grantor logs in with the new password")
    grantor.password = new_hash
    grantor.token = r.json["access_token"]
    eq(grantor.api("GET", "/api/sync").json["profile"]["organizations"], [], "non-owner membership removed")
    eq(grantor.api("GET", "/api/two-factor").json["data"], [], "no 2FA left")


def test_view_timeout(grantor):
    section("emergency access: view after the wait time (cron + lazy approval)")
    viewer = User("ea-viewer")
    personal = grantor.api("POST", "/api/ciphers", body=login_payload("ea-personal")).json["id"]
    invite(grantor, viewer.email, 0, days=2)
    eid = trusted(grantor)[viewer.email]["id"]
    grantor.api("POST", f"/api/emergency-access/{eid}/confirm", body={"key": "4.view-key"})
    viewer.api("POST", f"/api/emergency-access/{eid}/initiate")
    viewer.api("POST", f"/api/emergency-access/{eid}/view", expect=400)
    # One day left: not yet.
    local_sql(f"UPDATE emergency_access SET recovery_initiated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day') WHERE uuid = '{eid}'")
    call("GET", "/cdn-cgi/handler/scheduled?cron=0+3+*+*+*")
    eq(trusted(grantor)[viewer.email]["status"], 3, "still waiting")
    local_sql(f"UPDATE emergency_access SET recovery_initiated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-3 day') WHERE uuid = '{eid}'")
    call("GET", "/cdn-cgi/handler/scheduled?cron=0+3+*+*+*")
    eq(granted(viewer)[grantor.email]["status"], 4, "approved by the cron")
    v = viewer.api("POST", f"/api/emergency-access/{eid}/view").json
    eq((v["keyEncrypted"], v["object"]), ("4.view-key", "emergencyAccessView"), "view data")
    eq([c["id"] for c in v["ciphers"]], [personal], "grantor's personal items only")
    viewer.api("POST", f"/api/emergency-access/{eid}/takeover", expect=400)

    # Lazy approval: a request after the deadline approves without waiting for the cron.
    viewer.api("POST", f"/api/emergency-access/{eid}/delete")
    eq(trusted(grantor).get(viewer.email), None, "grantee removed the access")
    invite(grantor, viewer.email, 0, days=1)
    eid = trusted(grantor)[viewer.email]["id"]
    grantor.api("POST", f"/api/emergency-access/{eid}/confirm", body={"key": "4.view-key"})
    viewer.api("POST", f"/api/emergency-access/{eid}/initiate")
    local_sql(f"UPDATE emergency_access SET recovery_initiated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-2 day') WHERE uuid = '{eid}'")
    eq(len(viewer.api("POST", f"/api/emergency-access/{eid}/view").json["ciphers"]), 1, "lazy approval")
    grantor.api("DELETE", f"/api/emergency-access/{eid}")
    viewer.api("POST", f"/api/emergency-access/{eid}/view", expect=400)


def test_new_email(grantor):
    section("emergency access: invite an email without an account")
    email = new_email("ea-new")
    invite(grantor, email, 0)
    e = trusted(grantor)[email]
    eq(e["status"], 0, "invited")
    password = client_hash(f"ea-new-{uuid.uuid4()}")
    register(email, password)
    eq(trusted(grantor)[email]["status"], 1, "accepted on register (no mail)")
    grantor.api("POST", f"/api/emergency-access/{e['id']}/reinvite", expect=400)


def main():
    started = time.time()
    try:
        grantor = User("ea-grantor")
        takeover = User("ea-takeover")
        eid = test_invite_confirm(grantor, takeover)
        test_recovery(grantor, takeover, eid)
        test_view_timeout(grantor)
        test_new_email(grantor)
        check(USER_KEY, "keys")
    except Failure as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print(f"OK emergency ({time.time() - started:.0f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
