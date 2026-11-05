#!/usr/bin/env python3
"""End-to-end test for mail-enabled organization flows (invites by email, accept with token,
account recovery), against a server started with RESEND_API_KEY + MAIL_API_URL pointing at the
mock mail API this script runs on 127.0.0.1:$MAIL_MOCK_PORT (tests/run_local.sh does that).
Never talks to Resend.
"""

import http.server
import json
import os
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(__file__))

from smoke import RUN, Failure, User, call, check, client_hash, eq, login, register, section, sync  # noqa: E402
from smoke_orgs import DENIED, members, org_payload, put_policy, rw, sync_org_view  # noqa: E402

PORT = int(os.environ.get("MAIL_MOCK_PORT", "8799"))
OUTBOX = []
FAIL_FOR = set()


class MailMock(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        ok = self.path == "/emails" and self.headers.get("Authorization") == "Bearer local-test-key"
        if ok and not FAIL_FOR.intersection(body.get("to", [])):
            OUTBOX.append(body)
            self.send_response(200)
            payload = b'{"id":"mock"}'
        else:
            self.send_response(500 if ok else 401)
            payload = b'{"message":"mock failure"}'
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):  # noqa: A002
        pass


def mails_to(email, subject_part):
    return [m for m in OUTBOX if email in m["to"] and subject_part in m["subject"]]


def last_invite(email):
    found = mails_to(email, "Join ")
    check(found, f"invite email to {email}")
    m = found[-1]
    check(m["from"] == "AsDevWishes Vault <no-reply@vault.asdevwishes.com>", f"from: {m['from']}")
    url = next(w for w in m["text"].split() if "/#/accept-organization/?" in w)
    q = urllib.parse.parse_qs(url.split("?", 1)[1])
    for key in ("email", "organizationName", "organizationId", "organizationUserId", "token",
                "initOrganization", "orgUserHasExistingUser"):
        check(key in q, f"invite link has {key}")
    check("<p>" in m["html"], "html body present")
    return {k: v[0] for k, v in q.items()}


def test_invites():
    section("mail: invite existing account, accept with token, confirm")
    owner = User("mail-owner")
    org_id = owner.api("POST", "/api/organizations", body=org_payload("Mail Org")).json["id"]
    col = owner.api("GET", f"/api/organizations/{org_id}/collections").json["data"][0]["id"]
    eve = User("mail-eve")
    owner.api("POST", f"/api/organizations/{org_id}/users/invite", body={
        "emails": [eve.email], "type": 2, "groups": [], "collections": [rw(col)]})
    eq(members(owner, org_id)[eve.email]["status"], 0, "with mail, existing accounts stay invited")
    link = last_invite(eve.email)
    eq((link["organizationId"], link["orgUserHasExistingUser"], link["organizationName"]),
       (org_id, "true", "Mail Org"), "invite link fields")
    mid = link["organizationUserId"]

    pols = call("GET", f"/api/organizations/{org_id}/policies/token?token={link['token']}").json
    eq(pols["data"], [], "policies by invite token")
    call("GET", f"/api/organizations/{str(org_id)[:-1]}0/policies/token?token={link['token']}", expect=400)

    mallory = User("mail-mallory")
    mallory.api("POST", f"/api/organizations/{org_id}/users/{mid}/accept", body={"token": link["token"]}, expect=400)
    eve.api("POST", f"/api/organizations/{org_id}/users/{mid}/accept", body={"token": link["token"][:-2] + "xx"}, expect=400)
    eve.api("POST", f"/api/organizations/{org_id}/users/{mid}/accept", body={"token": link["token"]})
    eq(members(owner, org_id)[eve.email]["status"], 1, "accepted with token")
    check(mails_to(owner.email, "Invitation accepted"), "inviter notified of acceptance")
    eve.api("POST", f"/api/organizations/{org_id}/users/{mid}/accept", body={"token": link["token"]}, expect=400)

    owner.api("POST", f"/api/organizations/{org_id}/users/{mid}/confirm", body={"key": "4.eve"})
    check(mails_to(eve.email, "confirmed"), "confirmation email")
    eq(sync_org_view(eve)[0][org_id]["useResetPassword"], True, "useResetPassword with mail")

    section("mail: invite a new email, register, accept; reinvite; mail failure rolls back")
    email = f"mail-new-{RUN}@invited.test"
    password = client_hash(f"mail-new-{RUN}")
    owner.api("POST", f"/api/organizations/{org_id}/users/invite", body={
        "emails": [email], "type": 2, "groups": [], "collections": []})
    link = last_invite(email)
    eq(link["orgUserHasExistingUser"], "false", "new user link")
    owner.api("POST", f"/api/organizations/{org_id}/users/{link['organizationUserId']}/reinvite")
    eq(len(mails_to(email, "Join ")), 2, "reinvite resends the email")
    register(email, password)
    eq(members(owner, org_id)[email]["status"], 0, "with mail, registration doesn't auto-accept")
    _, r = login(email, password)
    call("POST", f"/api/organizations/{org_id}/users/{link['organizationUserId']}/accept",
         body={"token": last_invite(email)["token"]}, token=r.json["access_token"])
    eq(members(owner, org_id)[email]["status"], 1, "new user accepted")

    bad = f"mail-bounce-{RUN}@invited.test"
    FAIL_FOR.add(bad)
    owner.api("POST", f"/api/organizations/{org_id}/users/invite", body={
        "emails": [bad], "type": 2, "groups": [], "collections": []}, expect=400)
    check(bad not in members(owner, org_id), "failed invite leaves no member")
    try:
        register(bad, password)
        raise Failure("failed invite left a usable invitation")
    except Failure as e:
        check("401" in str(e), f"bounced invitee can't register: {e}")
    return owner, org_id, eve, mid


def test_recovery(owner, org_id, eve, mid):
    section("mail: account recovery (enroll, details, reset password)")
    owner.api("GET", f"/api/organizations/{org_id}/users/{mid}/reset-password-details", expect=400)  # no policy
    put_policy(owner, org_id, 8, True, {"autoEnrollEnabled": False})
    eve_id = eve.api("GET", "/api/accounts/profile").json["id"]
    eve.api("PUT", f"/api/organizations/{org_id}/users/{eve_id}/reset-password-enrollment",
            body={"resetPasswordKey": "4.reset-key", "masterPasswordHash": "wrong"}, expect=401)
    eve.api("PUT", f"/api/organizations/{org_id}/users/{eve_id}/reset-password-enrollment",
            body={"resetPasswordKey": "4.reset-key", "masterPasswordHash": eve.password})
    eq(members(owner, org_id)[eve.email]["resetPasswordEnrolled"], True, "enrolled")
    d = owner.api("GET", f"/api/organizations/{org_id}/users/{mid}/reset-password-details").json
    eq((d["resetPasswordKey"], d["encryptedPrivateKey"], d["masterPasswordSalt"], d["kdfIterations"]),
       ("4.reset-key", "2.org-priv|iv|mac", eve.email, 600000), "reset details")
    eve.api("GET", f"/api/organizations/{org_id}/users/{mid}/reset-password-details", expect=DENIED)

    new_pw = client_hash(f"eve-new-{RUN}")
    owner.api("PUT", f"/api/organizations/{org_id}/users/{mid}/recover-account", body={
        "newMasterPasswordHash": new_pw, "key": "2.new-user-key|iv|mac",
        "resetMasterPassword": True, "resetTwoFactor": False})
    check(mails_to(eve.email, "Admin account recovery"), "recovery email sent")
    call("GET", "/api/accounts/profile", token=eve.token, expect=401)  # stamp rotated
    login(eve.email, eve.password, expect=(400, 401))
    _, r = login(eve.email, new_pw)
    eq(r.json["Key"], "2.new-user-key|iv|mac", "new user key after recovery")

    # Auto-enroll: accepting without a reset key is refused.
    put_policy(owner, org_id, 8, True, {"autoEnrollEnabled": True})
    zed = User("mail-zed")
    owner.api("POST", f"/api/organizations/{org_id}/users/invite", body={
        "emails": [zed.email], "type": 2, "groups": [], "collections": []})
    link = last_invite(zed.email)
    zed.api("POST", f"/api/organizations/{org_id}/users/{link['organizationUserId']}/accept",
            body={"token": link["token"]}, expect=400)
    zed.api("POST", f"/api/organizations/{org_id}/users/{link['organizationUserId']}/accept",
            body={"token": link["token"], "resetPasswordKey": "4.zed-reset"})
    eq(members(owner, org_id)[zed.email]["resetPasswordEnrolled"], True, "auto-enrolled on accept")
    zed_id = zed.api("GET", "/api/accounts/profile").json["id"]
    zed.api("PUT", f"/api/organizations/{org_id}/users/{zed_id}/reset-password-enrollment",
            body={"resetPasswordKey": None}, expect=400)  # can't withdraw under auto-enroll
    check(sync(zed)["policies"] == [], "accepted member: no confirmed policies yet")


def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), MailMock)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    started = time.time()
    try:
        owner, org_id, eve, mid = test_invites()
        test_recovery(owner, org_id, eve, mid)
    except Failure as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1
    finally:
        server.shutdown()
    print(f"OK mail ({time.time() - started:.0f}s, {len(OUTBOX)} emails)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
