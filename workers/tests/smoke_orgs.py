#!/usr/bin/env python3
"""End-to-end HTTP test for organizations, collections, members and org ciphers (phase 3).

Same rules as tests/smoke.py (local server only, stdlib only); reuses its helpers. Run after
smoke.py against the same `wrangler dev --local` server (tests/run_local.sh does both).
"""

import sys
import time
import uuid

sys.path.insert(0, __import__("os").path.dirname(__file__))

from smoke import (  # noqa: E402
    PUBLIC_KEY,
    text_send,
    RUN,
    Failure,
    User,
    call,
    check,
    client_hash,
    eq,
    login,
    login_payload,
    register,
    section,
    sync,
)

ORG_KEY = "4.org-key-for-user"
DENIED = (400, 401, 403, 404)


def org_payload(name="Smoke Org"):
    return {
        "name": name,
        "billingEmail": f"billing-{RUN}@example.com",
        "collectionName": "2.default-col|iv|mac",
        "key": ORG_KEY,
        "keys": {"encryptedPrivateKey": "2.org-priv|iv|mac", "publicKey": "org-public-key"},
        "planType": 0,
    }


def members(owner, org):
    r = owner.api("GET", f"/api/organizations/{org}/users?includeCollections=true&includeGroups=true").json
    return {m["email"]: m for m in r["data"]}


def sync_org_view(u):
    s = sync(u)
    return (
        {o["id"]: o for o in s["profile"]["organizations"]},
        {c["id"]: c for c in s["collections"]},
        {c["id"]: c for c in s["ciphers"]},
    )


def test_org_lifecycle():
    section("organizations: create / get / keys / update")
    owner = User("org-owner")
    org = owner.api("POST", "/api/organizations", body=org_payload()).json
    org_id = org["id"]
    eq(org["object"], "organization", "org object")
    eq(org["name"], "Smoke Org", "org name")
    eq(org["hasPublicAndPrivateKeys"], True, "org keys flag")
    eq(owner.api("GET", f"/api/organizations/{org_id}").json["id"], org_id, "get org")
    keys = owner.api("GET", f"/api/organizations/{org_id}/keys").json
    eq((keys["publicKey"], keys.get("privateKey")), ("org-public-key", None), "org keys: public only")
    eq(owner.api("GET", f"/api/organizations/{org_id}/public-key").json["publicKey"], "org-public-key", "public key")
    owner.api("POST", f"/api/organizations/{org_id}/keys",
              body={"encryptedPrivateKey": "x", "publicKey": "y"}, expect=400)
    upd = owner.api("PUT", f"/api/organizations/{org_id}",
                    body={"name": "Smoke Org 2", "billingEmail": "B@example.com"}).json
    eq((upd["name"], upd["billingEmail"]), ("Smoke Org 2", "b@example.com"), "org update")

    orgs, cols, _ = sync_org_view(owner)
    check(org_id in orgs, "owner sync lists the org")
    o = orgs[org_id]
    eq((o["type"], o["status"], o["key"], o["object"]), (0, 2, ORG_KEY, "profileOrganization"), "owner membership")
    eq(len(cols), 1, "default collection in sync")
    default_col = next(iter(cols.values()))
    eq((default_col["organizationId"], default_col["manage"], default_col["readOnly"]),
       (org_id, True, False), "default collection flags")
    profile_orgs = owner.api("GET", "/api/accounts/profile").json["organizations"]
    eq([p["id"] for p in profile_orgs], [org_id], "profile organizations")
    return owner, org_id, default_col["id"]


def test_collections(owner, org_id):
    section("collections: create / update / details")
    col = owner.api("POST", f"/api/organizations/{org_id}/collections",
                    body={"name": "2.col-b|iv|mac", "externalId": None, "users": [], "groups": []}).json
    eq((col["object"], col["organizationId"], col["name"]), ("collection", org_id, "2.col-b|iv|mac"), "new collection")
    col_b = col["id"]
    upd = owner.api("PUT", f"/api/organizations/{org_id}/collections/{col_b}",
                    body={"name": "2.col-b2|iv|mac", "users": [], "groups": []}).json
    eq(upd["name"], "2.col-b2|iv|mac", "collection rename")
    listed = owner.api("GET", f"/api/organizations/{org_id}/collections").json["data"]
    eq(len(listed), 2, "org collections")
    details = owner.api("GET", f"/api/organizations/{org_id}/collections/details").json["data"]
    eq(len(details), 2, "collection details")
    check(all(d["object"] == "collectionAccessDetails" and d["assigned"] for d in details), "details assigned")
    eq(len(owner.api("GET", "/api/collections").json["data"]), 2, "user collections")
    return col_b


def test_org_ciphers(owner, org_id, col_a, col_b):
    section("org ciphers: create / share / collections / org-details")
    sent_a = login_payload("org-a", organizationId=org_id)
    ca = owner.api("POST", "/api/ciphers/create", body={"cipher": sent_a, "collectionIds": [col_a]}).json
    eq((ca["organizationId"], ca["collectionIds"], ca["edit"]), (org_id, [col_a], True), "org cipher create")
    eq(ca["organizationUseTotp"], True, "org cipher organizationUseTotp")
    check(ca.get("userId") is None, "org cipher has no userId")

    # Org cipher without collections needs full access (owner has it).
    owner.api("POST", "/api/ciphers", body=login_payload("org-nocol", organizationId=org_id))

    personal = owner.api("POST", "/api/ciphers", body=login_payload("to-share")).json
    shared_body = {"cipher": login_payload("shared", organizationId=org_id), "collectionIds": [col_b]}
    shared = owner.api("PUT", f"/api/ciphers/{personal['id']}/share", body=shared_body).json
    eq((shared["organizationId"], shared["collectionIds"], shared["name"]),
       (org_id, [col_b], "2.name-shared|iv|mac"), "share into org")
    owner.api("PUT", f"/api/ciphers/{personal['id']}/share",
              body={"cipher": login_payload("x", organizationId=org_id), "collectionIds": []}, expect=400)

    # Bulk share.
    p2 = owner.api("POST", "/api/ciphers", body=login_payload("bulk-share")).json
    bulk = owner.api("PUT", "/api/ciphers/share", body={
        "ciphers": [login_payload("bulk-shared", id=p2["id"], organizationId=org_id)],
        "collectionIds": [col_a],
    }).json
    eq([(c["id"], c["object"]) for c in bulk["data"]], [(p2["id"], "cipherMini")], "bulk share")

    details = owner.api("GET", f"/api/ciphers/organization-details?organizationId={org_id}").json["data"]
    eq(len(details), 4, "org details count")

    # Collections assignment.
    r = owner.api("PUT", f"/api/ciphers/{ca['id']}/collections_v2", body={"collectionIds": [col_a, col_b]}).json
    eq(sorted(r["cipher"]["collectionIds"]), sorted([col_a, col_b]), "collections_v2")
    eq(r["object"], "optionalCipherDetails", "collections_v2 object")
    r = owner.api("PUT", f"/api/ciphers/{ca['id']}/collections", body={"collectionIds": [col_a]}).json
    eq(r["collectionIds"], [col_a], "collections update")
    owner.api("PUT", f"/api/ciphers/{ca['id']}/collections", body={"collectionIds": [str(uuid.uuid4())]}, expect=400)
    owner.api("PUT", f"/api/ciphers/{p2['id']}/collections", body={"collectionIds": []})
    return ca["id"], shared["id"], p2["id"]


def test_members(owner, org_id, col_a, col_b, cid_a, cid_b):
    section("members: invite / confirm / access rules")
    alice = User("org-alice")
    bob = User("org-bob")
    owner.api("POST", f"/api/organizations/{org_id}/users/invite", body={
        "emails": [alice.email], "type": 2, "groups": [], "permissions": {},
        "collections": [{"id": col_a, "readOnly": True, "hidePasswords": True, "manage": False}],
    })
    owner.api("POST", f"/api/organizations/{org_id}/users/invite", body={
        "emails": [bob.email.upper()], "type": "2", "groups": [], "permissions": {},
        "collections": [{"id": col_b, "readOnly": False, "hidePasswords": False, "manage": False}],
    })
    owner.api("POST", f"/api/organizations/{org_id}/users/invite", body={
        "emails": [alice.email], "type": 2, "groups": [], "collections": []}, expect=400)
    # Non-owners may not invite admins; users can't invite at all.
    alice.api("POST", f"/api/organizations/{org_id}/users/invite", body={
        "emails": ["x@example.com"], "type": 2, "groups": [], "collections": []}, expect=DENIED)

    ms = members(owner, org_id)
    eq(ms[alice.email]["status"], 1, "existing account is accepted on invite (no mail)")
    eq(ms[alice.email]["collections"],
       [{"id": col_a, "readOnly": True, "hidePasswords": True, "manage": False}], "alice collections")
    eq(ms[bob.email]["status"], 1, "bob accepted")

    # Accepted (unconfirmed) members can't see org data yet.
    orgs, cols, ciphers = sync_org_view(alice)
    eq((orgs[org_id]["status"], orgs[org_id]["key"]), (1, None), "accepted membership in sync")
    eq((cols, ciphers), ({}, {}), "accepted member sees nothing")

    ids = [ms[alice.email]["id"], ms[bob.email]["id"]]
    upk = owner.api("GET", f"/api/users/{ms[alice.email]['userId']}/public-key").json
    eq((upk["publicKey"], upk["object"]), (PUBLIC_KEY, "userKey"), "user public key")
    owner.api("GET", f"/api/users/{uuid.uuid4()}/public-key", expect=404)
    pk = owner.api("POST", f"/api/organizations/{org_id}/users/public-keys", body={"ids": ids}).json["data"]
    eq(sorted(p["key"] for p in pk), [PUBLIC_KEY, PUBLIC_KEY], "member public keys")
    owner.api("POST", f"/api/organizations/{org_id}/users/{ids[0]}/confirm", body={"key": ""}, expect=400)
    res = owner.api("POST", f"/api/organizations/{org_id}/users/confirm",
                    body={"keys": [{"id": i, "key": f"4.key-{n}"} for n, i in enumerate(ids)]}).json["data"]
    eq([r["error"] for r in res], ["", ""], "bulk confirm")
    res = owner.api("POST", f"/api/organizations/{org_id}/users/confirm",
                    body={"keys": [{"id": ids[0], "key": "4.again"}]}).json["data"]
    check(res[0]["error"], "confirming twice reports an error")

    # Alice: read-only + hidden passwords on col_a.
    orgs, cols, ciphers = sync_org_view(alice)
    eq((orgs[org_id]["status"], orgs[org_id]["key"], orgs[org_id]["type"]), (2, "4.key-0", 2), "alice confirmed")
    eq(list(cols), [col_a], "alice collections in sync")
    eq((cols[col_a]["readOnly"], cols[col_a]["hidePasswords"], cols[col_a]["manage"]), (True, True, False),
       "alice collection flags")
    check(cid_a in ciphers and cid_b not in ciphers, "alice sees only col_a ciphers")
    c = ciphers[cid_a]
    eq((c["edit"], c["viewPassword"], c["permissions"]), (False, False, {"delete": False, "restore": False}),
       "alice read-only flags")
    got = alice.api("GET", f"/api/ciphers/{cid_a}").json
    eq((got["edit"], got["collectionIds"]), (False, [col_a]), "alice get cipher")
    alice.api("GET", f"/api/ciphers/{cid_b}", expect=404)
    alice.api("PUT", f"/api/ciphers/{cid_a}", body=login_payload("hijack", organizationId=org_id), expect=DENIED)
    alice.api("PUT", f"/api/ciphers/{cid_a}/delete", expect=DENIED)
    alice.api("DELETE", f"/api/ciphers/{cid_a}", expect=DENIED)
    alice.api("POST", "/api/ciphers/delete", body={"ids": [cid_a]})  # bulk ignores it
    check(cid_a in sync_org_view(owner)[2], "alice's bulk delete left the cipher alone")
    alice.api("PUT", f"/api/ciphers/{cid_a}/collections", body={"collectionIds": [col_a, col_b]}, expect=DENIED)
    alice.api("GET", f"/api/organizations/{org_id}/users", expect=DENIED)
    alice.api("GET", f"/api/ciphers/organization-details?organizationId={org_id}", expect=DENIED)
    eq(len(alice.api("GET", f"/api/ciphers/organization-details/assigned?organizationId={org_id}").json["data"]),
       1, "alice assigned org ciphers")
    alice.api("POST", "/api/ciphers/create", body={
        "cipher": login_payload("alice-org", organizationId=org_id), "collectionIds": [col_a]}, expect=DENIED)

    # Per-user state on an org cipher stays per user.
    alice.api("PUT", f"/api/ciphers/{cid_a}/partial", body={"favorite": True, "folderId": None})
    eq(alice.api("GET", f"/api/ciphers/{cid_a}").json["favorite"], True, "alice favorite")
    eq(owner.api("GET", f"/api/ciphers/{cid_a}").json["favorite"], False, "owner favorite unaffected")

    # Bob: read-write on col_b.
    upd = bob.api("PUT", f"/api/ciphers/{cid_b}", body=login_payload("bob-edit", organizationId=org_id)).json
    eq((upd["name"], upd["edit"]), ("2.name-bob-edit|iv|mac", True), "bob edits org cipher")
    eq(owner.api("GET", f"/api/ciphers/{cid_b}").json["name"], "2.name-bob-edit|iv|mac", "owner sees bob's edit")
    bob.api("PUT", f"/api/ciphers/{cid_b}", body=login_payload("bob-move"), expect=400)  # org mismatch
    made = bob.api("POST", "/api/ciphers/create", body={
        "cipher": login_payload("bob-new", organizationId=org_id), "collectionIds": [col_b]}).json
    eq(made["collectionIds"], [col_b], "bob creates in writable collection")
    bob.api("POST", "/api/ciphers/create", body={
        "cipher": login_payload("bob-bad", organizationId=org_id), "collectionIds": [col_a]}, expect=DENIED)
    bob.api("POST", "/api/ciphers", body=login_payload("bob-nocol", organizationId=org_id), expect=DENIED)
    bob.api("PUT", f"/api/ciphers/{made['id']}/delete")
    check(sync_org_view(owner)[2][made["id"]]["deletedDate"], "owner sees bob's soft delete")
    bob.api("PUT", f"/api/ciphers/{made['id']}/restore")
    bob.api("DELETE", f"/api/ciphers/{made['id']}")
    check(made["id"] not in sync_org_view(owner)[2], "bob hard-deleted his org cipher")

    # Collection membership change propagates.
    owner.api("PUT", f"/api/ciphers/{cid_a}/collections", body={"collectionIds": [col_a, col_b]})
    check(cid_a in sync_org_view(bob)[2], "bob sees cipher after it joins col_b")

    # Edit member: alice becomes read-write on col_b only.
    owner.api("PUT", f"/api/organizations/{org_id}/users/{ids[0]}", body={
        "type": 2, "collections": [{"id": col_b, "readOnly": False, "hidePasswords": False, "manage": False}],
        "groups": [], "permissions": {}, "accessAll": False})
    _, cols, ciphers = sync_org_view(alice)
    eq(list(cols), [col_b], "alice moved to col_b")
    eq(ciphers[cid_a]["edit"], True, "alice can now edit via col_b")
    check(cid_b in ciphers, "alice sees col_b cipher")
    got = owner.api("GET", f"/api/organizations/{org_id}/users/{ids[0]}?includeGroups=true").json
    eq((got["object"], got["type"], got["status"]), ("organizationUserDetails", 2, 2), "get member")

    # Manager role: may manage collections it can manage, not members.
    owner.api("PUT", f"/api/organizations/{org_id}/users/{ids[1]}", body={
        "type": 4, "collections": [{"id": col_b, "readOnly": False, "hidePasswords": False, "manage": True}],
        "groups": [], "permissions": {}})
    eq(sync_org_view(bob)[0][org_id]["type"], 4, "manager reported as custom")
    bob.api("PUT", f"/api/organizations/{org_id}/collections/{col_b}",
            body={"name": "2.col-b3|iv|mac", "users": [], "groups": []})
    bob.api("PUT", f"/api/organizations/{org_id}/collections/{col_a}",
            body={"name": "2.nope|iv|mac", "users": [], "groups": []}, expect=DENIED)
    bob.api("GET", f"/api/organizations/{org_id}/users/{ids[0]}", expect=DENIED)
    owner.api("PUT", f"/api/organizations/{org_id}/users/{ids[1]}", body={
        "type": 2, "collections": [{"id": col_b, "readOnly": False, "hidePasswords": False, "manage": False}],
        "groups": [], "permissions": {}})

    # Revoke / restore.
    owner.api("PUT", f"/api/organizations/{org_id}/users/{ids[1]}/revoke")
    eq(members(owner, org_id)[bob.email]["status"], -1, "bob revoked")
    eq(sync_org_view(bob)[2], {}, "revoked member sees no org ciphers")
    owner.api("PUT", f"/api/organizations/{org_id}/users/{ids[1]}/restore")
    eq(members(owner, org_id)[bob.email]["status"], 2, "bob restored")
    check(cid_b in sync_org_view(bob)[2], "restored member sees ciphers again")
    me_id = members(owner, org_id)[owner.email]["id"]
    owner.api("PUT", f"/api/organizations/{org_id}/users/{me_id}/revoke", expect=400)
    owner.api("PUT", f"/api/organizations/{org_id}/users/{me_id}",
              body={"type": 2, "collections": [], "groups": []}, expect=400)  # last owner

    # Remove / leave.
    owner.api("DELETE", f"/api/organizations/{org_id}/users/{ids[1]}")
    orgs, cols, ciphers = sync_org_view(bob)
    eq((orgs, cols, ciphers), ({}, {}, {}), "removed member sees nothing")
    alice.api("POST", f"/api/organizations/{org_id}/leave")
    eq(sync_org_view(alice)[0], {}, "alice left")
    owner.api("POST", f"/api/organizations/{org_id}/leave", expect=400)  # last owner
    return alice


def test_invite_new_email(owner, org_id, col_a, cid_a):
    section("members: invite an email without an account")
    email = f"invitee-{RUN}@invited.test"
    password = client_hash(f"invitee-{RUN}")
    # Not in ALLOWED_EMAILS: plain registration is refused...
    try:
        register(f"stranger-{RUN}@invited.test", password)
        raise Failure("non-invited email outside ALLOWED_EMAILS registered")
    except Failure as e:
        check("expected" in str(e) and "401" in str(e), f"stranger refused: {e}")
    owner.api("POST", f"/api/organizations/{org_id}/users/invite", body={
        "emails": [email], "type": 2, "groups": [], "permissions": {},
        "collections": [{"id": col_a, "readOnly": False, "hidePasswords": False, "manage": False}]})
    eq(members(owner, org_id)[email]["status"], 0, "new email is invited")
    login(email, password, expect=(400, 401))  # placeholder account can't log in
    owner.api("POST", f"/api/organizations/{org_id}/users/reinvite",
              body={"ids": [members(owner, org_id)[email]["id"]]})
    eq(members(owner, org_id)[email]["status"], 0, "reinvite keeps invited until registration")
    # ...but an invited one may register, which accepts the invite.
    register(email, password)
    m = members(owner, org_id)[email]
    eq(m["status"], 1, "registration accepts the invite")
    owner.api("POST", f"/api/organizations/{org_id}/users/{m['id']}/confirm", body={"key": "4.inv"})
    _, r = login(email, password)
    token = r.json["access_token"]
    s = call("GET", "/api/sync", token=token).json
    check(cid_a in {c["id"] for c in s["ciphers"]}, "invitee sees org cipher")
    # Deleting a pending member also drops the invitation.
    email2 = f"invitee2-{RUN}@invited.test"
    owner.api("POST", f"/api/organizations/{org_id}/users/invite", body={
        "emails": [email2], "type": 2, "groups": [], "collections": []})
    owner.api("DELETE", f"/api/organizations/{org_id}/users", body={"ids": [members(owner, org_id)[email2]["id"]]})
    try:
        register(email2, password)
        raise Failure("removed invitee could still register")
    except Failure as e:
        check("401" in str(e), f"removed invitee refused: {e}")


def join(owner, org_id, label, *, atype=2, collections=()):
    """Create a user, invite and confirm them. Returns (user, member_id)."""
    u = User(label)
    owner.api("POST", f"/api/organizations/{org_id}/users/invite", body={
        "emails": [u.email], "type": atype, "groups": [], "permissions": {},
        "collections": [dict(c) for c in collections]})
    mid = members(owner, org_id)[u.email]["id"]
    owner.api("POST", f"/api/organizations/{org_id}/users/{mid}/confirm", body={"key": f"4.key-{label}"})
    return u, mid


def rw(col, manage=False):
    return {"id": col, "readOnly": False, "hidePasswords": False, "manage": manage}


def test_groups(owner, org_id, col_a, col_b, cid_a, cid_b):
    section("groups: CRUD, membership, group-derived access")
    gina, gmid = join(owner, org_id, "org-gina")
    eq(sync_org_view(gina)[2], {}, "no collections: no ciphers")
    g = owner.api("POST", f"/api/organizations/{org_id}/groups", body={
        "name": "Readers", "accessAll": False, "externalId": None,
        "collections": [{"id": col_a, "readOnly": True, "hidePasswords": False, "manage": False}],
        "users": [gmid]}).json
    eq((g["object"], g["name"], g["organizationId"]), ("group", "Readers", org_id), "group create")
    gid = g["id"]
    _, cols, ciphers = sync_org_view(gina)
    eq(list(cols), [col_a], "group collection in sync")
    eq((ciphers[cid_a]["edit"], cols[col_a]["readOnly"]), (False, True), "group read-only access")
    eq(owner.api("GET", f"/api/organizations/{org_id}/groups/{gid}/users").json, [gmid], "group members")
    d = owner.api("GET", f"/api/organizations/{org_id}/groups/{gid}/details").json
    eq((d["object"], [c["id"] for c in d["collections"]]), ("groupDetails", [col_a]), "group details")
    eq([x["id"] for x in owner.api("GET", f"/api/organizations/{org_id}/groups").json["data"]], [gid], "group list")
    eq(len(owner.api("GET", f"/api/organizations/{org_id}/groups/details").json["data"]), 1, "group list details")
    m = owner.api("GET", f"/api/organizations/{org_id}/users/{gmid}?includeGroups=true").json
    eq(m["groups"], [gid], "member lists its group")
    gina.api("GET", f"/api/organizations/{org_id}/groups", expect=DENIED)
    owner.api("POST", f"/api/organizations/{org_id}/groups", body={
        "name": "bad", "collections": [rw(str(uuid.uuid4()))], "users": []}, expect=400)

    # A direct user grant overrides the group's flags for that collection.
    owner.api("PUT", f"/api/organizations/{org_id}/users/{gmid}", body={
        "type": 2, "collections": [rw(col_a)], "groups": [gid], "permissions": {}})
    eq(sync_org_view(gina)[2][cid_a]["edit"], True, "user grant overrides group read-only")
    owner.api("PUT", f"/api/organizations/{org_id}/users/{gmid}", body={
        "type": 2, "collections": [], "groups": [gid], "permissions": {}})

    # accessAll group: every org cipher, full rights.
    owner.api("PUT", f"/api/organizations/{org_id}/groups/{gid}", body={
        "name": "Everyone", "accessAll": True, "collections": [], "users": [gmid]})
    ciphers = sync_org_view(gina)[2]
    check(cid_a in ciphers and cid_b in ciphers, "accessAll group sees all org ciphers")
    eq(ciphers[cid_b]["edit"], True, "accessAll group can edit")
    gina.api("PUT", f"/api/ciphers/{cid_b}", body=login_payload("gina-edit", organizationId=org_id))

    # Collection access via bulk-access (users + groups replaced on each collection).
    owner.api("PUT", f"/api/organizations/{org_id}/groups/{gid}", body={
        "name": "Everyone", "accessAll": False, "collections": [], "users": [gmid]})
    eq(sync_org_view(gina)[2], {}, "group without access: nothing")
    owner.api("POST", f"/api/organizations/{org_id}/collections/bulk-access", body={
        "collectionIds": [col_b], "users": [], "groups": [{"id": gid, "readOnly": False, "hidePasswords": True, "manage": False}]})
    ciphers = sync_org_view(gina)[2]
    eq((cid_b in ciphers, ciphers[cid_b]["viewPassword"]), (True, False), "bulk-access group grant")
    det = {c["id"]: c for c in owner.api("GET", f"/api/organizations/{org_id}/collections/details").json["data"]}
    eq([x["id"] for x in det[col_b]["groups"]], [gid], "collection details list the group")

    owner.api("DELETE", f"/api/organizations/{org_id}/groups/{gid}")
    eq(sync_org_view(gina)[2], {}, "deleting the group removes its access")
    owner.api("GET", f"/api/organizations/{org_id}/groups/{gid}", expect=400)
    g2 = owner.api("POST", f"/api/organizations/{org_id}/groups", body={"name": "tmp", "collections": [], "users": []}).json
    owner.api("DELETE", f"/api/organizations/{org_id}/groups", body={"ids": [g2["id"]]})
    eq(owner.api("GET", f"/api/organizations/{org_id}/groups").json["data"], [], "bulk delete groups")
    return gina, gmid


def put_policy(owner, org_id, ptype, enabled, data=None):
    return owner.api("PUT", f"/api/organizations/{org_id}/policies/{ptype}",
                     body={"policy": {"enabled": enabled, "data": data}}).json


def test_policies(owner, org_id, col_a):
    section("policies: list/get/put and enforcement")
    pat, pmid = join(owner, org_id, "org-pat", collections=[rw(col_a)])
    eq(owner.api("GET", f"/api/organizations/{org_id}/policies").json["data"], [], "no policies yet")
    eq(owner.api("GET", f"/api/organizations/{org_id}/policies/5").json["enabled"], False, "default policy")
    owner.api("GET", f"/api/organizations/{org_id}/policies/4", expect=400)
    pat.api("GET", f"/api/organizations/{org_id}/policies", expect=DENIED)

    # Personal ownership: members can't save personal items; org items and admins are fine.
    p = put_policy(owner, org_id, 5, True)
    eq((p["type"], p["enabled"], p["object"]), (5, True, "policy"), "personal ownership on")
    pat.api("POST", "/api/ciphers", body=login_payload("pat-personal"), expect=400)
    pat.api("POST", "/api/ciphers/import", body={"ciphers": [login_payload("imp")], "folders": [], "folderRelationships": []}, expect=400)
    pat.api("POST", "/api/ciphers/create", body={"cipher": login_payload("pat-org", organizationId=org_id), "collectionIds": [col_a]})
    owner.api("POST", "/api/ciphers", body=login_payload("owner-personal"))
    s = sync(pat)
    eq([(x["type"], x["enabled"]) for x in s["policies"]], [(5, True)], "sync policies")
    eq(len(s["policiesNew"]), 1, "sync policiesNew")
    put_policy(owner, org_id, 5, False)
    pat.api("POST", "/api/ciphers", body=login_payload("pat-personal"))

    # Disable Send and Send options.
    put_policy(owner, org_id, 6, True)
    pat.api("POST", "/api/sends", body=text_send(), expect=400)
    put_policy(owner, org_id, 6, False)
    put_policy(owner, org_id, 7, True, {"disableHideEmail": True})
    pat.api("POST", "/api/sends", body=text_send(hideEmail=True), expect=400)
    pat.api("POST", "/api/sends", body=text_send(hideEmail=False))
    put_policy(owner, org_id, 7, False, {"disableHideEmail": True})

    # Master password policy reaches the login response.
    put_policy(owner, org_id, 1, True, {"minComplexity": 2, "minLength": 14, "requireUpper": True,
                                        "requireLower": False, "requireNumbers": False,
                                        "requireSpecial": False, "enforceOnLogin": False})
    mpp = pat.relogin()["MasterPasswordPolicy"]
    eq((mpp["MinLength"], mpp["RequireUpper"], mpp["Object"]), (14, True, "masterPasswordPolicy"), "login policy")
    eq(pat.api("GET", f"/api/organizations/{org_id}/policies/master-password").json["data"]["minLength"], 14,
       "member reads master-password policy")
    put_policy(owner, org_id, 1, False)

    # 2FA required: members without 2FA are revoked and can't be restored.
    put_policy(owner, org_id, 0, True)
    eq(members(owner, org_id)[pat.email]["status"], -1, "2FA policy revokes member without 2FA")
    eq(members(owner, org_id)[owner.email]["status"], 2, "owner exempt from 2FA policy")
    owner.api("PUT", f"/api/organizations/{org_id}/users/{pmid}/restore", expect=400)
    put_policy(owner, org_id, 0, False)
    owner.api("PUT", f"/api/organizations/{org_id}/users/{pmid}/restore")
    eq(members(owner, org_id)[pat.email]["status"], 2, "restored after policy off")

    # Single organization: members in another org are revoked.
    other = pat.api("POST", "/api/organizations", body=org_payload("Pat Org")).json["id"]
    put_policy(owner, org_id, 3, True)
    eq(members(owner, org_id)[pat.email]["status"], -1, "single-org revokes multi-org member")
    owner.api("PUT", f"/api/organizations/{org_id}/users/{pmid}/restore", expect=400)
    pat.api("DELETE", f"/api/organizations/{other}", body=pat.auth)
    owner.api("PUT", f"/api/organizations/{org_id}/users/{pmid}/restore")
    pat.api("POST", "/api/organizations", body=org_payload("Pat Org 2"), expect=400)  # single-org blocks new orgs
    put_policy(owner, org_id, 3, False)
    types = sorted(p["type"] for p in owner.api("GET", f"/api/organizations/{org_id}/policies").json["data"])
    eq(types, [0, 1, 3, 5, 6, 7], "stored policies")
    return pat


def test_bulk_export_import(owner, org_id, col_a, col_b):
    section("org: bulk collections, export, import, api key, events, no-mail guards")
    c1 = owner.api("POST", "/api/ciphers/create", body={
        "cipher": login_payload("bulk-1", organizationId=org_id), "collectionIds": [col_a]}).json["id"]
    owner.api("POST", "/api/ciphers/bulk-collections", body={
        "organizationId": org_id, "cipherIds": [c1], "collectionIds": [col_b], "removeCollections": False})
    eq(sorted(owner.api("GET", f"/api/ciphers/{c1}").json["collectionIds"]), sorted([col_a, col_b]), "bulk add")
    owner.api("POST", "/api/ciphers/bulk-collections", body={
        "organizationId": org_id, "cipherIds": [c1], "collectionIds": [col_a], "removeCollections": True})
    eq(owner.api("GET", f"/api/ciphers/{c1}").json["collectionIds"], [col_b], "bulk remove")

    before = len(owner.api("GET", f"/api/ciphers/organization-details?organizationId={org_id}").json["data"])
    owner.api("POST", f"/api/ciphers/import-organization?organizationId={org_id}", body={
        "ciphers": [login_payload("imp-1", organizationId=org_id), login_payload("imp-2", organizationId=org_id)],
        "collections": [{"name": "2.imported|iv|mac", "id": None, "externalId": None}, {"name": "x", "id": col_a}],
        "collectionRelationships": [{"key": 0, "value": 0}, {"key": 1, "value": 1}]})
    details = owner.api("GET", f"/api/ciphers/organization-details?organizationId={org_id}").json["data"]
    eq(len(details), before + 2, "import-organization adds ciphers")
    imported = [c for c in details if c["name"] in ("2.name-imp-1|iv|mac", "2.name-imp-2|iv|mac")]
    eq(sorted(len(c["collectionIds"]) for c in imported), [1, 1], "import relations")
    names = [c["name"] for c in owner.api("GET", f"/api/organizations/{org_id}/collections").json["data"]]
    check("2.imported|iv|mac" in names, "import created the new collection")

    exp = owner.api("GET", f"/api/organizations/{org_id}/export").json
    eq((len(exp["ciphers"]), len(exp["collections"])), (len(details), len(names)), "org export")

    k1 = owner.api("POST", f"/api/organizations/{org_id}/api-key", body=owner.auth).json
    eq((k1["object"], len(k1["apiKey"])), ("apiKey", 30), "org api key")
    eq(owner.api("POST", f"/api/organizations/{org_id}/api-key", body=owner.auth).json["apiKey"], k1["apiKey"], "api key stable")
    k2 = owner.api("POST", f"/api/organizations/{org_id}/rotate-api-key", body=owner.auth).json
    check(k2["apiKey"] != k1["apiKey"] and len(k2["apiKey"]) == 30, "api key rotated")
    owner.api("POST", f"/api/organizations/{org_id}/api-key", body={"masterPasswordHash": "x"}, expect=401)

    for path in (f"/api/organizations/{org_id}/events", f"/api/ciphers/{c1}/events"):
        eq(owner.api("GET", path).json["data"], [], f"events {path}")

    # Without mail: invite links, recovery and enrollment are unavailable (vaultwarden behavior).
    me = members(owner, org_id)[owner.email]
    owner.api("POST", f"/api/organizations/{org_id}/users/{me['id']}/accept", body={"token": "bogus"}, expect=400)
    call("GET", f"/api/organizations/{org_id}/policies/token?token=bogus", expect=400)
    owner.api("PUT", f"/api/organizations/{org_id}/users/{me['userId']}/reset-password-enrollment",
              body={"resetPasswordKey": "k", "masterPasswordHash": owner.password}, expect=400)
    check(not sync_org_view(owner)[0][org_id]["useResetPassword"], "useResetPassword off without mail")


def test_delete(owner, org_id, col_b):
    section("organizations: delete collection / account guard / delete org")
    personal = owner.api("POST", "/api/ciphers", body=login_payload("keep-me")).json["id"]
    owner.api("POST", f"/api/ciphers/purge?organizationId={org_id}", body={"masterPasswordHash": "wrong"}, expect=401)
    owner.api("POST", f"/api/ciphers/purge?organizationId={org_id}", body=owner.auth)
    ciphers = sync_org_view(owner)[2]
    eq([c["id"] for c in ciphers.values() if c["organizationId"]], [], "org purge removed org ciphers")
    check(personal in ciphers, "org purge kept personal ciphers")
    n = len(owner.api("GET", f"/api/organizations/{org_id}/collections").json["data"])
    owner.api("DELETE", f"/api/organizations/{org_id}/collections/{col_b}")
    eq(len(owner.api("GET", f"/api/organizations/{org_id}/collections").json["data"]), n - 1, "collection deleted")
    owner.api("DELETE", "/api/accounts", body=owner.auth, expect=400)  # sole owner
    owner.api("DELETE", f"/api/organizations/{org_id}", body={"masterPasswordHash": "wrong"}, expect=DENIED)
    owner.api("DELETE", f"/api/organizations/{org_id}", body=owner.auth)
    orgs, cols, ciphers = sync_org_view(owner)
    eq((orgs, cols), ({}, {}), "org gone from sync")
    check(all(c["organizationId"] is None for c in ciphers.values()), "org ciphers gone")
    owner.api("GET", f"/api/organizations/{org_id}", expect=404)
    owner.api("DELETE", "/api/accounts", body=owner.auth)


def main():
    started = time.time()
    try:
        owner, org_id, col_a = test_org_lifecycle()
        col_b = test_collections(owner, org_id)
        cid_a, cid_b, _ = test_org_ciphers(owner, org_id, col_a, col_b)
        test_members(owner, org_id, col_a, col_b, cid_a, cid_b)
        test_invite_new_email(owner, org_id, col_a, cid_a)
        test_groups(owner, org_id, col_a, col_b, cid_a, cid_b)
        test_policies(owner, org_id, col_a)
        test_bulk_export_import(owner, org_id, col_a, col_b)
        test_delete(owner, org_id, col_b)
    except Failure as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print(f"OK orgs ({time.time() - started:.0f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
