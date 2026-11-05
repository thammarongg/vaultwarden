#!/usr/bin/env python3
"""Attachment storage quota test (vaultwarden #7450). Needs a server started with
`--var ATTACHMENT_TOTAL_LIMIT_KB:16 --var ORG_ATTACHMENT_LIMIT_KB:8` (tests/run_local.sh runs it
on the second server). Stdlib only, local only.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from smoke import Failure, User, call, check, eq, login_payload, section  # noqa: E402
from smoke_orgs import org_payload  # noqa: E402

KB = 1024


def reserve(u, cid, size, expect=200):
    return u.api(
        "POST",
        f"/api/ciphers/{cid}/attachment/v2",
        body={"key": "2.k|i|m", "fileName": "2.f|i|m", "fileSize": size},
        expect=expect,
    )


def upload(u, cid, size):
    r = reserve(u, cid, size).json
    call("PUT", r["url"], raw=os.urandom(size), headers={"Content-Length": str(size)}, expect=201)
    return r["attachmentId"]


def error_of(r):
    j = r.json or {}
    return j.get("message") or j.get("error") or ""


def main():
    started = time.time()
    try:
        section("quota: personal items (16 KB per user)")
        u = User("quota")
        cid = u.api("POST", "/api/ciphers", body=login_payload("q1")).json["id"]
        upload(u, cid, 10 * KB)
        r = reserve(u, cid, 7 * KB, expect=400)
        check("exceeded" in error_of(r), f"over by one file: {error_of(r)}")
        reserve(u, cid, 6 * KB)  # reserved, not uploaded yet: still counts
        r = reserve(u, cid, 1, expect=400)
        check("limit reached" in error_of(r), f"full: {error_of(r)}")

        section("quota: organization items (8 KB per org, separate from the user's)")
        org = u.api("POST", "/api/organizations", body=org_payload("Quota Org")).json["id"]
        col = u.api("GET", f"/api/organizations/{org}/collections").json["data"][0]["id"]
        ocid = u.api(
            "POST",
            "/api/ciphers/create",
            body={"cipher": login_payload("q-org", organizationId=org), "collectionIds": [col]},
        ).json["id"]
        upload(u, ocid, 8 * KB)
        r = reserve(u, ocid, 1, expect=400)
        check("limit reached" in error_of(r), f"org full: {error_of(r)}")

        # Another member's personal quota is untouched by the org's files.
        v = User("quota-other")
        vc = v.api("POST", "/api/ciphers", body=login_payload("q2")).json["id"]
        upload(v, vc, 16 * KB)
        eq(reserve(v, vc, 1, expect=400).status, 400, "second user full at exactly 16 KB")
    except Failure as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print(f"OK quota ({time.time() - started:.0f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
