#!/usr/bin/env python3
"""End-to-end test for the current 2FA API (phase 4): `userVerificationToken` flows
(vaultwarden #7563) and WebAuthn security keys with a software authenticator.

Needs the `cryptography` package for ECDSA (run with `uv run --with cryptography`); everything
else follows tests/smoke.py (local server only).
"""

import base64
import hashlib
import json
import os
import struct
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(__file__))

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from smoke import BASE, Failure, User, check, eq, login, now_step, section, totp  # noqa: E402

RP_ID = urllib.parse.urlparse(BASE).hostname
ORIGIN = BASE


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def cbor(v):
    """Tiny CBOR encoder (ints, bytes, text, dicts) for the fake authenticator."""
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, fmt in ((24, ">B"), (25, ">H"), (26, ">I"), (27, ">Q")):
            if n < 1 << (8 * struct.calcsize(fmt)):
                return bytes([major << 5 | info]) + struct.pack(fmt, n)
        raise ValueError(n)

    if isinstance(v, bool):
        return bytes([0xF5 if v else 0xF4])
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return head(3, len(b)) + b
    if isinstance(v, dict):
        return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(v)


class SoftKey:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(16)
        self.counter = 0

    def cose(self):
        n = self.key.public_key().public_numbers()
        return cbor({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def register(self, options, origin=ORIGIN):
        client = json.dumps({"type": "webauthn.create", "challenge": options["challenge"], "origin": origin}).encode()
        auth = hashlib.sha256(RP_ID.encode()).digest() + bytes([0x41]) + struct.pack(">I", 0)
        auth += bytes(16) + struct.pack(">H", len(self.cred_id)) + self.cred_id + self.cose()
        att = cbor({"fmt": "none", "attStmt": {}, "authData": auth})
        return {
            "id": b64u(self.cred_id),
            "rawId": b64u(self.cred_id),
            "type": "public-key",
            "response": {"attestationObject": b64u(att), "clientDataJson": b64u(client)},
        }

    def assert_(self, options, *, counter=None, origin=ORIGIN):
        self.counter = self.counter + 1 if counter is None else counter
        client = json.dumps({"type": "webauthn.get", "challenge": options["challenge"], "origin": origin}).encode()
        auth = hashlib.sha256(RP_ID.encode()).digest() + bytes([0x01]) + struct.pack(">I", self.counter)
        sig = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return json.dumps({
            "id": b64u(self.cred_id),
            "rawId": b64u(self.cred_id),
            "type": "public-key",
            "extensions": {},
            "response": {
                "authenticatorData": b64u(auth),
                "clientDataJson": b64u(client),
                "signature": b64u(sig),
                "userHandle": None,
            },
        })


def challenge_for(u, provider):
    _, r = login(u.email, u.password, expect=400)
    check(str(provider) in r.json["TwoFactorProviders"], f"provider {provider} offered")
    return r.json["TwoFactorProviders2"][str(provider)]


def test_authenticator_uvt():
    section("2FA: authenticator with userVerificationToken")
    u = User("uvt")
    r = u.api("POST", "/api/two-factor/get-authenticator", body=u.auth).json
    eq(r["authenticator"]["enabled"], False, "authenticator.enabled")
    secret, uvt = r["authenticator"]["key"], r["userVerificationToken"]
    check(uvt and r["key"] == secret, "token issued, flat fields kept")
    code = totp(secret, now_step())
    u.api("POST", "/api/two-factor/authenticator", body={"key": secret, "token": code, "userVerificationToken": "x.y.z"}, expect=(400, 401))
    # A token for another key is rejected.
    other = u.api("POST", "/api/two-factor/get-authenticator", body=u.auth).json
    if other["authenticator"]["key"] != secret:
        u.api("POST", "/api/two-factor/authenticator", body={"key": secret, "token": code, "userVerificationToken": other["userVerificationToken"]}, expect=400)
    r = u.api("POST", "/api/two-factor/authenticator", body={"key": secret, "token": code, "userVerificationToken": uvt}).json
    eq(r["authenticator"], {"enabled": True, "key": secret}, "enabled with token")
    # The enable token (enabled=false) can't disable it.
    u.api("DELETE", "/api/two-factor/authenticator", body={"key": secret, "userVerificationToken": uvt}, expect=400)
    # Email tokens don't work for the authenticator.
    email_uvt = u.api("POST", "/api/two-factor/get-email", body=u.auth).json["userVerificationToken"]
    u.api("DELETE", "/api/two-factor/authenticator", body={"key": secret, "userVerificationToken": email_uvt}, expect=400)
    r = u.api("POST", "/api/two-factor/get-authenticator", body=u.auth).json
    eq(r["authenticator"]["enabled"], True, "enabled now")
    u.api("DELETE", "/api/two-factor/authenticator", body={"key": secret, "userVerificationToken": r["userVerificationToken"]})
    eq(u.api("GET", "/api/two-factor").json["data"], [], "disabled with token")


def test_webauthn():
    section("2FA: WebAuthn register / login / delete")
    u = User("webauthn")
    r = u.api("POST", "/api/two-factor/get-webauthn", body=u.auth).json
    eq(r["webAuthn"], {"enabled": False, "keys": []}, "no keys")
    uvt = r["userVerificationToken"]
    opts = u.api("POST", "/api/two-factor/get-webauthn-challenge", body={"userVerificationToken": uvt}).json["options"]
    eq((opts["rp"]["id"], opts["attestation"], opts["excludeCredentials"]), (RP_ID, "none", []), "creation options")
    key = SoftKey()
    # Wrong origin is refused, and the challenge is spent.
    u.api("POST", "/api/two-factor/webauthn", body={"id": 1, "name": "bad", "deviceResponse": key.register(opts, origin="https://evil.example"), "userVerificationToken": uvt}, expect=400)
    u.api("POST", "/api/two-factor/webauthn", body={"id": 1, "name": "k1", "deviceResponse": key.register(opts), "userVerificationToken": uvt}, expect=400)
    opts = u.api("POST", "/api/two-factor/get-webauthn-challenge", body={"userVerificationToken": uvt}).json["options"]
    r = u.api("POST", "/api/two-factor/webauthn", body={"id": 1, "name": "k1", "deviceResponse": key.register(opts), "userVerificationToken": uvt}).json
    eq(r["webAuthn"], {"enabled": True, "keys": [{"id": 1, "name": "k1", "migrated": False}]}, "registered")
    eq([p["type"] for p in u.api("GET", "/api/two-factor").json["data"]], [7], "provider listed")
    check(u.api("POST", "/api/two-factor/get-recover", body=u.auth).json["code"], "recovery code created")

    o = challenge_for(u, 7)
    eq((o["rpId"], [c["id"] for c in o["allowCredentials"]]), (RP_ID, [b64u(key.cred_id)]), "assertion options")
    _, r = login(u.email, u.password, twoFactorToken=key.assert_(o, origin="https://evil.example"), twoFactorProvider="7", expect=400)
    o = challenge_for(u, 7)
    token = key.assert_(o)
    _, r = login(u.email, u.password, twoFactorToken=token, twoFactorProvider="7")
    check(r.json.get("access_token"), "webauthn login")
    login(u.email, u.password, twoFactorToken=token, twoFactorProvider="7", expect=400)  # replay
    o = challenge_for(u, 7)
    login(u.email, u.password, twoFactorToken=key.assert_(o, counter=1), twoFactorProvider="7", expect=400)  # counter
    o = challenge_for(u, 7)
    impostor = SoftKey()
    impostor.cred_id = key.cred_id
    login(u.email, u.password, twoFactorToken=impostor.assert_(o, counter=50), twoFactorProvider="7", expect=400)

    section("2FA: WebAuthn key management")
    r = u.api("POST", "/api/two-factor/get-webauthn", body=u.auth).json
    uvt = r["userVerificationToken"]
    opts = u.api("POST", "/api/two-factor/get-webauthn-challenge", body={"userVerificationToken": uvt}).json["options"]
    eq([c["id"] for c in opts["excludeCredentials"]], [b64u(key.cred_id)], "existing key excluded")
    key2 = SoftKey()
    r = u.api("PUT", "/api/two-factor/webauthn", body={"id": 2, "name": "k2", "deviceResponse": key2.register(opts), "userVerificationToken": uvt}).json
    eq([k["id"] for k in r["webAuthn"]["keys"]], [1, 2], "two keys")
    uvt = u.api("POST", "/api/two-factor/get-webauthn", body=u.auth).json["userVerificationToken"]
    r = u.api("DELETE", "/api/two-factor/webauthn", body={"id": 1, "userVerificationToken": uvt}).json
    eq([k["id"] for k in r["webAuthn"]["keys"]], [2], "deleted one")
    o = challenge_for(u, 7)
    _, r = login(u.email, u.password, twoFactorToken=key2.assert_(o), twoFactorProvider="7")
    uvt = u.api("POST", "/api/two-factor/get-webauthn", body=u.auth).json["userVerificationToken"]
    r = u.api("DELETE", "/api/two-factor/webauthn/all", body={"userVerificationToken": uvt}).json
    eq(r["webAuthn"], {"enabled": False, "keys": []}, "deleted all")
    login(u.email, u.password)
    eq(u.api("POST", "/api/two-factor/get-recover", body=u.auth).json["code"], None, "recovery code cleared")


def main():
    started = time.time()
    try:
        test_authenticator_uvt()
        test_webauthn()
    except Failure as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1
    print(f"OK 2fa ({time.time() - started:.0f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
