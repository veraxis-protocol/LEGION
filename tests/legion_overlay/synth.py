"""SYNTHETIC VEIP v0.2 issuer + root, generated per run (throw-away keys; NOT the VEIP sandbox keys, which LEGION does not
hold). Used only for attacks that need a VALID signature: wrong trust root, and in-scope-signature-but-wrong-scope under a
trust anchor the harness explicitly configures. Built with CAGE's own Warrant model (digest = SHA-256(JCS(body)),
signature = Ed25519 over JCS(body + digest)) and manifest rules (trust_anchor.VerifiedKeyManifest.verify)."""
from __future__ import annotations
import base64, hashlib
from dataclasses import replace
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as S
from src.gateway.governance.warrant import Warrant
from src.gateway.governance.warrant.trust_anchor import WarrantTrustAnchor
from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
def b64u(b: bytes) -> str: return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def raw(k) -> bytes: return k.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
class SyntheticIssuer:
    def __init__(self, root_kid="legion-synthetic-root", issuer_kid="legion-synthetic-issuer"):
        self.root, self.issuer, self.root_kid, self.issuer_kid = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), root_kid, issuer_kid
    def anchor(self) -> WarrantTrustAnchor:
        spki = self.root.public_key().public_bytes(S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo)
        return WarrantTrustAnchor(root_kid=self.root_kid, public_key_b64=base64.b64encode(spki).decode(), expected_fingerprint="sha256:" + hashlib.sha256(raw(self.root)).hexdigest())
    def manifest(self, *, root_kid=None) -> dict:
        body = {"schema_version": "veip-key-manifest/0.2", "environment": "SANDBOX", "manifest_id": "legion-synthetic-manifest", "issuer": "LEGION-SYNTHETIC",
                "generated_at": "2026-10-07T14:00:00Z", "valid_until": "2026-11-07T14:00:00Z", "root_kid": root_kid or self.root_kid,
                "keys": [{"kid": self.issuer_kid, "alg": "Ed25519", "public_key_b64u": b64u(raw(self.issuer)), "status": "ACTIVE",
                          "not_before": "2026-10-07T00:00:00Z", "not_after": "2026-12-31T23:59:59Z", "revoked_at": ""}]}
        body["manifest_digest"] = hashlib.sha256(jcs_canonicalize_plan(body)).hexdigest()
        body["signature"] = b64u(self.root.sign(jcs_canonicalize_plan(body)))
        return body
    def sign(self, fields: dict) -> Warrant:
        w = Warrant(**{**fields, "kid": self.issuer_kid, "digest": "", "signature": ""})
        w = replace(w, digest=w.compute_digest())
        return replace(w, signature=b64u(self.issuer.sign(w.to_signed_bytes())))
