# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Warrant actor/system context binding (S60) and environment/authority binding (S67).

The VEIP sandbox artifacts are used byte-for-byte: the frozen v0.2 vectors and key
manifest, and the sandbox-root-signed ``veip-authority-authorization/0.1`` object
(hash-pinned below). Every other signed object here comes from a TEST-ONLY root
generated in-process; no private key leaves the test.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization as S
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.warrant import Warrant
from src.gateway.governance.warrant import execution_context as ec
from src.gateway.governance.warrant.authority import (
    AuthorityAuthorizationError,
    VerifiedAuthorityAuthorization,
)
from src.gateway.governance.warrant.model import RelianceStatus
from src.gateway.governance.warrant.trust_anchor import (
    VerifiedKeyManifest,
    WarrantTrustAnchor,
)
from src.gateway.governance.warrant.verifier import WarrantStandingVerifier
from src.gateway.server import workload_identity
from src.integrations.provider_05.warrant_source import VEIP_SANDBOX_TRUST_ANCHOR

pytestmark = [pytest.mark.unit, pytest.mark.local]

V02 = pathlib.Path("docs/partners/provider_05/veip_v02")
VECTORS: dict[str, dict[str, Any]] = json.loads((V02 / "warrants_v02_vectors.json").read_text())
SANDBOX_MANIFEST: dict[str, Any] = json.loads((V02 / "key_manifest.json").read_text())
OWNER_AUTHZ = (
    pathlib.Path(__file__).parent
    / "fixtures_r002"
    / "veip_authority_authorization_sandbox_2026-10-16.json"
)
OWNER_AUTHZ_SHA256 = "9e4396069a33c80cf3c0eed80b16bfa17da0393a6e6ed6aaff8da22c7eee2de8"
NOW = datetime(2026, 10, 7, 14, 0, 10, tzinfo=timezone.utc)
ADVISOR = "cage-advisor-sa.governance-stack.serviceaccount.identity.linkerd.cluster.local"
CONTEXT = {
    "action": "execute_trade",
    "jurisdiction": "EU_ECB",
    "governing_version": "cage-policy-2.1.0",
    "actor": "agent:governed_financial_advisor",
    "system": "cage-gateway",
}


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _raw(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)


class _TestOnlyRoot:
    """TEST-ONLY VEIP root + issuer key, mirroring the v0.2 signing rules."""

    def __init__(self, root_kid: str = "test-only-root", issuer_kid: str = "test-only-issuer"):
        self.root, self.issuer = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.root_kid, self.issuer_kid = root_kid, issuer_kid

    def anchor(self) -> WarrantTrustAnchor:
        spki = self.root.public_key().public_bytes(S.Encoding.DER, S.PublicFormat.SubjectPublicKeyInfo)
        return WarrantTrustAnchor(
            root_kid=self.root_kid,
            public_key_b64=base64.b64encode(spki).decode(),
            expected_fingerprint="sha256:" + hashlib.sha256(_raw(self.root)).hexdigest(),
        )

    def _root_sign(self, body: dict[str, Any], digest_key: str) -> dict[str, Any]:
        body = dict(body)
        body[digest_key] = hashlib.sha256(jcs_canonicalize_plan(body)).hexdigest()
        body["signature"] = _b64u(self.root.sign(jcs_canonicalize_plan(body)))
        return body

    def manifest(self, environment: str = "SANDBOX", issuer: str = "TEST-ONLY Technical Issuer") -> dict[str, Any]:
        return self._root_sign(
            {
                "schema_version": "veip-key-manifest/0.2",
                "environment": environment,
                "manifest_id": "test-only-manifest",
                "issuer": issuer,
                "generated_at": "2026-10-07T14:00:00Z",
                "valid_until": "2026-11-07T14:00:00Z",
                "root_kid": self.root_kid,
                "keys": [
                    {
                        "kid": self.issuer_kid,
                        "alg": "Ed25519",
                        "public_key_b64u": _b64u(_raw(self.issuer)),
                        "status": "ACTIVE",
                        "not_before": "2026-10-07T00:00:00Z",
                        "not_after": "2026-12-31T23:59:59Z",
                        "revoked_at": "",
                    }
                ],
            },
            "manifest_digest",
        )

    def authz(
        self,
        *,
        environment: str = "SANDBOX",
        manifest_issuer: str = "TEST-ONLY Technical Issuer",
        kid: str | None = None,
        authorities: tuple[str, ...] = ("Risk Oversight Committee (EU_ECB)",),
        status: str = "ACTIVE",
        valid_until: str = "2026-11-07T14:00:00Z",
    ) -> dict[str, Any]:
        return self._root_sign(
            {
                "schema_version": "veip-authority-authorization/0.1",
                "environment": environment,
                "authorization_id": "test-only-authz",
                "manifest_issuer": manifest_issuer,
                "generated_at": "2026-10-07T13:59:00Z",
                "valid_until": valid_until,
                "root_kid": self.root_kid,
                "authorizations": [
                    {
                        "kid": kid or self.issuer_kid,
                        "authorized_issuing_authorities": list(authorities),
                        "not_before": "2026-10-07T00:00:00Z",
                        "not_after": "2026-11-07T14:00:00Z",
                        "status": status,
                    }
                ],
            },
            "authorization_digest",
        )

    def warrant(self, **overrides: Any) -> Warrant:
        fields = {**VECTORS["ACTIVE"], **overrides, "kid": self.issuer_kid, "digest": "", "signature": ""}
        w = Warrant(**fields)
        w = replace(w, digest=w.compute_digest())
        return replace(w, signature=_b64u(self.issuer.sign(w.to_signed_bytes())))


def _owner_authz_raw() -> dict[str, Any]:
    data = OWNER_AUTHZ.read_bytes()
    assert hashlib.sha256(data).hexdigest() == OWNER_AUTHZ_SHA256
    return json.loads(data)


def _stand(warrant, manifest, authz, *, context=CONTEXT, environment="SANDBOX", require=True):
    return WarrantStandingVerifier.verify_standing(
        warrant,
        context=dict(context),
        now=NOW,
        key_manifest=manifest,
        authority_authorization=authz,
        require_authority_authorization=require,
        expected_environment=environment,
    )


def _test_world(root: _TestOnlyRoot, **authz_kw):
    anchor = root.anchor()
    manifest = VerifiedKeyManifest.verify(root.manifest(), anchor, now=NOW)
    return manifest, VerifiedAuthorityAuthorization.verify(root.authz(**authz_kw), anchor)


# ── Owner sandbox artifacts (byte-for-byte) ──────────────────────────────────


def test_owner_sandbox_authorization_verifies_under_pinned_sandbox_root() -> None:
    authz = VerifiedAuthorityAuthorization.verify(_owner_authz_raw(), VEIP_SANDBOX_TRUST_ANCHOR)
    assert authz.environment == "SANDBOX" and authz.manifest_issuer == "Veraxis"
    grant = authz.grant_for("veip-sandbox-issuer-2026-10")
    assert grant is not None and grant.admits("Risk Oversight Committee (EU_ECB)", NOW)


def test_frozen_active_vector_eligible_with_distinct_manifest_issuer() -> None:
    manifest = VerifiedKeyManifest.verify(SANDBOX_MANIFEST, VEIP_SANDBOX_TRUST_ANCHOR, now=NOW)
    authz = VerifiedAuthorityAuthorization.verify(_owner_authz_raw(), VEIP_SANDBOX_TRUST_ANCHOR)
    warrant = Warrant(**VECTORS["ACTIVE"])
    assert manifest.issuer != warrant.issuing_authority  # distinct roles, never equated
    result = _stand(warrant, manifest, authz)
    assert result.reliance_status is RelianceStatus.ELIGIBLE, result.reason


def test_required_authority_authorization_absent_is_ineligible() -> None:
    manifest = VerifiedKeyManifest.verify(SANDBOX_MANIFEST, VEIP_SANDBOX_TRUST_ANCHOR, now=NOW)
    result = _stand(Warrant(**VECTORS["ACTIVE"]), manifest, None)
    assert result.reliance_status is RelianceStatus.INELIGIBLE_AUTHENTICITY
    assert result.reason.startswith("AUTHORITY_AUTHORIZATION_MISSING")


@pytest.mark.parametrize(
    "vector", ["REVOKED", "SUSPENDED", "EXPIRED", "STALE_STATE", "TAMPERED_SIGNATURE", "UNKNOWN_KID"]
)
def test_frozen_lifecycle_vectors_keep_their_outcome_under_binding(vector: str) -> None:
    manifest = VerifiedKeyManifest.verify(SANDBOX_MANIFEST, VEIP_SANDBOX_TRUST_ANCHOR, now=NOW)
    authz = VerifiedAuthorityAuthorization.verify(_owner_authz_raw(), VEIP_SANDBOX_TRUST_ANCHOR)
    warrant = Warrant(**VECTORS[vector])
    legacy = WarrantStandingVerifier.verify_standing(
        warrant, context={k: CONTEXT[k] for k in ("action", "jurisdiction", "governing_version")},
        now=NOW, key_manifest=manifest,
    )
    bound = _stand(warrant, manifest, authz)
    assert not legacy.eligible and bound.reliance_status is legacy.reliance_status


# ── S60: actor / system scope ────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("actors", "systems"),
    [
        (["agent:unrelated_delegate"], ["cage-gateway"]),
        (["agent:governed_financial_advisor"], ["some-other-system"]),
        (["agent:unrelated_delegate"], ["some-other-system"]),
    ],
    ids=["wrong_actor", "wrong_system", "both_wrong"],
)
def test_s60_out_of_scope_actor_or_system_is_ineligible(actors, systems) -> None:
    root = _TestOnlyRoot()
    manifest, authz = _test_world(root)
    w = root.warrant(scope={**VECTORS["ACTIVE"]["scope"], "actors": actors, "systems": systems})
    assert _stand(w, manifest, authz).reliance_status is RelianceStatus.INELIGIBLE_OUT_OF_SCOPE


def test_correctly_scoped_and_explicit_wildcard_warrants_are_eligible() -> None:
    root = _TestOnlyRoot()
    manifest, authz = _test_world(root)
    narrow = root.warrant()
    wildcard = root.warrant(scope={**VECTORS["ACTIVE"]["scope"], "actors": ["*"], "systems": ["*"]})
    assert _stand(narrow, manifest, authz).eligible
    assert _stand(wildcard, manifest, authz).eligible


# ── S67: environment and institutional authority ─────────────────────────────


def test_s67_unauthorized_institutional_authority_is_ineligible() -> None:
    root = _TestOnlyRoot()
    manifest, authz = _test_world(root)
    w = root.warrant(issuing_authority="Unrelated Body (not the manifest issuer)")
    result = _stand(w, manifest, authz)
    assert result.reliance_status is RelianceStatus.INELIGIBLE_AUTHENTICITY
    assert result.reason.startswith("ISSUING_AUTHORITY_NOT_AUTHORIZED")


def test_s67_warrant_environment_differs_from_manifest() -> None:
    root = _TestOnlyRoot()
    manifest, authz = _test_world(root)
    result = _stand(root.warrant(environment="PRODUCTION"), manifest, authz)
    assert result.reason.startswith("ENVIRONMENT_MISMATCH")


def test_production_chain_presented_to_a_sandbox_deployment() -> None:
    root = _TestOnlyRoot()
    anchor = root.anchor()
    manifest = VerifiedKeyManifest.verify(root.manifest(environment="PRODUCTION"), anchor, now=NOW)
    authz = VerifiedAuthorityAuthorization.verify(root.authz(environment="PRODUCTION"), anchor)
    result = _stand(root.warrant(environment="PRODUCTION"), manifest, authz, environment="SANDBOX")
    assert result.reason.startswith("DEPLOYMENT_ENVIRONMENT_MISMATCH")


@pytest.mark.parametrize(
    ("authz_kw", "prefix"),
    [
        ({"status": "REVOKED"}, "ISSUING_AUTHORITY_NOT_AUTHORIZED"),
        ({"kid": "some-other-kid"}, "ISSUING_AUTHORITY_NOT_AUTHORIZED"),
        ({"authorities": ("Another Committee",)}, "ISSUING_AUTHORITY_NOT_AUTHORIZED"),
        ({"valid_until": "2026-10-07T14:00:05Z"}, "AUTHORITY_AUTHORIZATION_EXPIRED"),
        ({"manifest_issuer": "Someone Else"}, "AUTHORITY_AUTHORIZATION_ISSUER_MISMATCH"),
        ({"environment": "PRODUCTION"}, "AUTHORITY_AUTHORIZATION_ENVIRONMENT_MISMATCH"),
    ],
    ids=["grant_revoked", "wrong_kid", "other_authority", "expired", "issuer_changed", "authz_env"],
)
def test_authority_authorization_negative_branches(authz_kw, prefix) -> None:
    root = _TestOnlyRoot()
    manifest, authz = _test_world(root, **authz_kw)
    result = _stand(root.warrant(), manifest, authz)
    assert result.reliance_status is RelianceStatus.INELIGIBLE_AUTHENTICITY
    assert result.reason.startswith(prefix), result.reason


def test_authorization_from_another_root_is_refused_by_the_verifier() -> None:
    root, other = _TestOnlyRoot(), _TestOnlyRoot()
    manifest = VerifiedKeyManifest.verify(root.manifest(), root.anchor(), now=NOW)
    foreign = VerifiedAuthorityAuthorization.verify(other.authz(), other.anchor())
    assert _stand(root.warrant(), manifest, foreign).reason.startswith(
        "AUTHORITY_AUTHORIZATION_ROOT_MISMATCH"
    )
    with pytest.raises(AuthorityAuthorizationError):
        VerifiedAuthorityAuthorization.verify(other.authz(), root.anchor())


def test_authorization_schema_is_exact() -> None:
    root = _TestOnlyRoot()
    anchor = root.anchor()
    good = root.authz()
    forged = {**good, "authorizations": [{**good["authorizations"][0], "authorized_issuing_authorities": ["X", "Y"]}]}
    with pytest.raises(AuthorityAuthorizationError, match="digest mismatch"):
        VerifiedAuthorityAuthorization.verify(forged, anchor)
    # The unsigned ``bindings`` draft shape is refused even when root-signed.
    draft = {k: v for k, v in good.items() if k not in ("authorizations", "authorization_digest", "signature")}
    draft["bindings"] = [{"kid": root.issuer_kid, "authorized_issuing_authorities": ["Risk Oversight Committee (EU_ECB)"]}]
    with pytest.raises(AuthorityAuthorizationError, match="fields do not match"):
        VerifiedAuthorityAuthorization.verify(root._root_sign(draft, "authorization_digest"), anchor)
    extra = {k: v for k, v in good.items() if k not in ("authorization_digest", "signature")}
    extra["delegation"] = "any"
    with pytest.raises(AuthorityAuthorizationError, match="unexpected"):
        VerifiedAuthorityAuthorization.verify(root._root_sign(extra, "authorization_digest"), anchor)
    dup = {k: v for k, v in good.items() if k not in ("authorization_digest", "signature")}
    dup["authorizations"] = dup["authorizations"] * 2
    with pytest.raises(AuthorityAuthorizationError, match="duplicate"):
        VerifiedAuthorityAuthorization.verify(root._root_sign(dup, "authorization_digest"), anchor)


# ── Context policy ───────────────────────────────────────────────────────────


@pytest.fixture
def binding_env(monkeypatch: pytest.MonkeyPatch):
    def _set(**values: str) -> None:
        for name in (
            ec.BINDING_MODE_ENV, ec.ACTOR_BINDINGS_ENV, ec.SYSTEM_ID_ENV,
            ec.DEPLOYMENT_ENVIRONMENT_ENV, ec.IDENTITY_TRANSPORT_ENV,
        ):
            monkeypatch.delenv(name, raising=False)
        for name, value in values.items():
            monkeypatch.setenv(name, value)

    return _set


REQUIRED = {
    ec.BINDING_MODE_ENV: "required",
    ec.ACTOR_BINDINGS_ENV: json.dumps({ADVISOR: "agent:governed_financial_advisor"}),
    ec.SYSTEM_ID_ENV: "cage-gateway",
    ec.DEPLOYMENT_ENVIRONMENT_ENV: "SANDBOX",
}


def test_policy_defaults_to_legacy_only_when_not_enforcing(binding_env) -> None:
    binding_env()
    assert not ec.WarrantContextPolicy.from_env(enforcing=False).required
    with pytest.raises(ec.WarrantContextConfigError):
        ec.WarrantContextPolicy.from_env(enforcing=True)  # required, but nothing configured


@pytest.mark.parametrize(
    ("overrides", "enforcing"),
    [
        ({ec.BINDING_MODE_ENV: "legacy"}, True),
        ({}, True),  # the unverified test transport is refused when enforcing
        ({ec.DEPLOYMENT_ENVIRONMENT_ENV: "PRODUCTION"}, False),
        ({ec.ACTOR_BINDINGS_ENV: "{not json"}, False),
        ({ec.ACTOR_BINDINGS_ENV: json.dumps({"advisor": "agent:x"})}, False),
        ({ec.ACTOR_BINDINGS_ENV: json.dumps({ADVISOR: "trader-7"})}, False),
        ({ec.SYSTEM_ID_ENV: ""}, False),
        ({ec.DEPLOYMENT_ENVIRONMENT_ENV: "STAGING"}, False),
    ],
    ids=["legacy_enforcing", "unverified_transport_enforcing", "unverified_transport_production",
         "bad_json", "non_linkerd_identity", "non_agent_actor", "no_system", "unknown_environment"],
)
def test_policy_refuses_unusable_configuration(binding_env, overrides, enforcing) -> None:
    binding_env(**{**REQUIRED, ec.IDENTITY_TRANSPORT_ENV: "unverified-header-test-only", **overrides})
    with pytest.raises(ec.WarrantContextConfigError):
        ec.WarrantContextPolicy.from_env(enforcing=enforcing)


def test_policy_resolves_only_mapped_admitted_identities(binding_env) -> None:
    binding_env(**REQUIRED)
    policy = ec.WarrantContextPolicy.from_env(enforcing=False)
    assert policy.transport == ec.TRANSPORT_UNVERIFIED_TEST
    ctx, why = policy.resolve(None)
    assert ctx is None and why.startswith("EXECUTION_CONTEXT_MISSING")
    other = "rogue-sa.agents.serviceaccount.identity.linkerd.cluster.local"
    ctx, why = policy.resolve(other)
    assert ctx is None and why.startswith("ACTOR_BINDING_UNKNOWN")
    ctx, _ = policy.resolve(ADVISOR)
    assert (ctx.actor, ctx.system, ctx.environment) == ("agent:governed_financial_advisor", "cage-gateway", "SANDBOX")
    with pytest.raises(TypeError):
        policy.actor_bindings[other] = "agent:x"  # immutable


def test_linkerd_identity_pattern_matches_the_ingress_pattern() -> None:
    assert ec.LINKERD_IDENTITY_PATTERN == workload_identity._LINKERD_IDENTITY.pattern


# ── Ingress binding is request-scoped ────────────────────────────────────────


async def test_middleware_binds_admitted_identity_only_for_the_request() -> None:
    seen: list[str | None] = []

    async def app(scope, receive, send):
        seen.append(ec.admitted_workload_identity())
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    mw = workload_identity.WorkloadIdentityMiddleware(
        app, workload_identity.IdentityPolicy(trusted=frozenset({ADVISOR}))
    )

    async def receive():
        return {"type": "http.request", "body": b""}

    sent: list[dict] = []

    async def send(msg):
        sent.append(msg)

    def scope(*headers):
        return {"type": "http", "path": "/governance/validate-action", "headers": list(headers)}

    await mw(scope((b"l5d-client-id", ADVISOR.encode()), (b"x-cage-actor", b"agent:forged")), receive, send)
    assert seen == [ADVISOR] and ec.admitted_workload_identity() is None
    # Two identity headers, or an untrusted one, never reach the app.
    await mw(scope((b"l5d-client-id", ADVISOR.encode()), (b"l5d-client-id", ADVISOR.encode())), receive, send)
    await mw(scope((b"x-cage-actor", b"agent:governed_financial_advisor")), receive, send)
    assert seen == [ADVISOR]
