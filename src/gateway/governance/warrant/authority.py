# LEGION-100 modifications: see repository MODIFICATIONS.md; upstream CAGE Apache-2.0.
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

"""Root-signed VEIP issuing-authority authorization (``veip-authority-authorization/0.1``).

A verified key manifest says which keys the technical issuer (manifest ``issuer``,
e.g. ``Veraxis``) signs with. It says nothing about which *institutional*
authority (warrant ``issuing_authority``, e.g. ``Risk Oversight Committee
(EU_ECB)``) a key may speak for. Those are different roles, and CAGE never
equates them. This companion object, signed by the same out-of-band root as the
key manifest, grants each signing ``kid`` an explicit, finite set of
institutional authorities, bounded in time and by environment.

Verification mirrors :class:`~.trust_anchor.VerifiedKeyManifest`: exact field
set, ``authorization_digest = SHA-256(JCS(body without digest and signature))``,
root Ed25519 signature over ``JCS(body without signature)``. Exactly one schema
is accepted. The unsigned ``bindings`` draft shape is refused, never translated.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any

from src.gateway.governance.jcs_canonicalizer import jcs_canonicalize_plan
from src.gateway.governance.warrant.trust_anchor import WarrantTrustAnchor, _parse_utc

AUTHORITY_AUTHORIZATION_SCHEMA_V01 = "veip-authority-authorization/0.1"

_FIELDS: frozenset[str] = frozenset(
    {
        "schema_version",
        "environment",
        "authorization_id",
        "manifest_issuer",
        "generated_at",
        "valid_until",
        "root_kid",
        "authorizations",
        "authorization_digest",
        "signature",
    }
)
_GRANT_FIELDS: frozenset[str] = frozenset(
    {"kid", "authorized_issuing_authorities", "not_before", "not_after", "status"}
)
_ENVIRONMENTS: frozenset[str] = frozenset({"SANDBOX", "PRODUCTION"})
_GRANT_STATUSES: frozenset[str] = frozenset({"ACTIVE", "REVOKED"})

_AUTHORIZATION_SEAL = object()


class AuthorityAuthorizationError(ValueError):
    """Raised when an authority authorization fails structural, digest or signature checks."""


def _nonempty_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuthorityAuthorizationError(f"{what} must be a non-empty string")
    return value


@dataclass(frozen=True)
class AuthorityGrant:
    """One ``kid -> authorized_issuing_authorities`` grant."""

    kid: str
    authorities: frozenset[str]
    not_before: str
    not_after: str
    status: str

    def admits(self, issuing_authority: str, now: datetime) -> bool:
        """True only for an ACTIVE grant, inside its window, naming exactly this authority."""
        if now.tzinfo is None or self.status != "ACTIVE":
            return False
        if not (_parse_utc(self.not_before) <= now <= _parse_utc(self.not_after)):
            return False
        return issuing_authority in self.authorities


@dataclass(frozen=True)
class VerifiedAuthorityAuthorization:
    """An authority authorization verified against a :class:`WarrantTrustAnchor`.

    Cannot be instantiated directly; use :meth:`verify`.
    """

    schema_version: str
    environment: str
    authorization_id: str
    manifest_issuer: str
    generated_at: str
    valid_until: str
    root_kid: str
    authorization_digest: str
    anchor_fingerprint: str
    grants: Mapping[str, AuthorityGrant]
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _AUTHORIZATION_SEAL:
            raise TypeError(
                "VerifiedAuthorityAuthorization cannot be instantiated directly; "
                "use VerifiedAuthorityAuthorization.verify(raw, trust_anchor)"
            )
        object.__setattr__(self, "grants", MappingProxyType(dict(self.grants)))

    @classmethod
    def verify(
        cls, raw: Mapping[str, Any], trust_anchor: WarrantTrustAnchor
    ) -> VerifiedAuthorityAuthorization:
        """Verify ``raw`` against ``trust_anchor``.

        Raises:
            TypeError: wrong argument types.
            AuthorityAuthorizationError: any schema, digest, signature or entry check fails.
        """
        if not isinstance(trust_anchor, WarrantTrustAnchor):
            raise TypeError(
                f"trust_anchor must be a WarrantTrustAnchor, got {type(trust_anchor).__name__}"
            )
        if not isinstance(raw, Mapping):
            raise TypeError(f"authority authorization must be a Mapping, got {type(raw).__name__}")
        keys = set(raw)
        if keys != _FIELDS:
            raise AuthorityAuthorizationError(
                "authority authorization fields do not match "
                f"{AUTHORITY_AUTHORIZATION_SCHEMA_V01}: missing {sorted(_FIELDS - keys)}, "
                f"unexpected {sorted(keys - _FIELDS)}"
            )
        if raw["schema_version"] != AUTHORITY_AUTHORIZATION_SCHEMA_V01:
            raise AuthorityAuthorizationError(
                f"unsupported authority authorization schema_version {raw['schema_version']!r}"
            )
        if raw["environment"] not in _ENVIRONMENTS:
            raise AuthorityAuthorizationError(f"unknown environment {raw['environment']!r}")
        if raw["root_kid"] != trust_anchor.root_kid:
            raise AuthorityAuthorizationError(
                f"authority authorization root_kid {raw['root_kid']!r} does not match trust "
                f"anchor {trust_anchor.root_kid!r}"
            )
        declared = raw["authorization_digest"]
        if not isinstance(declared, str) or len(declared) != 64:
            raise AuthorityAuthorizationError("authorization_digest is missing or malformed")
        unsigned = {k: v for k, v in raw.items() if k not in ("authorization_digest", "signature")}
        computed = hashlib.sha256(jcs_canonicalize_plan(unsigned)).hexdigest()
        if computed != declared:
            raise AuthorityAuthorizationError(
                f"authorization digest mismatch: declared {declared} vs computed {computed}"
            )
        signed = {k: v for k, v in raw.items() if k != "signature"}
        if not trust_anchor.verify_signature(raw["signature"], jcs_canonicalize_plan(signed)):
            raise AuthorityAuthorizationError(
                f"authority authorization Ed25519 signature verification failed for root_kid "
                f"{raw['root_kid']!r}"
            )
        try:
            if _parse_utc(raw["generated_at"]) > _parse_utc(raw["valid_until"]):
                raise AuthorityAuthorizationError("generated_at is after valid_until")
        except (TypeError, ValueError) as exc:
            if isinstance(exc, AuthorityAuthorizationError):
                raise
            raise AuthorityAuthorizationError(f"invalid timestamps: {exc}") from exc
        entries = raw["authorizations"]
        if not isinstance(entries, list) or not entries:
            raise AuthorityAuthorizationError("authorizations must be a non-empty list")
        grants: dict[str, AuthorityGrant] = {}
        for item in entries:
            if not isinstance(item, Mapping) or set(item) != _GRANT_FIELDS:
                raise AuthorityAuthorizationError(
                    f"authorization entry fields must be exactly {sorted(_GRANT_FIELDS)}"
                )
            kid = _nonempty_str(item["kid"], "authorization kid")
            if kid in grants:
                raise AuthorityAuthorizationError(f"duplicate authorization for kid {kid!r}")
            names = item["authorized_issuing_authorities"]
            if (
                not isinstance(names, list)
                or not names
                or len(set(names)) != len(names)
                or not all(isinstance(n, str) and n for n in names)
            ):
                raise AuthorityAuthorizationError(
                    f"authorized_issuing_authorities for {kid!r} must be a non-empty list of "
                    "unique non-empty strings"
                )
            if item["status"] not in _GRANT_STATUSES:
                raise AuthorityAuthorizationError(f"unknown grant status {item['status']!r}")
            try:
                _parse_utc(item["not_before"])
                _parse_utc(item["not_after"])
            except (TypeError, ValueError) as exc:
                raise AuthorityAuthorizationError(f"invalid grant window for {kid!r}: {exc}") from exc
            grants[kid] = AuthorityGrant(
                kid=kid,
                authorities=frozenset(names),
                not_before=item["not_before"],
                not_after=item["not_after"],
                status=item["status"],
            )
        return cls(
            schema_version=raw["schema_version"],
            environment=raw["environment"],
            authorization_id=_nonempty_str(raw["authorization_id"], "authorization_id"),
            manifest_issuer=_nonempty_str(raw["manifest_issuer"], "manifest_issuer"),
            generated_at=raw["generated_at"],
            valid_until=raw["valid_until"],
            root_kid=raw["root_kid"],
            authorization_digest=declared,
            anchor_fingerprint=trust_anchor.fingerprint,
            grants=grants,
            _seal=_AUTHORIZATION_SEAL,
        )

    def is_valid_at(self, now: datetime) -> bool:
        if now.tzinfo is None:
            return False
        try:
            return _parse_utc(self.generated_at) <= now <= _parse_utc(self.valid_until)
        except ValueError:
            return False

    def grant_for(self, kid: str) -> AuthorityGrant | None:
        return self.grants.get(kid)


__all__ = [
    "AUTHORITY_AUTHORIZATION_SCHEMA_V01",
    "AuthorityAuthorizationError",
    "AuthorityGrant",
    "VerifiedAuthorityAuthorization",
]
