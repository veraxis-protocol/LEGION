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

"""
Warrant standing verifier (vendor-neutral kernel mechanism).

Governing Rule:
  A warrant failure removes CAGE's right to rely on that norm. It does not
  itself become an institutional ALLOW or DENY.

Precision:
  CAGE verifies the supplied warrant object is authentic, current, applicable,
  and eligible for reliance; it does not establish the underlying institutional
  truth.

Fail-closed invariant:
  The evaluation context must carry ``action``, ``jurisdiction`` and
  ``governing_version``; absence is UNRESOLVED, never "in scope".
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

from src.gateway.governance.warrant.model import (
    REQUIRED_CONTEXT_KEYS,
    SCOPE_DIMENSIONS,
    WARRANT_SCHEMA_VERSION_V02,
    RelianceStatus,
    StandingVerificationResult,
    Warrant,
    WarrantScope,
    WarrantStatus,
)
from src.gateway.governance.warrant.authority import VerifiedAuthorityAuthorization
from src.gateway.governance.warrant.trust_anchor import VerifiedKeyManifest

#: Default maximum age (seconds) for issuer-declared ``state_as_of`` in v0.2.
DEFAULT_STATE_MAX_AGE_SECONDS: float = 60.0


def _values_match(declared: Any, expected: Any) -> bool:
    if isinstance(expected, bool) or isinstance(declared, bool):
        return str(declared).lower() == str(expected).lower()
    if isinstance(expected, int | float | Decimal):
        try:
            return Decimal(str(declared)) == Decimal(str(expected))
        except InvalidOperation:
            return False
    return str(declared) == str(expected)


def _authority_failure(
    warrant: Warrant,
    key_manifest: VerifiedKeyManifest,
    authority: VerifiedAuthorityAuthorization | None,
    now: datetime,
    authority_error: str,
) -> str:
    """Empty string when ``authority`` grants ``warrant.kid`` its ``issuing_authority``."""
    if authority is None:
        return authority_error or "AUTHORITY_AUTHORIZATION_MISSING: no verified authority authorization"
    if not isinstance(authority, VerifiedAuthorityAuthorization):
        raise TypeError(
            f"authority_authorization must be a VerifiedAuthorityAuthorization, got "
            f"{type(authority).__name__}"
        )
    if (
        authority.anchor_fingerprint != key_manifest.anchor_fingerprint
        or authority.root_kid != key_manifest.root_kid
    ):
        return "AUTHORITY_AUTHORIZATION_ROOT_MISMATCH: not signed by the key manifest's root"
    if authority.environment != key_manifest.environment or authority.environment != warrant.environment:
        return (
            f"AUTHORITY_AUTHORIZATION_ENVIRONMENT_MISMATCH: authorization {authority.environment!r}, "
            f"manifest {key_manifest.environment!r}, warrant {warrant.environment!r}"
        )
    if authority.manifest_issuer != key_manifest.issuer:
        return (
            f"AUTHORITY_AUTHORIZATION_ISSUER_MISMATCH: authorization is for manifest issuer "
            f"{authority.manifest_issuer!r}, verified manifest issuer is {key_manifest.issuer!r}"
        )
    if not authority.is_valid_at(now):
        return (
            f"AUTHORITY_AUTHORIZATION_EXPIRED: {now.isoformat()} outside "
            f"[{authority.generated_at}, {authority.valid_until}]"
        )
    grant = authority.grant_for(warrant.kid)
    if grant is None or not grant.admits(warrant.issuing_authority, now):
        return (
            f"ISSUING_AUTHORITY_NOT_AUTHORIZED: kid {warrant.kid!r} holds no current grant to "
            f"speak for {warrant.issuing_authority!r}"
        )
    return ""


class WarrantStandingVerifier:
    """CAGE verifier for checking standing and reliance eligibility of warrants.

    Check order (first failure wins):
      0. Presence: a warrant was supplied (else MISSING).
      1. Context: action, jurisdiction and governing_version are supplied.
      2. Cryptographic Integrity & Authenticity:
         - v0.2: verified key manifest, ``kid`` resolution (UNKNOWN_KID fails
           closed), active key window, JCS digest, and Ed25519 signature over
           JCS(warrant_with_digest). Sets ``verification_status = "VERIFIED"``.
         - v0.1 (unsigned, no key manifest): JCS digest only;
           ``verification_status = "UNVERIFIED"``.
      3. Status: ACTIVE (REVOKED -> REVOKED; SUSPENDED/unknown -> UNRESOLVED).
      4. Currency: evaluation time within [valid_from, valid_until].
      4b. State Freshness (v0.2): evaluation time within ``max_age_seconds`` of
          ``state_as_of`` (else STALE).
      5. Version & Norm Parameters: ``governing_version`` (and ``norm_parameters``
         value when ``norm_value`` is in context) match runtime expectations.
      6. Scope: well-formed four-dimension scope admits the context.
    """

    @classmethod
    def verify_standing(
        cls,
        warrant: Warrant | None,
        context: dict[str, Any] | None = None,
        now: datetime | None = None,
        *,
        key_manifest: VerifiedKeyManifest | None = None,
        max_age_seconds: float | None = None,
        authority_authorization: VerifiedAuthorityAuthorization | None = None,
        require_authority_authorization: bool = False,
        authority_error: str = "",
        expected_environment: str | None = None,
    ) -> StandingVerificationResult:
        """Evaluate standing and return reliance eligibility."""
        if key_manifest is not None and not isinstance(
            key_manifest, VerifiedKeyManifest
        ):
            raise TypeError(
                f"key_manifest must be a VerifiedKeyManifest, got "
                f"{type(key_manifest).__name__}"
            )
        context = context or {}
        current_time = now or datetime.now(timezone.utc)
        attested_at = current_time.isoformat()

        if warrant is None:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=RelianceStatus.INELIGIBLE_MISSING,
                reason="Warrant is missing; cannot ground reliance on norm",
                attested_at=attested_at,
            )

        verified_status = "UNVERIFIED"

        def _ineligible(
            status: RelianceStatus, reason: str
        ) -> StandingVerificationResult:
            return StandingVerificationResult(
                eligible=False,
                reliance_status=status,
                reason=reason,
                attested_at=attested_at,
                warrant=warrant,
                warrant_id=warrant.warrant_id,
                warrant_digest=warrant.digest,
                verification_status=verified_status,
            )

        # 1. Context completeness
        missing_keys = [k for k in REQUIRED_CONTEXT_KEYS if not context.get(k)]
        if missing_keys:
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Evaluation context missing required keys: {missing_keys}",
            )

        # 2. Cryptographic integrity & authenticity
        if warrant.is_v02 or key_manifest is not None:
            if not warrant.is_v02:
                return _ineligible(
                    RelianceStatus.INELIGIBLE_AUTHENTICITY,
                    "Unsigned v0.1 warrant rejected: verified key manifest requires v0.2 signature",
                )
            if key_manifest is None:
                return _ineligible(
                    RelianceStatus.INELIGIBLE_AUTHENTICITY,
                    "Warrant carries v0.2 signature fields but no VerifiedKeyManifest was supplied",
                )
            if warrant.schema_version != WARRANT_SCHEMA_VERSION_V02:
                return _ineligible(
                    RelianceStatus.INELIGIBLE_UNRESOLVED,
                    f"Unsupported warrant schema_version: {warrant.schema_version!r}",
                )
            if not key_manifest.is_valid_at(current_time):
                return _ineligible(
                    RelianceStatus.INELIGIBLE_AUTHENTICITY,
                    f"Key manifest {key_manifest.manifest_id!r} is outside its validity window",
                )
            if not warrant.kid:
                return _ineligible(
                    RelianceStatus.INELIGIBLE_AUTHENTICITY,
                    "UNKNOWN_KID: warrant carries no kid",
                )
            key_entry = key_manifest.resolve_key(warrant.kid)
            if key_entry is None:
                return _ineligible(
                    RelianceStatus.INELIGIBLE_AUTHENTICITY,
                    f"UNKNOWN_KID: warrant kid {warrant.kid!r} not found in verified key manifest",
                )
            if not key_entry.is_active_at(current_time):
                return _ineligible(
                    RelianceStatus.INELIGIBLE_AUTHENTICITY,
                    f"Issuer key {warrant.kid!r} is not active or outside validity window",
                )
            if warrant.alg != "Ed25519":
                return _ineligible(
                    RelianceStatus.INELIGIBLE_AUTHENTICITY,
                    f"Unsupported warrant signature algorithm: {warrant.alg!r}",
                )
            if not warrant.digest:
                return _ineligible(
                    RelianceStatus.INELIGIBLE_AUTHENTICITY,
                    "Warrant carries no declared digest; integrity cannot be established",
                )
            computed_digest = warrant.compute_digest()
            if warrant.digest != computed_digest:
                return _ineligible(
                    RelianceStatus.INELIGIBLE_AUTHENTICITY,
                    f"Cryptographic digest mismatch: declared {warrant.digest} "
                    f"vs computed {computed_digest}",
                )
            if not warrant.signature or not key_entry.verify_signature(
                warrant.signature, warrant.to_signed_bytes()
            ):
                return _ineligible(
                    RelianceStatus.INELIGIBLE_AUTHENTICITY,
                    f"SIGNATURE_INVALID: Ed25519 signature verification failed for kid {warrant.kid!r}",
                )
            verified_status = "VERIFIED"
            # 2b. Environment (S67): the signed environment is the verified
            # manifest's and, when the stage supplies it, the deployment's.
            if warrant.environment != key_manifest.environment:
                return _ineligible(
                    RelianceStatus.INELIGIBLE_AUTHENTICITY,
                    f"ENVIRONMENT_MISMATCH: warrant environment {warrant.environment!r} "
                    f"!= verified key manifest environment {key_manifest.environment!r}",
                )
            if (
                expected_environment is not None
                and warrant.environment != expected_environment
            ):
                return _ineligible(
                    RelianceStatus.INELIGIBLE_AUTHENTICITY,
                    f"DEPLOYMENT_ENVIRONMENT_MISMATCH: warrant environment "
                    f"{warrant.environment!r} != deployment environment {expected_environment!r}",
                )
            # 2c. Institutional authority (S67): a root-signed grant must let
            # this kid speak for warrant.issuing_authority. The manifest issuer
            # (technical) and the issuing authority (institutional) are
            # different roles and are never compared for equality.
            if require_authority_authorization or authority_authorization is not None:
                failure = _authority_failure(
                    warrant, key_manifest, authority_authorization, current_time, authority_error
                )
                if failure:
                    return _ineligible(RelianceStatus.INELIGIBLE_AUTHENTICITY, failure)
        else:
            if not warrant.digest:
                return _ineligible(
                    RelianceStatus.INELIGIBLE_UNRESOLVED,
                    "Warrant carries no declared digest; integrity cannot be established",
                )
            computed_digest = warrant.compute_digest()
            if warrant.digest != computed_digest:
                return _ineligible(
                    RelianceStatus.INELIGIBLE_UNRESOLVED,
                    f"Cryptographic digest mismatch: declared {warrant.digest} "
                    f"vs computed {computed_digest}",
                )

        # 3. Status
        if warrant.status == WarrantStatus.REVOKED:
            return _ineligible(
                RelianceStatus.INELIGIBLE_REVOKED,
                f"Warrant revoked: {warrant.revocation_ref or 'revocation basis recorded'}",
            )
        if warrant.status == WarrantStatus.SUSPENDED:
            return _ineligible(
                RelianceStatus.INELIGIBLE_SUSPENDED,
                f"Warrant suspended: {warrant.revocation_ref or 'suspension active'}",
            )
        if warrant.status != WarrantStatus.ACTIVE:
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Warrant has unrecognised status: {warrant.status}",
            )

        # 4. Currency
        try:
            from_dt = datetime.fromisoformat(warrant.valid_from.replace("Z", "+00:00"))
            until_dt = datetime.fromisoformat(
                warrant.valid_until.replace("Z", "+00:00")
            )
            out_of_window = current_time < from_dt or current_time > until_dt
        except (TypeError, ValueError) as dt_exc:
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Invalid temporal comparison: {dt_exc}",
            )
        if out_of_window:
            return _ineligible(
                RelianceStatus.INELIGIBLE_EXPIRED,
                f"Warrant temporal window invalid: current {attested_at} outside "
                f"[{warrant.valid_from}, {warrant.valid_until}]",
            )

        # 4b. Issuer state freshness (v0.2 state_as_of)
        if warrant.state_as_of:
            try:
                state_dt = datetime.fromisoformat(
                    warrant.state_as_of.replace("Z", "+00:00")
                )
                state_age = (current_time - state_dt).total_seconds()
            except (TypeError, ValueError) as dt_exc:
                return _ineligible(
                    RelianceStatus.INELIGIBLE_UNRESOLVED,
                    f"Invalid state_as_of timestamp: {dt_exc}",
                )
            freshness_limit = (
                DEFAULT_STATE_MAX_AGE_SECONDS
                if max_age_seconds is None
                else max_age_seconds
            )
            if state_age < 0 or state_age > freshness_limit:
                return _ineligible(
                    RelianceStatus.INELIGIBLE_STALE,
                    f"Warrant state_as_of stale: {warrant.state_as_of} is "
                    f"{state_age:.3f}s old at {attested_at} (max {freshness_limit:g}s)",
                )

        # 5. Version & norm_parameters
        expected_version = context["governing_version"]
        if warrant.governing_version != expected_version:
            return _ineligible(
                RelianceStatus.INELIGIBLE_VERSION_MISMATCH,
                f"Governing version mismatch: expected {expected_version} "
                f"vs warrant {warrant.governing_version}",
            )
        if warrant.is_v02:
            if not isinstance(warrant.norm_parameters, Mapping) or not (
                warrant.norm_parameters
            ):
                return _ineligible(
                    RelianceStatus.INELIGIBLE_UNRESOLVED,
                    "Warrant norm_parameters is missing or empty",
                )
            if "norm_value" in context and context["norm_value"] is not None:
                leaf_key = warrant.norm_id.rsplit(".", 1)[-1]
                param_spec = warrant.norm_parameters.get(
                    warrant.norm_id
                ) or warrant.norm_parameters.get(leaf_key)
                if not isinstance(param_spec, Mapping) or "value" not in param_spec:
                    return _ineligible(
                        RelianceStatus.INELIGIBLE_UNRESOLVED,
                        f"Warrant norm_parameters has no value entry for {warrant.norm_id!r}",
                    )
                if not _values_match(param_spec["value"], context["norm_value"]):
                    return _ineligible(
                        RelianceStatus.INELIGIBLE_VERSION_MISMATCH,
                        f"Norm parameter value mismatch for {warrant.norm_id!r}: "
                        f"expected {context['norm_value']!r} vs warrant {param_spec['value']!r}",
                    )

        # 6. Scope
        if not isinstance(warrant.scope, WarrantScope):
            return _ineligible(
                RelianceStatus.INELIGIBLE_UNRESOLVED,
                f"Warrant scope malformed; all of {list(SCOPE_DIMENSIONS)} are required",
            )
        if not warrant.scope.contains(
            action=context["action"],
            jurisdiction=context["jurisdiction"],
            actor=context.get("actor"),
            system=context.get("system"),
        ):
            return _ineligible(
                RelianceStatus.INELIGIBLE_OUT_OF_SCOPE,
                f"Context ({context}) is outside warrant scope ({warrant.scope.to_dict()})",
            )

        return StandingVerificationResult(
            eligible=True,
            reliance_status=RelianceStatus.ELIGIBLE,
            reason="Warrant standing verified and active; norm eligible for reliance",
            attested_at=attested_at,
            warrant=warrant,
            warrant_id=warrant.warrant_id,
            warrant_digest=warrant.digest,
            verification_status=verified_status,
        )
