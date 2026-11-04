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

"""Trusted execution context for warrant reliance (actor, system, environment).

A v0.2 warrant is scoped to actors and systems. ``WarrantScope.contains`` admits
any value for a dimension the caller does not supply, so the scope binds only
if CAGE supplies both from sources the requester cannot write:

* **actor**: the workload identity that ``WorkloadIdentityMiddleware`` admitted
  for *this* request, bound in a request-scoped ``ContextVar`` (never read from
  params or headers by this module). It is mapped to a VEIP ``agent:`` actor
  through an operator-configured, immutable map (``CAGE_WARRANT_ACTOR_BINDINGS``).
  An identity with no mapping has no actor.
* **system**: the deployment's pinned system id (``CAGE_SYSTEM_ID``).
* **environment**: the deployment environment (``CAGE_DEPLOYMENT_ENVIRONMENT``).

The workload identity is only as trustworthy as its transport. With Linkerd,
the proxy sets ``l5d-client-id`` from the verified mTLS peer certificate. Without
it, any local process can send the header. ``CAGE_WORKLOAD_IDENTITY_TRANSPORT``
records which one this deployment has. An enforcing posture, or a PRODUCTION
environment, refuses to start unless it is ``linkerd-mtls``.
``unverified-header-test-only`` exists so scope logic can be exercised in DEV,
TEST and CI. It is never a claim that the identity was authenticated.

Binding mode (``CAGE_WARRANT_CONTEXT_BINDING``): ``required`` makes a missing,
unknown or unmapped actor, or a missing system, ineligible for every warranted
norm, including wildcard-scoped warrants (a wildcard widens scope; it does not
admit an anonymous caller). ``legacy`` keeps the v0.2 pre-binding behaviour and
is accepted only in a non-enforcing posture. Unset means ``required`` when
enforcing and ``legacy`` otherwise, the same posture split the kernel uses for
its other software fallbacks.
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Mapping
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from types import MappingProxyType

from src.gateway.governance.env_posture import is_enforcing

logger = logging.getLogger(__name__)

BINDING_MODE_ENV = "CAGE_WARRANT_CONTEXT_BINDING"
ACTOR_BINDINGS_ENV = "CAGE_WARRANT_ACTOR_BINDINGS"
SYSTEM_ID_ENV = "CAGE_SYSTEM_ID"
DEPLOYMENT_ENVIRONMENT_ENV = "CAGE_DEPLOYMENT_ENVIRONMENT"
IDENTITY_TRANSPORT_ENV = "CAGE_WORKLOAD_IDENTITY_TRANSPORT"

MODE_REQUIRED = "required"
MODE_LEGACY = "legacy"
TRANSPORT_LINKERD_MTLS = "linkerd-mtls"
TRANSPORT_UNVERIFIED_TEST = "unverified-header-test-only"
ENVIRONMENTS: frozenset[str] = frozenset({"SANDBOX", "PRODUCTION"})

#: Same pattern as ``src.gateway.server.workload_identity._LINKERD_IDENTITY``
#: (the kernel does not import the server layer; a test pins the two equal).
LINKERD_IDENTITY_PATTERN = (
    r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?"
    r"\.[a-z0-9]([-a-z0-9]*[a-z0-9])?"
    r"\.serviceaccount\.identity\.linkerd\."
    r"[a-z0-9]([-a-z0-9.]*[a-z0-9])?$"
)
_LINKERD_IDENTITY = re.compile(LINKERD_IDENTITY_PATTERN)
_VEIP_ACTOR = re.compile(r"^agent:[A-Za-z0-9][A-Za-z0-9._:/-]*$")
_SYSTEM_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")

#: The workload identity WorkloadIdentityMiddleware admitted for the current
#: request. Set and reset by the middleware around the downstream call; ``None``
#: outside a request. Request-scoped (contextvars), not process-global.
_ADMITTED_WORKLOAD_IDENTITY: ContextVar[str | None] = ContextVar(
    "cage_admitted_workload_identity", default=None
)


def admitted_workload_identity() -> str | None:
    """The workload identity admitted for the current request, if any."""
    return _ADMITTED_WORKLOAD_IDENTITY.get()


def bind_admitted_workload_identity(identity: str) -> Token[str | None]:
    """Bind ``identity`` for the current request; only the ingress middleware calls this."""
    return _ADMITTED_WORKLOAD_IDENTITY.set(identity)


def release_admitted_workload_identity(token: Token[str | None]) -> None:
    _ADMITTED_WORKLOAD_IDENTITY.reset(token)


class WarrantContextConfigError(ValueError):
    """The deployment's warrant execution-context configuration is unusable."""


@dataclass(frozen=True)
class TrustedExecutionContext:
    """Actor, system and environment CAGE supplies to the warrant verifier."""

    actor: str
    system: str
    environment: str
    workload_identity: str
    actor_method: str


@dataclass(frozen=True)
class WarrantContextPolicy:
    """Immutable deployment policy that turns an admitted identity into a context."""

    mode: str
    actor_bindings: Mapping[str, str] = field(default_factory=dict)
    system_id: str = ""
    environment: str = ""
    transport: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "actor_bindings", MappingProxyType(dict(self.actor_bindings)))

    @property
    def required(self) -> bool:
        return self.mode == MODE_REQUIRED

    @classmethod
    def legacy(cls) -> WarrantContextPolicy:
        return cls(mode=MODE_LEGACY)

    @classmethod
    def from_env(cls, *, enforcing: bool | None = None) -> WarrantContextPolicy:
        """Load the policy from the environment; refuse unusable configurations."""
        enforcing = is_enforcing() if enforcing is None else enforcing
        mode = os.environ.get(BINDING_MODE_ENV, "").strip().lower() or (
            MODE_REQUIRED if enforcing else MODE_LEGACY
        )
        if mode not in (MODE_REQUIRED, MODE_LEGACY):
            raise WarrantContextConfigError(
                f"{BINDING_MODE_ENV} must be {MODE_REQUIRED!r} or {MODE_LEGACY!r}, got {mode!r}"
            )
        if mode == MODE_LEGACY:
            if enforcing:
                raise WarrantContextConfigError(
                    f"{BINDING_MODE_ENV}={MODE_LEGACY} is refused in an enforcing posture: "
                    "warrant actor/system scope must be bound to a trusted execution context"
                )
            logger.warning(
                "WARRANT_CONTEXT_BINDING_LEGACY: warrant actor/system scope is not bound "
                "(non-enforcing posture only)"
            )
            return cls.legacy()
        raw = os.environ.get(ACTOR_BINDINGS_ENV, "")
        try:
            bindings = json.loads(raw) if raw.strip() else None
        except json.JSONDecodeError as exc:
            raise WarrantContextConfigError(f"{ACTOR_BINDINGS_ENV} is not valid JSON: {exc}") from exc
        if not isinstance(bindings, dict) or not bindings:
            raise WarrantContextConfigError(
                f"{ACTOR_BINDINGS_ENV} must be a non-empty JSON object mapping a Linkerd "
                "workload identity to a VEIP 'agent:' actor"
            )
        for identity, actor in bindings.items():
            if not isinstance(identity, str) or not _LINKERD_IDENTITY.match(identity):
                raise WarrantContextConfigError(
                    f"{ACTOR_BINDINGS_ENV} key {identity!r} is not a Linkerd workload identity"
                )
            if not isinstance(actor, str) or not _VEIP_ACTOR.match(actor):
                raise WarrantContextConfigError(
                    f"{ACTOR_BINDINGS_ENV}[{identity!r}] = {actor!r} is not a VEIP 'agent:' actor"
                )
        system_id = os.environ.get(SYSTEM_ID_ENV, "").strip()
        if not _SYSTEM_ID.match(system_id):
            raise WarrantContextConfigError(f"{SYSTEM_ID_ENV} must name this deployment's system id")
        environment = os.environ.get(DEPLOYMENT_ENVIRONMENT_ENV, "").strip()
        if environment not in ENVIRONMENTS:
            raise WarrantContextConfigError(
                f"{DEPLOYMENT_ENVIRONMENT_ENV} must be one of {sorted(ENVIRONMENTS)}, got {environment!r}"
            )
        transport = os.environ.get(IDENTITY_TRANSPORT_ENV, "").strip() or (
            TRANSPORT_LINKERD_MTLS if enforcing else TRANSPORT_UNVERIFIED_TEST
        )
        if transport not in (TRANSPORT_LINKERD_MTLS, TRANSPORT_UNVERIFIED_TEST):
            raise WarrantContextConfigError(f"{IDENTITY_TRANSPORT_ENV} has unknown value {transport!r}")
        if transport != TRANSPORT_LINKERD_MTLS and (enforcing or environment == "PRODUCTION"):
            raise WarrantContextConfigError(
                f"{IDENTITY_TRANSPORT_ENV}={transport} is refused for an enforcing posture or a "
                "PRODUCTION environment: the workload identity must come from Linkerd mTLS"
            )
        if transport == TRANSPORT_UNVERIFIED_TEST:
            logger.warning(
                "WARRANT_CONTEXT_IDENTITY_UNVERIFIED: workload identity is taken from a header "
                "with no mTLS proxy (test posture only); it is NOT cryptographically authenticated"
            )
        return cls(
            mode=MODE_REQUIRED,
            actor_bindings=bindings,
            system_id=system_id,
            environment=environment,
            transport=transport,
        )

    def resolve(self, workload_identity: str | None) -> tuple[TrustedExecutionContext | None, str]:
        """Context for the admitted identity, or ``(None, reason)`` when there is none."""
        if not self.required:
            return None, ""
        if not workload_identity:
            return None, (
                "EXECUTION_CONTEXT_MISSING: no admitted workload identity in request scope; "
                "warrant actor scope cannot be bound"
            )
        actor = self.actor_bindings.get(workload_identity)
        if actor is None:
            return None, (
                f"ACTOR_BINDING_UNKNOWN: workload identity {workload_identity!r} has no "
                "configured VEIP actor"
            )
        return (
            TrustedExecutionContext(
                actor=actor,
                system=self.system_id,
                environment=self.environment,
                workload_identity=workload_identity,
                actor_method=self.transport,
            ),
            "",
        )


__all__ = [
    "ACTOR_BINDINGS_ENV",
    "BINDING_MODE_ENV",
    "DEPLOYMENT_ENVIRONMENT_ENV",
    "IDENTITY_TRANSPORT_ENV",
    "LINKERD_IDENTITY_PATTERN",
    "SYSTEM_ID_ENV",
    "TrustedExecutionContext",
    "WarrantContextConfigError",
    "WarrantContextPolicy",
    "admitted_workload_identity",
    "bind_admitted_workload_identity",
    "release_admitted_workload_identity",
]
