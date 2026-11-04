# PREFLIGHT shim (TEST-ONLY, documented in CLAUDE_EXECUTION_REPORT.md): the Lean `zverdict` binary could not be built on
# this host (toolchain install refused), so the ZTL verdict uses ztl-swarm's Python rule (lean=False). Nothing else changes.
import functools
from tests.legion_overlay import ztl_service, harness
harness.ZtlEvidenceService = functools.partial(ztl_service.ZtlEvidenceService, lean=False)
