param(
    [Parameter(Mandatory = $true)][ValidateSet("B1", "S100")][string]$Campaign,
    [Parameter(Mandatory = $true)][string]$Family,
    [switch]$DryRun
)
# WO-LEGION100-CAUSAL-CLOSURE-007 final campaign runner (Claude runs this).
# Run ids: b1-<FAMILY> / s100-SYN-OTEL-04 under the CAUSAL_007 runs root.
# The NIM key (NIM_KEY_SOURCE environment variable) is read
# only by the provider-logging proxy process started by the core; it is
# never printed or logged here. This runner must NOT judge.
$ErrorActionPreference = "Stop"
$RunsRoot = if ($env:CAUSAL_RUNS_ROOT) { $env:CAUSAL_RUNS_ROOT } else { Join-Path $PSScriptRoot "runs" }
$RunId = if ($Campaign -eq "S100") { "s100-SYN-OTEL-04" } else { "b1-$Family" }
$RunDir = Join-Path $RunsRoot $RunId
if (Test-Path $RunDir) { throw "REFUSED: run directory already exists (no reruns): $RunDir" }
$Core = ($PSScriptRoot -replace '\\', '/') + "/run_campaign_core.sh"
$WslCore = $Core -replace '^C:', '/mnt/c' -replace '^([A-Za-z]):', '/mnt/$1'
$CoreArgs = @("-d", "Ubuntu-24.04", "--", "bash", $WslCore,
              "--campaign", $Campaign, "--family", $Family)
if ($DryRun) { $CoreArgs += "--dry-run" }
# The core registers RUN_HEADER (attempt_index=1, t_episode_registered and
# t_episode_registered_mono) BEFORE starting the proxy, creates per-agent
# proxy/world tokens for 100 workers, starts the provider-logging proxy,
# runs the mission host, stops the proxy, deletes token maps and scans
# for key material.
& wsl.exe @CoreArgs
if ($LASTEXITCODE -ne 0) { throw "campaign core failed: $LASTEXITCODE" }
Write-Output "campaign finished (not judged): $RunId"
