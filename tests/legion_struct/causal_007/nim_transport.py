"""WP-E: NIM transport control.

Global concurrency cap + queueing, HTTP 429 handling (Retry-After, jittered
backoff) and timeouts. Transport errors are separated from causal execution:
a retry never consumes a decision turn and never fabricates a decision.
The NIM key is read only by the provider-logging proxy process; this module
never sees it. ProviderLogWriter keeps one atomic record per call.
"""
from __future__ import annotations

import json
import os
import random
import re
import threading
import time


def parse_retry_after(headers):
    if not headers:
        return None
    for k, v in dict(headers).items():
        if str(k).lower() == "retry-after":
            try:
                return max(0.0, float(v))
            except (TypeError, ValueError):
                pass
            try:  # HTTP-date form
                import email.utils
                dt = email.utils.parsedate_to_datetime(str(v))
                if dt is not None:
                    return max(0.0, dt.timestamp() - time.time())
            except Exception:
                return None
            return None
    return None


class TransportResult:
    def __init__(self, status, payload, attempts, transport_retries,
                 retry_after_s=None, cooldown_s=0.0):
        self.status, self.payload = status, payload
        self.attempts, self.transport_retries = attempts, transport_retries
        self.retry_after_s = retry_after_s
        self.cooldown_s = cooldown_s
        # a decision exists only if the provider returned choices (caller's check)
        self.is_transport_error = status in (0, 429) or status >= 500


class NimTransport:
    def __init__(self, max_concurrency=8, max_retries=6, base_backoff_s=1.0,
                 cap_backoff_s=30.0, rng=None, sleep=time.sleep, clock=time.monotonic):
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        self._sem = threading.Semaphore(max_concurrency)
        self.max_retries, self.base, self.cap = max_retries, base_backoff_s, cap_backoff_s
        self.rng = rng or random.Random(1234567)
        self.sleep = sleep
        self.clock = clock
        self.stats = {"calls": 0, "retries_429": 0, "retries_5xx": 0,
                      "retries_timeout": 0, "transport_errors": 0}
        self._lock = threading.Lock()
        # P1-3: global 429 cooldown. A 429 from any in-flight call pauses
        # ALL upstream attempts until the cooldown expires, so concurrent
        # callers cannot thundering-herd NIM during a rate-limit window.
        self._cooldown_until = 0.0
        self._cooldown_total_s = 0.0
        self._last_retry_after_s = None
        self.min_spacing_s = float(
            os.environ.get("LEGION_NIM_MIN_SPACING_S", "0")
        )
        if self.min_spacing_s < 0:
            raise ValueError("negative upstream spacing")
        self._upstream_lock = threading.Lock()
        self._upstream_next = 0.0



    def _paced_call(self, call_fn):
        # One transport-wide lock, including all retry attempts.
        # Provider responses and model decisions remain unmodified.
        with self._upstream_lock:
            now = self.clock()
            delay = max(0.0, self._upstream_next - now)
            if delay:
                self.sleep(delay)

            current = self.clock()
            self._upstream_next = (
                max(current, self._upstream_next)
                + self.min_spacing_s
            )

            return call_fn()

    def backoff(self, attempt, retry_after=None):
        exp = min(self.base * (2 ** attempt), self.cap)
        jittered = exp / 2.0 + self.rng.uniform(0, exp / 2.0)
        if retry_after is not None:
            # P1-3: Retry-After is a floor, never capped. Retrying sooner
            # than the server asked (old: min(retry_after, 30)) amplifies
            # a 429 storm instead of bounding it.
            return max(float(retry_after), jittered)
        return jittered

    def _wait_cooldown(self):
        waited = 0.0
        while True:
            with self._lock:
                remaining = self._cooldown_until - self.clock()
            if remaining <= 0:
                return waited
            self.sleep(remaining)
            waited += remaining
            with self._lock:
                after = self._cooldown_until - self.clock()
            if after >= remaining - 1e-9:
                # Injected/fake sleep did not advance the clock; do not
                # busy-loop (real time.sleep always advances monotonic).
                return waited

    def _set_cooldown(self, delay):
        with self._lock:
            self._cooldown_until = max(self._cooldown_until, self.clock() + delay)
            self._cooldown_total_s += delay

    def execute(self, call_fn):
        """call_fn() -> (status, payload, headers). Retries 429/5xx/timeout.

        Returns TransportResult. Never invents a payload: on exhausted
        retries the last transport status is returned with payload None.
        """
        with self._sem:
            retries = 0
            cooldown_s = 0.0
            last_retry_after = None
            while True:
                cooldown_s += self._wait_cooldown()
                with self._lock:
                    self.stats["calls"] += 1
                try:
                    status, payload, headers = self._paced_call(call_fn)
                except (TimeoutError, ConnectionError, OSError):
                    status, payload, headers = 0, None, {}
                    with self._lock:
                        self.stats["retries_timeout"] += 1
                if status == 429:
                    with self._lock:
                        self.stats["retries_429"] += 1
                    last_retry_after = parse_retry_after(headers)
                    if last_retry_after is not None:
                        with self._lock:
                            self._last_retry_after_s = last_retry_after
                elif status >= 500:
                    with self._lock:
                        self.stats["retries_5xx"] += 1
                retryable = status == 429 or status >= 500 or status == 0
                if not retryable or retries >= self.max_retries:
                    if retryable:
                        with self._lock:
                            self.stats["transport_errors"] += 1
                    return TransportResult(status, payload, retries + 1, retries,
                                           retry_after_s=last_retry_after,
                                           cooldown_s=round(cooldown_s, 3))
                delay = self.backoff(retries, last_retry_after if status == 429 else None)
                if status == 429:
                    # Global cooldown first; this thread then also waits
                    # via _wait_cooldown at the top of the next iteration.
                    self._set_cooldown(delay)
                else:
                    self.sleep(delay)
                retries += 1


class ProviderLogWriter:
    """One record per provider call, atomic append, per-agent identity."""

    def __init__(self, path):
        self.path = str(path)
        self._lock = threading.Lock()
        Path_parent = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(Path_parent, exist_ok=True)

    def append(self, agent_id, request, response, provider_response_id):
        req = request if isinstance(request, dict) else {}
        resp = response if isinstance(response, dict) else {}
        rec = {"agent_id": agent_id, "agent": agent_id, "request": request, "response": response,
               "provider_response_id": provider_response_id, "t": time.time(),
               "t_start_mono": time.monotonic(), "t_end_mono": time.monotonic(),
               "model": req.get("model"), "request_messages": req.get("messages"),
               "usage": resp.get("usage"), "http_status": resp.get("http_status", 200),
               "status": resp.get("status", "OK"),
               "response_content": ((resp.get("choices") or [{}])[0].get("message") or {}).get("content")
               if isinstance(resp, dict) else None}
        return self.append_record(rec)

    def append_record(self, rec):
        data = (json.dumps(rec, default=str) + "\n").encode("utf-8")
        with self._lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                view = memoryview(data)
                while view:
                    n = os.write(fd, view)
                    if n <= 0:
                        raise OSError("os.write wrote no bytes")
                    view = view[n:]
            finally:
                os.close(fd)
        return rec


_TOKEN_SUFFIX_RE = re.compile(r"[^A-Za-z0-9]")


def agent_from_proxy_token(token_map, presented_token):
    """Per-agent identity comes from the token, never from the body."""
    return (token_map or {}).get(presented_token)
