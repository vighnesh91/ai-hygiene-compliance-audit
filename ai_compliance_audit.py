#!/usr/bin/env python3
"""Local AI credential hygiene and bounded internal service compliance audit.

Python: 3.11+
Missing runtime dependencies are installed automatically with pip on first run.
Filesystem text scanning examines at most 8,192 characters per logical line.

The network module accepts one explicitly supplied hostname/IP or a bounded
file of authorized internal hosts and CIDRs. A global semaphore limits active
TCP, HTTP, and webhook connections across all targets; asyncio.timeout bounds
the asynchronous network-and-notification phase. It uses TCP connects on a fixed
set of common service ports and sends unauthenticated GET requests to fixed
status/model-metadata routes. On ports 8000 or 8080, a GET /v1/models response
of 401, 403, 404, or 405 triggers one malformed POST to /v1/chat/completions
with only {"model":"test"} and no messages. It does not follow redirects,
submit credentials, read response bodies, or send a valid generation request.
Critical alerts are sent only to an explicitly configured Slack, Teams, or
Discord webhook; webhook URLs are read from the environment and omitted from reports.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib.util
import ipaddress
import json
import math
import os
import re
import socket
import stat
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


def ensure_runtime_dependencies() -> None:
    required = {"httpx": "httpx>=0.27,<1", "rich": "rich>=13.7,<15"}
    missing = [requirement for module, requirement in required.items() if importlib.util.find_spec(module) is None]
    if missing:
        import subprocess
        import sys

        print(f"Installing required runtime packages: {', '.join(missing)}", file=sys.stderr)
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", *missing],
            check=True,
        )


ensure_runtime_dependencies()

import httpx
from rich.console import Console
from rich.table import Table

PORTS = (11434, 8000, 8080, 7860, 8501, 6333, 19530, 8888)
SKIP_DIRS = {
    ".venv", "venv", "node_modules", "vendor", "__pycache__", ".cache",
    "dist", "build", ".next", ".tox", ".pytest_cache",
}
MAX_FILES = 250_000
MAX_LINE_CHARS = 8_192
MAX_TARGETS = 1_024
MAX_CIDR_ADDRESSES = 256


class AtomicFileBudget:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._count = 0
        self._lock = threading.Lock()

    def try_consume(self) -> bool:
        with self._lock:
            if self._count >= self.limit:
                return False
            self._count += 1
            return True

    @property
    def exhausted(self) -> bool:
        with self._lock:
            return self._count >= self.limit

    @property
    def count(self) -> int:
        with self._lock:
            return self._count


TOKEN_PATTERNS: dict[str, re.Pattern[str]] = {
    "OpenAI": re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
    "OpenAI-compatible hexadecimal token (DeepSeek/self-hosted)": re.compile(r"(?<![A-Za-z0-9])sk-[A-Fa-f0-9]{32,64}(?![A-Fa-f0-9])"),
    "Anthropic": re.compile(r"\bsk-ant-(?:api\d{2}-|sid\d{2}-)?[A-Za-z0-9_-]{30,}\b"),
    "Google Gemini": re.compile(r"\bAIzaSy[A-Za-z0-9_-]{33}\b"),
    "Hugging Face": re.compile(r"\bhf_[A-Za-z0-9]{34}\b"),
    "Groq": re.compile(r"\bgsk_[A-Za-z0-9]{32,64}\b"),
    "Together AI": re.compile(r"(?<![A-Za-z0-9])tgp_v1_[A-Za-z0-9_-]{20,}(?![A-Za-z0-9])"),
    "Perplexity AI": re.compile(r"(?<![A-Za-z0-9])pplx-[A-Za-z0-9_-]{16,}(?![A-Za-z0-9])", re.IGNORECASE),
}

LABELED_PATTERNS: dict[str, re.Pattern[str]] = {
    "OpenAI": re.compile(r"(?i)\b(?:OPENAI_API_KEY|OPENAI_KEY)\b\s*[:=]\s*['\"]?([^\s'\"`,;]{12,256})"),
    "Anthropic": re.compile(r"(?i)\b(?:ANTHROPIC_API_KEY|ANTHROPIC_KEY)\b\s*[:=]\s*['\"]?([^\s'\"`,;]{12,256})"),
    "Google Gemini": re.compile(r"(?i)\b(?:GEMINI_API_KEY|GOOGLE_API_KEY|GOOGLE_AI_API_KEY)\b\s*[:=]\s*['\"]?([^\s'\"`,;]{12,256})"),
    "Hugging Face": re.compile(r"(?i)\b(?:HF_TOKEN|HF_API_TOKEN|HUGGINGFACEHUB_API_TOKEN|HUGGING_FACE_HUB_TOKEN)\b\s*[:=]\s*['\"]?([^\s'\"`,;]{12,256})"),
    "Groq": re.compile(r"(?i)\b(?:GROQ_API_KEY|GROQ_KEY)\b\s*[:=]\s*['\"]?([^\s'\"`,;]{12,256})"),
    "Cohere": re.compile(r"(?i)\b(?:COHERE_API_KEY|COHERE_TOKEN|CO_API_KEY)\b\s*[:=]\s*['\"]?([^\s'\"`,;]{12,256})"),
    "Mistral AI": re.compile(r"(?i)\b(?:MISTRAL_API_KEY|MISTRAL_TOKEN)\b\s*[:=]\s*['\"]?([^\s'\"`,;]{12,256})"),
    "DeepSeek": re.compile(r"(?i)\b(?:DEEPSEEK_API_KEY|DEEPSEEK_TOKEN)\b\s*[:=]\s*['\"]?([^\s'\"`,;]{12,256})"),
    "Together AI": re.compile(r"(?i)\b(?:TOGETHER_API_KEY|TOGETHER_AI_API_KEY|TOGETHER_TOKEN)\b\s*[:=]\s*['\"]?([^\s'\"`,;]{12,256})"),
    "Perplexity AI": re.compile(r"(?i)\b(?:PERPLEXITY_API_KEY|PERPLEXITY_TOKEN|PPLX_API_KEY)\b\s*[:=]\s*['\"]?([^\s'\"`,;]{12,256})"),
}

ENTROPY_CANDIDATE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_+/=-]{24,128}(?![A-Za-z0-9])")
SERVICE_ROUTES: dict[int, tuple[str, ...]] = {
    11434: ("/api/tags",),
    8000: ("/v1/models", "/health"),
    8080: ("/health", "/v1/models"),
    7860: ("/",),
    8501: ("/",),
    6333: ("/healthz", "/"),
    19530: (),
    8888: ("/api/status", "/"),
}

console = Console()


def shannon_entropy(value: str) -> float:
    """Return Shannon entropy in bits per character for a string."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def mask_secret(value: str) -> str:
    clean = value.strip().strip("\"'")
    if len(clean) <= 8:
        return "*" * len(clean)
    return f"{clean[:5]}…{clean[-4:]} (len={len(clean)})"


def iter_bounded_lines(stream: Any):
    line_number = 1
    while True:
        first_fragment = stream.readline(MAX_LINE_CHARS)
        if not first_fragment:
            break
        line_finished = first_fragment.endswith("\n")
        truncated = False
        while not line_finished:
            remainder = stream.readline(MAX_LINE_CHARS)
            if not remainder:
                break
            truncated = True
            line_finished = remainder.endswith("\n")
        yield line_number, first_fragment.rstrip("\r\n"), truncated
        line_number += 1


def scan_filesystem(root: Path, entropy_threshold: float) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Scan root is not a directory: {root}")
    findings: list[dict[str, Any]] = []
    file_budget = AtomicFileBudget(MAX_FILES)
    stop_walk = False
    truncated_lines = 0

    for current, dirs, filenames in os.walk(root, topdown=True, followlinks=False):
        if file_budget.exhausted:
            dirs.clear()
            break
        current_path = Path(current)
        dirs[:] = [name for name in dirs if name not in SKIP_DIRS and not (current_path / name).is_symlink()]
        for filename in filenames:
            if file_budget.exhausted:
                dirs.clear()
                stop_walk = True
                break
            path = current_path / filename
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    continue
                with path.open("rb") as sample_stream:
                    if b"\x00" in sample_stream.read(8192):
                        continue
            except OSError:
                continue
            if not file_budget.try_consume():
                dirs.clear()
                stop_walk = True
                break
            try:
                stream = path.open("r", encoding="utf-8", errors="replace")
            except OSError:
                continue
            try:
                relative_path = str(path.relative_to(root))
            except ValueError:
                relative_path = path.name

            try:
                for line_number, line, line_truncated in iter_bounded_lines(stream):
                    if line_truncated:
                        truncated_lines += 1
                    line_entries: dict[tuple[str, str, str], dict[str, Any]] = {}
                    known_spans: list[tuple[int, int]] = []
                    for provider, pattern in TOKEN_PATTERNS.items():
                        for match in pattern.finditer(line):
                            value = match.group(0)
                            if provider == "OpenAI" and re.fullmatch(r"sk-[A-Fa-f0-9]{32,64}", value):
                                continue
                            known_spans.append(match.span())
                            line_entries[(provider, value, "provider-token-pattern")] = {
                                "provider": provider,
                                "path": relative_path,
                                "line": line_number,
                                "kind": "provider-token-pattern",
                                "masked_value": mask_secret(value),
                                "entropy_bits_per_character": round(shannon_entropy(value), 3),
                            }
                    for provider, pattern in LABELED_PATTERNS.items():
                        for match in pattern.finditer(line):
                            value = match.group(1).rstrip(".}")
                            if value.startswith("${") or value.startswith("{{"):
                                continue
                            known_spans.append(match.span(1))
                            line_entries[(provider, value, "provider-labeled-setting")] = {
                                "provider": provider,
                                "path": relative_path,
                                "line": line_number,
                                "kind": "provider-labeled-setting",
                                "masked_value": mask_secret(value),
                                "entropy_bits_per_character": round(shannon_entropy(value), 3),
                            }
                    for match in ENTROPY_CANDIDATE.finditer(line):
                        value = match.group(0)
                        if any(match.start() < end and match.end() > start for start, end in known_spans):
                            continue
                        if not any(char.isalpha() for char in value) or not any(char.isdigit() for char in value):
                            continue
                        entropy = shannon_entropy(value)
                        if entropy >= entropy_threshold:
                            line_entries[("Unlabeled high-entropy string", value, "entropy-threshold")] = {
                                "provider": "Unlabeled high-entropy string",
                                "path": relative_path,
                                "line": line_number,
                                "kind": "entropy-threshold",
                                "masked_value": mask_secret(value),
                                "entropy_bits_per_character": round(entropy, 3),
                            }
                    findings.extend(line_entries.values())
            except OSError:
                pass
            finally:
                stream.close()

            if file_budget.exhausted:
                dirs.clear()
                stop_walk = True
                break
        if stop_walk:
            break
    return findings, {
        "files_scanned": file_budget.count,
        "file_limit_reached": file_budget.exhausted,
        "lines_truncated_to_8192_chars": truncated_lines,
    }


def validate_target(target: str) -> tuple[str, str]:
    raw = target.strip()
    if not raw or "://" in raw or any(ch in raw for ch in "/?#@"):
        raise ValueError("Target must be one hostname or IP address, without a URL path or scheme")
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    try:
        ip = ipaddress.ip_address(raw)
        return raw, str(ip)
    except ValueError:
        pass
    hostname = raw.rstrip(".").lower()
    if len(hostname) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*", hostname):
        raise ValueError("Target is not a valid DNS hostname or IP address")
    return hostname, hostname


def load_targets(target_file: Path) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    try:
        stream = target_file.expanduser().open("r", encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"Cannot open target file: {exc}") from exc

    with stream:
        for line_number, raw_line in enumerate(stream, start=1):
            entry = raw_line.split("#", 1)[0].strip()
            if not entry:
                continue
            if "/" in entry:
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                except ValueError as exc:
                    raise ValueError(f"Invalid IP or CIDR on target-file line {line_number}") from exc
                if network.num_addresses > MAX_CIDR_ADDRESSES:
                    raise ValueError(
                        f"CIDR on target-file line {line_number} exceeds the {MAX_CIDR_ADDRESSES}-address expansion limit"
                    )
                expanded = (str(address) for address in network.hosts())
            else:
                try:
                    _, normalized = validate_target(entry)
                except ValueError as exc:
                    raise ValueError(f"Invalid target on target-file line {line_number}: {exc}") from exc
                expanded = (normalized,)

            for target in expanded:
                key = target.lower()
                if key in seen:
                    continue
                if len(targets) >= MAX_TARGETS:
                    raise ValueError(f"Target file exceeds the {MAX_TARGETS}-target safety limit")
                seen.add(key)
                targets.append(target)
    return targets


async def tcp_check(
    host: str,
    port: int,
    timeout: float,
    global_connections: asyncio.Semaphore,
) -> dict[str, Any]:
    try:
        async with global_connections:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        return {"port": port, "tcp_open": True, "error": None}
    except (OSError, asyncio.TimeoutError, socket.gaierror) as exc:
        return {"port": port, "tcp_open": False, "error": str(exc)[:180]}


async def probe_route(
    client: httpx.AsyncClient,
    host: str,
    port: int,
    path: str,
    global_connections: asyncio.Semaphore,
) -> dict[str, Any]:
    url_host = f"[{host}]" if ":" in host else host
    url = f"http://{url_host}:{port}{path}"
    try:
        async with global_connections:
            async with client.stream("GET", url, headers={"Accept": "application/json, text/html;q=0.8"}) as response:
                status = response.status_code
                if status in (401, 403):
                    assessment = "authentication_required"
                elif 200 <= status < 300 and path in ("/v1/models", "/api/tags", "/healthz", "/health", "/api/status"):
                    assessment = "unauthenticated_metadata_or_health_response_review"
                elif 200 <= status < 300:
                    assessment = "root_or_ui_reachable_review"
                elif status in (301, 302, 303, 307, 308):
                    assessment = "redirect_not_followed"
                elif status == 404:
                    assessment = "route_not_found"
                elif status == 405:
                    assessment = "method_not_allowed_post_fallback_eligible"
                else:
                    assessment = "inconclusive_http_response"
                return {
                    "port": port,
                    "method": "GET",
                    "path": path,
                    "http_status": status,
                    "assessment": assessment,
                    "server_header": response.headers.get("server", "")[:160],
                    "content_type": response.headers.get("content-type", "")[:120],
                    "error": None,
                }
    except httpx.HTTPError as exc:
        return {
            "port": port,
            "method": "GET",
            "path": path,
            "http_status": None,
            "assessment": "http_probe_failed",
            "server_header": "",
            "content_type": "",
            "error": str(exc)[:240],
        }


async def probe_post_validation(
    client: httpx.AsyncClient,
    host: str,
    port: int,
    global_connections: asyncio.Semaphore,
) -> dict[str, Any]:
    url_host = f"[{host}]" if ":" in host else host
    path = "/v1/chat/completions"
    url = f"http://{url_host}:{port}{path}"
    try:
        async with global_connections:
            async with client.stream(
                "POST",
                url,
                json={"model": "test"},
                headers={"Accept": "application/json"},
            ) as response:
                status = response.status_code
                severity = "critical" if 200 <= status < 300 else "review"
                if status in (401, 403):
                    assessment = "authentication_required_on_post"
                elif 200 <= status < 300:
                    assessment = "unauthenticated_post_accepted_high_priority_review"
                elif status in (400, 422):
                    assessment = "request_reached_validation_layer_auth_status_unconfirmed"
                elif status == 404:
                    assessment = "chat_completion_route_not_found"
                elif status == 405:
                    assessment = "post_method_not_allowed"
                elif status in (301, 302, 303, 307, 308):
                    assessment = "redirect_not_followed"
                else:
                    assessment = "inconclusive_post_response"
                return {
                    "port": port,
                    "method": "POST",
                    "path": path,
                    "http_status": status,
                    "severity": severity,
                    "assessment": assessment,
                    "server_header": response.headers.get("server", "")[:160],
                    "content_type": response.headers.get("content-type", "")[:120],
                    "trigger": "GET /v1/models returned 401, 403, 404, or 405",
                    "payload_shape": "{\"model\":\"test\"}; no messages or generation parameters",
                    "error": None,
                }
    except httpx.HTTPError as exc:
        return {
            "port": port,
            "method": "POST",
            "path": path,
            "http_status": None,
            "assessment": "post_probe_failed",
            "server_header": "",
            "content_type": "",
            "trigger": "GET /v1/models returned 401, 403, 404, or 405",
            "payload_shape": "{\"model\":\"test\"}; no messages or generation parameters",
            "error": str(exc)[:240],
        }


async def audit_target(
    target: str,
    concurrency: int,
    connect_timeout: float,
    global_connections: asyncio.Semaphore,
) -> dict[str, Any]:
    host, normalized_target = validate_target(target)
    semaphore = asyncio.Semaphore(concurrency)

    async def bounded_tcp(port: int) -> dict[str, Any]:
        async with semaphore:
            return await tcp_check(host, port, connect_timeout, global_connections)

    tcp_results = await asyncio.gather(*(bounded_tcp(port) for port in PORTS))
    open_ports = [item["port"] for item in tcp_results if item["tcp_open"]]
    http_results: list[dict[str, Any]] = []
    timeout = httpx.Timeout(connect=3.0, read=4.0, write=3.0, pool=4.0)
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=0)
    async with httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        verify=True,
        follow_redirects=False,
        trust_env=False,
        max_redirects=0,
    ) as client:
        tasks: list[asyncio.Task[dict[str, Any]]] = []
        for port in open_ports:
            routes = SERVICE_ROUTES.get(port, ())
            if not routes:
                http_results.append({
                    "port": port,
                    "method": None,
                    "path": None,
                    "http_status": None,
                    "assessment": "tcp_open_non_http_or_no_safe_route_configured",
                    "server_header": "",
                    "content_type": "",
                    "error": None,
                })
                continue
            for path in routes:
                tasks.append(asyncio.create_task(probe_route(client, host, port, path, global_connections)))
        if tasks:
            http_results.extend(await asyncio.gather(*tasks))
        fallback_ports = sorted({
            item["port"]
            for item in http_results
            if item["port"] in (8000, 8080)
            and item["path"] == "/v1/models"
            and item["http_status"] in (401, 403, 404, 405)
        })
        if fallback_ports:
            http_results.extend(await asyncio.gather(*(
                probe_post_validation(client, host, port, global_connections) for port in fallback_ports
            )))
    return {
        "target": normalized_target,
        "tcp_checks": tcp_results,
        "http_checks": http_results,
    }


async def audit_targets(
    targets: list[str],
    per_target_concurrency: int,
    connect_timeout: float,
    target_concurrency: int,
    global_connections: asyncio.Semaphore,
    progress: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    target_semaphore = asyncio.Semaphore(target_concurrency)

    async def run_one(target: str) -> dict[str, Any]:
        async with target_semaphore:
            try:
                result = await audit_target(target, per_target_concurrency, connect_timeout, global_connections)
            except Exception as exc:
                result = {
                    "target": target,
                    "tcp_checks": [],
                    "http_checks": [],
                    "error": type(exc).__name__,
                }
            progress[target] = result
            return result

    tasks = [asyncio.create_task(run_one(target)) for target in targets]
    try:
        return await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


def find_critical_exposures(network_audits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    exposures: list[dict[str, Any]] = []
    for audit in network_audits:
        for check in audit.get("http_checks", []):
            status = check.get("http_status")
            if check.get("method") == "POST" and isinstance(status, int) and 200 <= status < 300:
                exposures.append({
                    "target": audit.get("target", "unknown"),
                    "port": check.get("port"),
                    "path": check.get("path"),
                    "http_status": status,
                    "assessment": check.get("assessment", "unauthenticated_post_accepted_high_priority_review"),
                })
    return exposures


def format_critical_alert(exposures: list[dict[str, Any]]) -> str:
    lines = [
        "⚠️ CRITICAL EXPOSURE — Internal AI compliance audit",
        "A malformed unauthenticated inference-route request received a 2xx response. Review the service and gateway authentication immediately.",
    ]
    for exposure in exposures[:18]:
        lines.append(
            f"• {exposure['target']}:{exposure['port']}{exposure['path']} — HTTP {exposure['http_status']}"
        )
    if len(exposures) > 18:
        lines.append(f"• Plus {len(exposures) - 18} additional critical result(s); see the local audit report.")
    return "\n".join(lines)[:1800]


def make_webhook_payload(provider: str, message: str) -> dict[str, Any]:
    if provider == "slack":
        return {"text": message}
    if provider == "discord":
        return {"content": message[:1900]}
    if provider == "teams":
        return {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.2",
                    "body": [{"type": "TextBlock", "text": message, "wrap": True}],
                },
            }],
        }
    raise ValueError("Unsupported webhook provider")


async def dispatch_webhook(
    provider: str,
    webhook_url: str,
    message: str,
    global_connections: asyncio.Semaphore,
) -> dict[str, Any]:
    try:
        parsed = urlsplit(webhook_url)
        valid_url = parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password and not parsed.fragment
    except ValueError:
        valid_url = False
    if not valid_url:
        return {"provider": provider, "status": "rejected_invalid_webhook_url", "attempts": 0}
    payload = make_webhook_payload(provider, message)
    timeout = httpx.Timeout(connect=4.0, read=5.0, write=4.0, pool=4.0)
    limits = httpx.Limits(max_connections=1, max_keepalive_connections=0)
    last_status: int | None = None
    last_error: str | None = None
    async with httpx.AsyncClient(
        timeout=timeout,
        limits=limits,
        verify=True,
        follow_redirects=False,
        trust_env=False,
        max_redirects=0,
    ) as client:
        for attempt in range(1, 4):
            try:
                async with global_connections:
                    async with client.stream("POST", webhook_url, json=payload, headers={"Accept": "application/json"}) as response:
                        last_status = response.status_code
                        if 200 <= last_status < 300:
                            return {"provider": provider, "status": "delivered", "http_status": last_status, "attempts": attempt}
                        if last_status not in (429, 500, 502, 503, 504):
                            return {"provider": provider, "status": "delivery_rejected", "http_status": last_status, "attempts": attempt}
                        retry_after = response.headers.get("retry-after", "")
                        try:
                            delay = min(max(float(retry_after), 0.0), 5.0) if retry_after else min(2 ** (attempt - 1), 4)
                        except ValueError:
                            delay = min(2 ** (attempt - 1), 4)
            except httpx.HTTPError as exc:
                last_error = type(exc).__name__
                delay = min(2 ** (attempt - 1), 4)
            if attempt < 3:
                await asyncio.sleep(delay)
    result: dict[str, Any] = {"provider": provider, "status": "delivery_failed", "attempts": 3}
    if last_status is not None:
        result["http_status"] = last_status
    if last_error is not None:
        result["error"] = last_error
    return result


def render(findings: list[dict[str, Any]], network_audits: list[dict[str, Any]], notification: dict[str, Any] | None) -> None:
    findings_table = Table(title="Credential and entropy findings", header_style="bold cyan")
    for name in ("Provider / class", "File", "Line", "Masked value", "Entropy", "Detection"):
        findings_table.add_column(name, overflow="fold")
    if findings:
        for item in findings:
            findings_table.add_row(
                item["provider"], item["path"], str(item["line"]), item["masked_value"],
                str(item["entropy_bits_per_character"]), item["kind"],
            )
    else:
        findings_table.add_row("—", "No matches", "—", "—", "—", "—")
    console.print(findings_table)

    if network_audits:
        tcp_table = Table(title="Multi-target TCP inventory", header_style="bold yellow")
        for name in ("Target", "Port", "TCP status", "Detail"):
            tcp_table.add_column(name, overflow="fold")
        for audit in network_audits:
            if audit.get("error"):
                tcp_table.add_row(audit["target"], "—", "ERROR", audit["error"])
            for item in audit.get("tcp_checks", []):
                tcp_table.add_row(
                    audit["target"], str(item["port"]),
                    "OPEN" if item["tcp_open"] else "closed / filtered", item.get("error") or "—",
                )
        console.print(tcp_table)

        http_table = Table(title="HTTP compliance checks", header_style="bold green")
        for name in ("Target", "Port", "Method", "Path", "HTTP", "Assessment"):
            http_table.add_column(name, overflow="fold")
        http_count = 0
        for audit in network_audits:
            for item in audit.get("http_checks", []):
                http_count += 1
                status = item.get("http_status")
                http_table.add_row(
                    audit["target"], str(item.get("port", "—")), item.get("method") or "—",
                    item.get("path") or "—", str(status) if status is not None else "—",
                    item.get("assessment", "unknown"),
                )
        if not http_count:
            http_table.add_row("—", "—", "—", "—", "—", "No HTTP routes checked")
        console.print(http_table)

    if notification is not None:
        notification_table = Table(title="Security notification", header_style="bold magenta")
        notification_table.add_column("Provider")
        notification_table.add_column("Status")
        notification_table.add_column("HTTP")
        notification_table.add_column("Attempts")
        notification_table.add_row(
            notification.get("provider", "—"), notification.get("status", "unknown"),
            str(notification.get("http_status", "—")), str(notification.get("attempts", "—")),
        )
        console.print(notification_table)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local AI secret hygiene and internal staging compliance audit")
    parser.add_argument("target_arg", nargs="?", help="Authorized corporate hostname or IP; may be supplied as the only argument")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Local repository/log tree; defaults to the current directory")
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("--target", help="One authorized corporate hostname or IP address")
    target_group.add_argument("--target-file", type=Path, help="Text file of authorized hosts, IPs, or bounded CIDRs; one entry per line")
    parser.add_argument("--entropy-threshold", type=float, default=4.2, help="Shannon entropy threshold in bits/character")
    parser.add_argument("--concurrency", type=int, default=8, help="Concurrent port/HTTP checks per target, from 1 to 16")
    parser.add_argument("--target-concurrency", type=int, default=4, help="Concurrent targets, from 1 to 16")
    parser.add_argument("--global-connection-limit", type=int, default=32, help="Absolute concurrent network-connection limit across all targets and notifications")
    parser.add_argument("--connect-timeout", type=float, default=2.0, help="TCP connection timeout in seconds")
    parser.add_argument("--execution-timeout", type=float, default=900.0, help="Global async network-and-notification deadline in seconds")
    parser.add_argument("--notify", choices=("slack", "teams", "discord"), help="Send critical exposure alerts to this provider using AI_AUDIT_WEBHOOK_URL")
    parser.add_argument("--report", type=Path, default=Path("ai_compliance_report.json"), help="JSON audit report path")
    args = parser.parse_args()
    if not 1 <= args.concurrency <= 16:
        parser.error("--concurrency must be between 1 and 16")
    if not 1 <= args.target_concurrency <= 16:
        parser.error("--target-concurrency must be between 1 and 16")
    if not 1 <= args.global_connection_limit <= 256:
        parser.error("--global-connection-limit must be between 1 and 256")
    if not 1.0 <= args.execution_timeout <= 86_400.0:
        parser.error("--execution-timeout must be between 1 and 86400 seconds")
    if not 0.0 < args.entropy_threshold <= 8.0:
        parser.error("--entropy-threshold must be greater than 0 and at most 8")
    if not 0.1 <= args.connect_timeout <= 15.0:
        parser.error("--connect-timeout must be between 0.1 and 15 seconds")
    if args.target_arg and (args.target or args.target_file):
        parser.error("Use either the positional target, --target, or --target-file")
    if args.target_arg:
        args.target = args.target_arg
    args.notify = args.notify or os.environ.get("AI_AUDIT_WEBHOOK_PROVIDER")
    if args.notify and args.notify not in {"slack", "teams", "discord"}:
        parser.error("AI_AUDIT_WEBHOOK_PROVIDER must be slack, teams, or discord")
    if args.target:
        try:
            validate_target(args.target)
        except ValueError as exc:
            parser.error(str(exc))
    if args.target_file and not args.target_file.expanduser().is_file():
        parser.error("--target-file must name a readable file")
    if args.notify and not os.environ.get("AI_AUDIT_WEBHOOK_URL"):
        parser.error("Webhook notifications require AI_AUDIT_WEBHOOK_URL to be set in the environment")
    return args


async def async_main() -> int:
    args = parse_args()
    try:
        findings, filesystem_stats = scan_filesystem(args.root, args.entropy_threshold)
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]Filesystem scan failed:[/bold red] {exc}")
        return 2

    try:
        if args.target:
            targets = [validate_target(args.target)[1]]
        elif args.target_file:
            targets = load_targets(args.target_file)
        else:
            targets = []
    except (OSError, ValueError) as exc:
        console.print(f"[bold red]Target input failed:[/bold red] {exc}")
        return 2

    global_connections = asyncio.Semaphore(args.global_connection_limit)
    progress: dict[str, dict[str, Any]] = {}
    network_audits: list[dict[str, Any]] = []
    notification: dict[str, Any] | None = None
    timed_out = False
    critical_exposures: list[dict[str, Any]] = []

    try:
        async with asyncio.timeout(args.execution_timeout):
            if targets:
                network_audits = await audit_targets(
                    targets,
                    per_target_concurrency=args.concurrency,
                    connect_timeout=args.connect_timeout,
                    target_concurrency=args.target_concurrency,
                    global_connections=global_connections,
                    progress=progress,
                )
            critical_exposures = find_critical_exposures(network_audits)
            if args.notify:
                if critical_exposures:
                    notification = await dispatch_webhook(
                        args.notify,
                        os.environ["AI_AUDIT_WEBHOOK_URL"],
                        format_critical_alert(critical_exposures),
                        global_connections,
                    )
                else:
                    notification = {"provider": args.notify, "status": "no_critical_events", "attempts": 0}
            elif critical_exposures:
                notification = {"provider": None, "status": "critical_alert_not_configured", "attempts": 0}
    except TimeoutError:
        timed_out = True
        network_audits = [
            progress.get(target, {
                "target": target,
                "tcp_checks": [],
                "http_checks": [],
                "error": "global_execution_timeout",
            })
            for target in targets
        ]
        critical_exposures = find_critical_exposures(network_audits)
        if args.notify:
            notification = {"provider": args.notify, "status": "global_execution_timeout", "attempts": 0}
        elif critical_exposures:
            notification = {"provider": None, "status": "critical_alert_not_configured", "attempts": 0}
        console.print("[bold red]Global network/notification execution deadline reached.[/bold red]")

    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "filesystem_root": str(args.root.expanduser().resolve()),
            "filesystem_scan": filesystem_stats,
            "target_count": len(targets),
            "target_concurrency": args.target_concurrency,
            "global_connection_limit": args.global_connection_limit,
            "execution_timeout_seconds": args.execution_timeout,
            "execution_timed_out": timed_out,
            "ports_checked": list(PORTS) if targets else [],
            "network_behavior": "bounded internal target inventory; fixed GET routes; conditional malformed POST validation check on ports 8000/8080 after GET /v1/models returns 401/403/404/405; redirects disabled; no credentials; response bodies not read or stored",
            "entropy_threshold_bits_per_character": args.entropy_threshold,
        },
        "secret_findings": findings,
        "network_audit": network_audits,
        "critical_exposures": critical_exposures,
        "notification": notification,
        "interpretation": [
            "Credential patterns and entropy matches are indicators, not proof of credential validity.",
            "Entropy matches can include benign identifiers, hashes, and generated values; review in context.",
            "A successful malformed inference-route POST is a critical review signal; it is not proof that a valid generation request succeeds.",
            "An unauthenticated metadata or health response warrants owner review and is not by itself proof of exploitability.",
            "No response body, unmasked secret, or webhook URL is written to the report.",
            "For lines longer than 8,192 characters, only the first 8,192 characters are searched; truncation counts are reported.",
        ],
    }
    try:
        args.report.expanduser().parent.mkdir(parents=True, exist_ok=True)
        args.report.expanduser().write_text(json.dumps(report, indent=2), encoding="utf-8")
    except OSError as exc:
        console.print(f"[bold red]Could not write report:[/bold red] {exc}")
        return 2

    if filesystem_stats["lines_truncated_to_8192_chars"]:
        console.print(f"[bold yellow]Filesystem note:[/bold yellow] {filesystem_stats['lines_truncated_to_8192_chars']} long line(s) were scanned only through the first 8,192 characters.")
    if filesystem_stats["file_limit_reached"]:
        console.print(f"[bold yellow]Filesystem note:[/bold yellow] stopped at the {MAX_FILES:,}-file traversal budget.")
    if critical_exposures:
        console.print(f"[bold red]⚠️ CRITICAL EXPOSURE:[/bold red] {len(critical_exposures)} inference route(s) returned 2xx to the malformed unauthenticated probe.")
    render(findings, network_audits, notification)
    console.print(f"\nReport written to [bold green]{args.report.expanduser()}[/bold green]")
    if critical_exposures and (notification is None or notification.get("status") != "delivered"):
        return 3
    if timed_out:
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(async_main()))
