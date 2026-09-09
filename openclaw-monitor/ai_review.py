#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SEVERITY = {"OK": 0, "INFO": 1, "WARNING": 2, "HIGH": 3, "CRITICAL": 4}
DEFAULT_ROOT = Path.home() / "openclaw-monitor"


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def atomic_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return data


def _summary(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "meta": state.get("meta", {}),
        "system": state.get("system", {}),
        "resources": state.get("resources", {}),
        "storage": state.get("storage", {}),
        "network": state.get("network", {}),
        "security": state.get("security", {}),
        "services": state.get("services", {}),
    }


def build_ai_input(
    current: dict[str, Any],
    baseline: dict[str, Any],
    diff: dict[str, Any],
    findings: dict[str, Any],
) -> dict[str, Any]:
    """Build bounded, structured context for the LLM reviewer."""
    return {
        "generated_at": now_iso(),
        "deterministic": {
            "severity": str(findings.get("severity", "OK")).upper(),
            "needs_ai_review": bool(findings.get("needs_ai_review", False)),
            "findings": findings.get("findings", []),
        },
        "diff": diff,
        "current_summary": _summary(current),
        "baseline_summary": _summary(baseline),
        "device_context": {
            "baseline_devices": baseline.get("lan", {}).get("devices", []),
            "current_devices": current.get("lan", {}).get("devices", []),
        },
        "listening_context": {
            "baseline_listeners": baseline.get("listening", []),
            "current_listeners": current.get("listening", []),
        },
        "integrity_context": {
            "baseline": baseline.get("integrity", {}),
            "current": current.get("integrity", {}),
        },
    }


SYSTEM_PROMPT = """You are a read-only infrastructure and security reviewer for an OpenClaw host.
You receive structured monitoring evidence only. You have no tools, no shell, no SSH, no network access and no permission to remediate anything.
Analyze only the supplied JSON. Do not invent missing evidence.
The deterministic rules are authoritative minimum severity. Do not lower deterministic severity. You may raise severity when the supplied evidence justifies it.
Correlate related changes when useful, especially LAN devices, listening ports, SSH events, network changes, services, integrity and resource pressure.
Return exactly one JSON object. Write summary, analysis and recommendations in Polish.
Required keys:
- severity: one of OK, INFO, WARNING, HIGH, CRITICAL
- summary: short string
- analysis: concise evidence-based explanation
- recommendations: array of concrete administrator verification steps; no automatic remediation
- notify: boolean
- confidence: number from 0.0 to 1.0
Do not include markdown or any text outside the JSON object."""


def build_request_payload(
    *,
    model: str,
    ai_input: dict[str, Any],
    temperature: float = 0.1,
    max_tokens: int = 900,
) -> dict[str, Any]:
    return {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": "Review this monitoring evidence:\n" + json.dumps(ai_input, ensure_ascii=False, sort_keys=True),
            },
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "response_format": {"type": "json_object"},
        "stream": False,
    }


def parse_model_json(content: str) -> dict[str, Any]:
    text = str(content or "").strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        text = fenced.group(1).strip()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LM Studio returned non-JSON content: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("LM Studio response JSON must be an object")

    severity = str(parsed.get("severity", "")).upper()
    if severity not in SEVERITY:
        raise ValueError(f"Invalid model severity: {severity!r}")
    if not isinstance(parsed.get("summary"), str) or not parsed["summary"].strip():
        raise ValueError("Model response missing non-empty summary")
    if not isinstance(parsed.get("analysis"), str) or not parsed["analysis"].strip():
        raise ValueError("Model response missing non-empty analysis")
    recommendations = parsed.get("recommendations")
    if not isinstance(recommendations, list) or not all(isinstance(x, str) for x in recommendations):
        raise ValueError("Model recommendations must be an array of strings")
    if not isinstance(parsed.get("notify"), bool):
        raise ValueError("Model notify must be boolean")
    confidence = parsed.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0.0 <= float(confidence) <= 1.0:
        raise ValueError("Model confidence must be between 0.0 and 1.0")

    parsed["severity"] = severity
    parsed["confidence"] = float(confidence)
    return parsed


def enforce_severity_floor(model_result: dict[str, Any], deterministic_severity: str) -> dict[str, Any]:
    floor = str(deterministic_severity or "OK").upper()
    if floor not in SEVERITY:
        raise ValueError(f"Invalid deterministic severity: {floor!r}")
    model_severity = str(model_result.get("severity", "OK")).upper()
    if model_severity not in SEVERITY:
        raise ValueError(f"Invalid model severity: {model_severity!r}")

    result = dict(model_result)
    result["model_severity"] = model_severity
    if SEVERITY[model_severity] < SEVERITY[floor]:
        result["severity"] = floor
        result["severity_floor_applied"] = True
    else:
        result["severity"] = model_severity
        result["severity_floor_applied"] = False
    result["deterministic_severity"] = floor
    return result


def http_transport(
    url: str,
    payload: dict[str, Any],
    timeout_seconds: int,
    api_key: str | None = None,
) -> dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:2000]
        raise RuntimeError(f"LM Studio HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"LM Studio connection failed: {exc.reason}") from exc

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuntimeError("LM Studio endpoint returned invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("LM Studio endpoint response must be a JSON object")
    return parsed


def _extract_content(response: dict[str, Any]) -> str:
    try:
        content = response["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("LM Studio response missing choices[0].message.content") from exc
    if not isinstance(content, str) or not content.strip():
        raise ValueError("LM Studio returned empty message content")
    return content


def _history_path(root: Path) -> Path:
    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_%f")
    return root / "ai_reviews" / f"{stamp}.json"


def run_review(
    *,
    root: Path = DEFAULT_ROOT,
    config: dict[str, Any],
    transport: Callable[[str, dict[str, Any], int, str | None], dict[str, Any]] = http_transport,
    dry_run: bool = False,
) -> dict[str, Any]:
    root = Path(root)
    current = load_json(root / "state" / "current.json")
    baseline = load_json(root / "state" / "baseline.json")
    diff = load_json(root / "diff.json")
    findings = load_json(root / "findings.json")

    ai_input = build_ai_input(current, baseline, diff, findings)
    atomic_json(root / "ai_input.json", ai_input)

    deterministic_severity = str(findings.get("severity", "OK")).upper()
    if not bool(findings.get("needs_ai_review", False)):
        result = {
            "status": "SKIPPED",
            "reviewed_at": now_iso(),
            "deterministic_severity": deterministic_severity,
            "severity": deterministic_severity,
            "reason": "needs_ai_review=false",
        }
        atomic_json(root / "ai_review.json", result)
        return result

    model = str(config.get("model") or "").strip()
    url = str(config.get("lm_studio_url") or "").strip()
    if not model:
        raise ValueError("Missing config: model")
    if not url:
        raise ValueError("Missing config: lm_studio_url")

    payload = build_request_payload(
        model=model,
        ai_input=ai_input,
        temperature=float(config.get("temperature", 0.1)),
        max_tokens=int(config.get("max_tokens", 900)),
    )

    if dry_run:
        result = {
            "status": "DRY_RUN",
            "reviewed_at": now_iso(),
            "deterministic_severity": deterministic_severity,
            "severity": deterministic_severity,
            "model": model,
            "lm_studio_url": url,
        }
        atomic_json(root / "ai_review.json", result)
        return result

    timeout_seconds = int(config.get("timeout_seconds", 60))
    api_key = os.environ.get("LM_STUDIO_API_KEY") or config.get("api_key")
    raw_content: str | None = None
    try:
        response = transport(url, payload, timeout_seconds, api_key)
        raw_content = _extract_content(response)
        parsed = parse_model_json(raw_content)
        reviewed = enforce_severity_floor(parsed, deterministic_severity)
        result = {
            "status": "REVIEWED",
            "reviewed_at": now_iso(),
            "model": model,
            **reviewed,
        }
        atomic_json(root / "ai_review.json", result)
        atomic_json(_history_path(root), result)
        return result
    except Exception as exc:
        error_result = {
            "status": "ERROR",
            "reviewed_at": now_iso(),
            "deterministic_severity": deterministic_severity,
            "severity": deterministic_severity,
            "model": model,
            "error": str(exc),
        }
        if raw_content is not None:
            error_result["raw_model_content"] = raw_content[:4000]
        atomic_json(root / "ai_review.json", error_result)
        atomic_json(_history_path(root), error_result)
        raise


def load_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(
            f"Config not found: {path}. Copy config.example.json to config.json and set lm_studio_url/model."
        )
    return load_json(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OpenClaw Monitor Phase 3: read-only LM Studio review")
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT, help="Monitor root (default: ~/openclaw-monitor)")
    parser.add_argument("--config", type=Path, default=None, help="Config JSON (default: <root>/config.json)")
    parser.add_argument("--dry-run", action="store_true", help="Build ai_input.json but do not call LM Studio")
    args = parser.parse_args(argv)

    config_path = args.config or (args.root / "config.json")
    config = load_config(config_path)
    try:
        result = run_review(root=args.root, config=config, dry_run=args.dry_run)
    except Exception as exc:
        print(f"AI review failed: {exc}")
        return 3

    print(f"AI review status: {result['status']}")
    print(f"Severity: {result.get('severity', 'UNKNOWN')}")
    if result["status"] == "REVIEWED":
        print(f"Summary: {result.get('summary', '')}")
        print(f"Notify: {str(result.get('notify', False)).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
