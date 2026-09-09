import json
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ai_review import (
    build_ai_input,
    build_request_payload,
    parse_model_json,
    enforce_severity_floor,
    run_review,
)


def base_state():
    return {
        "meta": {"source_report": "/tmp/discovery.json"},
        "system": {"hostname": "OpenClaw"},
        "resources": {"ram_used_percent": 21.0, "swap_used_percent": 0.0},
        "storage": {"root_used_percent": 76.0},
        "network": {
            "default_gateway": "192.168.0.1",
            "dns_servers": ["192.168.0.1"],
            "public_ip": "194.0.154.6",
            "primary_interface": "enp6s18",
            "primary_state": "UP",
            "internet_reachable": True,
        },
        "lan": {
            "devices": [
                {"ip": "192.168.0.1", "mac": "aa:aa:aa:aa:aa:aa", "hostname": "router"},
                {"ip": "192.168.0.147", "mac": "bc:24:11:4a:51:3b", "hostname": "OpenClaw"},
            ]
        },
        "listening": [{"proto": "tcp", "address": "0.0.0.0", "port": 22, "process": "sshd"}],
        "security": {"uid0_users": ["root"], "sudo_users": ["openclaw"], "ssh_failed_logins_24h": 1},
        "services": {"openclaw_running": True, "llm_runtime_running": True},
        "integrity": {},
    }


class InputTests(unittest.TestCase):
    def test_ai_input_contains_full_device_context_and_findings(self):
        current = base_state()
        current["lan"]["devices"].append({"ip": "192.168.0.221", "mac": "11:22:33:44:55:66", "hostname": None})
        baseline = base_state()
        diff = {"changes": [{"type": "LAN_DEVICE_NEW", "entity": "mac:11:22:33:44:55:66"}]}
        findings = {
            "severity": "WARNING",
            "needs_ai_review": True,
            "findings": [{"rule_id": "LAN_NEW_DEVICE", "severity": "WARNING", "evidence": "192.168.0.221"}],
        }
        result = build_ai_input(current, baseline, diff, findings)
        self.assertEqual(len(result["device_context"]["baseline_devices"]), 2)
        self.assertEqual(len(result["device_context"]["current_devices"]), 3)
        self.assertEqual(result["deterministic"]["severity"], "WARNING")
        self.assertEqual(result["diff"]["changes"][0]["type"], "LAN_DEVICE_NEW")

    def test_payload_has_no_tools_and_requires_json(self):
        payload = build_request_payload(
            model="qwen/qwen3.5-9b",
            ai_input={"deterministic": {"severity": "HIGH"}},
            temperature=0.1,
            max_tokens=900,
        )
        self.assertNotIn("tools", payload)
        self.assertEqual(payload["model"], "qwen/qwen3.5-9b")
        self.assertEqual(payload["response_format"], {"type": "json_object"})
        self.assertIn("Do not lower", payload["messages"][0]["content"])


class OutputTests(unittest.TestCase):
    def test_parse_json_from_plain_content(self):
        raw = '{"severity":"HIGH","summary":"x","analysis":"y","recommendations":["z"],"notify":true,"confidence":0.9}'
        parsed = parse_model_json(raw)
        self.assertEqual(parsed["severity"], "HIGH")
        self.assertTrue(parsed["notify"])

    def test_parse_json_from_fenced_content(self):
        raw = '```json\n{"severity":"WARNING","summary":"x","analysis":"y","recommendations":[],"notify":false,"confidence":0.5}\n```'
        parsed = parse_model_json(raw)
        self.assertEqual(parsed["severity"], "WARNING")

    def test_ai_cannot_lower_deterministic_severity(self):
        model = {"severity": "INFO", "summary": "x", "analysis": "y", "recommendations": [], "notify": False, "confidence": 0.9}
        result = enforce_severity_floor(model, "HIGH")
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["model_severity"], "INFO")
        self.assertTrue(result["severity_floor_applied"])

    def test_ai_can_raise_severity(self):
        model = {"severity": "CRITICAL", "summary": "x", "analysis": "y", "recommendations": [], "notify": True, "confidence": 0.9}
        result = enforce_severity_floor(model, "WARNING")
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertFalse(result["severity_floor_applied"])


class WorkflowTests(unittest.TestCase):
    def _write_common(self, root: Path, *, needs_ai=True, severity="WARNING"):
        (root / "state").mkdir(parents=True)
        (root / "state" / "current.json").write_text(json.dumps(base_state()), encoding="utf-8")
        (root / "state" / "baseline.json").write_text(json.dumps(base_state()), encoding="utf-8")
        (root / "diff.json").write_text(json.dumps({"changes": [{"type": "TEST", "entity": "x"}]}), encoding="utf-8")
        (root / "findings.json").write_text(json.dumps({
            "severity": severity,
            "needs_ai_review": needs_ai,
            "findings": [{"rule_id": "TEST", "severity": severity, "evidence": "e"}] if needs_ai else [],
        }), encoding="utf-8")

    def test_skip_does_not_call_transport(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_common(root, needs_ai=False, severity="OK")
            calls = []

            def transport(*args, **kwargs):
                calls.append(1)
                raise AssertionError("transport must not be called")

            result = run_review(
                root=root,
                config={"lm_studio_url": "http://127.0.0.1:1234/v1/chat/completions", "model": "qwen/qwen3.5-9b"},
                transport=transport,
            )
            self.assertEqual(result["status"], "SKIPPED")
            self.assertEqual(calls, [])
            self.assertTrue((root / "ai_review.json").exists())

    def test_success_calls_transport_and_saves_history(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_common(root, needs_ai=True, severity="HIGH")
            captured = {}

            def transport(url, payload, timeout_seconds, api_key=None):
                captured["url"] = url
                captured["payload"] = payload
                return {
                    "choices": [{"message": {"content": json.dumps({
                        "severity": "WARNING",
                        "summary": "summary",
                        "analysis": "analysis",
                        "recommendations": ["check"],
                        "notify": True,
                        "confidence": 0.8,
                    })}}]
                }

            result = run_review(root=root, config={
                "lm_studio_url": "http://127.0.0.1:1234/v1/chat/completions",
                "model": "qwen/qwen3.5-9b",
                "temperature": 0.1,
                "max_tokens": 900,
                "timeout_seconds": 30,
            }, transport=transport)
            self.assertEqual(captured["url"], "http://127.0.0.1:1234/v1/chat/completions")
            self.assertEqual(result["status"], "REVIEWED")
            self.assertEqual(result["severity"], "HIGH")
            self.assertTrue(result["severity_floor_applied"])
            self.assertTrue((root / "ai_review.json").exists())
            self.assertEqual(len(list((root / "ai_reviews").glob("*.json"))), 1)
            self.assertTrue((root / "ai_input.json").exists())

    def test_invalid_model_json_is_persisted_as_error(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._write_common(root, needs_ai=True, severity="WARNING")

            def transport(url, payload, timeout_seconds, api_key=None):
                return {"choices": [{"message": {"content": "not json"}}]}

            with self.assertRaises(ValueError):
                run_review(
                    root=root,
                    config={"lm_studio_url": "http://127.0.0.1:1234/v1/chat/completions", "model": "qwen/qwen3.5-9b"},
                    transport=transport,
                )
            saved = json.loads((root / "ai_review.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["status"], "ERROR")
            self.assertEqual(saved["deterministic_severity"], "WARNING")


if __name__ == "__main__":
    unittest.main(verbosity=2)
