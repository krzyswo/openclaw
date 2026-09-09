# OpenClaw Monitor Phase 3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a read-only LM Studio review step after deterministic Phase 2 findings.

**Architecture:** `ai_review.py` consumes the existing Phase 2 state, diff and findings. It creates bounded structured input, skips the model when deterministic rules say no review is needed, otherwise calls an OpenAI-compatible LM Studio endpoint and stores validated JSON output. Deterministic severity is always the minimum final severity.

**Tech Stack:** Python 3.11+, standard library only, LM Studio OpenAI-compatible HTTP API.

**Spec:** Approved in the project conversation: Phase 3 is analysis only; no tools, shell, remediation or notifications.

## Global Constraints

- Preserve the existing Phase 1 collector and Phase 2 `compare.py` behavior.
- No model call when `needs_ai_review=false`.
- No `tools` field in LM Studio requests.
- Include full baseline/current LAN device context.
- AI may raise but never lower deterministic severity.
- Persist AI input and every review/error result.
- No notifications and no remediation in this phase.

---

### Task 1: Structured AI input and LM Studio request

**Files:**
- Create: `openclaw-monitor/ai_review.py`
- Test: `openclaw-monitor/tests/test_ai_review.py`

**Interfaces:**
- Consumes: `state/current.json`, `state/baseline.json`, `diff.json`, `findings.json`.
- Produces: `ai_input.json`, OpenAI-compatible request payload.

- [x] Write failing tests for full device context and tool-free strict JSON request.
- [x] Run tests and confirm failure because `ai_review.py` does not exist.
- [x] Implement `build_ai_input()` and `build_request_payload()`.
- [x] Run tests and confirm pass.

### Task 2: Validate model output and enforce severity floor

**Files:**
- Modify: `openclaw-monitor/ai_review.py`
- Test: `openclaw-monitor/tests/test_ai_review.py`

**Interfaces:**
- Consumes: LM Studio `choices[0].message.content`.
- Produces: validated review JSON with deterministic severity floor metadata.

- [x] Write tests for plain/fenced JSON, severity raise, and attempted severity downgrade.
- [x] Implement strict parsing and `enforce_severity_floor()`.
- [x] Run tests and confirm pass.

### Task 3: End-to-end Phase 3 workflow

**Files:**
- Modify: `openclaw-monitor/ai_review.py`
- Create: `openclaw-monitor/config.example.json`
- Create: `openclaw-monitor/README.md`
- Test: `openclaw-monitor/tests/test_ai_review.py`

**Interfaces:**
- Consumes: Phase 2 outputs and LM Studio endpoint configuration.
- Produces: `ai_review.json`, `ai_reviews/*.json`; `SKIPPED`, `DRY_RUN`, `REVIEWED`, or persisted `ERROR` state.

- [x] Write tests proving skip does not call transport, success persists history, and invalid model output persists an error.
- [x] Implement standard-library HTTP transport, workflow, CLI and dry-run.
- [x] Document configuration and execution.
- [x] Run the complete Phase 3 test suite and Python compilation.
