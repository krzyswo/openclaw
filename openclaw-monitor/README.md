# OpenClaw Monitor — Phase 2 + Phase 3

Simple monitoring pipeline built around the existing Phase 1 discovery collector.

## Architecture

```text
Phase 1 collector
  -> discovery.json + raw/

Phase 2: compare.py
  -> baseline/current/previous
  -> diff.json
  -> findings.json

Phase 3: ai_review.py
  -> reads findings.json + diff.json + current/baseline context
  -> if needs_ai_review=false: stops without calling a model
  -> if needs_ai_review=true: sends structured evidence to LM Studio
  -> ai_review.json + ai_reviews/<timestamp>.json
```

Phase 3 is read-only analysis. The model receives no tools, no shell, no SSH and no remediation capability.

## Runtime layout

Default root: `~/openclaw-monitor/`

```text
~/openclaw-monitor/
├── compare.py
├── ai_review.py
├── config.json
├── diff.json
├── findings.json
├── ai_input.json
├── ai_review.json
├── ai_reviews/
└── state/
    ├── baseline.json
    ├── previous.json
    └── current.json
```

## Phase 2

Create the baseline once:

```bash
python3 ~/openclaw-monitor/compare.py baseline
```

After a new Phase 1 report:

```bash
python3 ~/openclaw-monitor/compare.py run
```

`compare.py` exits `0` for OK/INFO and `2` for WARNING/HIGH/CRITICAL.

## Phase 3 configuration

Copy the example:

```bash
cp ~/openclaw-monitor/config.example.json ~/openclaw-monitor/config.json
```

Edit `lm_studio_url` if LM Studio runs on another host. The default assumes the API is reachable on the same host at port 1234.

Default model:

```text
qwen/qwen3.5-9b
```

No API key is required by default. If your LM Studio setup expects one, set it without storing it in the config:

```bash
export LM_STUDIO_API_KEY='...'
```

## Phase 3 dry run

Build exactly what would be sent to the model, but do not call LM Studio:

```bash
python3 ~/openclaw-monitor/ai_review.py --dry-run
cat ~/openclaw-monitor/ai_input.json
```

The input contains:

- deterministic severity and findings,
- semantic diff,
- current/baseline system summary,
- full baseline and current LAN device lists,
- baseline/current listening sockets,
- baseline/current integrity context.

## Phase 3 live review

```bash
python3 ~/openclaw-monitor/ai_review.py
```

If `findings.json` contains:

```json
{"needs_ai_review": false}
```

no model call is made.

If review is required, the wrapper calls the OpenAI-compatible LM Studio endpoint and requests strict JSON.

Result:

```text
~/openclaw-monitor/ai_review.json
```

History:

```text
~/openclaw-monitor/ai_reviews/YYYYMMDD_HHMMSS_microseconds.json
```

## Severity safety rule

Deterministic rules define a severity floor:

```text
FINAL_SEVERITY = max(DETERMINISTIC_SEVERITY, AI_SEVERITY)
```

The model can raise severity but cannot lower it.

## Expected model output

```json
{
  "severity": "HIGH",
  "summary": "Krótki opis problemu.",
  "analysis": "Analiza oparta wyłącznie na dostarczonych danych.",
  "recommendations": ["Krok weryfikacyjny dla administratora."],
  "notify": true,
  "confidence": 0.9
}
```

The wrapper validates this response before accepting it.

## Tests

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile compare.py ai_review.py
```

No notifications and no automatic remediation are implemented in Phase 3.
