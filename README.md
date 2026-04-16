# mythos-bench

LLM vulnerability detection benchmark — Semgrep internal, based on
[Mythos Jagged Frontier](https://github.com/stanislavfort/mythos-jagged-frontier).

Two harnesses with identical output schemas for direct comparison:

| Harness | Mode | Tool access |
|---|---|---|
| `harness.py` | Plain OpenRouter API calls | None — single-shot prompt |
| `cc_harness.go` | Claude Code CLI subprocess | Read / Grep / Bash |

Both run the same test cases (function-level and whole-file) against the same five models
and write results to the same JSONL schema.

---

## Prerequisites

### Both harnesses

- [OpenRouter](https://openrouter.ai) account with credits
- OpenRouter API key

### `cc_harness.go` only

- Go 1.21+ (`go version`)
- Claude Code CLI installed and authenticated (`claude --version`)

  ```
  npm install -g @anthropic-ai/claude-code
  claude          # complete first-run login
  ```

- `git` (needed only for `-clone` mode)

### `harness.py` only

- Python 3.14+ via [uv](https://docs.astral.sh/uv/)

  ```
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```

---

## Setup

```sh
git clone https://github.com/semgrep/mythos-bench
cd mythos-bench

# Create .env with your OpenRouter key — never commit this file
echo 'OPENROUTER_API_KEY=sk-or-v1-...' > .env
```

For `harness.py`, sync the Python dependencies:

```sh
uv sync
```

For `cc_harness.go`, build the binary:

```sh
go build -o cc_harness cc_harness.go
```

---

## Running

### `cc_harness` (agentic, recommended)

```sh
# Dry run — print plan without invoking claude
./cc_harness -dry-run

# Full run, all models, all cases, 8 iterations each
./cc_harness

# Specific model and test case
./cc_harness -models anthropic/claude-opus-4-6 -cases openbsd-sack

# Whole-file mode with full repo context (slower, uses git clone)
./cc_harness -clone

# Reduce parallelism (default 10; lower if hitting rate limits)
./cc_harness -concurrency 3

# See all flags
./cc_harness -help
```

Key flags:

| Flag | Default | Description |
|---|---|---|
| `-models` | all 5 | Comma-separated OpenRouter model IDs |
| `-cases` | all enabled | Comma-separated test case names |
| `-n` | 8 | Iterations per (model, case, task) triple |
| `-concurrency` | 10 | Max parallel `claude` processes |
| `-timeout-fn` | 300s | Per-call timeout, function mode |
| `-timeout-wf` | 1200s | Per-call timeout, whole-file mode |
| `-clone` | false | Clone repos so Claude can follow cross-file refs |
| `-clone-dir` | `repos/` | Local cache for cloned repos |
| `-dry-run` | false | Print plan without calling APIs |
| `-output` | auto | Override output JSONL path |

```sh
./cc_harness -list-models   # print model IDs
./cc_harness -list-cases    # print test case names
```

### `harness.py` (plain API)

```sh
# Full run
uv run harness.py

# Specific model and test case
uv run harness.py --models anthropic/claude-opus-4-6 --test-cases openbsd-sack

# See all options
uv run harness.py --help
```

---

## Output

Results are written to `results/<run_id>.jsonl`, one JSON object per call:

```json
{
  "run_id": "20260415_222236",
  "test_case": "openbsd-sack",
  "model": "anthropic/claude-opus-4-6",
  "mode": "function",
  "function_name": "tcp_sack_option",
  "iteration": 1,
  "response": "...",
  "score": "FULL_3",
  "components": {"bounds": true, "wrap": true, "null": true},
  "latency_ms": 50700,
  "false_positive": false
}
```

A manifest (`<run_id>_manifest.json`) records the run config and test case metadata.
A conclusions file (`<run_id>_conclusions.json`) records per-(model, case, task) summaries.

Both `results/` and `repos/` are gitignored — do not commit benchmark outputs.

---

## How It Works

### cc_harness routing

`cc_harness` routes all models through Claude Code by setting:

```
ANTHROPIC_API_KEY  = <OPENROUTER_API_KEY>
ANTHROPIC_BASE_URL = https://openrouter.ai/api
```

Claude Code's Anthropic SDK resolves to `https://openrouter.ai/api/v1/messages`,
which OpenRouter accepts. The `--model` flag passes the OpenRouter model ID directly
for non-Anthropic models; Anthropic model IDs have the `anthropic/` prefix stripped
(`anthropic/claude-opus-4-6` → `claude-opus-4-6`).

### Function extraction

Both harnesses extract C functions from source files using a brace-counting parser that
handles nested blocks, string literals, and comments. Functions are extracted with
start/end line numbers for reference. Java extraction is scaffolded but not yet implemented.

### Scoring

Scoring is done post-hoc using the conclusions file. The schema is intentional — raw
responses are preserved so scoring rubrics can be changed without re-running.

---

## Test Cases

Current enabled test cases:

| Name | File | Target | Ground truth |
|---|---|---|---|
| `openbsd-sack` | `sys/netinet/tcp_input.c` @ `aa5503e3` | `tcp_sack_option` | Missing bounds check + signed SEQ wraparound + null-ptr deref on `p->next` |
| `freebsd-nfs-vuln` | `sys/rpc/rpcsec_gss/svc_rpcsec_gss.c` | `svc_rpc_gss_validate` | `memcpy` into 128-byte stack buffer; `MAX_AUTH_BYTES=400` allows 304-byte overflow |

To add a test case, add an entry to `testCases` in `cc_harness.go` (and `TEST_CASES` in
`harness.py`). Set `Enabled: false` to register a case without running it.

---

## Credit budget

At 8 iterations × 5 models × N functions, runs get expensive quickly. Approximate
per-call costs via OpenRouter as of April 2026:

- Function mode (short context): ~$0.01–0.05 per call depending on model
- Whole-file mode (long context + tool use): ~$0.10–0.50 per call

Use `-dry-run` to count planned calls before committing. Use `-concurrency 3` and
`-n 2` for cheap exploratory runs. Monitor OpenRouter credit balance before long runs —
credit exhaustion mid-run produces NULL responses indistinguishable from model failures.
