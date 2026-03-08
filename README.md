# Sentinel Proto

Sentinel Proto is a thin desktop vessel for process and memory data.

The through line is simple:
- Collectors in WSL or Windows own the hard part.
- This app renders a stable JSON snapshot contract in a lightweight desktop UI.
- The old process-log analyzer still exists as a compatibility path for earlier experiments.

## What It Is Now

There are two modes in this repo:

1. Snapshot vessel mode
   The preferred path. A producer emits a JSON snapshot, and the Tauri UI renders memory, watchlist, alerts, and top process rows.

2. Legacy analyzer mode
   The original proof-of-concept path. `process_analyzer.py` parses tab-separated Windows process logs and produces a text report with security and resource findings.

The snapshot contract is documented in `contracts/memory_snapshot.schema.json`, `contracts/memory_snapshot.example.json`, and `contracts/README.md`.

## Python Workflow

The preferred Python workflow is now `uv`.

From the repo root:

```bash
uv sync --dev
uv run pytest
uv run python process_analyzer.py --help
```

If you want to run the analyzer directly against a log:

```bash
uv run python process_analyzer.py <logfile>
```

## Run The Desktop UI

From the repo root:

```bash
cd tauri-shell
cargo run
```

The UI will:
- reload the last snapshot JSON you selected, if one is remembered
- otherwise load the bundled example snapshot
- keep the legacy log analysis buttons available for older workflows

## Snapshot Contract

Top-level payload shape:

```json
{
  "version": "1.0",
  "captured_at": "2026-03-07T10:15:00Z",
  "source": {},
  "summary": {
    "total_processes": 148,
    "total_resident_mb": 18324.5
  },
  "watchlist": [],
  "alerts": [],
  "processes": [],
  "notes": []
}
```

Design rules:
- Keep the contract small and boring.
- Unknown fields are allowed and ignored by the current UI.
- Producers should treat this as a snapshot, not a streaming protocol.
- If optional counts are omitted, the desktop bridge backfills them from the arrays when possible.

See `contracts/README.md` for field guidance.

## Legacy Analyzer

Basic usage:

```bash
uv run python process_analyzer.py <logfile>
```

Save report to file:

```bash
uv run python process_analyzer.py <logfile> --output report.txt
```

Export JSON:

```bash
uv run python process_analyzer.py <logfile> --json results.json
```

Verbose output:

```bash
uv run python process_analyzer.py <logfile> -v
```

The analyzer still checks for:
- suspicious process chains
- masquerading or missing company info
- high CPU and high memory usage
- unsigned or high-risk processes
- configured watchlist process memory thresholds

Watchlist configuration lives in `config/sentinel_config.toml`.

## Current Direction

If you already have richer WSL-side tooling, keep that logic there.

The lowest-friction integration is:
- have your WSL tooling emit a JSON file that matches the snapshot contract
- load that file once in the desktop app
- use `Reload Last Snapshot` as you iterate, or point future tooling at the same file path

That keeps Sentinel Proto as a vessel UI instead of turning it into another collector.
