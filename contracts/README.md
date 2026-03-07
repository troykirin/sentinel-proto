# Memory Snapshot Contract

This contract is the handoff between your collectors and the Sentinel desktop UI.

The point is not to model everything. The point is to keep the UI simple while letting producers evolve independently.

## Contract Philosophy

- Treat each payload as a full snapshot.
- Keep required fields minimal.
- Prefer additive evolution over breaking shape changes.
- Allow producers to include extra fields without waiting on UI changes.

The current UI ignores unknown properties.

## Required Top-Level Fields

```json
{
  "version": "1.0",
  "captured_at": "2026-03-07T10:15:00Z",
  "summary": {
    "total_processes": 148,
    "total_resident_mb": 18324.5
  },
  "processes": []
}
```

Required:
- `version`
- `captured_at`
- `summary.total_processes`
- `summary.total_resident_mb`
- `processes`

Optional but supported:
- `source`
- `watchlist`
- `alerts`
- `notes`

## Field Intent

`source`
- Where the snapshot came from.
- Useful fields today: `kind`, `machine`, `environment`, `origin`.

`summary`
- Fast numbers for the cards at the top of the UI.
- `watchlist_count`, `alert_count`, and `threshold_mb` are optional.
- If `watchlist_count` or `alert_count` are omitted or zero, the desktop bridge backfills them from the array lengths when possible.

`watchlist`
- The subset of processes your collectors care about most.
- The UI expects the same shape as `processes`.

`alerts`
- Explicit alert objects for things that deserve attention now.
- Good place for threshold breaches, leak suspicion, regression notes, or run-to-run deltas.

`processes`
- The full or partial process list you want rendered.
- The UI sorts by `resident_mb` and shows the heaviest rows first.

`notes`
- Free-form producer context.
- Good for run metadata, known caveats, or links back to richer tooling.

## Process Object Shape

Supported process fields:

```json
{
  "name": "postgres",
  "pid": 1821,
  "ppid": 1,
  "resident_mb": 5128.4,
  "private_mb": 4980.1,
  "cpu_pct": 19.2,
  "status": "critical",
  "origin": "wsl",
  "command": "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main",
  "tags": ["watchlist", "database"]
}
```

Only `name` and `resident_mb` are required by the schema.

Suggested meanings:
- `status`: `ok`, `low`, `medium`, `high`, or `critical`
- `origin`: short source label like `wsl`, `windows`, `docker`, or `remote`
- `tags`: loose producer-owned labels for grouping

## Alert Object Shape

```json
{
  "severity": "critical",
  "title": "postgres exceeded threshold",
  "message": "Resident memory is 5128.4 MB, above the 4096 MB watchlist threshold.",
  "process": "postgres",
  "pid": 1821
}
```

Required:
- `severity`
- `title`
- `message`

## Producer Guidance

Good producer behavior:
- write full snapshots, not patches
- keep timestamps in ISO 8601 format
- emit stable process names for watchlist matching
- compute `summary.total_resident_mb` across the same process set you send in `processes`
- include alerts only for things that should stand out in the UI

Avoid:
- packing terminal-specific formatting into strings
- making the UI infer too much hidden meaning
- changing the meaning of existing fields between runs

## Suggested Workflow

1. Have your WSL tooling write a snapshot JSON file somewhere Windows can read.
2. Load that file once with `Load Snapshot JSON`.
3. Use `Reload Last Snapshot` while iterating on the producer.

That keeps the contract stable and the desktop side intentionally dumb.
