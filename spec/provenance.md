# DPKG Provenance Event Semantics

**Version:** 1.0
**Status:** Normative
**Date:** 2026-04-21

`provenance.jsonl` is the append-only event log of a package. It is the authoritative history of every claim's lifecycle.

## File Format

1. One JSON object per line.
2. Each line follows `canonical-serialization.md` Rule 1 (JSON canonical form).
3. Lines separated by a single LF (`0x0A`). The final line MUST also end with LF.
4. Empty lines are forbidden.
5. Lines MUST be ordered by embedded UUID v7 timestamp of `event_id`, monotonically non-decreasing.

## Event Types

| `event_type` | Requires body change? | State before → after |
|---|---|---|
| `create` | yes (new body) | (nil) → draft |
| `publish` | no | draft → active |
| `reaffirm` | no | active → active (via reaffirmed) |
| `revise` | yes (new body) | active → active (via revised; new `claim_instance_id`) |
| `supersede` | no | active → superseded |
| `withdraw` | no | any non-terminal → withdrawn |

## Required Fields by Event Type

| Field | create | publish | reaffirm | revise | supersede | withdraw |
|---|---|---|---|---|---|---|
| `event_id` | R | R | R | R | R | R |
| `event_type` | R | R | R | R | R | R |
| `timestamp` | R | R | R | R | R | R |
| `actor` | R | R | R | R | R | R |
| `claim_id` | R | R | R | R | R | R |
| `claim_instance_id` | R | – | – | R | R | – |
| `prev_event_id` | – | R | R | R | R | R |
| `superseded_by_claim_id` | – | – | – | – | R | – |
| `reason` | O | O | O | O | O | O |
| `extensions` | O | O | O | O | O | O |

Legend: `R` = required, `O` = optional, `–` = MUST be absent.

Rules enforced:
- `claim_instance_id` on `reaffirm` or `withdraw` → `ERR-SEM-014`.
- `claim_instance_id` missing on `create`, `revise`, `supersede` → `ERR-SEM-015`.
- `superseded_by_claim_id` missing on `supersede` → `ERR-SEM-009`.
- `prev_event_id` MUST reference a prior event's `event_id` for the same `claim_id` (except on `create`).

## Example `provenance.jsonl`

```jsonl
{"actor":"chris","claim_id":"0190ab63-5f8a-7a61-9b14-ffaa20c1d00d","claim_instance_id":"0190ab63-7c22-7b80-9b14-ffaa20c1d00e","event_id":"0190ab63-5f8a-7c00-8000-000000000001","event_type":"create","timestamp":"2026-04-21T00:00:00Z"}
{"actor":"chris","claim_id":"0190ab63-5f8a-7a61-9b14-ffaa20c1d00d","event_id":"0190ab64-0000-7c00-8000-000000000002","event_type":"publish","prev_event_id":"0190ab63-5f8a-7c00-8000-000000000001","timestamp":"2026-04-21T00:00:01Z"}
{"actor":"chris","claim_id":"0190ab63-5f8a-7a61-9b14-ffaa20c1d00d","claim_instance_id":"0190ab6a-0000-7b80-9b14-ffaa20c1d0ff","event_id":"0190ab6a-0000-7c00-8000-000000000003","event_type":"revise","prev_event_id":"0190ab64-0000-7c00-8000-000000000002","timestamp":"2026-04-21T00:10:00Z"}
```

Each line is a canonical JSON object; keys are alphabetically ordered; no extraneous whitespace; LF at end of every line including the last.

## Semantic Invariants

- **P-1** First event for any `claim_id` MUST be `create`.
- **P-2** `publish` MUST follow `create` with no intervening events.
- **P-3** Every `revise` MUST emit a new `claim_instance_id` never used before in this package.
- **P-4** `supersede` target (`superseded_by_claim_id`) MUST reference a claim that either (a) already exists in the same package, or (b) is declared as external via application-defined extensions.
- **P-5** No event MAY appear after a terminal-state event (`supersede` / `withdraw`) for the same `claim_id`.
