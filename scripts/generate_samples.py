"""Generate the v0.3.0 sample suite under C:/Users/user/dpkg/samples/.

Each sample directory contains:
  - manifest.json             (canonical, one-line JSON)
  - claims/<uuid>.md          (YAML frontmatter + markdown body)
  - provenance.jsonl          (one JSON object per line)
  - expected-normalized.json  (normalized view + validator_verdict)
  - README.md                 (<=40 lines describing intent)

This script is idempotent: re-run safely regenerates the whole samples/
tree. It is pure stdlib and deterministic (no clocks, no random).
"""

from __future__ import annotations

import json
import sys
import unicodedata
from pathlib import Path
from typing import Any

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"
SCHEMA_URL = "../../schemas/expected-normalized-v0.3.json"

# Deterministic ids
PKG = "0193{n}-0000-7000-8000-000000000001"
CLAIM = "0193{n}-0000-7000-8000-00000000aaaa"
CLAIM_B = "0193{n}-0000-7000-8000-00000000bbbb"
INSTANCE = "0193{n}-0000-7000-8000-aaaaaaaaaaaa"
INSTANCE_2 = "0193{n}-0000-7000-8000-aaaaaaaaaaab"
INSTANCE_B = "0193{n}-0000-7000-8000-bbbbbbbbbbbb"
EVENT = "0193{n}-0000-7000-8000-eeee{suffix}"


def _canon_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _write_json(path: Path, obj: Any) -> None:
    _write(path, _canon_json(obj) + "\n")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    lines = [_canon_json(r) for r in rows]
    _write(path, ("\n".join(lines) + "\n") if rows else "")


def _claim_md(frontmatter: dict, body: str) -> str:
    keys = sorted(frontmatter)
    lines = ["---"]
    for k in keys:
        v = frontmatter[k]
        if isinstance(v, list):
            lines.append(f'"{k}":')
            for item in v:
                lines.append(f'  - "{item}"')
        elif isinstance(v, (int, float)):
            lines.append(f'"{k}": {v}')
        else:
            lines.append(f'"{k}": "{v}"')
    lines.append("---")
    return "\n".join(lines) + "\n" + body.rstrip() + "\n"


def _manifest(n: str, claims: list[dict]) -> dict:
    return {
        "claims": claims,
        "created_at": "2026-04-21T00:00:00Z",
        "format_version": "1.0",
        "license": "Apache-2.0",
        "package_id": PKG.format(n=n),
        "producer": "dpkg-sample-gen",
        "provenance_path": "provenance.jsonl",
    }


def _claim_entry(claim_id: str, instance_id: str, hash_hex: str, state: str = "active",
                 superseded_by: str | None = None) -> dict:
    entry = {
        "claim_id": claim_id,
        "claim_instance_id": instance_id,
        "hash": hash_hex,
        "path": f"claims/{claim_id}.md",
        "state": state,
    }
    if superseded_by:
        entry["superseded_by_claim_id"] = superseded_by
    return entry


def _event(n: str, suffix: str, event_type: str, claim_id: str,
           instance_id: str | None = None, ts: str = "2026-04-21T00:00:00Z",
           prev: str | None = None, actor: str = "gen",
           target_instance: str | None = None) -> dict:
    ev: dict = {
        "actor": actor,
        "claim_id": claim_id,
        "event_id": EVENT.format(n=n, suffix=suffix),
        "event_type": event_type,
        "timestamp": ts,
    }
    if instance_id:
        ev["claim_instance_id"] = instance_id
    if prev:
        ev["prev_event_id"] = prev
    if target_instance:
        ev["target_claim_instance_id"] = target_instance
    return ev


def _expected(verdict: str, notes: dict, error_code: str | None = None) -> dict:
    out: dict = {
        "$schema": SCHEMA_URL,
        "expected_normalized_version": "0.3",
        "validator_verdict": verdict,
        "notes": notes,
    }
    if error_code:
        out["error_code"] = error_code
    return out


# Placeholder hash for frontmatter payload.
# Test vectors in tests/vectors/hash_vectors.json are authoritative; sample
# hashes here are synthetic illustrations (validator treats them as opaque).
H1 = "a" * 64
H2 = "b" * 64
H3 = "c" * 64
H4 = "d" * 64


def build_architecture_claim() -> None:
    n = "0001"
    claim_id = CLAIM.format(n=n)
    instance_id = INSTANCE.format(n=n)
    manifest = _manifest(n, [_claim_entry(claim_id, instance_id, H1)])
    claim_md = _claim_md(
        {
            "claim_id": claim_id,
            "claim_instance_id": instance_id,
            "created_at": "2026-04-21T00:00:00Z",
            "object": "per-claim sha256",
            "predicate": "supports",
            "source": "adr-0001",
            "state": "active",
            "subject": "DPKG",
            "type": "architecture_decision",
            "updated_at": "2026-04-21T00:00:00Z",
        },
        "DPKG adopts per-claim SHA-256 as the content-hash granularity.",
    )
    events = [_event(n, "00000001", "create", claim_id, instance_id)]
    base = SAMPLES_DIR / "architecture-claim"
    _write_json(base / "manifest.json", manifest)
    _write(base / f"claims/{claim_id}.md", claim_md)
    _write_jsonl(base / "provenance.jsonl", events)
    _write_json(
        base / "expected-normalized.json",
        _expected(
            "valid",
            {
                "claim_ids": [claim_id],
                "event_count": 1,
                "final_states": {claim_id: "active"},
                "demonstrates": "single supports-relationship claim with one create event",
            },
        ),
    )
    _write(
        base / "README.md",
        "# Sample: architecture-claim\n\n"
        "Canonical single-claim DPKG demonstrating a `supports`-relationship "
        "architecture decision. Expected verdict: valid.\n\n"
        "- 1 claim, state=active\n- 1 create event\n- No revisions, no withdraws\n",
    )


def build_contradictory_claim() -> None:
    n = "0002"
    a = CLAIM.format(n=n)
    b = CLAIM_B.format(n=n)
    ia = INSTANCE.format(n=n)
    ib = INSTANCE_B.format(n=n)
    manifest = _manifest(
        n,
        [
            _claim_entry(a, ia, H1),
            _claim_entry(b, ib, H2),
        ],
    )
    claim_a = _claim_md(
        {
            "claim_id": a,
            "claim_instance_id": ia,
            "created_at": "2026-04-21T00:00:00Z",
            "object": "memory aggregation",
            "predicate": "supports",
            "source": "chris",
            "state": "active",
            "subject": "DPKG",
            "type": "architecture_opinion",
            "updated_at": "2026-04-21T00:00:00Z",
        },
        "DPKG should support memory aggregation directly.",
    )
    claim_b = _claim_md(
        {
            "claim_id": b,
            "claim_instance_id": ib,
            "created_at": "2026-04-21T00:00:01Z",
            "object": "memory aggregation",
            "predicate": "rejects",
            "source": "xcouncil",
            "state": "active",
            "subject": "DPKG",
            "type": "architecture_opinion",
            "updated_at": "2026-04-21T00:00:01Z",
        },
        "DPKG MUST NOT include aggregation; that is an application concern.",
    )
    events = [
        _event(n, "00000001", "create", a, ia, "2026-04-21T00:00:00Z"),
        _event(n, "00000002", "create", b, ib, "2026-04-21T00:00:01Z"),
    ]
    base = SAMPLES_DIR / "contradictory-claim"
    _write_json(base / "manifest.json", manifest)
    _write(base / f"claims/{a}.md", claim_a)
    _write(base / f"claims/{b}.md", claim_b)
    _write_jsonl(base / "provenance.jsonl", events)
    _write_json(
        base / "expected-normalized.json",
        _expected(
            "valid",
            {
                "claim_ids": [a, b],
                "event_count": 2,
                "final_states": {a: "active", b: "active"},
                "demonstrates": (
                    "two claims with contradictory predicate/object stored "
                    "side-by-side without merging; consumer-layer decides"
                ),
            },
        ),
    )
    _write(
        base / "README.md",
        "# Sample: contradictory-claim\n\n"
        "Two concurrently-active claims whose `predicate` values contradict "
        "(`supports` vs `rejects`) on the same `(subject, object)` pair. "
        "DPKG stores polarity without merging; reconciliation is the "
        "consumer's job. Expected verdict: valid.\n",
    )


def build_revise_withdraw_flow() -> None:
    n = "0003"
    claim_id = CLAIM.format(n=n)
    i1 = INSTANCE.format(n=n)
    i2 = INSTANCE_2.format(n=n)
    manifest = _manifest(
        n,
        [_claim_entry(claim_id, i2, H2, state="withdrawn")],
    )
    claim_md = _claim_md(
        {
            "claim_id": claim_id,
            "claim_instance_id": i2,
            "created_at": "2026-04-21T00:00:00Z",
            "source": "draft",
            "state": "withdrawn",
            "type": "draft_proposal",
            "updated_at": "2026-04-21T00:00:02Z",
            "withdrawn_reason": "superseded by xcouncil consensus",
        },
        "Revised draft proposal body, then retracted.",
    )
    e1 = _event(n, "00000001", "create", claim_id, i1, "2026-04-21T00:00:00Z")
    e2 = _event(
        n, "00000002", "revise", claim_id, i2,
        ts="2026-04-21T00:00:01Z",
        prev=e1["event_id"],
        target_instance=i1,
    )
    e3 = _event(
        n, "00000003", "withdraw", claim_id,
        ts="2026-04-21T00:00:02Z",
        prev=e2["event_id"],
        target_instance=i2,
    )
    base = SAMPLES_DIR / "revise-withdraw-flow"
    _write_json(base / "manifest.json", manifest)
    _write(base / f"claims/{claim_id}.md", claim_md)
    _write_jsonl(base / "provenance.jsonl", [e1, e2, e3])
    _write_json(
        base / "expected-normalized.json",
        _expected(
            "valid",
            {
                "claim_ids": [claim_id],
                "event_count": 3,
                "final_states": {claim_id: "withdrawn"},
                "instance_ids_seen": [i1, i2],
                "demonstrates": "create -> revise -> withdraw lifecycle chain",
            },
        ),
    )
    _write(
        base / "README.md",
        "# Sample: revise-withdraw-flow\n\n"
        "One claim walks through `create` -> `revise` -> `withdraw` over three "
        "events. Two `claim_instance_id`s are emitted (create + revise); "
        "`withdraw` reuses the latest instance. Final state is `withdrawn`.\n",
    )


def build_minimal_empty() -> None:
    n = "0004"
    manifest = _manifest(n, [])
    base = SAMPLES_DIR / "minimal-empty"
    _write_json(base / "manifest.json", manifest)
    _write(base / "claims/.gitkeep", "")
    _write(base / "provenance.jsonl", "")
    _write_json(
        base / "expected-normalized.json",
        _expected(
            "valid",
            {
                "claim_ids": [],
                "event_count": 0,
                "final_states": {},
                "demonstrates": "smallest legal DPKG: zero claims, empty provenance file",
            },
        ),
    )
    _write(
        base / "README.md",
        "# Sample: minimal-empty\n\n"
        "Legal-but-empty DPKG: `manifest.claims = []`, `provenance.jsonl` is "
        "an empty file (still present). Tests the zero-row edge of every "
        "schema. Expected verdict: valid.\n",
    )


def build_unicode_normalization() -> None:
    n = "0005"
    claim_id = CLAIM.format(n=n)
    instance_id = INSTANCE.format(n=n)
    # NFD source: "café" written as 'café' (combining acute)
    nfd_subject = "café"
    nfc_subject = unicodedata.normalize("NFC", nfd_subject)
    manifest = _manifest(n, [_claim_entry(claim_id, instance_id, H1)])
    claim_md = _claim_md(
        {
            "claim_id": claim_id,
            "claim_instance_id": instance_id,
            "created_at": "2026-04-21T00:00:00Z",
            "source": "unicode-test",
            "state": "active",
            "subject": nfc_subject,
            "type": "unicode_smoke",
            "updated_at": "2026-04-21T00:00:00Z",
        },
        f"Body contains NFD input: {nfd_subject} (must render NFC after normalization).",
    )
    events = [_event(n, "00000001", "create", claim_id, instance_id)]
    base = SAMPLES_DIR / "unicode-normalization"
    _write_json(base / "manifest.json", manifest)
    _write(base / f"claims/{claim_id}.md", claim_md)
    _write_jsonl(base / "provenance.jsonl", events)
    _write_json(
        base / "expected-normalized.json",
        _expected(
            "valid",
            {
                "claim_ids": [claim_id],
                "event_count": 1,
                "nfc_subject": nfc_subject,
                "demonstrates": "NFD input in claim body must be NFC-normalized by validator",
            },
        ),
    )
    _write(
        base / "README.md",
        "# Sample: unicode-normalization\n\n"
        "Source author typed `cafe\\u0301` (NFD, two codepoints). After "
        "canonical normalization the validator MUST see `caf\\u00e9` (NFC, one "
        "codepoint). `expected-normalized.json` stores the post-NFC form.\n",
    )


def build_multi_source_claim() -> None:
    n = "0006"
    claim_id = CLAIM.format(n=n)
    instance_id = INSTANCE.format(n=n)
    manifest = _manifest(n, [_claim_entry(claim_id, instance_id, H1)])
    claim_md = _claim_md(
        {
            "claim_id": claim_id,
            "claim_instance_id": instance_id,
            "created_at": "2026-04-21T00:00:00Z",
            "source": "merged",
            "state": "active",
            "type": "fact",
            "updated_at": "2026-04-21T00:00:02Z",
        },
        "Claim reaffirmed by two additional actors.",
    )
    e1 = _event(n, "00000001", "create", claim_id, instance_id, "2026-04-21T00:00:00Z", actor="chris")
    e2 = _event(
        n, "00000002", "reaffirm", claim_id,
        ts="2026-04-21T00:00:01Z",
        prev=e1["event_id"], actor="gemini", target_instance=instance_id,
    )
    e3 = _event(
        n, "00000003", "reaffirm", claim_id,
        ts="2026-04-21T00:00:02Z",
        prev=e2["event_id"], actor="codex", target_instance=instance_id,
    )
    base = SAMPLES_DIR / "multi-source-claim"
    _write_json(base / "manifest.json", manifest)
    _write(base / f"claims/{claim_id}.md", claim_md)
    _write_jsonl(base / "provenance.jsonl", [e1, e2, e3])
    _write_json(
        base / "expected-normalized.json",
        _expected(
            "valid",
            {
                "claim_ids": [claim_id],
                "event_count": 3,
                "source_actors": ["chris", "codex", "gemini"],
                "demonstrates": "one claim reaffirmed by multiple actors keeps a single claim_instance_id",
            },
        ),
    )
    _write(
        base / "README.md",
        "# Sample: multi-source-claim\n\n"
        "One claim created by `chris`, reaffirmed by `gemini` and `codex`. "
        "Reaffirm events MUST NOT allocate a new `claim_instance_id`; the "
        "original instance is the reaffirmation target. Final state: active.\n",
    )


def build_duplicate_reaffirm_collision() -> None:
    n = "0007"
    claim_id = CLAIM.format(n=n)
    ia = INSTANCE.format(n=n)
    ib = INSTANCE_B.format(n=n)
    # Two standalone packages that collide when merged: same claim_id, different hashes.
    pkg_a_manifest = _manifest(n, [_claim_entry(claim_id, ia, H1)])
    pkg_b_manifest_dict = _manifest(n, [_claim_entry(claim_id, ib, H2)])
    pkg_b_manifest_dict["package_id"] = (
        pkg_a_manifest["package_id"][:-1] + "2"
    )
    claim_a = _claim_md(
        {
            "claim_id": claim_id,
            "claim_instance_id": ia,
            "created_at": "2026-04-21T00:00:00Z",
            "source": "actor-a",
            "state": "active",
            "type": "fact",
            "updated_at": "2026-04-21T00:00:00Z",
        },
        "Version A of the body.",
    )
    claim_b = _claim_md(
        {
            "claim_id": claim_id,
            "claim_instance_id": ib,
            "created_at": "2026-04-21T00:00:00Z",
            "source": "actor-b",
            "state": "active",
            "type": "fact",
            "updated_at": "2026-04-21T00:00:00Z",
        },
        "Version B of the body (colliding content).",
    )
    base = SAMPLES_DIR / "duplicate-reaffirm-collision"
    _write_json(base / "package-a/manifest.json", pkg_a_manifest)
    _write(base / f"package-a/claims/{claim_id}.md", claim_a)
    _write_jsonl(
        base / "package-a/provenance.jsonl",
        [_event(n, "00000001", "create", claim_id, ia, actor="actor-a")],
    )
    _write_json(base / "package-b/manifest.json", pkg_b_manifest_dict)
    _write(base / f"package-b/claims/{claim_id}.md", claim_b)
    _write_jsonl(
        base / "package-b/provenance.jsonl",
        [_event(n, "00000002", "create", claim_id, ib, actor="actor-b")],
    )
    _write_json(
        base / "expected-normalized.json",
        _expected(
            "invalid",
            {
                "collision_claim_id": claim_id,
                "collision_instance_ids": [ia, ib],
                "demonstrates": (
                    "same claim_id with different content_hash across two packages; "
                    "merge-time validator MUST reject"
                ),
                "scope": "applies only when both packages are imported into the same consumer; "
                         "each package individually is valid",
            },
            error_code="ERR-SEM-DUPLICATE-HASH-COLLISION",
        ),
    )
    _write(
        base / "README.md",
        "# Sample: duplicate-reaffirm-collision\n\n"
        "Two packages (`package-a/`, `package-b/`) each legal on their own. "
        "When imported into the same consumer, the shared `claim_id` with "
        "different `content_hash` values MUST raise "
        "`ERR-SEM-DUPLICATE-HASH-COLLISION`. Individual validation passes.\n",
    )


def build_withdraw_then_illegal_reaffirm() -> None:
    n = "0008"
    claim_id = CLAIM.format(n=n)
    instance_id = INSTANCE.format(n=n)
    manifest = _manifest(
        n, [_claim_entry(claim_id, instance_id, H1, state="withdrawn")]
    )
    claim_md = _claim_md(
        {
            "claim_id": claim_id,
            "claim_instance_id": instance_id,
            "created_at": "2026-04-21T00:00:00Z",
            "source": "lifecycle-test",
            "state": "withdrawn",
            "type": "lifecycle_probe",
            "updated_at": "2026-04-21T00:00:01Z",
            "withdrawn_reason": "author retracted",
        },
        "Withdrawn claim that is then illegally reaffirmed.",
    )
    e1 = _event(n, "00000001", "create", claim_id, instance_id, "2026-04-21T00:00:00Z")
    e2 = _event(
        n, "00000002", "withdraw", claim_id,
        ts="2026-04-21T00:00:01Z",
        prev=e1["event_id"], target_instance=instance_id,
    )
    e3 = _event(
        n, "00000003", "reaffirm", claim_id,
        ts="2026-04-21T00:00:02Z",
        prev=e2["event_id"], target_instance=instance_id,
    )
    base = SAMPLES_DIR / "withdraw-then-illegal-reaffirm"
    _write_json(base / "manifest.json", manifest)
    _write(base / f"claims/{claim_id}.md", claim_md)
    _write_jsonl(base / "provenance.jsonl", [e1, e2, e3])
    _write_json(
        base / "expected-normalized.json",
        _expected(
            "invalid",
            {
                "claim_ids": [claim_id],
                "illegal_event_id": e3["event_id"],
                "demonstrates": (
                    "reaffirm on a withdrawn claim is an illegal transition; "
                    "validator MUST reject"
                ),
            },
            error_code="ERR-SEM-LIFECYCLE-ILLEGAL",
        ),
    )
    _write(
        base / "README.md",
        "# Sample: withdraw-then-illegal-reaffirm\n\n"
        "`create` -> `withdraw` -> `reaffirm` on the same claim. Withdrawn is "
        "terminal: reaffirm is NOT a legal transition from `withdrawn`. The "
        "validator MUST flag `ERR-SEM-LIFECYCLE-ILLEGAL` on the third event.\n",
    )


BUILDERS = [
    build_architecture_claim,
    build_contradictory_claim,
    build_revise_withdraw_flow,
    build_minimal_empty,
    build_unicode_normalization,
    build_multi_source_claim,
    build_duplicate_reaffirm_collision,
    build_withdraw_then_illegal_reaffirm,
]


def main() -> int:
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    for build in BUILDERS:
        build()
    print(f"generated {len(BUILDERS)} samples under {SAMPLES_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
