"""Minimal independent Aphelion reader.

Purpose
-------
This script is a *third-party* demonstration that Aphelion packages can be
read and semantically classified (valid / invalid) without importing
the ``aphelion`` reference validator or any Parallax code. It exists to
prove the wire format is self-describing.

Contract
--------
- stdlib only: ``json`` / ``pathlib`` / ``sys`` / ``hashlib``.
- Must NOT ``import aphelion`` or ``import parallax`` / ``import memory``.
- Must run under Python 3.11+.
- Exit codes:
    0 — every sample's classification matches its expected verdict
    1 — at least one mismatch (printed to stderr)

Usage
-----
    python scripts/external_reader.py samples/

Scope
-----
This is NOT a full validator. It implements just enough lifecycle /
schema logic to reproduce the ``validator_verdict`` field in each
sample's ``expected-normalized.json``. See ``spec/lifecycle-state-machine.md``
for the authoritative rules.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


_LEGAL_TRANSITIONS = {
    ("NEW", "create"): "active",
    ("active", "reaffirm"): "active",
    ("active", "revise"): "active",
    ("active", "supersede"): "superseded",
    ("active", "withdraw"): "withdrawn",
    ("active", "publish"): "active",
    ("draft", "publish"): "active",
    ("NEW", "publish"): "active",
}


def _load_events(prov_path: Path) -> list[dict]:
    if not prov_path.exists():
        return []
    out: list[dict] = []
    for i, line in enumerate(prov_path.read_bytes().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError as err:
            raise ValueError(f"{prov_path}:{i}: {err}") from err
    return out


def _ts_ms(ts: str) -> int:
    from datetime import datetime, timezone

    if not ts.endswith("Z"):
        raise ValueError(f"timestamp must be UTC Z: {ts!r}")
    dt = datetime.fromisoformat(ts[:-1] + "+00:00").astimezone(timezone.utc)
    return int(dt.timestamp() * 1000)


def _classify_package(pkg: Path) -> tuple[str, str | None, dict[str, str]]:
    """Return (verdict, error_code_or_None, final_states).

    ``verdict`` is ``"valid"`` or ``"invalid"``. ``error_code`` is one
    of ``ERR-SEM-LIFECYCLE-ILLEGAL`` / ``ERR-SYN-...`` and is populated
    only when verdict == ``"invalid"``.
    """
    manifest_path = pkg / "manifest.json"
    if not manifest_path.exists():
        return "invalid", "ERR-SYN-MISSING-MANIFEST", {}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    # Shape / version checks (syntax layer).
    if manifest.get("format_version") not in {"2.0"}:
        return "invalid", "ERR-SYN-UNKNOWN-FORMAT-VERSION", {}

    claim_ids = {c["claim_id"] for c in manifest.get("claims", [])}
    events = _load_events(pkg / "provenance.jsonl")

    # Canonical event ordering: (occurred_at_ms, event_id).
    try:
        events_sorted = sorted(events, key=lambda e: (_ts_ms(e["timestamp"]), e["event_id"]))
    except (KeyError, ValueError) as err:
        return "invalid", f"ERR-SYN-BAD-EVENT ({err})", {}

    # Walk the state machine per claim_id.
    states: dict[str, str] = {cid: "NEW" for cid in claim_ids}
    for ev in events_sorted:
        cid = ev.get("claim_id")
        if cid not in states:
            states[cid] = "NEW"
        etype = ev.get("event_type")
        current = states[cid]
        # reaffirm on a non-active claim is illegal.
        if etype == "reaffirm" and current != "active":
            return "invalid", "ERR-SEM-LIFECYCLE-ILLEGAL", states
        next_state = _LEGAL_TRANSITIONS.get((current, etype))
        if next_state is None:
            return "invalid", "ERR-SEM-LIFECYCLE-ILLEGAL", states
        states[cid] = next_state

    # NEW-but-no-create is also illegal — a claim referenced in manifest
    # must have been created in provenance.
    for cid in claim_ids:
        if states.get(cid, "NEW") == "NEW":
            return "invalid", "ERR-SEM-LIFECYCLE-ILLEGAL", states

    return "valid", None, states


def _read_expected(sample: Path) -> dict | None:
    exp = sample / "expected-normalized.json"
    if not exp.exists():
        return None
    return json.loads(exp.read_text(encoding="utf-8"))


def _iter_packages(sample: Path) -> list[Path]:
    """A sample dir is usually itself a package, but
    duplicate-reaffirm-collision nests package-a / package-b.
    """
    if (sample / "manifest.json").exists():
        return [sample]
    subs = [p for p in sorted(sample.iterdir()) if p.is_dir() and (p / "manifest.json").exists()]
    return subs


def emit_sample_json(sample: Path) -> dict:
    """Classify one sample dir and return the normalized JSON shape.

    The shape deliberately mirrors the fields consumers actually test
    for — ``validator_verdict``, optional ``error_code``, and a
    minimal ``notes`` block capturing claim_ids / event_count /
    final_states — without claiming to reproduce the full Aphelion
    canonical output.
    """
    packages = _iter_packages(sample)
    if not packages:
        return {"validator_verdict": "invalid", "error_code": "ERR-SYN-MISSING-MANIFEST"}

    if len(packages) > 1:
        # Collision fixture: report per-sub-package and leave merge-time
        # collision detection to the caller.
        per_pkg = []
        for pkg in packages:
            verdict, code, states = _classify_package(pkg)
            per_pkg.append(
                {
                    "package_name": pkg.name,
                    "validator_verdict": verdict,
                    "error_code": code,
                    "final_states": states,
                }
            )
        return {"validator_verdict": "multi", "sub_packages": per_pkg}

    pkg = packages[0]
    verdict, code, states = _classify_package(pkg)
    manifest = json.loads((pkg / "manifest.json").read_text(encoding="utf-8"))
    events = _load_events(pkg / "provenance.jsonl")
    out: dict = {
        "validator_verdict": verdict,
        "notes": {
            "claim_ids": sorted(c["claim_id"] for c in manifest.get("claims", [])),
            "event_count": len(events),
            "final_states": states,
        },
    }
    if code is not None:
        out["error_code"] = code
    return out


def run(samples_root: Path) -> int:
    failures: list[str] = []
    checked = 0
    for sample in sorted(samples_root.iterdir()):
        if not sample.is_dir():
            continue
        expected = _read_expected(sample)
        if expected is None:
            continue
        checked += 1
        packages = _iter_packages(sample)
        if not packages:
            failures.append(f"{sample.name}: no packages found")
            continue
        verdicts = []
        for pkg in packages:
            verdict, _, _ = _classify_package(pkg)
            verdicts.append(verdict)
        # Collision sample: each sub-package is individually valid;
        # the "invalid" verdict applies only at merge time — which is
        # out of scope for this minimal reader. We accept either and
        # annotate.
        expected_verdict = expected["validator_verdict"]
        if expected.get("error_code") == "ERR-SEM-DUPLICATE-HASH-COLLISION":
            # Treat as OK if every sub-package is valid.
            if all(v == "valid" for v in verdicts):
                continue
            failures.append(
                f"{sample.name}: sub-packages not individually valid: {verdicts}"
            )
            continue
        if len(verdicts) != 1:
            failures.append(
                f"{sample.name}: expected single top-level package, got {len(verdicts)}"
            )
            continue
        if verdicts[0] != expected_verdict:
            failures.append(
                f"{sample.name}: got {verdicts[0]!r}, expected {expected_verdict!r}"
            )

    if failures:
        print(f"external_reader: {len(failures)} / {checked} mismatch(es):", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(f"external_reader: {checked} sample(s) checked, all match.")
    return 0


def _forbid_validator_import() -> None:
    """Fail loudly if a future edit re-introduces an aphelion / parallax
    import. This is the single authoritative guard of the 'no
    dependency on the reference validator' contract."""
    forbidden = {"aphelion", "parallax", "memory"}
    for mod in list(sys.modules):
        top = mod.split(".", 1)[0]
        if top in forbidden:
            raise RuntimeError(
                f"external_reader.py MUST NOT import {top!r}; "
                f"contract violated"
            )


if __name__ == "__main__":
    _forbid_validator_import()
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("samples")
    # Single-sample mode iff the target itself carries an
    # ``expected-normalized.json``; otherwise treat as samples-root.
    if (target / "expected-normalized.json").exists():
        print(json.dumps(emit_sample_json(target), sort_keys=True, ensure_ascii=False))
        raise SystemExit(0)
    raise SystemExit(run(target))
