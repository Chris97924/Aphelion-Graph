"""Deterministic package corpus for the W-M5 two-implementation byte-equality gate.

The M5 gate (``preregister.json`` → ``option (a) W-M5``) asks whether two
*independent* implementations of ``spec/canonical-serialization.md`` produce
byte-identical archives from the same logical input. Answering that needs more
input variety than the eight committed ``samples/`` fixtures provide, so this
module generates a deterministic corpus that deliberately stresses the places
where two implementers are most likely to drift:

* JSON string escaping (quotes, backslashes, C0 control characters)
* raw (non-``\\uXXXX``) emission of non-ASCII, and NFD → NFC normalization
* object key ordering by Unicode codepoint, including keys around the
  ASCII letter range (``0`` ``A`` ``Z`` ``_`` ``a`` ``z`` ``~``)
* integer forms (zero, negative, values beyond 2**53)
* ``claims[].hash`` recomputation — some source manifests carry a
  well-formed-but-wrong digest, so an implementation that copies the input
  hash through instead of recomputing it diverges
* tar member ordering and 512-byte block padding — claim bodies are sized to
  land exactly on, one byte below, and one byte above block boundaries

Every source ``manifest.json`` is written **non-canonically** (two-space indent,
keys in deliberately non-alphabetical order). An implementation that echoes the
input bytes rather than re-serializing them cannot match.

Pure stdlib and free of any ``aphelion`` import, so the corpus itself takes no
side between the two implementations under comparison. Deterministic: no clock,
no randomness, no filesystem ordering dependence.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

# A well-formed SHA-256 that is not the digest of anything we write. Used to
# prove both implementations recompute ``claims[].hash`` from the claim bytes
# rather than trusting the manifest.
WRONG_BUT_WELL_FORMED_HASH = "0" * 64

_BASE_TS = "2026-04-21T00:00:0"


def _pkg_id(index: int) -> str:
    return f"0193{index:04x}-0000-7000-8000-000000000001"


def _claim_id(index: int, slot: int) -> str:
    return f"0193{index:04x}-0000-7000-8000-c1a1{slot:08x}"


def _instance_id(index: int, slot: int) -> str:
    return f"0193{index:04x}-0000-7000-8000-{slot:012x}"


def _event_id(index: int, slot: int) -> str:
    return f"0193{index:04x}-0000-7000-8000-eeee{slot:08x}"


def _ts(seconds: int, millis: int | None = None) -> str:
    stamp = f"2026-04-21T00:00:{seconds:02d}"
    return f"{stamp}.{millis:03d}Z" if millis is not None else f"{stamp}Z"


@dataclass
class _Package:
    """One source package under construction."""

    index: int
    name: str
    description: str
    claims: list[dict] = field(default_factory=list)
    claim_bodies: dict[str, bytes] = field(default_factory=dict)
    events: list[dict] = field(default_factory=list)
    manifest_extra: dict = field(default_factory=dict)
    notice: bytes | None = None

    def add_claim(
        self,
        slot: int,
        *,
        title: str = "Claim",
        body: str = "",
        pad_to: int | None = None,
        state: str = "active",
        entry_extra: dict | None = None,
        hash_override: str | None = None,
        with_create_event: bool = True,
    ) -> str:
        claim_id = _claim_id(self.index, slot)
        instance_id = _instance_id(self.index, slot)
        blob = _claim_bytes(claim_id, instance_id, title, body, pad_to)
        path = f"claims/{claim_id}.md"
        self.claim_bodies[path] = blob
        entry = {
            "state": state,
            "path": path,
            "claim_id": claim_id,
            "hash": hash_override or hashlib.sha256(blob).hexdigest(),
            "claim_instance_id": instance_id,
        }
        if entry_extra:
            entry.update(entry_extra)
        self.claims.append(entry)
        if with_create_event:
            self.add_event(
                slot,
                "create",
                claim_id,
                claim_instance_id=instance_id,
                seconds=slot,
            )
        return claim_id

    def add_event(
        self,
        slot: int,
        event_type: str,
        claim_id: str,
        *,
        seconds: int = 0,
        millis: int | None = None,
        actor: str = "corpus",
        **extra: object,
    ) -> str:
        event_id = _event_id(self.index, slot)
        # Deliberately non-alphabetical insertion order — the canonical form
        # must sort these regardless of how they arrived.
        event: dict = {
            "timestamp": _ts(seconds, millis),
            "event_type": event_type,
            "actor": actor,
            "event_id": event_id,
            "claim_id": claim_id,
        }
        event.update({k: v for k, v in extra.items() if v is not None})
        self.events.append(event)
        return event_id

    def manifest(self) -> dict:
        # Non-alphabetical insertion order on purpose (see module docstring).
        manifest: dict = {
            "producer": "aphelion-w-m5-corpus",
            "format_version": "2.0",
            "claims": self.claims,
            "provenance_path": "provenance.jsonl",
            "package_id": _pkg_id(self.index),
            "license": "Apache-2.0",
            "created_at": "2026-04-21T00:00:00Z",
            "aphelion_spec_version": "0.4.0",
        }
        manifest.update(self.manifest_extra)
        return manifest

    def write(self, root: Path) -> Path:
        dest = root / self.name
        dest.mkdir(parents=True, exist_ok=True)
        for path, blob in self.claim_bodies.items():
            target = dest / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob)
        # Pretty-printed and unsorted: forces real re-serialization.
        raw = json.dumps(self.manifest(), ensure_ascii=False, indent=2)
        (dest / "manifest.json").write_bytes(raw.encode("utf-8") + b"\n")
        lines = b"".join(
            json.dumps(event, ensure_ascii=False, separators=(", ", ": ")).encode("utf-8")
            + b"\n"
            for event in self.events
        )
        (dest / "provenance.jsonl").write_bytes(lines)
        if self.notice is not None:
            (dest / "NOTICE").write_bytes(self.notice)
        return dest


def _claim_bytes(
    claim_id: str,
    instance_id: str,
    title: str,
    body: str,
    pad_to: int | None,
) -> bytes:
    document = (
        "---\n"
        f'"claim_id": "{claim_id}"\n'
        f'"claim_instance_id": "{instance_id}"\n'
        f'"title": "{title}"\n'
        "---\n"
        f"{body}\n"
    )
    blob = document.encode("utf-8")
    if pad_to is None:
        return blob
    if len(blob) > pad_to:
        raise ValueError(f"claim already exceeds pad_to={pad_to}: {len(blob)}")
    # Pad with ASCII so the byte count is exact, keeping the terminating LF.
    return blob[:-1] + b"." * (pad_to - len(blob)) + b"\n"


# --------------------------------------------------------------------------- #
# The corpus                                                                   #
# --------------------------------------------------------------------------- #

_NFD_CAFE = unicodedata.normalize("NFD", "café")
_CONTROL_SOUP = "tab\tnl\ncr\rbs\bff\fnul\x00soh\x01us\x1fdel\x7f"


def _builders() -> list[_Package]:
    packages: list[_Package] = []

    def new(name: str, description: str) -> _Package:
        pkg = _Package(index=len(packages) + 1, name=name, description=description)
        packages.append(pkg)
        return pkg

    # 1 — the zero-claim edge: empty claims array, empty provenance file.
    new("empty-package", "zero claims, zero events, empty provenance member")

    # 2 — the baseline single claim.
    new("single-claim", "one claim, one create event").add_claim(1)

    # 3 — three claims: member ordering across several claim ids.
    pkg = new("three-claims", "three claims exercise tar member ordering")
    for slot in (3, 1, 2):  # inserted out of order on purpose
        pkg.add_claim(slot)

    # 4 — ten claims: heavier ordering + multi-block archive.
    pkg = new("ten-claims", "ten claims stress member sort and archive length")
    for slot in range(10, 0, -1):
        pkg.add_claim(slot)

    # 5 — non-ASCII must be emitted raw, never \uXXXX escaped.
    pkg = new("unicode-raw", "non-ASCII emitted raw per Rule 1 §4")
    pkg.manifest_extra["extensions"] = {
        "chinese": "中文字元",
        "emoji": "🎉🚀",
        "accents": "café naïve Åström",
        "cjk-ext": "𠀋𠮟",
    }
    pkg.add_claim(1, title="Unicode café 中文 🎉")

    # 6 — NFD input must normalize to NFC before sorting and hashing.
    pkg = new("nfd-normalization", "NFD source normalizes to NFC per Rule 2")
    pkg.manifest_extra["extensions"] = {
        "nfd-value": _NFD_CAFE,
        unicodedata.normalize("NFD", "clé"): "nfd-key",
    }
    pkg.add_claim(1, title="NFD in the manifest, not the claim body")

    # 7 — every C0 escape branch plus DEL (which is NOT escaped).
    pkg = new("control-characters", "C0 escapes: \\b \\f \\n \\r \\t and \\u00XX")
    pkg.manifest_extra["extensions"] = {"soup": _CONTROL_SOUP}
    pkg.add_claim(1)

    # 8 — the two characters JSON must escape structurally.
    pkg = new("quotes-and-backslashes", 'literal " and \\ and / in string values')
    pkg.manifest_extra["extensions"] = {
        "quote": 'he said "hi"',
        "backslash": "C:\\\\Users\\\\path",
        "solidus": "a/b/c",
        "mixed": '"\\/\t"',
    }
    pkg.add_claim(1)

    # 9 — key ordering around the ASCII letter block.
    pkg = new("key-sort-order", "keys sorted by codepoint, not case-folded")
    pkg.manifest_extra["extensions"] = {
        "~tilde": 7,
        "_under": 6,
        "Zebra": 2,
        "apple": 3,
        "0digit": 1,
        "zulu": 5,
        "Apple": 4,
    }
    pkg.add_claim(1)

    # 10 — nested containers: recursion through objects and arrays.
    pkg = new("nested-extensions", "recursive key sorting through nested containers")
    pkg.manifest_extra["extensions"] = {
        "outer": {
            "z": {"inner-z": [1, 2, {"deep-b": "x", "deep-a": "y"}]},
            "a": [[], {}, [{"k": "v"}]],
        },
        "list-of-objects": [{"b": 1, "a": 2}, {"d": 3, "c": 4}],
    }
    pkg.add_claim(1)

    # 11 — integer forms. Floats are forbidden outright by Rule 1 §5.
    pkg = new("integer-forms", "zero, negative, and beyond-2**53 integers")
    pkg.manifest_extra["extensions"] = {
        "zero": 0,
        "negative": -42,
        "big": 9007199254740993,
        "huge": 2**70,
        "small": -(2**70),
    }
    pkg.add_claim(1)

    # 12 — the three JSON literals.
    pkg = new("literals", "true / false / null round-trip")
    pkg.manifest_extra["extensions"] = {
        "yes": True,
        "no": False,
        "nothing": None,
        "nested": {"t": True, "f": False, "n": None},
    }
    pkg.add_claim(1)

    # 13 — the optional NOTICE member, which sorts before "claims/".
    pkg = new("notice-member", "NOTICE member sorts ahead of claims/ (N < c)")
    pkg.manifest_extra["notice_path"] = "NOTICE"
    pkg.notice = "Portions © 2026 Aphelion Contributors.\n".encode("utf-8")
    pkg.add_claim(1)

    # 14 — optional claim-entry fields.
    pkg = new("claim-entry-options", "tags and labels on a claim entry")
    pkg.add_claim(
        1,
        entry_extra={
            "tags": ["zeta", "alpha", "middle"],
            "labels": {"team": "core", "area": "serialization"},
        },
    )

    # 15 — hash recomputation: source manifest carries a wrong digest.
    pkg = new("wrong-source-hash", "manifest hash must be recomputed, not trusted")
    pkg.add_claim(1, hash_override=WRONG_BUT_WELL_FORMED_HASH)

    # 16 — wrong digests on several claims at once.
    pkg = new("wrong-source-hash-multi", "every claim digest recomputed")
    for slot in (1, 2, 3):
        pkg.add_claim(slot, hash_override=WRONG_BUT_WELL_FORMED_HASH)

    # 17-20 — claim bodies sized around the 512-byte tar block boundary.
    for pad in (511, 512, 513, 1024):
        pkg = new(f"block-boundary-{pad}", f"claim file is exactly {pad} bytes")
        pkg.add_claim(1, pad_to=pad)

    # 21 — a claim file of exactly zero payload beyond the frontmatter.
    pkg = new("empty-claim-body", "claim body is a single LF")
    pkg.add_claim(1, body="")

    # 22 — create → reaffirm → reaffirm.
    pkg = new("reaffirm-chain", "create then two reaffirms keep one instance")
    claim = pkg.add_claim(1)
    instance = _instance_id(pkg.index, 1)
    first = pkg.add_event(
        2,
        "reaffirm",
        claim,
        seconds=2,
        actor="reviewer-one",
        prev_event_id=_event_id(pkg.index, 1),
        target_claim_instance_id=instance,
    )
    pkg.add_event(
        3,
        "reaffirm",
        claim,
        seconds=3,
        actor="reviewer-two",
        prev_event_id=first,
        target_claim_instance_id=instance,
    )

    # 23 — create → revise (allocates a second instance).
    pkg = new("revise-chain", "revise allocates a new claim_instance_id")
    claim = pkg.add_claim(1)
    pkg.add_event(
        2,
        "revise",
        claim,
        seconds=2,
        claim_instance_id=_instance_id(pkg.index, 20),
        prev_event_id=_event_id(pkg.index, 1),
        target_claim_instance_id=_instance_id(pkg.index, 1),
    )

    # 24 — create → withdraw, with the terminal state on the claim entry.
    pkg = new("withdraw-flow", "withdraw is terminal; entry state matches")
    claim = pkg.add_claim(
        1,
        state="withdrawn",
        entry_extra={"withdrawn_reason": "retracted by author"},
    )
    pkg.add_event(
        2,
        "withdraw",
        claim,
        seconds=2,
        prev_event_id=_event_id(pkg.index, 1),
        target_claim_instance_id=_instance_id(pkg.index, 1),
    )

    # 25 — supersede: two claims, one pointing at the other.
    pkg = new("supersede-flow", "supersede sets state and superseded_by_claim_id")
    successor = pkg.add_claim(2)
    predecessor = pkg.add_claim(
        1,
        state="superseded",
        entry_extra={"superseded_by_claim_id": successor},
    )
    pkg.add_event(
        3,
        "supersede",
        predecessor,
        seconds=3,
        claim_instance_id=_instance_id(pkg.index, 30),
        prev_event_id=_event_id(pkg.index, 1),
        superseded_by_claim_id=successor,
        target_claim_instance_id=_instance_id(pkg.index, 1),
    )

    # 26 — millisecond timestamps (Rule 4 §3).
    pkg = new("millisecond-timestamps", "3-digit fractional seconds per Rule 4")
    claim = pkg.add_claim(1, with_create_event=False)
    pkg.add_event(
        1,
        "create",
        claim,
        seconds=0,
        millis=250,
        claim_instance_id=_instance_id(pkg.index, 1),
    )
    pkg.add_event(
        2,
        "reaffirm",
        claim,
        seconds=0,
        millis=750,
        prev_event_id=_event_id(pkg.index, 1),
        target_claim_instance_id=_instance_id(pkg.index, 1),
    )

    # 27 — many events across many claims.
    pkg = new("many-events", "twelve events across four claims")
    for slot in (1, 2, 3, 4):
        claim = pkg.add_claim(slot)
        pkg.add_event(
            10 + slot,
            "reaffirm",
            claim,
            seconds=10 + slot,
            prev_event_id=_event_id(pkg.index, slot),
            target_claim_instance_id=_instance_id(pkg.index, slot),
        )
        pkg.add_event(
            20 + slot,
            "reaffirm",
            claim,
            seconds=20 + slot,
            actor="second-" + _NFD_CAFE,
            prev_event_id=_event_id(pkg.index, 10 + slot),
            target_claim_instance_id=_instance_id(pkg.index, slot),
        )

    # 28 — event-level extensions plus a reason string.
    pkg = new("event-extensions", "extensions and reason on a provenance event")
    claim = pkg.add_claim(1)
    pkg.add_event(
        2,
        "reaffirm",
        claim,
        seconds=2,
        reason="re-confirmed after review — 審查通過",
        extensions={"confidence-note": "high", "nested": {"b": 2, "a": 1}},
        prev_event_id=_event_id(pkg.index, 1),
        target_claim_instance_id=_instance_id(pkg.index, 1),
    )

    # 29 — non-ASCII in a required top-level manifest field.
    pkg = new("unicode-producer", "non-ASCII in a required manifest string")
    pkg.manifest_extra["producer"] = "aphelion-產生器-café"
    pkg.manifest_extra["license"] = "Apache-2.0"
    pkg.add_claim(1)

    # 30 — every optional manifest field at once.
    pkg = new("all-manifest-options", "notice_path, extensions and both semvers")
    pkg.manifest_extra.update(
        {
            "notice_path": "NOTICE",
            "exchange_profile_version": "1.2.3",
            "aphelion_spec_version": "0.4.0",
            "extensions": {"vendor": {"z": 1, "a": [True, None, -1]}},
        }
    )
    pkg.notice = "NOTICE with non-ASCII: café 中文\n".encode("utf-8")
    pkg.add_claim(1, entry_extra={"tags": ["b", "a"]})

    return packages


@dataclass(frozen=True)
class CorpusPackage:
    """A materialized corpus package."""

    name: str
    description: str
    path: Path


def build_corpus(root: Path) -> list[CorpusPackage]:
    """Materialize the corpus under ``root`` and return one entry per package.

    Deterministic: the same ``root`` contents result from every invocation.
    """
    root.mkdir(parents=True, exist_ok=True)
    out: list[CorpusPackage] = []
    for package in _builders():
        path = package.write(root)
        out.append(
            CorpusPackage(
                name=package.name,
                description=package.description,
                path=path,
            )
        )
    return out


CORPUS_SIZE = len(_builders())
