"""Syntax-layer schema validator (hand-coded, stdlib-only).

Covers the strict subset of the published JSON schemas for:
  * manifest.json
  * provenance.jsonl (one event per call)

Does NOT perform semantic/cross-reference checks - those live in verifier.py.

All raised codes come from :class:`aphelion.error_codes.ErrorCode`.
"""

from __future__ import annotations

import re
from typing import Any

from aphelion import SCHEMA_VERSION_MAX
from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError


UUID_V7_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CLAIM_PATH_RE = re.compile(
    r"^claims/[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.md$"
)
LABEL_PATH_RE = re.compile(r"^[A-Za-z0-9_./-]+$")

MANIFEST_REQUIRED = {
    "claims",
    "created_at",
    "format_version",
    "license",
    "package_id",
    "producer",
    "provenance_path",
}
MANIFEST_ALLOWED = MANIFEST_REQUIRED | {
    "aphelion_spec_version",
    "exchange_profile_version",
    "extensions",
    "notice_path",
    "signature",
}

# v0.4.0 wire is format_version 2.0 only. v0.3 (1.0/1.1) packages are
# rejected; the migration path is `aphe migrate` (see aphelion.migrate).
SUPPORTED_SCHEMA_VERSIONS: set[str] = {"2.0"}

# Semver pattern used for aphelion_spec_version / exchange_profile_version.
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$")

CLAIM_ENTRY_REQUIRED = {"claim_id", "claim_instance_id", "hash", "path", "state"}
CLAIM_ENTRY_ALLOWED = CLAIM_ENTRY_REQUIRED | {
    "labels",
    "superseded_by_claim_id",
    "tags",
    "withdrawn_reason",
}
CLAIM_STATES = {"draft", "active", "superseded", "withdrawn"}

EVENT_REQUIRED = {"actor", "claim_id", "event_id", "event_type", "timestamp"}
EVENT_ALLOWED = EVENT_REQUIRED | {
    "claim_instance_id",
    "extensions",
    "prev_event_id",
    "reason",
    "superseded_by_claim_id",
    "target_claim_instance_id",
}
EVENT_TYPES = {"create", "publish", "reaffirm", "revise", "supersede", "withdraw"}
EVENT_REQUIRES_INSTANCE = {"create", "revise", "supersede"}
EVENT_FORBIDS_INSTANCE = {"reaffirm", "withdraw", "publish"}


def _check_type(name: str, value: Any, expected: type | tuple[type, ...]) -> None:
    if not isinstance(value, expected):
        exp = expected.__name__ if isinstance(expected, type) else str(expected)
        raise SchemaError(
            code=ErrorCode.TYPE_MISMATCH,
            msg=f"field {name!r} must be {exp}, got {type(value).__name__}",
        )


def _check_pattern(name: str, value: str, pattern: re.Pattern[str]) -> None:
    if not pattern.fullmatch(value):
        raise SchemaError(
            code=ErrorCode.PATTERN_MISMATCH,
            msg=f"field {name!r} does not match required pattern: {value!r}",
        )


def _check_allowed(name: str, keys: set[str], allowed: set[str]) -> None:
    extra = keys - allowed
    if extra:
        raise SchemaError(
            code=ErrorCode.EXTRA_FIELD,
            msg=f"{name}: unexpected fields {sorted(extra)!r}",
        )


def _check_enum(name: str, value: Any, allowed: set[str]) -> None:
    if value not in allowed:
        raise SchemaError(
            code=ErrorCode.ENUM_INVALID,
            msg=f"field {name!r} must be one of {sorted(allowed)}, got {value!r}",
        )


def _check_version(format_version: Any, mode: str = "strict",
                   warnings: list[str] | None = None) -> None:
    _check_type("format_version", format_version, str)
    if format_version in SUPPORTED_SCHEMA_VERSIONS:
        return
    major = format_version.split(".", 1)[0] if "." in format_version else format_version
    known_majors = {v.split(".", 1)[0] for v in SUPPORTED_SCHEMA_VERSIONS}
    if major in known_majors:
        # Unknown MINOR in a known MAJOR: strict rejects, lenient warns.
        msg = (
            f"format_version {format_version!r} has known MAJOR {major!r} but "
            f"unknown MINOR; supported: {sorted(SUPPORTED_SCHEMA_VERSIONS)}"
        )
        if mode == "lenient" and warnings is not None:
            warnings.append(f"[{ErrorCode.UNSUPPORTED_SCHEMA_VERSION.value}] {msg}")
            return
        raise SchemaError(code=ErrorCode.UNSUPPORTED_SCHEMA_VERSION, msg=msg)
    # Unknown MAJOR is always rejected.
    raise SchemaError(
        code=ErrorCode.VERSION_UNKNOWN_MAJOR,
        msg=(
            f"format_version {format_version!r} has unknown MAJOR; "
            f"supported: {sorted(SUPPORTED_SCHEMA_VERSIONS)}"
        ),
    )


def validate_manifest(obj: Any, mode: str = "strict",
                      warnings: list[str] | None = None) -> None:
    """Raise SchemaError if obj is not a valid manifest per the JSON schema.

    ``mode`` is ``"strict"`` (default) or ``"lenient"``. In lenient mode,
    unknown MINOR format_versions are downgraded from an error to an
    entry in ``warnings`` (required when lenient). Unknown MAJORs are
    always rejected.
    """
    _check_type("manifest", obj, dict)
    missing = MANIFEST_REQUIRED - obj.keys()
    if missing:
        raise SchemaError(
            code=ErrorCode.REQUIRED_FIELD_MISSING,
            msg=f"manifest missing required fields: {sorted(missing)!r}",
        )
    _check_allowed("manifest", set(obj.keys()), MANIFEST_ALLOWED)
    _check_version(obj["format_version"], mode=mode, warnings=warnings)
    _check_type("license", obj["license"], str)
    if not obj["license"]:
        raise SchemaError(code=ErrorCode.EMPTY_VALUE, msg="license must be non-empty")
    _check_type("producer", obj["producer"], str)
    if not obj["producer"]:
        raise SchemaError(code=ErrorCode.EMPTY_VALUE, msg="producer must be non-empty")
    _check_type("package_id", obj["package_id"], str)
    _check_pattern("package_id", obj["package_id"], UUID_V7_RE)
    _check_type("created_at", obj["created_at"], str)
    _check_pattern("created_at", obj["created_at"], TIMESTAMP_RE)
    _check_type("provenance_path", obj["provenance_path"], str)
    if obj["provenance_path"] != "provenance.jsonl":
        raise SchemaError(
            code=ErrorCode.CONST_MISMATCH,
            msg="provenance_path must be exactly 'provenance.jsonl'",
        )
    _check_type("claims", obj["claims"], list)
    seen_claim_ids: set[str] = set()
    for idx, entry in enumerate(obj["claims"]):
        path = f"claims[{idx}]"
        _validate_claim_entry(entry, path)
        claim_id = entry["claim_id"]
        if claim_id in seen_claim_ids:
            raise SchemaError(
                code=ErrorCode.DUPLICATE_CLAIM_ID,
                msg=f"duplicate claim_id {claim_id!r} at {path}",
            )
        seen_claim_ids.add(claim_id)
    if "notice_path" in obj:
        _check_type("notice_path", obj["notice_path"], str)
        _check_pattern("notice_path", obj["notice_path"], LABEL_PATH_RE)
    for semver_field in ("aphelion_spec_version", "exchange_profile_version"):
        if semver_field in obj:
            _check_type(semver_field, obj[semver_field], str)
            if not SEMVER_RE.match(obj[semver_field]):
                raise SchemaError(
                    code=ErrorCode.VERSION_NOT_SEMVER,
                    msg=f"{semver_field} must be semver X.Y.Z, got {obj[semver_field]!r}",
                )


def _validate_claim_entry(entry: Any, path: str) -> None:
    _check_type(path, entry, dict)
    missing = CLAIM_ENTRY_REQUIRED - entry.keys()
    if missing:
        raise SchemaError(
            code=ErrorCode.REQUIRED_FIELD_MISSING,
            msg=f"{path}: missing required fields {sorted(missing)!r}",
        )
    _check_allowed(path, set(entry.keys()), CLAIM_ENTRY_ALLOWED)
    _check_type(f"{path}.claim_id", entry["claim_id"], str)
    _check_pattern(f"{path}.claim_id", entry["claim_id"], UUID_V7_RE)
    _check_type(f"{path}.claim_instance_id", entry["claim_instance_id"], str)
    _check_pattern(f"{path}.claim_instance_id", entry["claim_instance_id"], UUID_V7_RE)
    _check_type(f"{path}.hash", entry["hash"], str)
    _check_pattern(f"{path}.hash", entry["hash"], SHA256_RE)
    _check_type(f"{path}.path", entry["path"], str)
    _check_pattern(f"{path}.path", entry["path"], CLAIM_PATH_RE)
    _check_enum(f"{path}.state", entry["state"], CLAIM_STATES)
    if entry["state"] == "superseded":
        if "superseded_by_claim_id" not in entry:
            raise SchemaError(
                code=ErrorCode.REQUIRED_FIELD_MISSING,
                msg=f"{path}: superseded state requires superseded_by_claim_id",
            )
    if "superseded_by_claim_id" in entry:
        _check_pattern(
            f"{path}.superseded_by_claim_id",
            entry["superseded_by_claim_id"],
            UUID_V7_RE,
        )
    if "tags" in entry:
        _check_type(f"{path}.tags", entry["tags"], list)
        seen: set[str] = set()
        for t in entry["tags"]:
            _check_type(f"{path}.tags[*]", t, str)
            if not t:
                raise SchemaError(code=ErrorCode.EMPTY_VALUE, msg=f"{path}: empty tag")
            if t in seen:
                raise SchemaError(
                    code=ErrorCode.DUPLICATE_TAG,
                    msg=f"{path}: duplicate tag {t!r}",
                )
            seen.add(t)


def validate_provenance_event(obj: Any) -> None:
    """Raise SchemaError if obj is not a valid provenance event."""
    _check_type("event", obj, dict)
    missing = EVENT_REQUIRED - obj.keys()
    if missing:
        raise SchemaError(
            code=ErrorCode.REQUIRED_FIELD_MISSING,
            msg=f"event missing required fields: {sorted(missing)!r}",
        )
    _check_allowed("event", set(obj.keys()), EVENT_ALLOWED)
    _check_type("actor", obj["actor"], str)
    if not obj["actor"]:
        raise SchemaError(code=ErrorCode.EMPTY_VALUE, msg="actor must be non-empty")
    _check_pattern("claim_id", obj["claim_id"], UUID_V7_RE)
    _check_pattern("event_id", obj["event_id"], UUID_V7_RE)
    _check_pattern("timestamp", obj["timestamp"], TIMESTAMP_RE)
    _check_enum("event_type", obj["event_type"], EVENT_TYPES)

    etype = obj["event_type"]
    if etype in EVENT_REQUIRES_INSTANCE and "claim_instance_id" not in obj:
        raise SchemaError(
            code=ErrorCode.REQUIRED_FIELD_MISSING,
            msg=f"event_type {etype!r} requires claim_instance_id",
        )
    if etype in EVENT_FORBIDS_INSTANCE and "claim_instance_id" in obj:
        raise SchemaError(
            code=ErrorCode.FORBIDDEN_FIELD,
            msg=f"event_type {etype!r} must not carry claim_instance_id",
        )
    if etype == "supersede" and "superseded_by_claim_id" not in obj:
        raise SchemaError(
            code=ErrorCode.REQUIRED_FIELD_MISSING,
            msg="supersede event requires superseded_by_claim_id",
        )
    if etype == "create":
        if "prev_event_id" in obj:
            raise SchemaError(
                code=ErrorCode.FORBIDDEN_FIELD,
                msg="create event must NOT carry prev_event_id",
            )
    else:
        if "prev_event_id" not in obj:
            raise SchemaError(
                code=ErrorCode.REQUIRED_FIELD_MISSING,
                msg=f"event_type {etype!r} requires prev_event_id",
            )
        _check_pattern("prev_event_id", obj["prev_event_id"], UUID_V7_RE)
    if "claim_instance_id" in obj:
        _check_pattern("claim_instance_id", obj["claim_instance_id"], UUID_V7_RE)
    if "superseded_by_claim_id" in obj:
        _check_pattern(
            "superseded_by_claim_id", obj["superseded_by_claim_id"], UUID_V7_RE
        )
    if "target_claim_instance_id" in obj:
        _check_pattern(
            "target_claim_instance_id", obj["target_claim_instance_id"], UUID_V7_RE
        )


def validate_package(manifest_obj: Any, events: list[Any],
                     mode: str = "strict") -> list[str]:
    """Top-level syntax validation: manifest + every provenance event.

    Runs in three passes: (1) manifest shape, (2) per-event shape,
    (3) lifecycle state-machine walk over all events grouped by claim_id.
    The lifecycle pass enforces the transition matrix in
    ``spec/lifecycle-state-machine.md`` and rejects sub-millisecond
    timestamps with ``PX_E_3005``.

    ``mode`` is ``"strict"`` (default) or ``"lenient"``. Lenient mode
    downgrades unknown-MINOR format_versions from errors to warnings;
    all other gates remain strict. Returns the collected warning list
    (empty in strict mode).
    """
    if mode not in {"strict", "lenient"}:
        raise ValueError(f"mode must be 'strict' or 'lenient', got {mode!r}")
    warnings: list[str] = []
    validate_manifest(manifest_obj, mode=mode, warnings=warnings)
    for idx, ev in enumerate(events):
        try:
            validate_provenance_event(ev)
        except SchemaError as e:
            e.path = f"provenance.jsonl:{idx + 1}"
            raise
    # Lifecycle walk — imported lazily so the shape-only validators above
    # stay available even if lifecycle.py is stripped in a minimal build.
    from aphelion.lifecycle import check_lifecycle

    check_lifecycle(events)
    return warnings
