"""Version-strategy conformance tests (v0.3.0 spec: VERSIONING.md).

Covers the two independent semver axes:

* ``format_version`` — wire-shape MAJOR.MINOR (1.0 legacy, 1.1 current).
  Unknown MAJOR is rejected hard (``PX_E_3003``). Unknown MINOR within a
  known MAJOR is rejected in strict mode (``PX_E_3001``) and downgraded
  to a warning in lenient mode.
* ``dpkg_spec_version`` / ``exchange_profile_version`` — optional semver
  release labels. Non-semver values raise ``PX_E_3004``. Absence is fine.
"""

from __future__ import annotations

import copy

import pytest

from dpkg.errors import SchemaError
from dpkg.validator import (
    SEMVER_RE,
    SUPPORTED_SCHEMA_VERSIONS,
    validate_manifest,
)


BASE = {
    "claims": [],
    "created_at": "2026-04-21T00:00:00Z",
    "format_version": "1.1",
    "license": "CC0-1.0",
    "package_id": "01930000-0000-7000-8000-000000000001",
    "producer": "dpkg-test",
    "provenance_path": "provenance.jsonl",
}


@pytest.mark.parametrize("version", sorted(SUPPORTED_SCHEMA_VERSIONS))
def test_supported_schema_versions_accepted(version: str) -> None:
    m = copy.deepcopy(BASE)
    m["format_version"] = version
    validate_manifest(m)


def test_unknown_major_rejected() -> None:
    m = copy.deepcopy(BASE)
    m["format_version"] = "2.0"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code.value == "PX_E_3003"


def test_unknown_minor_on_known_major_rejected_as_3001() -> None:
    """Known MAJOR + unknown MINOR -> UNSUPPORTED_SCHEMA_VERSION (PX_E_3001)."""
    m = copy.deepcopy(BASE)
    m["format_version"] = "1.99"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code.value == "PX_E_3001"


def test_missing_dpkg_spec_version_accepted() -> None:
    """``dpkg_spec_version`` is optional — absence MUST NOT error."""
    m = copy.deepcopy(BASE)
    assert "dpkg_spec_version" not in m
    validate_manifest(m)


def test_present_dpkg_spec_version_accepted() -> None:
    m = copy.deepcopy(BASE)
    m["dpkg_spec_version"] = "1.1.0"
    validate_manifest(m)


def test_present_exchange_profile_version_accepted() -> None:
    m = copy.deepcopy(BASE)
    m["exchange_profile_version"] = "0.3.0"
    validate_manifest(m)


@pytest.mark.parametrize(
    "value",
    ["1", "1.0", "not-a-version", "1.2.3.4", "a.b.c", ""],
)
def test_non_semver_dpkg_spec_version_rejected(value: str) -> None:
    m = copy.deepcopy(BASE)
    m["dpkg_spec_version"] = value
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code.value == "PX_E_3004"


def test_non_semver_exchange_profile_version_rejected() -> None:
    m = copy.deepcopy(BASE)
    m["exchange_profile_version"] = "draft"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code.value == "PX_E_3004"


@pytest.mark.parametrize(
    "value",
    ["0.1.0", "1.0.0", "10.20.30", "1.0.0-alpha", "1.0.0-rc.1"],
)
def test_semver_accepts_prerelease_and_multidigit(value: str) -> None:
    assert SEMVER_RE.match(value), f"SEMVER_RE failed to match {value!r}"


# ---- --lenient / --strict mode ---------------------------------------------


def test_lenient_mode_downgrades_unknown_minor_to_warning() -> None:
    """Unknown MINOR on a known MAJOR becomes a warning in lenient mode."""
    from dpkg.validator import validate_package

    m = copy.deepcopy(BASE)
    m["format_version"] = "1.99"
    warnings = validate_package(m, [], mode="lenient")
    assert any("PX_E_3001" in w for w in warnings), warnings


def test_strict_mode_is_default() -> None:
    """Omitting ``mode`` behaves as ``strict``."""
    from dpkg.validator import validate_package

    m = copy.deepcopy(BASE)
    m["format_version"] = "1.99"
    with pytest.raises(SchemaError) as exc:
        validate_package(m, [])
    assert exc.value.code.value == "PX_E_3001"


def test_lenient_mode_still_rejects_unknown_major() -> None:
    """Unknown MAJOR is always fatal, even lenient."""
    from dpkg.validator import validate_package

    m = copy.deepcopy(BASE)
    m["format_version"] = "2.0"
    with pytest.raises(SchemaError) as exc:
        validate_package(m, [], mode="lenient")
    assert exc.value.code.value == "PX_E_3003"


def test_invalid_mode_raises_value_error() -> None:
    from dpkg.validator import validate_package

    with pytest.raises(ValueError):
        validate_package(copy.deepcopy(BASE), [], mode="bogus")
