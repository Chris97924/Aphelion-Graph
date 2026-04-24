"""Version-strategy conformance tests (v0.4.0 spec: VERSIONING.md).

Covers the two independent semver axes:

* ``format_version`` — wire-shape MAJOR.MINOR. v0.4 accepts only ``2.0``;
  any v0.3 legacy version (``1.0`` / ``1.1``) is rejected with
  ``PX_E_3003``. Unknown MINOR on the known MAJOR (``2.99``) is rejected
  in strict mode (``PX_E_3001``) and downgraded to a warning in lenient
  mode.
* ``aphelion_spec_version`` / ``exchange_profile_version`` — optional
  semver release labels. Non-semver values raise ``PX_E_3004``. Absence
  is fine.
"""

from __future__ import annotations

import copy

import pytest

from aphelion.errors import SchemaError
from aphelion.validator import (
    SEMVER_RE,
    SUPPORTED_SCHEMA_VERSIONS,
    validate_manifest,
)


BASE = {
    "aphelion_spec_version": "0.4.0",
    "claims": [],
    "created_at": "2026-04-21T00:00:00Z",
    "format_version": "2.0",
    "license": "CC0-1.0",
    "package_id": "01930000-0000-7000-8000-000000000001",
    "producer": "aphelion-test",
    "provenance_path": "provenance.jsonl",
}


@pytest.mark.parametrize("version", sorted(SUPPORTED_SCHEMA_VERSIONS))
def test_supported_schema_versions_accepted(version: str) -> None:
    m = copy.deepcopy(BASE)
    m["format_version"] = version
    validate_manifest(m)


def test_unknown_major_rejected() -> None:
    m = copy.deepcopy(BASE)
    m["format_version"] = "3.0"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code.value == "PX_E_3003"


def test_legacy_v03_major_rejected() -> None:
    """v0.3 wire (format_version 1.x) is a known-historic MAJOR, still rejected by v0.4.

    Downstream migration path: ``aphe migrate``.
    """
    m = copy.deepcopy(BASE)
    m["format_version"] = "1.1"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code.value == "PX_E_3003"


def test_unknown_minor_on_known_major_rejected_as_3001() -> None:
    """Known MAJOR + unknown MINOR -> UNSUPPORTED_SCHEMA_VERSION (PX_E_3001)."""
    m = copy.deepcopy(BASE)
    m["format_version"] = "2.99"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code.value == "PX_E_3001"


def test_missing_aphelion_spec_version_accepted() -> None:
    """``aphelion_spec_version`` is optional — absence MUST NOT error."""
    m = copy.deepcopy(BASE)
    del m["aphelion_spec_version"]
    assert "aphelion_spec_version" not in m
    validate_manifest(m)


def test_present_aphelion_spec_version_accepted() -> None:
    m = copy.deepcopy(BASE)
    m["aphelion_spec_version"] = "0.4.0"
    validate_manifest(m)


def test_present_exchange_profile_version_accepted() -> None:
    m = copy.deepcopy(BASE)
    m["exchange_profile_version"] = "0.4.0"
    validate_manifest(m)


@pytest.mark.parametrize(
    "value",
    ["1", "1.0", "not-a-version", "1.2.3.4", "a.b.c", ""],
)
def test_non_semver_aphelion_spec_version_rejected(value: str) -> None:
    m = copy.deepcopy(BASE)
    m["aphelion_spec_version"] = value
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code.value == "PX_E_3004"


def test_non_semver_exchange_profile_version_rejected() -> None:
    m = copy.deepcopy(BASE)
    m["exchange_profile_version"] = "draft"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code.value == "PX_E_3004"


def test_legacy_dpkg_spec_version_field_rejected_as_unknown() -> None:
    """The v0.3 ``dpkg_spec_version`` field is no longer in the allowed set.

    Writing it into a v0.4 manifest MUST fail as an unknown top-level field.
    """
    m = copy.deepcopy(BASE)
    m["dpkg_spec_version"] = "0.3.0"
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code.value == "PX_E_2002"


@pytest.mark.parametrize(
    "value",
    ["0.1.0", "1.0.0", "10.20.30", "1.0.0-alpha", "1.0.0-rc.1"],
)
def test_semver_accepts_prerelease_and_multidigit(value: str) -> None:
    assert SEMVER_RE.match(value), f"SEMVER_RE failed to match {value!r}"


# ---- --lenient / --strict mode ---------------------------------------------


def test_lenient_mode_downgrades_unknown_minor_to_warning() -> None:
    """Unknown MINOR on a known MAJOR becomes a warning in lenient mode."""
    from aphelion.validator import validate_package

    m = copy.deepcopy(BASE)
    m["format_version"] = "2.99"
    warnings = validate_package(m, [], mode="lenient")
    assert any("PX_E_3001" in w for w in warnings), warnings


def test_strict_mode_is_default() -> None:
    """Omitting ``mode`` behaves as ``strict``."""
    from aphelion.validator import validate_package

    m = copy.deepcopy(BASE)
    m["format_version"] = "2.99"
    with pytest.raises(SchemaError) as exc:
        validate_package(m, [])
    assert exc.value.code.value == "PX_E_3001"


def test_lenient_mode_still_rejects_unknown_major() -> None:
    """Unknown MAJOR is always fatal, even lenient."""
    from aphelion.validator import validate_package

    m = copy.deepcopy(BASE)
    m["format_version"] = "3.0"
    with pytest.raises(SchemaError) as exc:
        validate_package(m, [], mode="lenient")
    assert exc.value.code.value == "PX_E_3003"


def test_lenient_mode_still_rejects_legacy_v03() -> None:
    from aphelion.validator import validate_package

    m = copy.deepcopy(BASE)
    m["format_version"] = "1.1"
    with pytest.raises(SchemaError) as exc:
        validate_package(m, [], mode="lenient")
    assert exc.value.code.value == "PX_E_3003"


def test_invalid_mode_raises_value_error() -> None:
    from aphelion.validator import validate_package

    with pytest.raises(ValueError):
        validate_package(copy.deepcopy(BASE), [], mode="bogus")
