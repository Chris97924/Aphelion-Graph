"""Property-based tests (hypothesis) — hardens the validate + verify layer.

These complement fixture-driven golden tests by exercising the code against
randomised inputs, catching corner cases that hand-written fixtures miss.
"""

from __future__ import annotations

import copy

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from dpkg.canonical_json import dumps, loads, normalize
from dpkg.error_codes import ErrorCode
from dpkg.errors import SchemaError
from dpkg.initializer import InitOptions, init_skeleton
from dpkg.validator import UUID_V7_RE, validate_manifest


UUID = "0191aaaa-0000-7000-8000-00000000aaaa"
UUID_INST = "0191aaaa-0000-7000-8000-aaaaaaaaaaaa"
UUID_PKG = "0191aaaa-0000-7000-8000-000000000001"
HASH64 = "a" * 64


BASE_MANIFEST = {
    "claims": [
        {
            "claim_id": UUID,
            "claim_instance_id": UUID_INST,
            "hash": HASH64,
            "path": f"claims/{UUID}.md",
            "state": "active",
        }
    ],
    "created_at": "2026-04-21T00:00:00Z",
    "format_version": "1.0",
    "license": "Apache-2.0",
    "package_id": UUID_PKG,
    "producer": "dpkg-test",
    "provenance_path": "provenance.jsonl",
}


# ---------- Strategy helpers ----------

# JSON-safe value strategy (no floats, no NaN, only canonical-allowed types).
_primitives = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=20),
)
_json_values = st.recursive(
    _primitives,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(
            keys=st.text(
                alphabet=st.characters(
                    blacklist_categories=("Cs",),
                    blacklist_characters=("\x00",),
                ),
                min_size=1,
                max_size=8,
            ),
            values=children,
            max_size=4,
        ),
    ),
    max_leaves=10,
)


# ---------- Property 1: canonical-JSON round-trip ----------


@given(obj=_json_values)
@settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
def test_prop_canonical_json_roundtrip(obj: object) -> None:
    """``loads(dumps(normalize(x)))`` must equal ``normalize(x)`` for every JSON-safe x."""
    try:
        normalized = normalize(obj)
    except SchemaError:
        # Hypothesis can generate NFC-colliding keys; skip those.
        return
    serialized = dumps(normalized)
    parsed = loads(serialized)
    assert parsed == normalized


# ---------- Property 2: validator rejects any random extra top-level field ----------


_field_name = st.text(
    alphabet=st.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters=("_",),
    ),
    min_size=1,
    max_size=16,
).filter(
    lambda s: s
    not in {
        "claims",
        "created_at",
        "format_version",
        "license",
        "package_id",
        "producer",
        "provenance_path",
        "extensions",
        "notice_path",
        "signature",
    }
)


@given(key=_field_name, value=_primitives)
@settings(max_examples=50)
def test_prop_unknown_manifest_field_rejected(key: str, value: object) -> None:
    """Any unknown top-level manifest key must produce PX_E_2002 (EXTRA_FIELD)."""
    m = copy.deepcopy(BASE_MANIFEST)
    m[key] = value
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    assert exc.value.code == ErrorCode.EXTRA_FIELD


# ---------- Property 3: non-UUID strings always fail pattern check ----------


_bad_uuid = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)),
    min_size=0,
    max_size=40,
).filter(
    # Exclude any string that satisfies the full UUID v7 pattern — those are
    # valid inputs, not counter-examples. Cheap pre-filter by length before
    # the regex call.
    lambda s: not (len(s) == 36 and UUID_V7_RE.fullmatch(s))
)


@given(bad=_bad_uuid)
@settings(max_examples=100)
def test_prop_non_uuid_claim_id_rejected(bad: str) -> None:
    m = copy.deepcopy(BASE_MANIFEST)
    m["claims"][0]["claim_id"] = bad
    with pytest.raises(SchemaError) as exc:
        validate_manifest(m)
    # Either pattern mismatch on the claim_id itself, or type mismatch if str
    # validation inverted on specific inputs — both are acceptable rejections.
    assert exc.value.code in (
        ErrorCode.PATTERN_MISMATCH,
        ErrorCode.TYPE_MISMATCH,
        ErrorCode.EMPTY_VALUE,
    )


# ---------- Property 4: init is idempotent under fixed overrides ----------


@given(
    pkg_id=st.just(UUID_PKG),
    created=st.just("2026-04-21T00:00:00Z"),
    producer=st.text(
        alphabet=st.characters(
            whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters=("-",)
        ),
        min_size=1,
        max_size=16,
    ),
)
@settings(max_examples=20, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_prop_init_deterministic(
    tmp_path_factory: pytest.TempPathFactory,
    pkg_id: str,
    created: str,
    producer: str,
) -> None:
    """Running ``init`` twice with the same overrides must produce byte-identical output."""
    a = tmp_path_factory.mktemp("a")
    b = tmp_path_factory.mktemp("b")
    opts = dict(package_id=pkg_id, created_at=created, producer=producer)
    init_skeleton(InitOptions(dest=a, **opts))
    init_skeleton(InitOptions(dest=b, **opts))
    assert (a / "manifest.json").read_bytes() == (b / "manifest.json").read_bytes()
    assert (a / "provenance.jsonl").read_bytes() == (b / "provenance.jsonl").read_bytes()
