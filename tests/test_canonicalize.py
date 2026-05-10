"""Tests for aphelion.canonicalize and aphelion.yaml_canonical.

Spec ground truth: spec/v0.3-claim-semantics.md §9.1.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aphelion.canonicalize import (
    canonicalize_data,
    canonicalize_path,
    canonicalize_text,
)
from aphelion.error_codes import ErrorCode
from aphelion.errors import SchemaError
from aphelion.yaml_canonical import (
    emit_frontmatter,
    parse_frontmatter,
    split_frontmatter,
)


CLAIM_ID = "0193e2b1-0001-7000-8000-000000000001"
INSTANCE_ID = "0193e2b1-0001-7000-8000-000000000002"


def _doc(yaml_body: str, body: str = "Body text.\n") -> str:
    return f"---\n{yaml_body}---\n{body}"


# ---- yaml_canonical ----------------------------------------------------------

@pytest.mark.unit
class TestYamlCanonical:
    def test_parse_simple_mapping(self) -> None:
        text = 'a: "x"\nb: 1\nc: 1.5\nd: true\ne: null\n'
        data, order = parse_frontmatter(text)
        assert data == {"a": "x", "b": 1, "c": 1.5, "d": True, "e": None}
        assert order == ["a", "b", "c", "d", "e"]

    def test_parse_block_sequence(self) -> None:
        text = 'tags:\n  - "parallax"\n  - "preference"\n'
        data, _order = parse_frontmatter(text)
        assert data == {"tags": ["parallax", "preference"]}

    def test_parse_block_mapping_one_level(self) -> None:
        text = 'labels:\n  priority: "high"\n  scope: "global"\n'
        data, _order = parse_frontmatter(text)
        assert data == {"labels": {"priority": "high", "scope": "global"}}

    def test_parse_rejects_duplicate_key(self) -> None:
        with pytest.raises(SchemaError) as exc:
            parse_frontmatter('a: 1\na: 2\n')
        assert exc.value.code == ErrorCode.PARSE_ERROR

    def test_parse_rejects_unexpected_line(self) -> None:
        with pytest.raises(SchemaError) as exc:
            parse_frontmatter('not_a_kv_line\n')
        assert exc.value.code == ErrorCode.PARSE_ERROR

    def test_emit_round_trip(self) -> None:
        original = {"alpha": "x", "beta": [1, 2, 3]}
        emitted = emit_frontmatter(original)
        reparsed, _ = parse_frontmatter(emitted)
        assert reparsed == original

    def test_split_frontmatter_separates_yaml_and_body(self) -> None:
        doc = '---\na: 1\n---\nbody line\n'
        yaml, body = split_frontmatter(doc)
        assert yaml == "a: 1\n"
        assert body == "body line\n"

    def test_split_rejects_no_opening_fence(self) -> None:
        with pytest.raises(SchemaError) as exc:
            split_frontmatter("a: 1\n")
        assert exc.value.code == ErrorCode.PARSE_ERROR

    def test_split_rejects_no_closing_fence(self) -> None:
        with pytest.raises(SchemaError) as exc:
            split_frontmatter("---\na: 1\nbody\n")
        assert exc.value.code == ErrorCode.PARSE_ERROR


# ---- canonicalize_data (pure transform) --------------------------------------

@pytest.mark.unit
class TestCanonicalizeData:
    def test_keys_sorted_ascii_ascending(self) -> None:
        out = canonicalize_data({"zeta": 1, "alpha": 2, "mu": 3})
        assert list(out.keys()) == ["alpha", "mu", "zeta"]

    def test_supersedes_sorted_and_deduplicated(self) -> None:
        out = canonicalize_data({"supersedes": ["b", "a", "a", "c"]})
        assert out["supersedes"] == ["a", "b", "c"]

    def test_confidence_rounded_to_3dp(self) -> None:
        out = canonicalize_data({"confidence": 0.85123456})
        # Float value rounded; emitter strings the exact 3dp form.
        assert out["confidence"] == pytest.approx(0.851)

    def test_supersedes_with_non_string_passes_through_for_validator(self) -> None:
        # Validator catches type errors — canonicalize doesn't fix them.
        out = canonicalize_data({"supersedes": [1, 2]})
        assert out["supersedes"] == [1, 2]


# ---- canonicalize_text (full pipeline) ---------------------------------------

@pytest.mark.unit
class TestCanonicalizeText:
    def _full_yaml(self) -> str:
        # Intentionally unsorted, with 2dp confidence and unsorted+dup
        # supersedes.
        return (
            'type: "user_preference"\n'
            f'claim_id: "{CLAIM_ID}"\n'
            'subject: "chris"\n'
            'confidence: 0.85\n'
            'polarity: "affirm"\n'
            'created_at: "2026-05-09T10:00:00Z"\n'
            'updated_at: "2026-05-09T10:00:00Z"\n'
            'state: "active"\n'
            'source: "conversation"\n'
            f'claim_instance_id: "{INSTANCE_ID}"\n'
            'supersedes:\n'
            '  - "0193e2b1-0001-7000-8000-00000000bbbb"\n'
            '  - "0193e2b1-0001-7000-8000-00000000aaaa"\n'
            '  - "0193e2b1-0001-7000-8000-00000000aaaa"\n'
        )

    def test_full_canonicalization_marks_changed(self) -> None:
        result = canonicalize_text(_doc(self._full_yaml()))
        assert result.changed is True
        # Re-parse the output to assert the structural transforms.
        out_yaml, _body = split_frontmatter(result.text)
        data, order = parse_frontmatter(out_yaml)
        # Keys lex-sorted
        assert order == sorted(order)
        # Supersedes dedup + sorted
        assert data["supersedes"] == [
            "0193e2b1-0001-7000-8000-00000000aaaa",
            "0193e2b1-0001-7000-8000-00000000bbbb",
        ]
        # Confidence emitted exactly as 3dp text
        assert "confidence: 0.850" in result.text

    def test_already_canonical_returns_unchanged(self) -> None:
        # Build a canonical doc by canonicalizing once, then re-running.
        first = canonicalize_text(_doc(self._full_yaml()))
        second = canonicalize_text(first.text)
        assert second.changed is False
        assert second.text == first.text

    def test_invalid_v03_field_raises_validator_error(self) -> None:
        # polarity wrong value — surfaces during post-canonicalize validation.
        bad = (
            f'claim_id: "{CLAIM_ID}"\n'
            'polarity: "yes"\n'
            'subject: "chris"\n'
        )
        with pytest.raises(SchemaError) as exc:
            canonicalize_text(_doc(bad))
        assert exc.value.code == ErrorCode.CLAIM_POLARITY_VALUE

    def test_unparseable_yaml_raises_parse_error(self) -> None:
        with pytest.raises(SchemaError) as exc:
            canonicalize_text("---\n!!! garbage\n---\nbody\n")
        assert exc.value.code == ErrorCode.PARSE_ERROR

    def test_body_preserved(self) -> None:
        body = "## Heading\n\nLine with a ``code`` segment.\n"
        original = _doc('a: 1\n', body=body)
        result = canonicalize_text(original)
        assert result.text.endswith(body)


# ---- canonicalize_path (filesystem wrapper) ----------------------------------

@pytest.mark.unit
class TestCanonicalizePath:
    def test_in_place_write(self, tmp_path: Path) -> None:
        f = tmp_path / "claim.md"
        f.write_text(
            _doc(f'subject: "chris"\nclaim_id: "{CLAIM_ID}"\n'),
            encoding="utf-8",
        )
        result = canonicalize_path(f, in_place=True)
        assert result.changed is True
        text = f.read_text(encoding="utf-8")
        assert text.index("claim_id") < text.index("subject")

    def test_out_to_separate_file(self, tmp_path: Path) -> None:
        src = tmp_path / "src.md"
        out = tmp_path / "out.md"
        src.write_text(
            _doc(f'subject: "chris"\nclaim_id: "{CLAIM_ID}"\n'),
            encoding="utf-8",
        )
        result = canonicalize_path(src, out=out)
        assert result.changed is True
        # Source untouched, out written
        assert "claim_id" in src.read_text(encoding="utf-8")
        assert out.read_text(encoding="utf-8") == result.text

    def test_in_place_and_out_mutually_exclusive(self, tmp_path: Path) -> None:
        f = tmp_path / "claim.md"
        f.write_text(_doc("a: 1\n"), encoding="utf-8")
        with pytest.raises(SchemaError):
            canonicalize_path(f, out=tmp_path / "out.md", in_place=True)

    def test_dry_run_does_not_write(self, tmp_path: Path) -> None:
        f = tmp_path / "claim.md"
        original = _doc(f'subject: "chris"\nclaim_id: "{CLAIM_ID}"\n')
        f.write_text(original, encoding="utf-8")
        result = canonicalize_path(f)
        assert result.changed is True
        assert f.read_text(encoding="utf-8") == original
