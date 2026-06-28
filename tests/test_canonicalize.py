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

    # -- safety contract: reject non-canonical / unsupported YAML --------------

    @pytest.mark.parametrize(
        "token",
        [
            "[1, 2]",   # flow sequence
            "{a: 1}",   # flow mapping
            "&anchor x",  # anchor
            "*alias",   # alias
            "!tag v",   # tag
        ],
    )
    def test_parse_rejects_unsupported_yaml_tokens(self, token: str) -> None:
        # Flow style, anchors, aliases, and tags are outside the canonical
        # Aphelion subset and MUST be rejected, never silently coerced to a
        # plain string (which would let a non-canonical doc earn a hash).
        with pytest.raises(SchemaError) as exc:
            parse_frontmatter(f"a: {token}\n")
        assert exc.value.code == ErrorCode.PARSE_ERROR

    def test_parse_false_scalar(self) -> None:
        data, _ = parse_frontmatter("flag: false\n")
        assert data == {"flag": False}
        assert data["flag"] is False

    def test_parse_unquoted_string_falls_through_non_number(self) -> None:
        # A bare token that is neither bool/null nor a valid int/float falls
        # through the numeric parse (ValueError) and is treated as a string.
        # "world" exercises the int() path; "1.2.3" the float() path.
        data, _ = parse_frontmatter("a: world\nb: 1.2.3\n")
        assert data == {"a": "world", "b": "1.2.3"}

    def test_parse_skips_blank_and_comment_lines_top_level(self) -> None:
        text = "a: 1\n\n# a comment\nb: 2\n"
        data, order = parse_frontmatter(text)
        assert data == {"a": 1, "b": 2}
        assert order == ["a", "b"]

    def test_parse_skips_blank_and_comment_lines_inside_block(self) -> None:
        text = 'tags:\n  - "a"\n\n  # note\n  - "b"\n'
        data, _ = parse_frontmatter(text)
        assert data == {"tags": ["a", "b"]}

    def test_parse_rejects_key_with_no_value_and_no_block(self) -> None:
        # `a:` with nothing indented after it is not a valid block scalar.
        with pytest.raises(SchemaError) as exc:
            parse_frontmatter("a:\n")
        assert exc.value.code == ErrorCode.PARSE_ERROR

    def test_parse_rejects_mixed_block_under_sequence(self) -> None:
        # First block line is a list item, a later line is not — reject.
        text = 'tags:\n  - "a"\n  notalist\n'
        with pytest.raises(SchemaError) as exc:
            parse_frontmatter(text)
        assert exc.value.code == ErrorCode.PARSE_ERROR

    def test_parse_rejects_mixed_block_under_mapping(self) -> None:
        # First block line is a nested key/value, a later line is a list item.
        text = 'labels:\n  priority: "high"\n  - notakv\n'
        with pytest.raises(SchemaError) as exc:
            parse_frontmatter(text)
        assert exc.value.code == ErrorCode.PARSE_ERROR

    def test_parse_rejects_nested_mapping_deeper_than_one_level(self) -> None:
        # A nested key with no scalar value implies a 2nd nesting level.
        text = 'labels:\n  deep:\n'
        with pytest.raises(SchemaError) as exc:
            parse_frontmatter(text)
        assert exc.value.code == ErrorCode.PARSE_ERROR

    def test_parse_rejects_unknown_block_shape(self) -> None:
        # Block line is neither a list item nor a nested key/value.
        text = 'weird:\n  plaintext\n'
        with pytest.raises(SchemaError) as exc:
            parse_frontmatter(text)
        assert exc.value.code == ErrorCode.PARSE_ERROR

    # -- emit_frontmatter: scalar / container edge shapes ----------------------

    def test_emit_none_true_false(self) -> None:
        out = emit_frontmatter({"a": None, "b": True, "c": False})
        assert out == "a: null\nb: true\nc: false\n"

    def test_emit_string_with_double_quote_uses_single_quote(self) -> None:
        out = emit_frontmatter({"a": 'say "hi"'})
        assert out == "a: 'say \"hi\"'\n"
        # Round-trips back to the original value.
        reparsed, _ = parse_frontmatter(out)
        assert reparsed == {"a": 'say "hi"'}

    def test_emit_string_with_both_quote_forms_raises(self) -> None:
        with pytest.raises(SchemaError) as exc:
            emit_frontmatter({"a": 'he said "hi" it\'s done'})
        assert exc.value.code == ErrorCode.PARSE_ERROR

    def test_emit_unsupported_scalar_type_raises(self) -> None:
        with pytest.raises(SchemaError) as exc:
            emit_frontmatter({"a": object()})
        assert exc.value.code == ErrorCode.PARSE_ERROR

    def test_emit_empty_list(self) -> None:
        assert emit_frontmatter({"tags": []}) == "tags: []\n"

    def test_emit_empty_dict(self) -> None:
        assert emit_frontmatter({"labels": {}}) == "labels: {}\n"

    def test_emit_nested_mapping_sorts_inner_keys(self) -> None:
        out = emit_frontmatter({"labels": {"y": "2", "x": "1"}})
        assert out == 'labels:\n  x: "1"\n  y: "2"\n'
        reparsed, _ = parse_frontmatter(out)
        assert reparsed == {"labels": {"x": "1", "y": "2"}}

    # -- split_frontmatter: CRLF handling --------------------------------------

    def test_split_strips_crlf_after_opening_fence(self) -> None:
        yaml, body = split_frontmatter("---\r\na: 1\n---\nbody\n")
        assert yaml == "a: 1\n"
        assert body == "body\n"

    def test_split_crlf_document_roundtrips(self) -> None:
        # A fully CRLF document: the opening-fence CRLF is stripped (the
        # \r\n branch) and the body retains its own line endings.
        yaml, body = split_frontmatter("---\r\na: 1\r\n---\r\nbody\r\n")
        assert yaml == "a: 1\r\n"
        assert body == "body\r\n"
        data, _ = parse_frontmatter(yaml)
        assert data == {"a": 1}


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

    def test_non_utf8_input_raises_utf8_invalid(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.md"
        f.write_bytes(b"\xff\xfe\xfd invalid bytes")
        with pytest.raises(SchemaError) as exc:
            canonicalize_path(f)
        assert exc.value.code == ErrorCode.UTF8_INVALID


# ---- P1 regression: confidence range validation before rounding ---------------

@pytest.mark.unit
class TestConfidenceRangeValidation:
    """confidence must be validated against [0, 1] on the unrounded value."""

    def _doc_with_confidence(self, confidence: str) -> str:
        return _doc(
            f'claim_id: "{CLAIM_ID}"\n'
            f'confidence: {confidence}\n'
            'created_at: "2026-05-09T10:00:00Z"\n'
            'polarity: "affirm"\n'
            'source: "conversation"\n'
            'state: "active"\n'
            'subject: "chris"\n'
            'type: "user_preference"\n'
            f'updated_at: "2026-05-09T10:00:00Z"\n'
            f'claim_instance_id: "{INSTANCE_ID}"\n'
        )

    def test_confidence_above_one_raises_range_error(self) -> None:
        with pytest.raises(SchemaError) as exc:
            canonicalize_text(self._doc_with_confidence("1.0004"))
        assert exc.value.code == ErrorCode.CLAIM_CONFIDENCE_RANGE

    def test_confidence_negative_raises_range_error(self) -> None:
        with pytest.raises(SchemaError) as exc:
            canonicalize_text(self._doc_with_confidence("-0.0001"))
        assert exc.value.code == ErrorCode.CLAIM_CONFIDENCE_RANGE

    def test_confidence_one_accepted(self) -> None:
        result = canonicalize_text(self._doc_with_confidence("1.0"))
        assert "confidence: 1.000" in result.text

    def test_confidence_zero_accepted(self) -> None:
        result = canonicalize_text(self._doc_with_confidence("0.0"))
        assert "confidence: 0.000" in result.text

    def test_confidence_mid_range_accepted(self) -> None:
        result = canonicalize_text(self._doc_with_confidence("0.5"))
        assert "confidence: 0.500" in result.text


# ---- P2 regression: unterminated quoted scalar rejection ---------------------

@pytest.mark.unit
class TestUnterminatedQuotedScalar:
    """Scalars that open with a quote but lack a matching close quote must fail."""

    def test_double_quote_unterminated_raises_parse_error(self) -> None:
        yaml = 'subject: "chris\n'
        with pytest.raises(SchemaError) as exc:
            parse_frontmatter(yaml)
        assert exc.value.code == ErrorCode.PARSE_ERROR

    def test_single_quote_unterminated_raises_parse_error(self) -> None:
        yaml = "subject: 'chris\n"
        with pytest.raises(SchemaError) as exc:
            parse_frontmatter(yaml)
        assert exc.value.code == ErrorCode.PARSE_ERROR

    def test_double_quote_terminated_parses(self) -> None:
        data, _ = parse_frontmatter('subject: "chris"\n')
        assert data["subject"] == "chris"

    def test_single_quote_terminated_parses(self) -> None:
        data, _ = parse_frontmatter("subject: 'chris'\n")
        assert data["subject"] == "chris"
