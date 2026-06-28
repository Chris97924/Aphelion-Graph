"""CLI error-branch tests.

Covers the exception handling paths in ``aphelion.cli.main`` that the fixture
suite does not naturally exercise:

  * blank line in provenance.jsonl (``continue``)
  * malformed JSON line in provenance.jsonl -> SchemaError with decorated path
  * argparse SystemExit pass-through for usage errors
  * FileNotFoundError -> MISSING_FILE
  * catch-all Exception -> UNKNOWN with exit 1
  * ``python -m aphelion`` module entrypoint
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import pytest

from aphelion.canonical_json import dumps, normalize
from aphelion.error_codes import ErrorCode
from aphelion.errors import EXIT_VALIDATION, SchemaError

from conftest import run_cli as _run


UUID_PKG = "0191aaaa-0000-7000-8000-000000000001"
UUID_CLAIM_A = "0191aaaa-0000-7000-8000-00000000aaaa"
UUID_INSTANCE_A = "0191aaaa-0000-7000-8000-aaaaaaaaaaaa"
UUID_EVENT_1 = "0191aaaa-0000-7000-8000-eeee00000001"


def _error_payload(stderr: str) -> dict | None:
    for line in stderr.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "code" in parsed:
            return parsed
    return None


def _minimal_source(dest: Path) -> Path:
    import hashlib

    (dest / "claims").mkdir(parents=True, exist_ok=True)
    claim = (
        "---\n"
        '"body_format": "markdown"\n'
        f'"claim_id": "{UUID_CLAIM_A}"\n'
        '"title": "hi"\n'
        "---\n"
    ).encode("utf-8")
    (dest / f"claims/{UUID_CLAIM_A}.md").write_bytes(claim)
    manifest = {
        "claims": [
            {
                "claim_id": UUID_CLAIM_A,
                "claim_instance_id": UUID_INSTANCE_A,
                "hash": hashlib.sha256(claim).hexdigest(),
                "path": f"claims/{UUID_CLAIM_A}.md",
                "state": "active",
            }
        ],
        "aphelion_spec_version": "0.4.0",
        "created_at": "2026-04-21T00:00:00Z",
        "format_version": "2.0",
        "license": "Apache-2.0",
        "package_id": UUID_PKG,
        "producer": "aphelion-test",
        "provenance_path": "provenance.jsonl",
    }
    (dest / "manifest.json").write_bytes(dumps(normalize(manifest)))
    event = {
        "actor": "t",
        "claim_id": UUID_CLAIM_A,
        "claim_instance_id": UUID_INSTANCE_A,
        "event_id": UUID_EVENT_1,
        "event_type": "create",
        "timestamp": "2026-04-21T00:00:00Z",
    }
    (dest / "provenance.jsonl").write_bytes(dumps(normalize(event)))
    return dest


# ---------- _cmd_validate: blank line skip (line 65) ----------


def test_validate_skips_blank_lines_in_provenance(tmp_path: Path) -> None:
    src = _minimal_source(tmp_path / "pkg")
    # Insert blank + whitespace-only lines around the real event; both are skipped.
    event_line = (src / "provenance.jsonl").read_bytes()
    (src / "provenance.jsonl").write_bytes(b"\n   \n" + event_line + b"\n")
    code, _, err = _run(["validate", str(src)])
    assert code == 0, err


# ---------- _cmd_validate: malformed JSON in provenance (lines 68-70) ----------


def test_validate_malformed_provenance_line_decorates_path(tmp_path: Path) -> None:
    src = _minimal_source(tmp_path / "pkg")
    (src / "provenance.jsonl").write_bytes(b"not-json-at-all\n")
    code, _, err = _run(["validate", str(src)])
    assert code == 3, err
    payload = _error_payload(err)
    assert payload is not None
    assert payload["code"] == ErrorCode.PARSE_ERROR.value
    assert payload["path"] == "provenance.jsonl:1"


# ---------- main(): argparse SystemExit pass-through (lines 162-164) ----------


def test_main_invalid_subcommand_returns_usage_exit_code() -> None:
    # argparse raises SystemExit(2) for unknown subcommands; main() forwards it.
    code, _, _ = _run(["not-a-real-subcommand"])
    assert code == 2


def test_main_missing_required_arg_returns_usage_exit_code() -> None:
    # `validate` requires a positional `source`; argparse -> SystemExit(2).
    code, _, _ = _run(["validate"])
    assert code == 2


# ---------- main(): FileNotFoundError branch (lines 170-174) ----------


def test_main_missing_manifest_emits_missing_file(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    code, _, err = _run(["validate", str(empty)])
    assert code == 3, err
    payload = _error_payload(err)
    assert payload is not None
    assert payload["code"] == ErrorCode.MISSING_FILE.value


# ---------- main(): generic Exception branch (lines 175-179) ----------


def test_main_generic_exception_emits_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = _minimal_source(tmp_path / "pkg")

    def _boom(_manifest: dict, _events: list, **_kwargs) -> None:
        raise RuntimeError("unexpected boom")

    # Monkeypatch inside the lazily-imported module used by _cmd_validate.
    import aphelion.validator as validator_mod

    monkeypatch.setattr(validator_mod, "validate_package", _boom)

    code, _, err = _run(["validate", str(src)])
    assert code == 1, err  # EXIT_GENERIC for unexpected exceptions
    payload = _error_payload(err)
    assert payload is not None
    assert payload["code"] == ErrorCode.UNKNOWN.value
    assert "RuntimeError" in payload["msg"]


# ---------- SchemaError SystemExit handling preserves exit code ----------


def test_main_schema_error_from_command_returns_exit_3(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = _minimal_source(tmp_path / "pkg")

    def _fail(_manifest: dict, _events: list, **_kwargs) -> None:
        raise SchemaError(code=ErrorCode.TYPE_MISMATCH, msg="boom")

    import aphelion.validator as validator_mod

    monkeypatch.setattr(validator_mod, "validate_package", _fail)
    code, _, err = _run(["validate", str(src)])
    assert code == 3, err
    payload = _error_payload(err)
    assert payload is not None
    assert payload["code"] == ErrorCode.TYPE_MISMATCH.value


# ---------- __main__ entrypoint (line 183) ----------


def test_module_entrypoint_runs_via_python_dash_m(tmp_path: Path) -> None:
    """`python -m aphelion --version` exits cleanly via the __main__ block."""
    repo_root = Path(__file__).resolve().parent.parent
    env = {
        **dict(__import__("os").environ),
        "PYTHONPATH": str(repo_root / "src"),
    }
    result = subprocess.run(
        [sys.executable, "-m", "aphelion", "--version"],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(repo_root),
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "aphelion" in result.stdout.lower()


# ---------- _cmd_canonicalize: dry-run stdout is pipe-safe ----------


CLAIM_ID_DRY = "0191aaaa-0000-7000-8000-cccccccccccc"


def test_canonicalize_dry_run_stdout_is_only_document(tmp_path: Path) -> None:
    """Dry-run stdout must be the canonical document only — no status text.

    Regression for Codex P2 round-5: ``writer.success()`` was polluting stdout
    after the document, breaking ``aphe canonicalize file.md > out.md`` pipes.
    """
    # Write a claim whose keys are out of canonical order so canonicalization
    # changes the content (result.changed == True).  Keys must be unquoted
    # (YAML bare keys) to be parseable; canonical output quotes values only.
    f = tmp_path / "claim.md"
    original = (
        "---\n"
        f'claim_id: "{CLAIM_ID_DRY}"\n'
        'body_format: "markdown"\n'
        "---\n"
        "Body.\n"
    )
    f.write_text(original, encoding="utf-8")

    code, out, _err = _run(["canonicalize", str(f)])

    assert code == 0
    # stdout must not contain any status / "[ok]" line — only the canonical doc.
    assert "[ok]" not in out
    assert "dry-run" not in out
    assert "canonicalize" not in out  # no command echo on stdout
    # The canonical text must itself be valid YAML frontmatter — non-empty.
    assert out.startswith("---\n")


# ===========================================================================
# `aphe sign` CLI command — error-branch + round-trip coverage
#
# signer.py is exercised 100% via the API by test_signer/test_verifier_signed,
# but the CLI wiring in _cmd_sign (argv -> exit code -> JSON error payload) had
# no direct coverage of its guard branches. These lock in:
#   * package file not found            -> EXIT_VALIDATION + MISSING_FILE
#   * key file missing or zero-length   -> EXIT_VALIDATION + MISSING_FILE
#   * unknown --algorithm value         -> EXIT_VALIDATION + ENUM_INVALID
#   * signer-layer error surfaced       -> EXIT_VALIDATION + algorithm code
#   * manifest.json absent in archive   -> EXIT_VALIDATION + MISSING_FILE
#   * hmac-sha256 / ed25519 round trips  -> exit 0 + a verifiable signed tar
# ===========================================================================


HMAC_KEY = b"test-hmac-key-cli-sign-32bytes!!"


def _packed_tar(tmp_path: Path, name: str = "pkg.tar") -> Path:
    """Build a minimal valid source dir and pack it into a .aphelion.tar."""
    from aphelion.packer import pack

    src = _minimal_source(tmp_path / "pkgsrc")
    out = tmp_path / name
    pack(src, out)
    return out


def _pkg_canonical_hash(tar_path: Path) -> str:
    """Compute the package canonical hash from a packed tar's manifest."""
    from aphelion.canonical_tar import read_members
    from aphelion.signer import compute_package_canonical_hash

    members = read_members(tar_path.read_bytes())
    manifest_raw = next(m.data for m in members if m.path == "manifest.json")
    assert manifest_raw is not None
    manifest_obj = normalize(json.loads(manifest_raw))
    claims_tuples = [
        (c["claim_id"], c["claim_instance_id"], c["hash"])
        for c in manifest_obj["claims"]
    ]
    return compute_package_canonical_hash(
        format_version=manifest_obj["format_version"],
        package_id=manifest_obj["package_id"],
        claims=claims_tuples,
    )


# ---------- package file not found (lines 279-283) ----------


def test_sign_package_not_found_emits_missing_file(tmp_path: Path) -> None:
    key_file = tmp_path / "key.bin"
    key_file.write_bytes(HMAC_KEY)  # valid key, so only the package guard can fire
    out = tmp_path / "signed.tar"

    code, _, err = _run(
        [
            "sign",
            "--package", str(tmp_path / "does-not-exist.aphelion.tar"),
            "--signer-id", "s1",
            "--algorithm", "hmac-sha256",
            "--key-file", str(key_file),
            "--out", str(out),
        ]
    )

    assert code == EXIT_VALIDATION, err
    payload = _error_payload(err)
    assert payload is not None
    assert payload["code"] == ErrorCode.MISSING_FILE.value
    # Teeth: the explicit guard's message distinguishes it from main()'s generic
    # FileNotFoundError fallback. Removing `if not pkg_path.exists()` would let
    # read_bytes() raise and surface the raw OSError string instead.
    assert "package not found" in payload["msg"]
    assert not out.exists()


# ---------- key file missing (lines 287-291) ----------


def test_sign_key_file_missing_emits_missing_file(tmp_path: Path) -> None:
    pkg = _packed_tar(tmp_path)
    out = tmp_path / "signed.tar"

    code, _, err = _run(
        [
            "sign",
            "--package", str(pkg),
            "--signer-id", "s1",
            "--algorithm", "hmac-sha256",
            "--key-file", str(tmp_path / "no-such-key.bin"),
            "--out", str(out),
        ]
    )

    assert code == EXIT_VALIDATION, err
    payload = _error_payload(err)
    assert payload is not None
    assert payload["code"] == ErrorCode.MISSING_FILE.value
    assert "key file not found or empty" in payload["msg"]
    assert not out.exists()


# ---------- key file zero-length (lines 287-291) ----------


def test_sign_key_file_empty_emits_missing_file(tmp_path: Path) -> None:
    pkg = _packed_tar(tmp_path)
    empty_key = tmp_path / "empty.bin"
    empty_key.write_bytes(b"")  # exists but zero-length
    out = tmp_path / "signed.tar"

    code, _, err = _run(
        [
            "sign",
            "--package", str(pkg),
            "--signer-id", "s1",
            "--algorithm", "hmac-sha256",
            "--key-file", str(empty_key),
            "--out", str(out),
        ]
    )

    # Strong teeth: without the `or stat().st_size == 0` guard, an empty key
    # would build a valid HMACSigner and SUCCEED (exit 0, signed tar written).
    assert code == EXIT_VALIDATION, err
    payload = _error_payload(err)
    assert payload is not None
    assert payload["code"] == ErrorCode.MISSING_FILE.value
    assert not out.exists()


# ---------- unknown --algorithm: argparse choices guard (exit 2) ----------


def test_sign_unknown_algorithm_rejected_by_argparse(tmp_path: Path) -> None:
    """`--algorithm bogus` is blocked by argparse choices before _cmd_sign runs."""
    pkg = _packed_tar(tmp_path)
    key_file = tmp_path / "key.bin"
    key_file.write_bytes(HMAC_KEY)

    code, _, _ = _run(
        [
            "sign",
            "--package", str(pkg),
            "--signer-id", "s1",
            "--algorithm", "totally-bogus",
            "--key-file", str(key_file),
            "--out", str(tmp_path / "signed.tar"),
        ]
    )
    assert code == 2  # argparse usage error


# ---------- unknown algorithm reaching the else branch (lines 307-312) ----------


def test_sign_cmd_unknown_algorithm_emits_enum_invalid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The defensive ``else`` branch in _cmd_sign emits ENUM_INVALID.

    argparse ``choices`` normally blocks any non-registered algorithm, so this
    branch is only reachable by invoking the command handler directly with a
    crafted Namespace. We assert it fails closed with ENUM_INVALID rather than
    silently constructing an unbound signer.
    """
    from aphelion.cli import _cmd_sign
    from aphelion.output import Writer

    pkg = _packed_tar(tmp_path)
    key_file = tmp_path / "key.bin"
    key_file.write_bytes(HMAC_KEY)
    out = tmp_path / "signed.tar"

    args = argparse.Namespace(
        package=str(pkg),
        signer_id="s1",
        algorithm="rot13",  # not in {hmac-sha256, ed25519}
        key_file=str(key_file),
        out=str(out),
    )
    writer = Writer(json_mode=False, color=False, stdout=sys.stdout)

    code = _cmd_sign(args, writer)

    assert code == EXIT_VALIDATION
    payload = _error_payload(capsys.readouterr().err)
    assert payload is not None
    assert payload["code"] == ErrorCode.ENUM_INVALID.value
    assert not out.exists()


# ---------- signer-layer SignerVerificationError surfaced (lines 313-318) ----------


def test_sign_ed25519_algorithm_unavailable_surfaces_json_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the signer layer reports the algorithm is unavailable, the CLI emits
    a JSON error line and returns EXIT_VALIDATION — it must not crash.

    Simulates a venv without the ``cryptography`` extra by patching
    ``_require_cryptography`` to raise (the import is lazy inside _cmd_sign,
    so the patched attribute is picked up at call time).
    """
    import aphelion.signer as signer_mod
    from aphelion.signer import SignerVerificationError

    def _boom() -> tuple[type, type]:
        raise SignerVerificationError(
            "E_SIGNER_ALGORITHM_UNAVAILABLE", "cryptography extra not installed"
        )

    monkeypatch.setattr(signer_mod, "_require_cryptography", _boom)

    pkg = _packed_tar(tmp_path)
    key_file = tmp_path / "key.bin"
    key_file.write_bytes(b"x" * 32)
    out = tmp_path / "signed.tar"

    code, _, err = _run(
        [
            "sign",
            "--package", str(pkg),
            "--signer-id", "s1",
            "--algorithm", "ed25519",
            "--key-file", str(key_file),
            "--out", str(out),
        ]
    )

    # Teeth: if the `except SignerVerificationError` handler were removed, the
    # error would fall through to main()'s generic handler as UNKNOWN/exit 1.
    assert code == EXIT_VALIDATION, err
    payload = _error_payload(err)
    assert payload is not None
    assert payload["code"] == "E_SIGNER_ALGORITHM_UNAVAILABLE"
    assert not out.exists()


# ---------- manifest.json absent inside the archive (lines 330-334) ----------


def test_sign_manifest_absent_in_archive_emits_missing_file(tmp_path: Path) -> None:
    from aphelion.canonical_tar import read_members
    from aphelion.canonical_tar import pack as tar_pack

    pkg = _packed_tar(tmp_path)
    # Rebuild the tar with manifest.json dropped (signer reads members, then
    # fails closed because it cannot find manifest.json to compute the hash).
    members = [m for m in read_members(pkg.read_bytes()) if m.path != "manifest.json"]
    pkg.write_bytes(tar_pack(members))

    key_file = tmp_path / "key.bin"
    key_file.write_bytes(HMAC_KEY)
    out = tmp_path / "signed.tar"

    code, _, err = _run(
        [
            "sign",
            "--package", str(pkg),
            "--signer-id", "s1",
            "--algorithm", "hmac-sha256",
            "--key-file", str(key_file),
            "--out", str(out),
        ]
    )

    # Teeth: removing the `if manifest_raw is None` guard would feed None to
    # the canonical-json loader and surface UNKNOWN/exit 1 instead.
    assert code == EXIT_VALIDATION, err
    payload = _error_payload(err)
    assert payload is not None
    assert payload["code"] == ErrorCode.MISSING_FILE.value
    assert "manifest.json not found in archive" in payload["msg"]
    assert not out.exists()


# ---------- successful round trips (lines 299-306) ----------


@pytest.mark.filterwarnings(
    "ignore:hmac-sha256 envelopes have zero non-repudiation:UserWarning"
)
def test_sign_hmac_round_trip_produces_verifiable_tar(tmp_path: Path) -> None:
    from aphelion.verifier import verify_package

    pkg = _packed_tar(tmp_path)
    key_file = tmp_path / "key.bin"
    key_file.write_bytes(HMAC_KEY)
    out = tmp_path / "signed.tar"

    code, _, err = _run(
        [
            "sign",
            "--package", str(pkg),
            "--signer-id", "hmac-signer",
            "--algorithm", "hmac-sha256",
            "--key-file", str(key_file),
            "--out", str(out),
        ]
    )

    assert code == 0, err
    assert out.exists()
    # Teeth: the emitted tar must actually verify (require_signed forces §5).
    result = verify_package(out, require_signed=True)
    assert len(result.envelopes) == 1
    assert result.envelopes[0].signer_id == "hmac-signer"
    assert result.envelopes[0].algorithm == "hmac-sha256"


def test_sign_ed25519_round_trip_produces_verifiable_tar(tmp_path: Path) -> None:
    pytest.importorskip("cryptography", reason="ed25519 requires the cryptography extra")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from aphelion.verifier import verify_package

    pkg = _packed_tar(tmp_path)

    # The CLI expects the key file to hold the raw 32-byte ed25519 private key.
    priv_raw = Ed25519PrivateKey.generate().private_bytes_raw()
    assert len(priv_raw) == 32
    key_file = tmp_path / "ed.key"
    key_file.write_bytes(priv_raw)
    out = tmp_path / "signed.tar"

    code, _, err = _run(
        [
            "sign",
            "--package", str(pkg),
            "--signer-id", "ed-signer",
            "--algorithm", "ed25519",
            "--key-file", str(key_file),
            "--out", str(out),
        ]
    )

    assert code == 0, err
    assert out.exists()
    # Teeth: a real Ed25519 signature over the package canonical hash must verify.
    result = verify_package(out, require_signed=True)
    assert len(result.envelopes) == 1
    assert result.envelopes[0].signer_id == "ed-signer"
    assert result.envelopes[0].algorithm == "ed25519"
    assert result.envelopes[0].package_canonical_hash == _pkg_canonical_hash(pkg)
