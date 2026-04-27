"""Aphelion reference CLI entrypoint.

Seven commands (v0.4.0):
  init      - create an empty Aphelion skeleton in a directory
  validate  - syntax + lifecycle check of manifest + provenance
  pack      - deterministic source_dir -> .aphelion.tar
  unpack    - safe streaming extract
  verify    - post-unpack semantic cross-reference check
  diff      - layered diff between two unpacked Aphelion packages
  migrate   - one-shot v0.3 -> v0.4 wire migration

Global flags (accepted before or after the subcommand):
  --json        emit a JSON line on stdout instead of human text
  --no-color    disable ANSI color even when stdout is a tty
  --version     show package + spec + schema versions
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Sequence

from aphelion import __version__, SCHEMA_VERSION_MAX, SPEC_VERSION
from aphelion.canonical_json import loads
from aphelion.error_codes import ErrorCode
from aphelion.errors import (
    EXIT_OK,
    EXIT_USAGE,
    EXIT_VALIDATION,
    AphelionError,
    SchemaError,
    emit_error,
    exit_code_for,
)
from aphelion.output import Writer, detect_color


VERSION_STRING = (
    f"aphelion {__version__} (spec {SPEC_VERSION}, schema {SCHEMA_VERSION_MAX})"
)


def _cmd_init(args: argparse.Namespace, writer: Writer) -> int:
    from aphelion.initializer import InitOptions, init_skeleton

    dest = Path(args.dest)
    opts = InitOptions(
        dest=dest,
        spec_version=args.spec_version,
        force=args.force,
        confirmed=args.i_know_what_im_doing,
    )
    init_skeleton(opts)
    writer.success(
        "init",
        summary=f"Initialized empty Aphelion skeleton in {dest}",
        data={"dest": str(dest), "spec_version": args.spec_version},
    )
    writer.hint("Next steps:")
    writer.hint(f"  1. Add claim files under {dest / 'claims'}/<uuid>.md")
    writer.hint("  2. Register each claim in manifest.json")
    writer.hint(f"  3. Run `aphelion validate {dest}` to confirm.")
    return EXIT_OK


def _cmd_validate(args: argparse.Namespace, writer: Writer) -> int:
    from aphelion.validator import validate_package

    source = Path(args.source)
    manifest = loads((source / "manifest.json").read_bytes())
    events: list[dict[str, Any]] = []
    provenance_path = source / "provenance.jsonl"
    if provenance_path.exists():
        for idx, line in enumerate(provenance_path.read_bytes().splitlines(), start=1):
            if not line.strip():
                continue
            try:
                events.append(loads(line))
            except SchemaError as err:
                err.path = f"provenance.jsonl:{idx}"
                raise
    warnings = validate_package(manifest, events, mode=args.validate_mode)
    data: dict[str, Any] = {
        "source": str(source),
        "event_count": len(events),
        "mode": args.validate_mode,
    }
    if warnings:
        data["warnings"] = warnings
    writer.success(
        "validate",
        summary=f"{source}: syntax + schema OK ({len(events)} event(s))",
        data=data,
    )
    for w in warnings:
        writer.hint(f"warning: {w}")
    return EXIT_OK


def _cmd_pack(args: argparse.Namespace, writer: Writer) -> int:
    from aphelion.packer import pack as do_pack

    do_pack(args.source, args.output)
    out = Path(args.output)
    size = out.stat().st_size if out.exists() else None
    writer.success(
        "pack",
        summary=f"{args.source} -> {args.output}",
        data={"source": str(args.source), "output": str(args.output), "bytes": size},
    )
    return EXIT_OK


def _cmd_unpack(args: argparse.Namespace, writer: Writer) -> int:
    from aphelion.unpacker import ExtractPolicy, unpack as do_unpack

    policy = ExtractPolicy(
        max_files=args.max_files,
        max_total_bytes=args.max_total_bytes,
        max_file_bytes=args.max_file_bytes,
        max_compression_ratio=args.max_compression_ratio,
        max_path_length=args.max_path_length,
    )
    do_unpack(args.archive, args.dest, policy=policy)
    writer.success(
        "unpack",
        summary=f"{args.archive} -> {args.dest}",
        data={"archive": str(args.archive), "dest": str(args.dest)},
    )
    return EXIT_OK


def _cmd_diff(args: argparse.Namespace, writer: Writer) -> int:
    from aphelion.diff import diff_packages, is_empty, render_human

    result = diff_packages(args.a, args.b)
    if args.json_mode:
        writer.success(
            "diff",
            summary=f"diff {args.a} {args.b}",
            data=result,
        )
    else:
        sys.stdout.write(render_human(result))
    # Exit 0 when diff is empty (identical), 1 when differences found.
    return EXIT_OK if is_empty(result) else 1


def _cmd_migrate(args: argparse.Namespace, writer: Writer) -> int:
    from aphelion.migrate import MigrateOptions, migrate

    opts = MigrateOptions(
        src=Path(args.src),
        dst=Path(args.dst),
        force=args.force,
    )
    out = migrate(opts)
    writer.success(
        "migrate",
        summary=f"{args.src} -> {args.dst} (v0.3 -> v0.4)",
        data={"src": str(args.src), "dst": str(args.dst), "output": str(out)},
    )
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace, writer: Writer) -> int:
    from pathlib import Path as _Path
    from aphelion.verifier import verify as do_verify, verify_package
    from aphelion.signer import SignerVerificationError

    target = _Path(args.dir)
    require_signed: bool = getattr(args, "require_signed", False)
    require_notary: bool = getattr(args, "require_notary", False)
    if require_notary:
        require_signed = True

    # If target is a tar file, use verify_package() (v0.5 path).
    # If it's a directory, fall back to legacy verify() (v0.4 only).
    if target.is_file() and (require_signed or require_notary or target.suffix in (".tar",) or str(target).endswith(".aphelion.tar")):
        try:
            result = verify_package(target, require_signed=require_signed, require_notary=require_notary)
        except SignerVerificationError as exc:
            from aphelion.errors import emit_error, SchemaError, EXIT_VALIDATION
            from aphelion.error_codes import ErrorCode
            import sys
            # Emit as JSON error line to stderr then return non-zero
            import json
            sys.stderr.write(json.dumps({"code": exc.code, "severity": "error", "msg": str(exc)}, sort_keys=True) + "\n")
            sys.stderr.flush()
            return EXIT_VALIDATION
        data: dict = {"path": str(target), "envelopes": len(result.envelopes)}
        writer.success(
            "verify",
            summary=f"{target}: semantic + signature OK ({len(result.envelopes)} envelope(s))",
            data=data,
        )
    else:
        do_verify(args.dir)
        writer.success(
            "verify",
            summary=f"{args.dir}: semantic cross-reference OK",
            data={"dir": str(args.dir)},
        )
    return EXIT_OK


def _cmd_sign(args: argparse.Namespace, writer: Writer) -> int:
    """Pack a signed .aphelion.tar from an existing package tar.

    Reads the HMAC key (or Ed25519 private key) from --key-file,
    computes the canonical package hash, produces a SignatureEnvelope,
    writes/merges signatures.jsonl and signers/<signer_id>.json,
    then repacks into --out.
    """
    import json as _json
    from pathlib import Path as _Path
    from aphelion.canonical_tar import read_members, TarMember
    from aphelion.canonical_tar import pack as tar_pack
    from aphelion.canonical_json import loads as cj_loads, normalize, dumps as cj_dumps
    from aphelion.signer import (
        HMACSigner,
        SignerVerificationError,
        compute_package_canonical_hash,
    )
    from aphelion.sig_pack import write_signatures_jsonl, read_signatures_jsonl
    import datetime

    pkg_path = _Path(args.package)
    if not pkg_path.exists():
        from aphelion.errors import SchemaError, EXIT_VALIDATION
        from aphelion.error_codes import ErrorCode
        from aphelion.errors import emit_error
        emit_error(SchemaError(code=ErrorCode.MISSING_FILE, msg=f"package not found: {pkg_path}"))
        return EXIT_VALIDATION

    key_path = _Path(args.key_file)
    if not key_path.exists() or key_path.stat().st_size == 0:
        from aphelion.errors import SchemaError, EXIT_VALIDATION
        from aphelion.error_codes import ErrorCode
        from aphelion.errors import emit_error
        emit_error(SchemaError(code=ErrorCode.MISSING_FILE, msg=f"key file not found or empty: {key_path}"))
        return EXIT_VALIDATION

    key_bytes = key_path.read_bytes()
    algorithm = args.algorithm
    signer_id = args.signer_id

    # Build the signer
    try:
        if algorithm == "hmac-sha256":
            signer = HMACSigner(signer_id=signer_id, secret=key_bytes)
        elif algorithm == "ed25519":
            import base64 as _base64
            from aphelion.signer import Ed25519Signer, _require_cryptography
            _require_cryptography()
            priv_b64 = _base64.standard_b64encode(key_bytes).decode("ascii")
            signer = Ed25519Signer(signer_id=signer_id, private_key_b64=priv_b64)
        else:
            from aphelion.errors import SchemaError, EXIT_VALIDATION
            from aphelion.error_codes import ErrorCode
            from aphelion.errors import emit_error
            emit_error(SchemaError(code=ErrorCode.ENUM_INVALID, msg=f"unknown algorithm: {algorithm!r}"))
            return EXIT_VALIDATION
    except SignerVerificationError as exc:
        import sys
        import json
        sys.stderr.write(json.dumps({"code": exc.code, "severity": "error", "msg": str(exc)}, sort_keys=True) + "\n")
        sys.stderr.flush()
        return EXIT_VALIDATION

    # Read existing tar members
    members = read_members(pkg_path.read_bytes())

    # Find manifest.json in tar to compute canonical hash
    manifest_raw: bytes | None = None
    for m in members:
        if m.path == "manifest.json":
            manifest_raw = m.data
            break
    if manifest_raw is None:
        from aphelion.errors import SchemaError, EXIT_VALIDATION
        from aphelion.error_codes import ErrorCode
        from aphelion.errors import emit_error
        emit_error(SchemaError(code=ErrorCode.MISSING_FILE, msg="manifest.json not found in archive"))
        return EXIT_VALIDATION

    manifest_obj = normalize(cj_loads(manifest_raw))
    claims_tuples = [
        (c["claim_id"], c["claim_instance_id"], c["hash"])
        for c in manifest_obj["claims"]
    ]
    pkg_hash = compute_package_canonical_hash(
        format_version=manifest_obj["format_version"],
        package_id=manifest_obj["package_id"],
        claims=claims_tuples,
    )

    signed_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    envelope = signer.sign(package_canonical_hash=pkg_hash, signed_at_iso=signed_at)
    manifest_record = signer.manifest()

    # Merge with existing signatures if present
    existing_sigs_bytes: bytes | None = None
    for m in members:
        if m.path == "signatures.jsonl":
            existing_sigs_bytes = m.data
            break

    existing_envelopes: list = []
    if existing_sigs_bytes:
        existing_envelopes = list(read_signatures_jsonl(existing_sigs_bytes))

    # Remove existing envelopes from same signer_id (replace with new one)
    existing_envelopes = [e for e in existing_envelopes if e.signer_id != signer_id]
    all_envelopes = existing_envelopes + [envelope]
    new_sig_bytes = write_signatures_jsonl(all_envelopes)

    manifest_json = cj_dumps(normalize({
        "signer_id": manifest_record.signer_id,
        "algorithm": manifest_record.algorithm,
        "public_key_b64": manifest_record.public_key_b64,
        "key_fingerprint": manifest_record.key_fingerprint,
        "notary_uri": None,
    }))

    # Build new members list (replace/add signatures.jsonl + signers/<id>.json)
    signer_manifest_path = f"signers/{signer_id}.json"
    new_members = [
        m for m in members
        if m.path not in ("signatures.jsonl", signer_manifest_path)
    ]
    new_members.append(TarMember(path="signatures.jsonl", data=new_sig_bytes, is_dir=False))
    new_members.append(TarMember(path=signer_manifest_path, data=manifest_json, is_dir=False))

    out_path = _Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(tar_pack(new_members))

    writer.success(
        "sign",
        summary=f"signed {pkg_path} -> {out_path} (signer={signer_id}, algo={algorithm})",
        data={"package": str(pkg_path), "out": str(out_path), "signer_id": signer_id, "algorithm": algorithm},
    )
    return EXIT_OK


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aphelion", description="Aphelion reference CLI")
    parser.add_argument("--version", action="version", version=VERSION_STRING)
    parser.add_argument(
        "--json",
        dest="json_mode",
        action="store_true",
        help="emit machine-readable JSON on stdout (errors are always JSON on stderr)",
    )
    parser.add_argument(
        "--no-color",
        dest="no_color",
        action="store_true",
        help="disable ANSI color on stdout (auto-disabled for non-tty / NO_COLOR)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create an empty Aphelion skeleton in DEST")
    p_init.add_argument("dest", help="destination directory")
    p_init.add_argument(
        "--spec-version",
        default=SPEC_VERSION,
        help=f"spec version to stamp (default: {SPEC_VERSION})",
    )
    p_init.add_argument(
        "--force",
        action="store_true",
        help="allow overwriting an existing Aphelion skeleton (REQUIRES --i-know-what-im-doing)",
    )
    p_init.add_argument(
        "--i-know-what-im-doing",
        dest="i_know_what_im_doing",
        action="store_true",
        help="confirm destructive overwrite (must pair with --force)",
    )
    p_init.set_defaults(func=_cmd_init)

    p_val = sub.add_parser("validate", help="syntax-layer check of manifest + events")
    p_val.add_argument("source", help="directory containing manifest.json + provenance.jsonl")
    mode = p_val.add_mutually_exclusive_group()
    mode.add_argument(
        "--strict",
        dest="validate_mode",
        action="store_const",
        const="strict",
        help="default; any unknown optional field or MINOR version mismatch is an error",
    )
    mode.add_argument(
        "--lenient",
        dest="validate_mode",
        action="store_const",
        const="lenient",
        help="downgrade unknown-MINOR-version and unknown optional fields to warnings (default: strict)",
    )
    p_val.set_defaults(func=_cmd_validate, validate_mode="strict")

    p_pack = sub.add_parser("pack", help="deterministic pack: source_dir -> .aphelion.tar")
    p_pack.add_argument("source", help="source directory")
    p_pack.add_argument("output", help="output .aphelion.tar path")
    p_pack.set_defaults(func=_cmd_pack)

    p_unp = sub.add_parser("unpack", help="safe streaming extract of a .aphelion.tar")
    p_unp.add_argument("archive", help=".aphelion.tar archive path")
    p_unp.add_argument("dest", help="destination directory")
    p_unp.add_argument("--max-files", type=int, default=10_000)
    p_unp.add_argument("--max-total-bytes", type=int, default=100 * 1024 * 1024)
    p_unp.add_argument("--max-file-bytes", type=int, default=25 * 1024 * 1024)
    p_unp.add_argument("--max-compression-ratio", type=int, default=100)
    p_unp.add_argument("--max-path-length", type=int, default=512)
    p_unp.set_defaults(func=_cmd_unpack)

    p_ver = sub.add_parser(
        "verify",
        help="semantic cross-reference check (unpacked dir) or v0.5 tar verification",
    )
    p_ver.add_argument("dir", help="unpacked Aphelion directory or .aphelion.tar path")
    p_ver.add_argument(
        "--require-signed",
        dest="require_signed",
        action="store_true",
        help="require at least one valid signature (E_SIGNER_REQUIRED if absent)",
    )
    p_ver.add_argument(
        "--require-notary",
        dest="require_notary",
        action="store_true",
        help="require notary attestation (implies --require-signed; E_SIGNER_NOTARY_REQUIRED if only local)",
    )
    p_ver.set_defaults(func=_cmd_verify, require_signed=False, require_notary=False)

    p_diff = sub.add_parser("diff", help="layered diff between two unpacked Aphelion packages")
    p_diff.add_argument("a", help="path to package A (unpacked directory)")
    p_diff.add_argument("b", help="path to package B (unpacked directory)")
    p_diff.set_defaults(func=_cmd_diff)

    p_sign = sub.add_parser(
        "sign",
        help="sign a .aphelion.tar and write signed tar to --out",
    )
    p_sign.add_argument("--package", required=True, help=".aphelion.tar to sign")
    p_sign.add_argument("--signer-id", dest="signer_id", required=True, help="signer identity string")
    p_sign.add_argument(
        "--algorithm",
        choices=["hmac-sha256", "ed25519"],
        required=True,
        help="signing algorithm",
    )
    p_sign.add_argument("--key-file", dest="key_file", required=True, help="raw key bytes file")
    p_sign.add_argument("--out", required=True, help="output .aphelion.tar path")
    p_sign.set_defaults(func=_cmd_sign)

    p_mig = sub.add_parser(
        "migrate",
        help="one-shot v0.3 -> v0.4 wire migration (dir->dir or tar->tar)",
    )
    p_mig.add_argument("src", help="source v0.3 Aphelion (unpacked dir or .aphelion.tar)")
    p_mig.add_argument("dst", help="destination v0.4 Aphelion (matches src shape)")
    p_mig.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing destination",
    )
    p_mig.set_defaults(func=_cmd_migrate)

    return parser


def _build_writer(args: argparse.Namespace) -> Writer:
    # --json and --no-color are global flags declared on the root parser, so
    # argparse always populates them (store_true defaults to False). No
    # defensive getattr needed.
    json_mode = args.json_mode
    if json_mode or args.no_color:
        color = False
    else:
        color = detect_color(sys.stdout)
    return Writer(json_mode=json_mode, color=color, stdout=sys.stdout)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse raises SystemExit(2) on usage errors; pass through
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    writer = _build_writer(args)
    try:
        return args.func(args, writer)
    except AphelionError as err:
        emit_error(err)
        return exit_code_for(err)
    except FileNotFoundError as err:
        emit_error(
            SchemaError(code=ErrorCode.MISSING_FILE, msg=str(err))
        )
        return EXIT_VALIDATION
    except Exception as err:  # unexpected — still surface machine-readably
        emit_error(
            SchemaError(code=ErrorCode.UNKNOWN, msg=f"{type(err).__name__}: {err}")
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
