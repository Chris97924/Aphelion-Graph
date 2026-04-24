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
    from aphelion.verifier import verify as do_verify

    do_verify(args.dir)
    writer.success(
        "verify",
        summary=f"{args.dir}: semantic cross-reference OK",
        data={"dir": str(args.dir)},
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

    p_ver = sub.add_parser("verify", help="semantic cross-reference check on an unpacked tree")
    p_ver.add_argument("dir", help="unpacked Aphelion directory")
    p_ver.set_defaults(func=_cmd_verify)

    p_diff = sub.add_parser("diff", help="layered diff between two unpacked Aphelion packages")
    p_diff.add_argument("a", help="path to package A (unpacked directory)")
    p_diff.add_argument("b", help="path to package B (unpacked directory)")
    p_diff.set_defaults(func=_cmd_diff)

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
