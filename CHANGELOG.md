# Changelog

## [0.7.0] — 2026-10-29

### Added

- **LongMemEval 3-arm benchmark harness** (`benchmarks/longmemeval/`) — the
  measurement rig for the G2 kill-gate, built pre-registered so its result is
  reportable whichever way it comes out.
  - **Three arms, one independent variable.** Arm A (`PlainStore`) keeps every
    claim, duplicates included; Arm B (`NaiveDedupStore`) is the honest middle
    control, exact-string dedup after whitespace collapse; Arm C
    (`AphelionStore`) is the machinery under test — lineage-gated
    `content_hash` coalescing, event state-machine suppression, and R4
    conflict resolution. The answering model, the extractor model and the
    shared deterministic BM25 retriever are identical across all three, so the
    memory layer is the only thing that varies.
  - **Six metrics.** M1 QA accuracy on knowledge-update (the gated one), M2
    deduplication precision/recall/F1 over labeled pairs, M3 knowledge-update
    contamination rate, M4 storage/latency sanity with a non-gating 10x
    tripwire, M5 cross-tool round-trip determinism, and AG, the adversarial
    slice.
  - **`preregister.json`** — the pinned protocol: seed, split sizes and
    sampling algorithm, model pins, retriever, per-metric gates, and a
    `design_doc_sha256` over `docs/benchmark/longmemeval-3arm-design.md`. Four
    §6.3 amendments are recorded in it rather than applied silently.
  - **Offline smokes** that need no model and no network, and a resumable
    real-model execution layer whose every durable artefact is append-only.
- **`--extract-only` run mode** — runs the shared extraction stage alone for a
  chosen split/limit/haystack, filling `extractions.jsonl` with the rows the
  graded run would write, so the extractor can be paid for and measured before
  the graded run starts. It answers nothing and judges nothing, writes its own
  provenance record (`extract-manifest.json`, whose `resumes` list names the
  slice each later pass extracted) plus the cache's own identity record
  (`extractions-identity.json` — see Compatibility below) so a later `--real`
  run in the same directory resumes cleanly, and annotates each fresh cache row
  with the call's wall time and the endpoint's token counts where reported.
- **Canonical serialization layer in `scripts/external_reader.py`** — the
  stdlib-only reader grew a second, fully independent implementation of
  canonical JSON, NFC, `claims[].hash` recomputation and POSIX ustar framing.
  `tarfile` is never imported and `json.dumps` is never called, because the
  reference writer is built on both and reusing them would collapse the
  comparison into an implementation checked against itself. This is what
  unblocks the pinned M5 gate: 30/30 packages in a deterministic stress corpus
  and 6/6 packable committed samples are byte-identical to `aphelion.packer.pack`.
- **The CLI's JSON error line carries the error's notes.** When an error has
  notes (Python 3.11+), such as one naming a directory a failed `unpack` or
  `migrate --force` left behind, the line includes them as a `"notes"` list
  of strings. Lines for errors without notes are unchanged.
- **New public names.** In `aphelion.unpacker`: `check_member_names`,
  which runs the header checks of `unpack` without extracting anything,
  and the name checks `unpack` and `pack` share: `MemberNames` (finds the
  first collision), `member_path_key` (the collision key), `path_parts`,
  `non_portable_component`, `WINDOWS_RESERVED_CHARS` and
  `WINDOWS_DEVICE_RE`. In `aphelion.signer` (and its `__all__`):
  `parse_signer_manifest`, which checks a signer manifest against spec
  v0.5 §2.3.

### Changed

- **`verify_package` no longer re-reads the archive once per envelope.**
  Signer-manifest extraction was called inside the notary-resolution loop,
  re-reading the whole tar and re-parsing each signer manifest with an
  unguarded `json.loads` — work `validate_signatures` had already done once
  behind typed-error guards. `validator._validate_signatures_full()` now
  returns the parsed `SignerManifest` objects alongside the envelopes and
  `verify_package` reuses that mapping. Extraction is O(1) rather than O(N) in
  the envelope count, the duplicate unprotected parse is gone, and the public
  `validate_signatures()` signature is unchanged.
- **`spec/canonical-serialization.md` 1.0 → 1.1** — Rule 5 §10 and §7
  corrected to describe what conformant tar writers actually emit. §10 as
  written ("No extra trailing bytes") matched no tar writer in existence, and
  §7 admitted two byte-different encodings of zero. Both gaps were found by
  building the independent implementation above and byte-comparing it against
  the reference. **No producer or consumer behaviour changes** — the reference
  already emitted the now-documented form; the document was what was wrong.
- **`unpack` and `migrate --force` are all-or-nothing.** `unpack` extracts
  into a staging directory and moves entries into place only once every
  member has passed every check; `migrate --force` builds the new tree beside
  the destination and then swaps it in. If either fails or is interrupted
  (Ctrl-C included) before every entry is in place, the destination is put
  back as it was, or the error or a `RuntimeWarning` names the directory
  that still holds the original files, which is deleted only once it is
  empty. A staging or backup directory left behind is named in a note on
  the error (Python 3.11+) or in a `RuntimeWarning` that is shown even
  where warnings are ignored or turned into errors. A file in the
  destination is replaced by renaming the new one onto its name, so other
  hard links to it keep their content.
- **`unpack` refuses more destinations and archives**, and leaves the
  destination as it was:
  - a destination that is a symlink, a junction or a Windows mounted folder
    (unpack into a directory inside it instead), on Windows also when it is
    spelled `.` or `x/..` and the current directory or `x`'s parent, as
    named, is such a link;
  - a symlink or junction already in the destination where the archive has a
    file or a directory, and a directory where it has a file; such entries
    are left as they are;
  - two members that reach one entry on the target filesystem, for instance
    by a Windows 8.3 short name (`PX_E_6007`). `pack` does not see such
    aliases;
  - on a filesystem that reports no file identity (inode number 0), most
    archives into an existing destination (see Known limits below).
- **`migrate` refuses a destination that is, contains or lies inside the
  source** (`PX_E_2006`), before anything is written. So migrating an
  archive in place (`aphe migrate pkg.aphelion.tar pkg.aphelion.tar
  --force`) and migrating a directory into a subdirectory of itself no
  longer run, and `--force` no longer removes a source that lies inside
  the destination.
- **On Windows, `pack`, `unpack`, signature validation
  (`validate_signatures`) and `verify_package` (`aphe verify` on a package
  file) refuse member names Win32 cannot create**: device names such as
  `CON` or `aux.md`, names ending in a dot or a space, and the characters
  `<>:"|?*` and control characters. They also treat names that differ
  only by trailing dots or spaces as colliding. Other platforms accept
  both, as before.
- **Member names that collide once normalised are refused** (`PX_E_6007`)
  by `pack`, `unpack`, signature validation (`validate_signatures`) and
  `verify_package` (`aphe verify` on a package file), before anything is
  written. Names are compared without a leading `./` or empty and `.`
  segments, after NFC normalisation and full Unicode case folding (on
  Windows also without trailing dots and spaces), so two spellings of one
  file or directory, or a file and a directory of one name, can no longer
  share an archive. Full case folding also refuses pairs that NTFS keeps
  apart, such as `ß` and `ss`, `ﬁ` and `fi`, or `ς` and `σ`.
- **Signature validation (`validate_signatures`) refuses an archive whose
  members declare sizes `unpack` would refuse**, with the same codes: a
  member over the per-file limit (`PX_E_6010`), or a running total over the
  total limit (`PX_E_6011`) or over the compression-ratio limit
  (`PX_E_6012`), each at `unpack`'s defaults.
- **Every reader reads an archive once from front to back, and what it
  hands `tarfile` is bounded by the member headers it has checked**
  (`PX_E_6013`). `unpack`, `check_member_names`,
  `extract_signatures_jsonl`, `extract_signer_manifests`, signature
  validation (`validate_signatures`) and `verify_package` read an archive
  in `tarfile`'s stream mode, which never goes back, and keeps no list of
  the members it has read. Before reading on from a member, `tarfile` may
  be handed up to H bytes past the end of that member's data, for the next
  member's headers (pax or GNU long-name headers and its own). H is room
  for a pax header holding a path of `max_path_length` four-byte UTF-8
  characters and about 1 KiB of other records, plus the member's own
  header: the larger of 4,096 bytes and 1,024 bytes plus 4 ×
  `max_path_length` + 1,024 bytes rounded up to a multiple of 512 (4,096
  bytes at the default `max_path_length` of 512; 6,144 at 1,000). Before
  the first member, H + 1,024 bytes, as its headers may take 1,024 bytes
  more for global pax headers in front of it. A member whose header blocks
  take more is refused (`PX_E_6013`), so at the default policy so is a
  member whose pax header holds larger records, such as an extended
  attribute of about 3 KB or more. `max_path_length`
  counts characters after NFC normalisation, so a name stored decomposed
  (NFD, as HFS+ stores names) can need more than four bytes per counted
  character, and a member whose header blocks then take more than H is
  refused (`PX_E_6013`) too. Asking for more, or
  reading on after reaching the end of the archive 8 times, fails before
  another byte is handed out. An archive that ends before the end of a
  member's data, padded to a whole 512-byte block (inside the data or the
  padding after it), fails with `tarfile.ReadError` at the first read that
  finds its end, whatever is missing (unless its declared sizes are
  refused first), on every Python release; for a
  compressed archive, this is when its decompressed content ends there.
  So one pass hands `tarfile` at most
  `max_total_bytes` plus H + 511 bytes per `max_files` member plus H +
  1,024 bytes: 150,932,720 bytes at the default policy. A decompressing
  reader (gzip, bzip2, zstd) may decompress up to `io.DEFAULT_BUFFER_SIZE`
  (8 KiB, or 128 KiB from Python 3.14) ahead of that. Header bytes are
  bounded by this per-member allowance; the compression-ratio limit
  (`PX_E_6012`) counts the members' declared sizes only, as before. The
  archive must be a seekable file (not a pipe): its first bytes are read
  to tell its compression, and then it is read from the start.
- **Each call reads an archive a fixed number of times**, whatever it
  holds: `check_member_names`, `extract_signatures_jsonl`,
  `extract_signer_manifests` and `validate_signatures` once (signature
  validation collects `signatures.jsonl`, the signer manifests and
  `manifest.json` in the pass that checks the headers), `unpack` twice,
  and `verify_package` twice (the second pass of its unpack also collects
  what the signature checks read). `unpack` refuses (`PX_E_6013`), before
  writing it, a member its second pass sees with another name, type, size
  or place than its first, and an archive with one member more or fewer.
  The accessors, signature validation and `verify_package` use the
  default policy. The accessors run `unpack`'s header checks other than
  the name checks, so they too now refuse a link, device or other member
  type `unpack` refuses (`PX_E_6008`), more members than `max_files`
  (`PX_E_6009`), and an archive whose declared sizes `unpack` refuses.
- **A member that would take a reader further than its size says is
  refused before its data is read**: a sparse member, or one after a pax
  header with a `GNU.sparse.*` key `tarfile` can parse (`PX_E_6008`); a
  regular-file header in the old form (typeflag NUL) whose name field
  ends in `/` after a pax or GNU long-name or long-link header, which
  Python releases read as different types (a directory, or a regular file
  followed by its data) (`PX_E_6008`); such a header with no such header
  before it, which is a directory, if its size field is not 0, as `tar`
  programs read it as a directory with or without that many bytes of data
  after it (`PX_E_6008`); a negative size, in the member's header (for a
  GNU sparse member, also its real size), in a pax or GNU long-name header
  before it or in a pax record, and a member after a pax header with a
  `size` key (`PX_E_6010`); header blocks that do not lead, size by size,
  from where the member before ends to the member's own header, and a
  member `tarfile` reports with another type or size than its own header
  gives (`PX_E_6013`). A pax header here is any before the member, local
  or global, the first or a later one (`tarfile` may take a member's size
  from a later one). A negative size, and then a pax header that a Python
  release stops reading the archive at (below), in the header blocks read
  before the allowance is passed, come first; then reading past what the
  header allowance lets `tarfile` read (`PX_E_6013`); then a
  pax header that releases only read differently (below); then the
  member's other refusals. A member past `max_files` is refused as a
  release that stops at its headers reports it (a negative size, then a
  pax header of either kind), else as one too many (`PX_E_6009`). These
  header blocks, every pax record and the member's own header, with the
  member's type and size, are read again from the bytes handed to
  `tarfile`. Taken from `tarfile` are where the member's data and its
  headers begin, its name (with a pax path or GNU long name applied) and
  whether it is sparse; its type and size must be what its own header
  gives, and where its header blocks do not lead to its own header (it is
  then refused) its type only picks the code. So whether a member is
  refused is the same on every Python release, whether its `tarfile`
  reports a member with a negative size, skips it, stops there or reads
  on, and whichever type it gives such a header. So is the code, but for
  two cases: a pax header that a release stops at, followed later in the
  same header blocks by a negative size, can be `tarfile.ReadError` on
  some releases and `PX_E_6010` on others; and a number in a
  `GNU.sparse.*` value (a size, an offset or length, or a map entry) with
  more digits than `int()` reads from a string is `tarfile.ReadError`,
  while one it reads is refused as above (`PX_E_6008`, or `PX_E_6010` for
  a negative size). That digit limit is 4,300 by default, can be changed,
  and does not exist before Python 3.10.7; at 4,300, a value that long
  fits in the header allowance only with a `max_path_length` above the
  default. The `PX_E_6008` refusals of a header whose name field ends in
  `/` and the `PX_E_6010` refusals of a negative size in the header blocks
  give the header's place in the archive (and the name field), not the
  member's name, so their message is the same on every release, unless a
  negative pax `size` has more digits than `int()` reads (which, at the
  default limit of 4,300, also needs a `max_path_length` above the
  default): its member is then refused for
  having its size in a pax header. A GNU
  sparse member in the old form (type `S`) whose real size is negative is
  refused with its name. The text of a `tarfile.ReadError` depends on the
  release. A package never has any of these. A directory's size, if not
  negative, is ignored, as `tarfile` ignores it (no data follows a
  directory); a negative size is refused for every member type. A
  NUL-typeflag header whose name field ends in `/` with no such header
  before it and a size of 0 is a directory, as every release and `tar`
  program reads it.
- **A pax header that Python releases read differently is a read error
  on every release** (`tarfile.ReadError`, `PX_E_9001` at the command
  line), as on the releases that fail on it, whether this release's
  `tarfile` fails on it or reads on. Releases stop reading the archive at
  one with a record that is not whole (a length that is not 1 to 20
  digits followed by a space, a length under 5 or past the header's data,
  an empty key, no `=`, or a last byte that is not a newline), on which
  `tarfile` from Python 3.10.15, 3.11.10 and 3.12.6 on fails, while
  earlier releases stop reading its records there or read them
  differently, and read on; and at one whose first
  `<digits> hdrcharset=<value>` line, found anywhere in its data, has a
  value that is not UTF-8, on which earlier releases fail. Releases only
  read differently a header in which that line names `BINARY` and the header's
  first `hdrcharset` record does not, or the other way round (earlier
  releases take the line as the encoding of the header's names, later
  ones the record); a global pax header with a `hdrcharset` record or
  line, which earlier releases apply to the headers after it, so an
  archive whose global pax header carries one is refused, as is one whose
  writer adds a global `hdrcharset` because its global values are not
  UTF-8; and, for a GNU sparse 0.0 member, an `offset` or `numbytes` value
  that `int()` cannot read, on which later releases fail only after
  reading the headers after it (other sparse headers stay refused as
  sparse, `PX_E_6008`, and so does a value `int()` reads; how many digits
  it reads is above). Any other local pax header with a `hdrcharset` (its
  line's value UTF-8, and its line and first record agreeing on whether
  the names are `BINARY`) is read as before.
- **What `tarfile` or the decompressor raises for a damaged archive is
  `tarfile.ReadError`**: anything `tarfile` raises while it parses a member
  header other than an operating-system or out-of-memory error (for
  example `ValueError` for a `GNU.sparse.*` value it cannot read), and
  what the decompressor raises for a compressed archive that is damaged or
  cut short (`EOFError`, gzip's `BadGzipFile`, `zlib.error`,
  `lzma.LZMAError`, zstd's `ZstdError`, and the `OSError` without an
  errno that the bz2 module raises for invalid data). So is an archive, or
  the content of a compressed one, that ends inside a member's data or the
  padding after it (above). An operating-system
  error reading the archive file (an `OSError` with an errno) is raised
  unchanged, whatever the compression. The refusals above keep their
  codes. The command line reports `tarfile.ReadError`, like any error
  without a code of its own, as `PX_E_9001`. Known limit: a compressed
  archive's own integrity checks (the gzip CRC and length, a bzip2 block's
  CRC) run only when a read reaches them. A reader stops H bytes after the
  last member, and how far the decompressor reads ahead depends on the
  Python release (above), so whether damage that only these checks find
  is reported can differ by release.
- **Bytes after the end of the archive**: the H bytes (4,096 at the
  default policy) after the end of the last member, or after the start of
  an archive with no members, must be zeros, else every reader fails with
  `tarfile.ReadError` ("data after the end of the archive") on every
  Python release. Anything further on is not checked, and once a member
  has been read it is not read either. So of two archives written one
  after the other, the second is ignored if it starts more than H bytes
  after the end of the first one's last member, and the whole is refused
  if it starts within them.
- **xz and LZMA-alone archives are decompressed with at most 100,762,596
  bytes of decoder memory**, 1.5 times what the largest xz preset (`-9`,
  `-9e`) needs (about 67.2 MB; the exact figure depends on the liblzma
  build); one that needs more fails with `PX_E_6013` before the memory is
  taken. Concatenated xz streams are read one after another, as
  `lzma.LZMAFile` reads them. zstd archives (Python 3.14 and later) are
  decompressed with the library's default limit on the window size, 128
  MiB, so decoding one may take that much memory; one whose frame needs a
  larger window fails with `tarfile.ReadError`.
- **`unpack`, `check_member_names`, the accessors, signature validation
  (`validate_signatures`) and `verify_package` tell a compressed archive
  by its first bytes**, as `tarfile`'s stream mode does: gzip,
  bzip2, xz, zstd (Python 3.14 and later) and LZMA-alone whose header
  starts `5d 00 00 80` (the default properties, and a dictionary of 8 MiB
  or 8 MiB plus a multiple of 16 MiB); anything else is read as an
  uncompressed tar. Any other LZMA-alone archive, or a zstd archive that
  starts with a skippable frame, which `tarfile.open` read before, now
  fails with `tarfile.ReadError`. A package, an uncompressed or
  gzip-compressed ustar archive, is not affected.
- **Recommended Python versions for reading archives**: 3.10.21, 3.11.16,
  3.12.14, 3.13.15 or 3.14.7 and later. The limits above hold on earlier
  releases too; there, reading some archive headers can take longer.
- **`pack` refuses the member paths `unpack` refuses**: empty (`PX_E_6006`),
  absolute (`PX_E_6002`), containing a backslash (`PX_E_6004`),
  drive-prefixed such as `a:b.md` (`PX_E_6003`, on every platform), or with
  a `..` segment (`PX_E_6001`). It no longer writes member paths that
  `unpack` on the same platform refuses, but for one case: on platforms
  other than Windows, a library caller can still give `pack` names that
  contain NUL. Readers cut each name field at the NUL, so `unpack` writes
  such a member under another name, refuses it if nothing is left
  (`PX_E_6006`) or what is left has a `..` segment (`PX_E_6001`), and
  refuses two that become one (`PX_E_6007`). File
  names cannot contain NUL, so `aphe pack` never writes one.
- **`aphe sign --signer-id` must be a single path component.** An empty id,
  `.`, `..`, or an id containing `/`, `\` or NUL is refused (`PX_E_6001`)
  before any file is read or written; the id names
  `signers/<signer_id>.json`.
- **`verify` (and so `aphe verify`) performs the semantic checks
  `spec/validator.md` requires**, so a package that passed before can now
  fail: a `claim_instance_id` used by two manifest entries or emitted by two
  provenance events (`PX_E_4011`, ERR-SEM-005); an `event_id` used twice
  (`PX_E_4012`, ERR-SEM-006); a superseded or withdrawn manifest state
  that disagrees with the claim's last event, or a last supersede or
  withdraw without that state (`PX_E_5005`, ERR-SEM-013); a
  `target_claim_instance_id` that is not the instance in force at that
  event, or a manifest `claim_instance_id` its claim's provenance never
  emitted (`PX_E_5004`); a manifest path other than `claims/<claim_id>.md`
  (`PX_E_5002`). `spec/error-codes.md` gains `PX_E_4011`, `PX_E_4012` and
  `PX_E_5005`. Every sample and valid fixture in the repository passes.
  `pack` does not run these checks, so a package `pack` writes can fail
  `verify`.
- **`aphe verify --require-signed` and `--require-notary` need the package
  file.** Given an unpacked directory (which passed on the semantic checks
  alone) or any other path that is not a file, they now fail with
  `E_SIGNER_REQUIRED` (exit 3): signatures can only be checked on the
  `.aphelion.tar`. Verifying a directory without these flags is unchanged.
- **Malformed signer input is refused with typed errors, and base64 is
  decoded strictly.** A signer manifest is checked against spec v0.5 §2.3
  before it is used (a JSON object with a string `signer_id` equal to the
  file's stem and a string `algorithm`, standard-base64 `public_key_b64`,
  64-character lowercase hex `key_fingerprint`, and a string or null
  `notary_uri`); anything else is `E_SIGNER_MALFORMED`, where a raw
  `TypeError` or a later, unrelated code came out before. Public keys,
  private keys and signatures with characters outside the base64 alphabet
  are rejected instead of silently trimmed. A malformed
  `package_canonical_hash` in an envelope is `E_SIGNATURE_MALFORMED`, an
  Ed25519 key of the wrong length is `E_SIGNER_MALFORMED`, and `aphe sign`
  checks the key file before reading the package (exit 3 on a bad key).

### Removed

- **`aphe sign --algorithm hmac-sha256`.** `aphe sign` now accepts only
  `ed25519`; any other algorithm is a usage error. hmac-sha256 is a
  test-only algorithm (spec v0.5 §3.2) whose signer manifest carries the
  shared secret as `public_key_b64`; the library's `HMACSigner` and
  `HMACVerifier` stay for test fixtures. Packages already signed with it
  verify as before, with the test-algorithm warning. To sign from the CLI,
  pass `--algorithm ed25519` and a raw 32-byte Ed25519 private key as
  `--key-file` (this needs the `aphelion[signer]` extra).

### Fixed

- **Content-hash object keys are sorted by UTF-16 code unit, per RFC 8785
  §3.2.3** — not by Unicode code point. See Compatibility below.
- **`external_reader._LEGAL_TRANSITIONS` accepted an illegal lifecycle
  transition.** A spurious `("active", "publish") -> active` entry let the
  independent reader accept a `create -> publish` stream the reference
  validator correctly rejects with `ERR-SEM-LIFECYCLE-ILLEGAL`; per
  `spec/lifecycle-state-machine.md`, `publish` may only *reach* `active` from
  `(new)`/`draft`, never *from* `active`. Found by the differential test suite
  below — the first real bug it caught.
- **Extractor-output parsing no longer reports offsets into a payload the
  model never sent.** Standalone code-fence delimiter lines were deleted before
  parsing, which shifted every offset after them and could splice out a
  delimiter line sitting between two members of a broken object. They are now
  blanked to spaces of equal width: spaces are JSON whitespace, so the line is
  still skipped, while the text keeps its geometry and every reported offset
  indexes the completion as received. Parse errors now lead with the failing
  object's start offset and report the decoder's own position beside it.
- **Whitespace between extractor claim objects is JSON's four characters,**
  not `str.isspace`, which is also true for NBSP, form feed, vertical tab and
  the Unicode separators. Skipping those let the reader accept, between two
  claim objects, bytes it would refuse inside one.
- **`verify_package(..., require_notary=True)` implies `require_signed`,**
  as `aphe verify --require-notary` always has: a package with no
  signatures now fails with `E_SIGNER_REQUIRED` instead of passing when a
  caller passes `require_notary=True` alone.

### Compatibility

- **Content hashes change only for payloads with non-BMP object keys.** RFC
  8785 sorts object members by UTF-16 code unit, and that order coincides with
  code-point order for every BMP key — a BMP character's UTF-16 encoding is a
  single code unit equal to its code point — so BMP-only payloads are
  byte-identical to the previous code-point-sorted output and their hashes are
  unchanged. The orders diverge only when a key contains a supplementary-plane
  character (U+10000..U+10FFFF), whose leading UTF-16 surrogate unit
  (0xD800..0xDBFF) sorts below U+E000..U+FFFF: a `U+1F600` key now precedes a
  `U+FFFF` key. A package whose manifest carries such a key hashes differently
  than it did before this change. `spec/content-hash.md` records the rule as
  Rule 0.
- **Benchmark run directories created before this branch are refused on their
  next `--real` resume.** The extraction cache now carries its own provenance
  record, `extractions-identity.json`, written beside `extractions.jsonl` and
  naming the extractor pin and model config, the haystack, the split, the corpus
  directory and the digests of the corpus, the split manifest and
  `benchmarks/longmemeval/`. Both `--real` and `--extract-only` reconcile against
  it before reading or appending a row, and rows with **no** record are refused
  rather than adopted: nothing says which extractor, corpus or harness revision
  produced them, and writing this pass's identity over them would mint an
  attestation for bytes it never produced. Every output directory created before
  this change holds `extractions.jsonl` and no sidecar, so it hits exactly that
  refusal and raises `ExtractionIdentityMismatchError`.

  **There is no supported way to attest such a cache after the fact, and a fresh
  `--out-dir` is required.** The record's `extraction_harness_sha256` is a digest
  over the harness source *as it was when the rows were written*, which this
  branch has changed and which no older run recorded — so even a hand-written
  sidecar could not honestly reproduce it, and one carrying today's digest would
  attest to code that did not produce those rows. The refusal message names the
  manual restore path for the one operator who can independently vouch for a
  cache's provenance; it is an escape hatch, not a migration. Extraction work
  already paid for under a pre-branch revision has to be re-extracted.
- The benchmark harness is additive and imports nothing into the shipped
  package; `src/aphelion/` is untouched by it.

### Known limits

- **On a filesystem that reports no file identity** (inode number 0 for
  every file), any two of its entries look like one entry, so these fail
  where they worked before:
  - `unpack` into an existing destination, even an empty one, with
    `FileExistsError` (`PX_E_9001` at the command line): "cannot unpack
    over the backup directory" when two members share a top-level entry
    (as in a package with two or more claims or signers, or an archive
    with a directory entry and a file in it), and "cannot unpack over the
    staging directory" when the archive would replace an entry the
    destination has or add into one of its directories;
  - `verify_package` (`aphe verify` on a package file), the same way, when
    the temporary directory is on such a filesystem and two members of the
    package share a top-level entry;
  - `migrate`, with `PX_E_2006`, when the source and the destination are
    both on it.

  Still working there: `unpack` into a new destination, and into an
  existing one when the archive only adds new top-level entries of one
  member each; `check_member_names`, `validate_signatures` and `pack`;
  and `migrate` from or to another filesystem.
- **On Windows without long-path support, `unpack` and `migrate` build
  under paths up to 53 characters longer than the final ones**, while
  Windows creates a file only up to 259 characters and a directory only
  up to 247 (a member is staged 28 characters deeper, and an existing
  destination's backup directory is 53 characters longer than its path).
  So these fail, or leave files behind, where they worked before:
  - `unpack` of a member whose final path is a file of 232 to 259
    characters, or that is or lies in a directory of 220 to 247
    characters, and of any archive into a new destination of 220
    characters or more or into an existing one of 195 or more, with
    `FileNotFoundError` (`PX_E_2005` at the command line);
  - `verify_package` (`aphe verify` on a package file), which has the
    same limits with its temporary directory as an existing destination:
    every package fails when the directory for temporary files has a path
    of 183 characters or more (so the directory it makes there has 195 or
    more), with `FileNotFoundError` (`PX_E_2005`);
  - migrating a directory whose new tree would hold such a file or
    directory path, with `shutil.Error`, which the command line reports
    as `PX_E_9001` (exit 1) with a message listing each file or directory
    it could not copy, and migrating one to a destination of 220
    characters or more (new, or existing with `--force`), with
    `FileNotFoundError` (`PX_E_2005`);
  - `migrate --force` over a destination that holds a file or directory
    path of 231 characters or more puts the new tree in place, but leaves
    the old one in `.<dst>.replaced-*`, with a warning naming it.
- **A destination whose name (its last path component) is 228
  characters or longer (bytes on Linux), within 27 of the 255 limit,
  cannot be staged**, on every platform: `unpack` into a new destination
  of such a name, and migrating a directory to one, with or without
  `--force`, fail with `OSError` (`PX_E_9001` at the command line; on
  Windows without long-path support such a destination's path is over
  220 characters and already fails as above), and `migrate` also warns
  that it could not remove a staging
  directory it never created. This limit does not apply to `unpack` into
  an existing destination.

### Tests

- **Differential and fuzz hardening for the package format**
  (`tests/test_diff_fuzz_hardening.py`), in three families:
  1. **Differential** — generated and mutated single-claim packages, schema-valid
     by construction, asserting the reference validator and the stdlib-only
     `scripts/external_reader.py` agree on the lifecycle classification. A
     hand-picked scenario matrix, a Hypothesis biconditional over random event
     streams, and the soundness invariant *reference-valid ⇒ external-valid*.
  2. **Canonical-byte / hash stability** — identical logical input yields
     identical canonical bytes and content/package hashes across NFC-vs-NFD
     Unicode, CRLF-vs-LF frontmatter, and JSON/YAML key-order perturbation.
  3. **Security-surface fuzz** — path traversal, hostile member types,
     archive-bomb budgets, malformed signer/notary envelopes,
     `signatures.jsonl` order and trailing-newline invariants, and
     non-canonical YAML, each asserted to be a typed rejection with a
     deterministic error code, identical on repeated runs.
- Regression test asserting `extract_signer_manifests` is called at most once
  for a two-envelope package (it was called three times before).
- UTF-16 code-unit key-order tests, including the non-BMP divergence.

## [0.6.0] — 2026-06-27

### Added

- **R7.2 — Notary attestation envelope** per the new
  `spec/v0.6-notary-attestation.md`. This fills the v0.5 §4 trust-notary
  *extension point* (which only ever yielded `"verified-locally"`) with a
  pinned envelope format and verification path:
  - **`NotaryAttestationEnvelope`** frozen dataclass
    (`src/aphelion/trust.py`) — a notary's detached attestation that a
    `key_fingerprint` is the key it associates with a `signer_id`. Fields:
    `notary_id`, `signer_id`, `key_fingerprint`, `algorithm`, `signed_at_iso`,
    `signature_b64`.
  - **`compute_attestation_canonical_hash`** — `sha256` over the canonical
    JSON of `{key_fingerprint, notary_id, signer_id}`. Binds notary, signer,
    and key; deliberately does NOT bind a package hash, so one attestation is
    reusable across every package that key signs.
  - **`canonical_attestation_bytes`** / **`parse_attestation_line`** — byte-
    deterministic round-trip over the existing canonical-JSON machinery;
    structural failures raise `E_SIGNATURE_MALFORMED`.
  - **`resolve_notary_attestation(signer_manifest, attestation,
    notary_manifest)`** — returns `"verified-by-notary"` when every §3 rule
    holds: signer/key/notary identity binding, registry algorithm,
    pre-dispatch algorithm-match confused-deputy guard, notary fingerprint
    recompute, and signature verification (hmac-sha256 reference + real
    ed25519 under the `[signer]` extra).
- New error code **`E_SIGNER_NOTARY_INVALID`** (`spec/error-codes.md`,
  `spec/v0.6-notary-attestation.md` §4) for an attestation that is
  structurally present but fails an identity/fingerprint binding check.

### Compatibility

- Strictly additive over v0.5. The v0.5 `resolve_notary` stub and the
  `NotaryAttestation` `Literal` (`"verified-locally"` | `"verified-by-notary"`)
  are unchanged; a package with no attestation behaves exactly as before. No
  mandatory new file. `E_SIGNER_NOTARY_REQUIRED` wiring (v0.5) is unchanged.

### Tests

- 537 tests GREEN (was 513). +24 in `tests/test_trust_notary_envelope.py`
  (canonical-hash determinism + field binding, envelope round-trip + malformed
  rejection, full §3 rule sequence per error code, ed25519 round-trip/tamper
  under the `[signer]` extra, and regression guards that the v0.5 stub and
  Literal are untouched).

## [0.5.1] — 2026-06-15

### Fixed

- **Signer manifest guard** (`src/aphelion/validator.py`): `validate_signatures`
  loaded `manifest.json` behind a bare `assert manifest_member is not None`.
  Under `python -O` the assert is stripped, so a crafted archive whose
  `manifest.json` is a non-regular member (directory / symlink) made
  `tarfile.extractfile()` return `None` and surfaced a raw `AttributeError`
  on `.read()` instead of a typed validation error; an absent `manifest.json`
  raised `KeyError`. Replaced the assert with explicit typed raises matching
  the codebase's None-handling idiom: `SchemaError` `MISSING_FILE` for an
  absent manifest, `SecurityError` `DISALLOWED_MEMBER_TYPE` for a non-regular
  member. The guard now holds with asserts stripped.

### Changed

- Applied ruff safe autofixes (F401 unused imports, E741 ambiguous variable
  names). No behavioural change.

### Tests

- 513 tests GREEN (was 412 in v0.5.0). Added RED-first coverage in
  `tests/test_verifier_signed.py` for the absent-manifest and
  non-regular-manifest shapes, including a `python -O` subprocess check
  confirming the guard holds when asserts are stripped.

### Compatibility

- Fully backward-compatible bugfix release. No format, schema, or public API
  changes; every package that validated under v0.5.0 still validates.

## [0.5.0] — 2026-04-27

### Added (additive — v0.4 readers ignoring `signatures.jsonl` + `signers/` still validate every previously-conforming v0.4 package unchanged)

- **Signer / trust extension** per `spec/v0.5-signer-trust.md`. Three roles
  separated: `author` (v0.3 frontmatter, unchanged), `approver` (new
  optional `approvers: [...]` frontmatter), `signer` (new package-level,
  per-package signature envelope).
- **`SignatureEnvelope`** + **`SignerManifest`** frozen dataclasses
  (`src/aphelion/signer.py`). Package signatures are detached, append-only,
  written to `signatures.jsonl` at archive root, lex-sorted by
  `(signer_id, signed_at_iso)` for byte-deterministic round-trip.
- **Algorithm registry**: `hmac-sha256` (TEST-ONLY reference; emits a
  warning when verified unless `--allow-test-algorithms`) and `ed25519`
  (RFC 8032; real impl available under `aphelion[signer]` extra requiring
  `cryptography >= 42`; algorithm-agnostic core ships in stdlib).
- **`src/aphelion/sig_pack.py`** — `write_signatures_jsonl` /
  `read_signatures_jsonl` / `is_sorted_correctly`. Pure, deterministic,
  spec §2.4 line-ordering enforced; mismatch raises
  `E_SIGNATURE_ORDER` / `E_SIGNATURE_MALFORMED`.
- **`src/aphelion/trust.py`** — `resolve_notary` /
  `attestation_is_acceptable` extension-point stubs per spec §4. v0.5
  performs zero notary I/O; every lookup yields `verified-locally`.
  Normative resolver protocol reserved for v0.6+.
- **Verifier integration** (`src/aphelion/verifier.py`):
  `verify_package(tar_path, *, require_signed=False, require_notary=False)
  -> VerifyResult`. Spec §5 verification chain runs whenever
  `signatures.jsonl` is present in the archive, regardless of
  `require_signed` (presence opts the package into §5). `require_signed`
  controls whether ABSENCE is an error; `require_notary` controls whether
  `verified-locally` is acceptable.
- **CLI**: new `aphe sign --package … --signer-id … --algorithm
  {hmac-sha256,ed25519} --key-file … --out …` subcommand, plus
  `--require-signed` / `--require-notary` flags on `aphe verify`. Existing
  CLI subcommands unchanged.
- **`src/aphelion/unpacker.py`** — additive read-only accessors
  `extract_signatures_jsonl(tar_path) -> bytes | None` and
  `extract_signer_manifests(tar_path) -> Mapping[str, bytes]`.
- **`src/aphelion/validator.py`** — `validate_signatures(tar_path)
  -> tuple[SignatureEnvelope, ...]`, full §5 rule sequence: parse, order
  check, manifest lookup, fingerprint recompute, canonical-hash recompute,
  algorithm registry, signature verify.
- Optional dependency: `aphelion[signer] = ["cryptography>=42"]`.
- Spec error codes (§6): `E_SIGNATURE_MALFORMED`, `E_SIGNATURE_HASH_MISMATCH`,
  `E_SIGNATURE_INVALID`, `E_SIGNATURE_ORDER`, `E_SIGNER_MISSING`,
  `E_SIGNER_MALFORMED`, `E_SIGNER_FINGERPRINT_MISMATCH`,
  `E_SIGNER_ALGORITHM_UNKNOWN`, `E_SIGNER_ALGORITHM_UNAVAILABLE`,
  `E_SIGNER_REQUIRED`, `E_SIGNER_NOTARY_REQUIRED`. Documented in
  `spec/error-codes.md`.

### Tests

- 412 tests GREEN (was 305 in v0.4.0). +107 in v0.5: 57 in `test_signer.py`,
  19 in `test_sig_pack.py`, 9 in `test_trust.py`, 22 in
  `test_verifier_signed.py`. Coverage: signer.py / sig_pack.py / trust.py
  100%; validator.py 96%; verifier.py 97%; unpacker.py 97%; cli.py 85%.

### Compatibility

- v0.5 is **strictly additive**. Existing v0.4 packages verify with
  identical behavior. v0.5 reader on an unsigned v0.4 package returns
  `VerifyResult(envelopes=(), attestations=())` and exits 0. No v0.4 →
  v0.5 migration is required.

## [0.4.0] — 2026-04-24

### Breaking (wire seal)

- `manifest.format_version` is now `"2.0"` only. v0.3 packages
  (`"1.0"` / `"1.1"`) are rejected with `PX_E_3003`
  (`ERR-SYN-VERSION-UNKNOWN-MAJOR`) in both `--strict` and `--lenient`.
  Migrate legacy packages via `aphe migrate` (see below).
- `manifest.dpkg_spec_version` renamed to `aphelion_spec_version`
  (top-level, optional, semver). The nested
  `extensions.dpkg_spec_version` that v0.3 `init_skeleton` wrote is
  also gone; v0.4 `init` emits the top-level field directly.
- `SUPPORTED_SPEC_VERSIONS` in `aphelion.initializer` narrows to
  `{"0.4.0"}`. Asking `init` for `"0.2.x"` / `"0.3.0"` now raises
  `UNSUPPORTED_SPEC_VERSION`; those packages belong to v0.3 and are
  fed through `aphe migrate` instead.

### Added

- `aphelion.migrate` — one-shot v0.3 → v0.4 transform plus directory
  and `.aphelion.tar` wrappers. Pure data transform (no IO) is exposed
  as `migrate_v03_to_v04(manifest) -> manifest`; wrappers
  `migrate_directory(src, dst)` and `migrate_archive(src, dst)` copy
  every non-manifest byte verbatim and rewrite only `manifest.json`.
- `aphe migrate <src> <dst> [--force]` CLI subcommand. Refuses to
  overwrite an existing destination unless `--force`.
- `schemas/aphelion-v0.4.json` — new aggregate `$ref` bundle under the
  `https://aphelion.spec/schemas/` namespace. Replaces the
  `https://dpkg.spec/...` URL that v0.3 artifacts used.
- `schemas/diff-v0.4.json` + `schemas/expected-normalized-v0.4.json` —
  v0.4-namespaced companions for the diff and sample contracts.
- `spec/migration-v0.3-to-v0.4.md` — normative one-shot migration
  contract and pre/post conditions.
- `tests/test_migrate.py` — 23 tests covering the transform,
  directory + archive wrappers (incl. size budgets, directory
  pass-through, atomic write, force overwrite), and the `aphe
  migrate` CLI path.
- Fixture `invalid-syntax/schema-version-legacy` — locks the expected
  `PX_E_3003` rejection of a `format_version: "1.1"` manifest under
  v0.4.

### Changed

- `SCHEMA_VERSION_MAX` `1.1 → 2.0`; `SPEC_VERSION` `0.3.0 → 0.4.0`;
  package `__version__` `0.3.0 → 0.4.0`.
- `schemas/manifest.schema.json`: `$id` migrated to
  `https://aphelion.spec/...`, title `"DPKG Manifest"` →
  `"Aphelion Manifest"`, `format_version` enum narrowed to
  `["2.0"]`, top-level property `dpkg_spec_version` removed in favour
  of `aphelion_spec_version`.
- `init_skeleton` now stamps `format_version: "2.0"` +
  `aphelion_spec_version: "0.4.0"` (was `1.1` / extensions nested).
- `aphelion.content_hash.EXCLUDED_KEYS`: `dpkg_spec_version` removed,
  `aphelion_spec_version` added. Reserved-prefix exclusion unchanged.
- `aphelion.diff` emits `diff_spec_version: "0.4.0"` and points at the
  new `schemas/diff-v0.4.json` artifact.
- `scripts/external_reader.py` accepts `format_version: "2.0"` only.
- Eight canonical samples regenerated against the v0.4 wire
  (`aphelion_spec_version` + `format_version: "2.0"` in every
  `manifest.json`, `expected-normalized.json` pinned to
  `expected_normalized_version: "0.4"`).

### Preserved deliberately

- `schemas/dpkg-v0.3.json` / `schemas/diff-v0.3.json` /
  `schemas/expected-normalized-v0.3.json` stay verbatim as historical
  wire artifacts referenced by v0.3 tags.
- `PX_E_*` error-code prefix — remains the Parallax-ecosystem
  taxonomy, unchanged across the v0.3 → v0.4 break.
- v0.2.x / v0.3.0 `CHANGELOG` entries stay historical (references to
  `dpkg_spec_version` in those entries describe what was true at the
  time of shipping and are not rewritten).

## [0.3.0] — 2026-04-23

### Renamed

- Package renamed from `dpkg` to `aphelion`; CLI command changed to `aphe`
  (shorter type for frequent invocation). Wire format field
  `dpkg_spec_version`, schema artifact filenames (`schemas/dpkg-v0.3.json`,
  `schemas/diff-v0.3.json`, `schemas/expected-normalized-v0.3.json`), and
  error-code prefix `PX_E_*` are preserved verbatim: those are v0.3
  wire/ecosystem contracts and will be re-spec'd in v0.4 when the format
  itself advances. Archive extension changed `.dpkg.tar` → `.aphelion.tar`.

### Added

- `format_version` 1.1 — the wire-schema bump accepted alongside 1.0.
  `manifest.schema.json` `format_version` is now `enum: ["1.0", "1.1"]`;
  the validator accepts both, packers emit 1.1 for new skeletons.
- `aphelion.lifecycle` — state-machine enforcement module (pure stdlib).
  Walks provenance per `claim_id` in canonical `(occurred_at_ms,
  event_id_lex)` order, raising `PX_E_5101`
  (`ERR-SEM-LIFECYCLE-ILLEGAL`) on illegal transitions and
  `PX_E_5102` (`REAFFIRM_MISSING_TARGET`) when a `reaffirm` lacks
  `target_claim_instance_id`. Wired into `validate_package` as the
  third pass so every validate call enforces semantic lifecycle.
- `target_claim_instance_id` enforcement (spec §5.5) —
  `aphelion.lifecycle` rejects `create` / `publish` that carry the field
  (→ `PX_E_5101`, neither has a prior instance to point at) and
  `reaffirm` / `revise` / `supersede` / `withdraw` that omit it
  (→ `PX_E_5102` for `reaffirm`, `PX_E_5101` for the other three).
  `aphelion.validator` additionally pattern-checks the field against
  UUID-v7 (`PX_E_4001`) at the schema layer.
- `aphelion diff <a> <b>` command + `aphelion.diff` module — layered diff
  (manifest / claim-set / per-claim evidence / provenance timeline).
  `--json` emits a structured payload validated against
  `schemas/diff-v0.3.json` (`diff_spec_version: "0.3.0"`); the
  human-text form carries the mandatory
  `"NOTE: Human-readable diff is informational only; the JSON form
  (--json) is the machine contract"` banner. Exit 0 iff the diff is
  empty.
- `aphelion validate --strict` / `--lenient` mutually-exclusive modes
  (default strict).
- `schemas/dpkg-v0.3.json` — aggregate JSON Schema that `$ref`s
  manifest / claim-frontmatter / provenance-event, giving an external
  consumer a single document to point a JSON Schema validator at.
- `schemas/diff-v0.3.json` — JSON Schema for the diff output shape.
- `schemas/expected-normalized-v0.3.json` — schema for the
  `expected-normalized.json` fixture companion format.
- `scripts/external_reader.py` — stdlib-only reference reader
  (~160 LOC) that classifies every sample under `samples/` without
  importing `aphelion` / `parallax` / `memory`. Proves the wire format
  is self-describing. `tests/test_external_reader.py` guards the
  stdlib-only contract via AST scan and the verdict contract via
  subprocess exit code.
- 8 canonical samples under `samples/` — each with `manifest.json`,
  `provenance.jsonl`, claim files, `README.md`, and
  `expected-normalized.json`: `architecture-claim`,
  `contradictory-claim`, `duplicate-reaffirm-collision`,
  `minimal-empty`, `multi-source-claim`, `revise-withdraw-flow`,
  `unicode-normalization`, `withdraw-then-illegal-reaffirm`.
- `spec/content-hash.md`, `spec/lifecycle-state-machine.md`,
  `spec/VERSIONING.md`, `spec/reserved-namespaces.md`,
  `spec/error-codes.md`, `adr/0001-content-hash-granularity.md`,
  plus the normative Parallax-side mirror
  `<parallax-repo>/spec/parallax-exchange.md`.
- `.forbidden-terms.txt` + `scripts/check_forbidden_terms.py` +
  `tests/test_forbidden_terms.py` — CI-enforced guard against the
  public leaking of pre-rename terms. Pre-commit hook installable
  separately.
- Reserved namespace prefixes `parallax:` / `internal:` — opaque
  pass-through in Aphelion. Excluded from content-hash computation.
  Adapter layer MUST strip them on export.
- Version axes separated: `format_version` (wire, semver MAJOR.MINOR)
  and `dpkg_spec_version` (release, semver). Unknown MAJOR is
  `PX_E_3003` (hard reject); known MAJOR + unknown MINOR is
  `PX_E_3001` (warn in `--lenient`, reject in `--strict`). See
  `spec/VERSIONING.md`.
- Archive format frozen at uncompressed POSIX ustar. Extraction
  limits codified in `spec/packaging.md` §7: `max_decompressed_size`
  100 MiB, `max_files` 10 000, `max_file_bytes` 25 MiB,
  `max_compression_ratio` 100, `max_path_length` 512. Module
  constants `PACKAGE_TOTAL_BYTES_LIMIT` and
  `PACKAGE_SINGLE_FILE_BYTES_LIMIT` exported by `aphelion.unpacker`.
- Error code bands documented: 1NN TYPE, 2NN STRUCTURE, 3NN VERSION,
  4NN FORMAT, 5NN CONSISTENCY, 6NN SECURITY.

### Changed

- `SCHEMA_VERSION_MAX` bumped `1.0` → `1.1`; `SPEC_VERSION`
  `0.2.2` → `0.3.0`; package `__version__` `0.2.2` → `0.3.0`.
- `init_skeleton` now stamps `format_version: "1.1"` and
  `dpkg_spec_version: "0.3.0"` by default (older spec versions
  remain accepted via `--spec-version`).
- `validate_package` now runs three passes in order: (1) shape /
  type, (2) chain integrity, (3) lifecycle state machine. The
  additional lifecycle pass catches errors that previously slipped
  through when only the verifier was run.

## [0.2.2] — 2026-04-21

### Added

- `.github/workflows/ci.yml`: 9-cell CI matrix (ubuntu-latest /
  windows-latest / macos-latest × Python 3.10 / 3.11 / 3.12). Windows +
  py3.11 listed first in the matrix because the 2026-04-19 cp950 incident
  showed it is the most fragile cell, so surfacing failures there earliest
  saves runtime on the other 8. Each cell runs `pytest --cov ... --cov-fail-under=80`
  plus a `init → validate → pack → unpack → verify` smoke test (bash on
  Linux/macOS, PowerShell on Windows).
- `aphelion.output.Writer` + `detect_color`: bound output policy (`json_mode`,
  `color`, stdout) threaded through every subcommand. Color is auto-off for
  non-tty streams and when `NO_COLOR` is set (per https://no-color.org).
- `aphelion --json`: global flag that switches success output on stdout to a
  single JSON line `{"ok": true, "command": ..., "summary": ..., ...}`
  suitable for shell pipelines. Errors stay as JSON lines on stderr whether
  or not `--json` is passed, preserving the v0.2.1 error contract.
- `aphelion --no-color`: force plain text even when stdout is a tty.
- `aphelion --version` dual display: now reports package + spec + schema
  (`aphelion 0.2.2 (spec 0.2.2, schema 1.0)`) so users never have to guess
  which number their validator cares about. Closes Top-5 risk #5.
- `SPEC_VERSION` constant in `aphelion.__init__` (tracked independently from
  `__version__` so a maintenance release can ship without bumping the
  on-disk format).
- `tests/test_cli_output.py`: 15 tests covering --json structure, ANSI
  stripping in non-tty / `NO_COLOR` / `--no-color`, Writer unit behavior,
  `--version` dual display, and a full 5-step JSON-mode pipeline smoke.
- README quickstart rewritten as a copy-pastable 5-minute walkthrough with
  expected output for every command.

### Changed

- `aphelion.initializer.SUPPORTED_SPEC_VERSIONS` accepts `0.2.2` in addition to
  `0.2.0` / `0.2.1`.
- `src/aphelion/cli.py` refactored to use `Writer` for success output; error
  handling paths (`DpkgError` / `FileNotFoundError` / catch-all) unchanged.

### Risk mitigations (v0.2.2 Top-5)

| # | Risk                                | Mitigation shipped in this release                               |
|---|-------------------------------------|------------------------------------------------------------------|
| 1 | `init` destroys existing DB         | Two-key gesture (`--force` + `--i-know-what-im-doing`) from v0.2.1 carried through — CI smoke exercises default-safe path. |
| 3 | Error code granularity              | Registry stable since v0.2.1; no new codes in this release.      |
| 4 | Windows cp950 / newlines            | CI sets `PYTHONIOENCODING=utf-8` + `PYTHONUTF8=1`; Windows+py3.11 first in the matrix. |
| 5 | Spec vs package version confusion   | `--version` now shows both numbers side by side.                 |

## [0.2.1] — 2026-04-21

### Added

- `aphelion.error_codes`: canonical `ErrorCode` registry using the
  `PX_E_<CCNN>` scheme across six category bands (1NN TYPE, 2NN STRUCTURE,
  3NN VERSION, 4NN FORMAT, 5NN CONSISTENCY, 6NN SECURITY) plus a 9NN GENERIC
  fallback. Single source of truth for every machine-readable error code
  emitted by the package. See `spec/error-codes.md`.
- `aphelion.initializer` + `aphelion init` CLI subcommand: creates an Aphelion skeleton
  (`manifest.json`, `provenance.jsonl`, `claims/`) in an empty destination.
  Default refuses an existing package; overwrite requires both `--force`
  **and** `--i-know-what-im-doing` (two-key safety gesture). Supports
  `--spec-version 0.2.0` / `0.2.1` via `extensions.dpkg_spec_version`.
- `tests/test_properties.py`: four `hypothesis`-based property tests
  covering canonical JSON round-trip, unknown-field rejection, non-UUID
  claim_id rejection, and `init` determinism.
- Extended fixture factory to 41 golden cases.

### Changed

- All source modules migrated from legacy `ERR-VAL-*` / `ERR-SEM-*` /
  `ERR-SEC-*` string literals to `ErrorCode.*` enum members. No hardcoded
  `PX_E_*` strings remain outside `error_codes.py`.
- `README.md` + `spec/validator.md`: reference the new registry; former
  `ERR-SEM-*` codes are annotated as migrated.

### Coverage

- 123 tests pass (up from 89 baseline).
- `aphelion.validator`: 99%, `aphelion.verifier`: 96%, `aphelion.initializer`: 98%,
  `aphelion.error_codes`: 98%, package total: 93%.

## [0.2.0] — 2026-04-21

### Added

- `aphelion.canonical_json`: deterministic JSON serializer (NFC at insert time,
  duplicate-key rejection, NaN/Infinity rejection, float rejection). Reproduces
  the spec worked example (`{"a":"café","b":2}\n`) to SHA-256
  `d2995dc401d3e4b85320775178dbf4cff5393f8ba3b6f63c489ea7acde97f682`.
- `aphelion.canonical_tar`: deterministic uncompressed POSIX ustar writer with
  fixed mtime/uid/gid/uname/gname, NFC-sorted member order, and rejection of
  symlink/hardlink/device/fifo members.
- `aphelion.errors`: exception hierarchy (`DpkgError`, `SchemaError`,
  `SecurityError`, `SemanticError`, `VerificationError`) with
  machine-readable codes and single-line JSON emission to stderr.
- `aphelion.validator`: hand-coded strict-subset validator for `manifest.json`
  and `provenance.jsonl` events (no `jsonschema` dependency).
- `aphelion.packer`: deterministic source-dir → `.aphelion.tar` packing with hash
  recomputation and re-canonicalization.
- `aphelion.unpacker`: safe streaming extract with budgets for file count,
  total bytes, per-file bytes, compression ratio, and path length. Rejects
  path traversal, absolute paths, Windows drive paths, backslashes,
  symlinks, hardlinks, devices, and fifos.
- `aphelion.verifier`: four-check semantic verification (hash, fileset, chain,
  refs).
- `aphelion.cli`: `argparse`-based CLI exposing `validate`, `pack`, `unpack`,
  `verify` (`init` deferred to v0.2.1; `diff` deferred to v0.3.0).
- Golden fixture suite: 33 cases across `valid/` (8), `invalid-syntax/` (10),
  `invalid-semantic/` (6), `archive-security/` (7), and `round-trip/` (4),
  each with a README describing expected exit code and error code.
- pytest suite: 87 tests covering worked-example reproduction, round-trip
  byte-equality, security rejections, and every ERR-* code path.

### Invariants

- `pyproject.toml`: `dependencies = []` — zero runtime dependencies.
- `pack(src) → bytes` is byte-deterministic across runs (verified via
  SHA-256 equality in unit tests).
- `pack → unpack → pack` yields byte-identical archives (verified across 4
  round-trip fixtures including NFD-input normalisation).
