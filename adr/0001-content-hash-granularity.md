# ADR-0001: Content Hash Granularity

- **Status:** Accepted
- **Date:** 2026-04-21
- **Deciders:** Chris (奇軒 / Datesheet lead)
- **Consulted:** Parallax architecture track
- **Supersedes:** —

## Context

DPKG must define what a "content hash" identifies. Two candidate granularities were considered:

1. **Per-claim SHA-256** — each claim's canonical bytes hash to a single digest; each claim is independently addressable and verifiable.
2. **Aggregate SHA-256 across sources** — one digest spans multiple sources / packages and is used to de-duplicate or attest cross-source identity.

This decision blocks downstream work:
- v0.2.0 fixtures cannot be authored without a fixed hash contract.
- Downstream consumers (Parallax and others) depend on knowing whether DPKG owns cross-source identity.

## Decision

**DPKG adopts per-claim SHA-256 as the single content-hash granularity.**

1. The hash of a claim is the SHA-256 of its canonical serialized bytes (see `spec/canonical-serialization.md`).
2. The hash of the package is the SHA-256 of the canonical `*.dpkg.tar` byte stream (see `spec/packaging.md`).
3. **Cross-source aggregation is explicitly out of scope for the DPKG format.**
   - Merging, deduplicating, or re-attesting claims across different source packages is an **application-layer concern**.
   - Parallax, Cmemory, or any downstream consumer MAY define their own aggregate identity, but such aggregates are NOT DPKG constructs and MUST NOT be encoded inside the package.

## Consequences

### Positive

- **Verifiability**: any single claim can be integrity-checked in isolation.
- **Composability**: applications can mix claims from multiple packages without DPKG-level re-hashing.
- **Spec minimality**: one hash rule, one granularity — no "which hash?" ambiguity.

### Negative

- **No built-in dedup**: if the same logical claim appears in two packages, DPKG cannot natively detect it. Consumers that need dedup must implement their own canonicalization.
- **Application-layer split**: downstream systems carry the burden of cross-source identity. We accept this trade to keep the format simple.

### Neutral

- `manifest.json` includes a `claims[].hash` field per claim. No aggregate hash field exists at the package level beyond the tar digest.

## Alternatives Rejected

- **Per-package Merkle tree**: rejected. Added complexity for marginal benefit; per-claim hashes already allow incremental verification, and a Merkle root can be computed by applications if needed.
- **Cross-source content hash**: rejected. Conflates format-level identity with application-level identity, creating coupling we explicitly want to avoid.

## Signatures

- **Chris** (Datesheet lead) — Accepted, 2026-04-21
