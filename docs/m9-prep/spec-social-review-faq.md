# Aphelion Spec Social Review — FAQ

> **文件版本**：m9-prep / draft  
> **受眾**：External implementors（Go / TypeScript / Rust 等語言的 Aphelion library 作者）  
> **目的**：在 spec review 階段，預先回答最常見的疑慮與設計質疑。  
> **License**：本文件隨 Aphelion spec 以 Apache 2.0 釋出。

---

## Q1: Why per-claim SHA-256 content_hash, not package-level?

**為什麼每個 claim 各自計算 SHA-256 content_hash，而不是整個 package 算一個就好？**

A: 核心考量是 **granular integrity verification**。一個 Aphelion package 可能包含數十甚至上百個 claims，若只有 package-level hash，任何單一 claim 的 bit-flip 或 tampering 都只能整包判定為 invalid，無法定位到具體哪個 claim 出了問題。Per-claim hash 讓 verifier 可以做到：

1. **Selective verification** — 只驗證你關心的 claims，不必解開整包。
2. **Partial download** — 在頻寬受限的 edge 場景（IoT、mobile），可以只 fetch + verify 單一 claim。
3. **Audit trail** — 每個 claim 的 hash 會寫進 event log（見 Q3），形成不可否認的 integrity chain。

Package-level hash 仍然可以作為 **optional convenience checksum**（在 `MANIFEST.json` 裡放一個 `package_hash`），但它不取代 per-claim hash。這是 Aphelion-ADR-0001 的最終決策，經過三輪 trade-off 討論。

---

## Q2: Why is canonical serialization tar order + mtime=0 + NFC + LF + key sort?

**為什麼 canonical serialization 要規定 tar 順序、mtime=0、NFC normalization、LF line ending、JSON key sort？**

A: 一句話：**cross-platform hash determinism**。不同 OS、不同 filesystem、不同 locale 會在以下環節產生 non-deterministic output：

| 問題來源 | 解法 |
|---|---|
| tar entry order 依賴 filesystem | 強制 **lexicographic byte-order sort** |
| mtime 因 build 時間不同而異 | 強制 `mtime = 0`（Unix epoch） |
| macOS NFD vs Linux NFC | 強制 **Unicode NFC** normalization |
| Windows CRLF vs Unix LF | 強制 **LF only** |
| JSON object key order 各語言不同 | 強制 **lexicographic key sort**（RFC 8785 / JCS-like） |

這些規則寫在 `spec/canonical-serialization.md` Rule 1–6（特別是 Rule 5 — tar Entry Canonicalization）。Implementor 只要在 serialization pipeline 末端加一個 `canonicalize()` pass，就能保證：同一組 claims，不論在哪個平台 build，產出的 `.aphelion.tar` 逐 byte 相同，SHA-256 一致。這對 reproducible build 和 supply chain security 至關重要。

---

## Q3: What's the event state machine?

**Claim 的 event state machine 長什麼樣？**

A: Aphelion 的每個 claim 都有一個 **lifecycle state**，由 event log 驅動狀態轉換。完整狀態機（normative source: `spec/lifecycle-state-machine.md` §3 + §4）：

```
       create
[*] ───────────▶ draft ──publish──▶ active ──reaffirm──▶ reaffirmed
                  │                  │  ▲                  │
                  │                  │  └──── decay ────────┘
                  │                  │
                  │                  ├──revise──▶ revised ──decay──▶ active (new instance)
                  │                  │
                  │                  ├──supersede──▶ superseded ──▶ [*]
                  │                  │
                  │                  └──withdraw──▶ withdrawn ──▶ [*]
                  │
                  └──── withdraw ────────────────▶ withdrawn ──▶ [*]
```

幾個重點：

- **draft → active**：透過 `publish`/`create` event。**Signer 為 optional per-package 屬性**（見 Q5 + `spec/v0.5-signer-trust.md` §1），**不是** lifecycle transition 的前置條件 — unsigned package 一樣 valid。
- **draft → withdrawn**：合法的 terminal 路徑（`spec/lifecycle-state-machine.md` §4 matrix `draft|withdraw`）。
- **active ⇄ reaffirmed / revised**：reaffirmed / revised 是 transient labels（不在 `manifest.json.claims[].state`），會 decay 回 active。
- **superseded / withdrawn**：terminal read-only — 任何後續 event 都是 `ERR-SEM-LIFECYCLE-ILLEGAL`。

每個 state transition 都是一個 **Event object**，帶 timestamp、actor、reason，串成 append-only log。Implementor 只需實作這個 state machine，不需要自己發明 lifecycle 管理邏輯。

---

## Q4: How does archive security work?

**Aphelion 的 archive 安全機制如何防範惡意內容？**

A: `.aphelion.tar` 本質上是 tar-based archive，而 tar 格式眾所周知有 path traversal 等攻擊面。`spec/packaging.md` Rule 5（Forbidden Inputs）+ Rule 6（Archive Format Freeze）+ Rule 7（Extraction Limits）規定了一組 **strict validation rules**，implementor 必須在 **deserialization 時**（而非事後）執行：

1. **No `..` in paths** — 任何 entry path 包含 `..` 即 reject。
2. **No absolute paths** — path 以 `/` 開頭即 reject。
3. **No symlinks** — tar entry type 為 symlink 即 reject。
4. **No hardlinks** — 同上，hardlink 也 reject（避免 link-based oracle attack）。
5. **Whole-archive size ≤ 100 MiB (104,857,600 bytes)** — `PX_E_6011`，反 decompression bomb。
6. **Per-file size ≤ 25 MiB**（reference impl 上限；spec 建議 50 MiB）— `PX_E_6010`。
7. **Entry count limit: 10,000** — 防止 inode exhaustion attack。
8. **No device files / FIFOs** — tar entry type 為 block/char device 或 FIFO 即 reject。

這些規則的設計哲學是 **deny by default, allowlist by spec**。Implementor 建議在 `ArchiveReader.open()` 內一次性跑完所有 checks，fail-fast。reference implementation（Python）的 `src/aphelion/unpacker.py` 就是 test oracle。

---

## Q5: Should I implement signer/trust?

**我需要實作 signer 和 trust model 嗎？**

A: **Short answer：v0.5 optional，v1 strongly recommended，v2 可能 mandatory。**

在 v0.5 spec 中，signer/trust 是 **optional extension**（`spec/v0.5-signer-trust.md` §1：role 表 `signer = Optional; per-package`）。一個沒有簽名的 `.aphelion.tar` 仍然 valid（§5：unsigned-valid 等同於 v0.4 通過），驗證器只會走 structural + hash 路徑。這讓早期 implementor 可以先 focus 在 core packaging 邏輯。

但在 v1（預計 2025 Q4），我們計劃將 signer 列為 **recommended**，理由是：

- Supply chain attacks 頻率上升，unsigned package 的信任度越來越低。
- Parallax runtime（見 Q7）在 production 環境會 **refuse unsigned claims**。
- Trust model（TOFU、CA-based、web-of-trust）的 spec 規範在 `spec/v0.5-signer-trust.md`（envelope §2.2 / algorithm §3 / verification §5 / 預留 §7）。

建議 implementor 現在就預留 `Signer` interface，即使 v0.5 只實作 `NoopSigner`。這樣 v1 升級時只需 plug in real implementation，不需要大改架構。

---

## Q6: How to migrate from v0.x to v1?

**從 v0.x 遷移到 v1 有多痛苦？**

A: 我們盡量讓遷移 **non-breaking**。具體策略：

**v0.1 → v1（one-shot migration script）：**

- `schema_version` 從 `0.1` 升到 `1.0`。
- 主要 breaking change：canonical serialization 規則（Q2）從 optional 變 mandatory。
- 我們會提供 migration CLI（Python，也可作為 library import）。**v0.5 已 ship `aphe migrate`** 作為 v0.3 ↔ v0.4 的範本（見 `src/aphelion/migrate.py`）；v1 migration 在 v1 spec 拍板後沿用同一 subcommand surface。
- 範例（**planned v1 syntax — exact CLI surface 待 v1 spec 拍板**）：
  ```bash
  # planned v1 invocation (subject to change before v1 ships)
  aphe migrate --from 0.x --to 1.0 ./my-packages/
  ```
- 該 tool 會重新計算所有 content_hash、重排 tar entries、更新 MANIFEST。

**v1 → v2（future-proofing）：**

- `schema_version` 欄位已經在 v1 MANIFEST 中佔位，type 為 `semver string`。
- v2 的 breaking changes（如果有）會透過 `schema_version` range 來區分。
- Implementor 建議在 deserialization 時做 **version gating**：
  ```python
  if manifest.schema_version.major > SUPPORTED_MAJOR:
      raise UnsupportedVersion(...)
  ```

總結：v0.x → v1 跑一次 script；v1 → v2 應該是 transparent minor upgrade，但我們保留了 breaking 的 escape hatch。

---

## Q7: Does Aphelion depend on Parallax runtime?

**Aphelion 是否依賴 Parallax runtime？**

A: **No. Absolutely not.** 這是最常見的誤解，我們在這裡正式澄清：

- **Aphelion** 是一個 **package format + lifecycle spec**，完全 runtime-agnostic。
- **Parallax** 是 Aphelion 的一個 **consumer**（也是由我們團隊開發），但它只是眾多可能的 runtime 之一。

Aphelion spec 的所有 dependencies 都是 **standard library level**：

| 依賴 | 說明 |
|---|---|
| SHA-256 | 各語言 stdlib 或 well-known crypto lib |
| tar | 各語言 stdlib 或 well-known archive lib |
| JSON | 各語言 stdlib |
| Unicode NFC | 各語言 stdlib 或 ICU |

沒有任何 Parallax-specific 的 API、data type、或 runtime hook。你可以用 Go、Rust、TypeScript、甚至 C 實作 Aphelion library，完全不需要知道 Parallax 的存在。如果有人告訴你「Aphelion 是 Parallax 的子專案」，那是錯誤的。它們是 **sibling projects with a shared team**。

---

## Q8: How will PyPI publish work?

**Aphelion 的 PyPI 發佈策略是什麼？**

A: 目前已上架 PyPI 的是單一 package `aphelion`（`pyproject.toml` `[project].name = "aphelion"`），bundles library + CLI 在同一 distribution 內：

- `aphelion.archive`（packer / unpacker / canonical serialization）
- `aphelion.claim`（claim model + event state machine）
- `aphelion.signer`（`aphelion[signer]` extra：Ed25519 + HMAC-SHA256 test-only）
- `aphelion.migrate`（v0.3 ↔ v0.4，v1 sequel pending）
- 對應 CLI 進入點 `aphe`（[`pyproject.toml` `[project.scripts]`](https://packaging.python.org/en/latest/specifications/entry-points/) 中註冊）

> 是否在 v1 之前再發佈第二個「opinionated CLI wrapper」package（先前 draft 中的 `decision-package` / `decision build|verify|inspect` 構想）尚未拍板；本文件**不視為對該 wrapper 命名或 surface 的承諾**。在拍板前，請使用 `pip install aphelion` + `aphe <subcommand>`。

**License**：以 **Apache 2.0** 釋出，implementor 可以自由 fork、商用、修改。

**Release pipeline**：
- Code push → GitHub Actions（GHA）自動跑 test suite + lint。
- Tag `vX.Y.Z` → GHA 自動 build wheel + sdist → `twine upload` 到 PyPI。
- Release notes 自動從 CHANGELOG.md 生成。

**Versioning**：嚴格遵循 SemVer。`aphelion` package 的 version 與 spec version 解耦（library 可能比 spec 更頻繁發 patch release）。

---

## 附錄：快速參考

| 資源 | 連結 |
|---|---|
| Spec + reference impl repo | `github.com/Chris97924/Aphelion-Graph` |
| ADR-0001 (content hash granularity) | `adr/0001-content-hash-granularity.md` |
| Trust model spec | `spec/v0.5-signer-trust.md` |
| Lifecycle state machine | `spec/lifecycle-state-machine.md` |
| Canonical serialization | `spec/canonical-serialization.md` |
| Packaging spec | `spec/packaging.md` |
| Test fixtures | `tests/fixtures/` (in repo) |
| Discussion | `github.com/Chris97924/Aphelion-Graph/discussions` |

---

> **給 implementor 的一句話**：Aphelion 的設計原則是 **simple core, extensible edges**。Core spec 只定義 archive format + hash + state machine，其餘都是 extension。先實作 core，再逐步加 signer / trust / migration，你會發現它比看起來簡單很多。歡迎在 Discussion 區提問或開 PR！
