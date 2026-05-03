```markdown
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

這些規則寫在 spec §4.2「Canonical Archive Encoding」。Implementor 只要在 serialization pipeline 末端加一個 `canonicalize()` pass，就能保證：同一組 claims，不論在哪個平台 build，產出的 `.aphpkg` 逐 byte 相同，SHA-256 一致。這對 reproducible build 和 supply chain security 至關重要。

---

## Q3: What's the event state machine?

**Claim 的 event state machine 長什麼樣？**

A: Aphelion 的每個 claim 都有一個 **lifecycle state**，由 event log 驅動狀態轉換。完整狀態機如下：

```
draft ──publish──▶ active ──reaffirm──▶ reaffirmed
                      │                      │
                      │◀───── reaffirm ──────┘
                      │
                      ├──revise──▶ revised ──▶ active (new version)
                      │
                      ├──supersede──▶ superseded
                      │
                      └──withdraw──▶ withdrawn
```

幾個重點：

- **draft → active**：唯一需要 signer authority 的轉換（見 Q5）。
- **active ⇄ reaffirmed**：reaffirmed 本質上是 active 的「心跳」，表示 claim 仍然有效，通常由 TTL 或 policy 驅動自動觸發。
- **revised**：內容有變更時產生新 version，舊版自動進入 `superseded`。
- **withdrawn**：不可逆，代表 claim 被永久撤回，verifier 應將其視為 invalid。

每個 state transition 都是一個 **Event object**，帶 timestamp、actor、reason，串成 append-only log。Implementor 只需實作這個 state machine，不需要自己發明 lifecycle 管理邏輯。

---

## Q4: How does archive security work?

**Aphelion 的 archive 安全機制如何防範惡意內容？**

A: `.aphpkg` 本質上是 tar-based archive，而 tar 格式眾所周知有 path traversal 等攻擊面。Aphelion spec §6「Archive Security」規定了一組 **strict validation rules**，implementor 必須在 **deserialization 時**（而非事後）執行：

1. **No `..` in paths** — 任何 entry path 包含 `..` 即 reject。
2. **No absolute paths** — path 以 `/` 開頭即 reject。
3. **No symlinks** — tar entry type 為 symlink 即 reject。
4. **No hardlinks** — 同上，hardlink 也 reject（避免 link-based oracle attack）。
5. **Size limit: 100 MB per entry** — 防止 decompression bomb。
6. **Entry count limit: 10,000** — 防止 inode exhaustion attack。
7. **No device files / FIFOs** — tar entry type 為 block/char device 或 FIFO 即 reject。

這些規則的設計哲學是 **deny by default, allowlist by spec**。Implementor 建議在 `ArchiveReader.open()` 內一次性跑完所有 checks，fail-fast。我們也提供了一個 reference implementation（Python）作為 test oracle。

---

## Q5: Should I implement signer/trust?

**我需要實作 signer 和 trust model 嗎？**

A: **Short answer：v0.5 optional，v1 strongly recommended，v2 可能 mandatory。**

在 v0.5 spec 中，signer/trust 是 **optional extension**。一個沒有簽名的 `.aphpkg` 仍然 valid，只是 verifier 會標記 `integrity: hash-only, no signature`。這讓早期 implementor 可以先 focus 在 core packaging 邏輯。

但在 v1（預計 2025 Q4），我們計劃將 signer 列為 **recommended**，理由是：

- Supply chain attacks 頻率上升，unsigned package 的信任度越來越低。
- Parallax runtime（見 Q7）在 production 環境會 **refuse unsigned claims**。
- Trust model（TOFU、CA-based、web-of-trust）的 spec 已在 Aphelion-ADR-0007 中定義。

建議 implementor 現在就預留 `Signer` interface，即使 v0.5 只實作 `NoopSigner`。這樣 v1 升級時只需 plug in real implementation，不需要大改架構。

---

## Q6: How to migrate from v0.x to v1?

**從 v0.x 遷移到 v1 有多痛苦？**

A: 我們盡量讓遷移 **non-breaking**。具體策略：

**v0.1 → v1（one-shot migration script）：**

- `schema_version` 從 `0.1` 升到 `1.0`。
- 主要 breaking change：canonical serialization 規則（Q2）從 optional 變 mandatory。
- 我們會提供 `aphelion-migrate` CLI tool（Python，也可作為 library import），一行指令完成轉換：
  ```bash
  aphelion-migrate --from 0.1 --to 1.0 ./my-packages/
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

A: 我們計劃發佈 **兩個** PyPI package：

1. **`aphelion-kit`** — reference implementation library，包含：
   - `aphelion.archive` — archive 讀寫 + canonical serialization
   - `aphelion.claim` — claim model + event state machine
   - `aphelion.signer` — signer interface + NoopSigner
   - `aphelion.migrate` — v0.x → v1 migration tool

2. **`decision-package`**（名稱待確認）— CLI tool，wrap `aphelion-kit`，提供：
   - `decision build` — 從 source directory build `.aphpkg`
   - `decision verify` — 驗證 `.aphpkg` integrity + signature
   - `decision inspect` — 查看 package metadata + event log

**License**：兩個 package 都以 **Apache 2.0** 釋出，implementor 可以自由 fork、商用、修改。

**Release pipeline**：
- Code push → GitHub Actions（GHA）自動跑 test suite + lint。
- Tag `vX.Y.Z` → GHA 自動 build wheel + sdist → `twine upload` 到 PyPI。
- Release notes 自動從 CHANGELOG.md 生成。

**Versioning**：嚴格遵循 SemVer。`aphelion-kit` 的 version 與 spec version 解耦（library 可能比 spec 更頻繁發 patch release）。

---

## 附錄：快速參考

| 資源 | 連結 |
|---|---|
| Spec repo | `github.com/aphelion-spec/aphelion` |
| ADR-0001 (per-claim hash) | `docs/adr/0001-per-claim-content-hash.md` |
| ADR-0007 (trust model) | `docs/adr/0007-trust-model.md` |
| Reference impl (Python) | `github.com/aphelion-spec/aphelion-kit` |
| Test vectors | `tests/vectors/` |
| Discussion | `github.com/aphelion-spec/aphelion/discussions` |

---

> **給 implementor 的一句話**：Aphelion 的設計原則是 **simple core, extensible edges**。Core spec 只定義 archive format + hash + state machine，其餘都是 extension。先實作 core，再逐步加 signer / trust / migration，你會發現它比看起來簡單很多。歡迎在 Discussion 區提問或開 PR！
```
