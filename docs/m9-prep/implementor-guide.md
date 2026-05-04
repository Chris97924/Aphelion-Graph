# Aphelion v1 — Implementor Guide

> **文件版本：** M9-prep draft  
> **最後更新：** 2026-05-04（ultrareview 修正：signer envelope / CRLF / size limits / lifecycle / uuid7）  
> **授權：** Apache 2.0  
> **語言約定：** 正文繁體中文，所有 spec terms、code blocks、error codes 維持英文原文。

---

## 文件目的 / 受眾

本文件為想用 **Go、TypeScript、Rust、Java**（或其他語言）實作 Aphelion-compatible library 的開源貢獻者撰寫。目標是給你一條從 **zero 到 first compatible release** 的明確路徑。

Aphelion v0.5.x 已有完整的 Python reference implementation（Apache 2.0），發佈於 PyPI。本 guide 假設你已熟悉至少一種目標語言的套件管理與測試框架，但 **不假設** 你讀過 Aphelion spec。

> **核心原則：** Aphelion 是一個 **package format specification**，不是服務、不是 API、不是平台。你的 library 只需要做到一件事——**產生與 Python reference impl byte-equal 的 output**。

---

## Step 0: 起步前——先讀這些 Spec

在寫任何一行 code 之前，請依序閱讀以下五份 spec 文件。它們位於 `spec/` 目錄下：

| # | Spec 文件 | 為什麼必讀 |
|---|-----------|-----------|
| 1 | `identity-event.md` | 定義 `claim_id` 的產生規則（UUID v7）與 event 的 identity model。這是所有後續步驟的基礎，搞錯 identity 就全盤皆錯。 |
| 2 | `lifecycle-state-machine.md` | 定義 claim 的合法狀態轉換（draft → active → reaffirmed/revised → superseded → withdrawn）。你的 library 必須 enforce 這些轉換，否則會產生 invalid package。 |
| 3 | `canonical-serialization.md` | **最脆弱、最容易出錯的一份。** 定義了 byte-level 的 serialization 規則：Unicode normalization、key sorting、tar entry ordering、timestamp format。任何偏差都會導致 hash 分叉。 |
| 4 | `content-hash.md` | 定義 content-addressable hash 的計算方式，與 canonical serialization 緊密耦合。讀完 canonical serialization 後立刻讀這份。 |
| 5 | `error-codes.md` | 定義所有 machine-readable error codes。你的 library 必須使用這些既有 codes，不要自行發明。 |

> **建議：** 讀完 spec 後，先花半天讀 Python reference impl 的對應 modules，建立「spec → code」的 mental mapping。

---

## Step 1: Identity + Event State Machine（基礎中的基礎）

### 1.1 claim_id = UUID v7

每個 Aphelion claim 必須有一個全域唯一的 `claim_id`，格式為 **UUID v7**（RFC 9562）。UUID v7 的前 48 bits 為 millisecond-precision Unix timestamp，後面帶有 random bits。

```
# UUID v7 結構 (128 bits)
# ┌─────────────────────────────────────────────────────────────┐
# │ 48-bit unix_ts_ms │ 4-bit ver │ 12-bit rand_a │ var │ 62-bit rand_b │
# └─────────────────────────────────────────────────────────────┘
```

**Implementor Checklist:**

- [ ] 使用 RFC 9562 compliant 的 UUID v7 generator（不要用 v4 random UUID）
- [ ] `claim_id` 一旦 minted 就 **immutable**——不可重新產生、不可更改
- [ ] Equality check 必須是 **byte-equal**（16 bytes 逐 byte 比對），**不是** semantic equality
- [ ] String representation 為 lowercase hex with hyphens: `550e8400-e29b-41d4-a716-446655440000`

**Python reference impl 對照（`src/aphelion/initializer.py:_new_uuid_v7`）：**

```python
# Python reference impl — feature-detect with hand-rolled fallback
# (pyproject.toml requires-python = ">=3.10"; uuid.uuid7 是 stdlib **3.14+** only)
import secrets
import time
import uuid

def _new_uuid_v7() -> str:
    if hasattr(uuid, "uuid7"):
        return str(uuid.uuid7())  # type: ignore[attr-defined]
    # Manual v7 construction for Python 3.10–3.13
    unix_ts_ms = int(time.time() * 1000)
    rand_bytes = secrets.token_bytes(10)
    # ... see src/aphelion/initializer.py for the full byte layout
    return ...  # 16-byte UUID v7 string
```

### 1.2 State Transitions

Claim lifecycle 必須嚴格遵守 `spec/lifecycle-state-machine.md` 定義的狀態機。**以下圖為 §3 Mermaid 的等價 ASCII 摘要**；spec 的 Mermaid 為 normative，本圖任何分歧以 spec 為準。

```
       create
[*] ──────────► draft ──publish──► active ──reaffirm──► reaffirmed
                  │                  │  ▲                  │
                  │                  │  └──── decay ────────┘
                  │                  │
                  │                  ├──revise──► revised ──decay──► active (new instance)
                  │                  │
                  │                  ├──supersede──► superseded ──► [*]
                  │                  │
                  │                  └──withdraw──► withdrawn ──► [*]
                  │
                  └────────── withdraw ──────────► withdrawn ──► [*]
```

**禁止轉換**（依 `lifecycle-state-machine.md` §4 transition matrix；違反即 `ERR-SEM-LIFECYCLE-ILLEGAL`）：

- `superseded → *`（任何 event）— superseded 為 read-only terminal。
- `withdrawn → *`（任何 event）— withdrawn 為 terminal。
- `reaffirmed`、`revised` 為 transient labels，不在 `manifest.json.claims[].state` 出現。

**Implementor Checklist:**

- [ ] 實作 `transition(claim, from_state, to_state)` 函式，非法轉換必須 throw/reject
- [ ] 每次 transition 必須記錄 timestamp（UTC, Z-suffix）
- [ ] `withdrawn` 是 terminal state——不可再轉換
- [ ] 參考 `lifecycle-state-machine.md` 的完整 transition table，不要自行推斷合法路徑

---

## Step 2: Canonical Serialization（最容易出錯的部分）

這是整個實作中 **最脆弱** 的環節。Canonical serialization 的目標是：**相同的 logical content 必須產生 byte-identical 的 output**，否則 content hash 會分叉。

### 2.1 Text Canonicalization Rules

所有 text fields 在 serialization 前必須經過以下處理：

1. **Unicode NFC normalization** — 使用 Unicode NFC（Canonical Decomposition, followed by Canonical Composition）
2. **LF line endings (REJECT CRLF)** — `spec/canonical-serialization.md` Rule 3.1 + `spec/packaging.md` Rule 5/Rule 6 都規定 CRLF 與 lone CR 是 syntax error；packager **必須 reject 並 emit `ERR-SYN-004`**，**不可** silently 轉成 LF（silent normalization 會掩蓋 producer 端的真正 bug）
3. **No trailing whitespace** — 每行結尾的空白字元必須移除
4. **Key ASCII sort** — JSON/dict 的 keys 必須以 ASCII byte order 排序（即 `A < Z < a < z`）

```go
// Go 範例：canonical text validation (NOT normalization)
func ValidateCanonicalText(input string) error {
    // 1. NFC normalization
    if norm.NFC.String(input) != input {
        return fmt.Errorf("ERR-SYN-NFC: input not NFC-normalized")
    }
    // 2. CRLF / lone CR — MUST reject, not rewrite
    if strings.ContainsAny(input, "\r") {
        return fmt.Errorf("ERR-SYN-004: CRLF or CR in input")
    }
    // 3. Trailing whitespace per line
    for _, line := range strings.Split(input, "\n") {
        if line != strings.TrimRight(line, " \t") {
            return fmt.Errorf("ERR-SYN-WS: trailing whitespace")
        }
    }
    return nil
}
```

### 2.2 Tar Archive Rules

Aphelion packages 以 tar 格式封裝。Tar entries 必須遵守：

- **Entry ordering:** 字典序（lexicographic order by entry path）
- **mtime = 0:** 所有 entries 的 modification time 必須設為 Unix epoch 0（`1970-01-01T00:00:00Z`）
- **No extra metadata:** owner/group 設為 `0`，mode 設為合理預設值

### 2.3 Timestamp Rules

所有 timestamps 必須（依 `spec/canonical-serialization.md` Rule 4）：

- 使用 **ISO 8601** 格式
- **強制 Z-suffix**（UTC）：`2025-07-01T12:00:00Z`
- **不接受** `+00:00` 變體、不接受無 timezone 的 local time
- Precision 為 **seconds 或 milliseconds**：`YYYY-MM-DDTHH:MM:SSZ` 或 `YYYY-MM-DDTHH:MM:SS.sssZ`（恰好 3 位小數）。**6 位 microsecond / 9 位 nanosecond 一律禁止**（`ERR-SYN-TIMESTAMP-NS`）。
- ⚠️ **v0.5 signer envelopes**（`signatures.jsonl`）的 `signed_at_iso` **強制要求 millisecond precision**（見 `spec/v0.5-signer-trust.md` §2.2）— 不可 emit second-only。

```rust
// Rust 範例：canonical timestamp formatting
// 兩種形式都合法；signer envelopes 一律走 ms。
fn canonical_timestamp_seconds(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
fn canonical_timestamp_millis(dt: DateTime<Utc>) -> String {
    // %.3f 確保固定 3 位 ms（非 6 位 µs / 9 位 ns）
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}
```

### 2.4 Cross-Platform Verification

**這是強制要求。** 你的 library 產生的 tarball，在 Linux、macOS、Windows 上 unpack 後再 repack，content hash 必須 **byte-equal**。

```bash
# Cross-platform 驗證套路
# 在三個 OS 上分別執行：
$ aphelion pack ./my-claim claim.tar
$ sha256sum claim.tar
# 三個 OS 的 hash 必須完全一致
```

**Implementor Checklist:**

- [ ] NFC normalization 使用 well-tested library（ICU / `unicode-normalization` crate / `java.text.Normalizer`）
- [ ] Tar library 支援設定 mtime=0（部分 libraries 預設不為 0）
- [ ] Key sorting 為 ASCII byte order，**不是** locale-dependent sort
- [ ] Timestamp 強制 Z-suffix，parsing 時 reject `+00:00`
- [ ] 在至少 2 個不同 OS 上跑 cross-platform hash equivalence test

---

## Step 3: Schema Validation 三層

Aphelion 的 validation 分為三個明確的層次，每層有不同職責：

| 層次 | 職責 | 範例 |
|------|------|------|
| **Syntax** | 字面格式正確性 | JSON 合法、UUID 格式正確、timestamp 為 ISO 8601 |
| **Schema** | 結構與欄位完整性 | 必要欄位存在、型別正確、enum 值合法 |
| **Semantic** | 業務邏輯正確性 | State transition 合法、claim 不是 withdrawn 狀態仍嘗試 reaffirm |

**Implementor Checklist:**

- [ ] 三層 validation 各自獨立，可單獨呼叫
- [ ] 所有 validation errors 使用 `error-codes.md` 定義的 machine-readable error codes
- [ ] **不要發明新的 error codes**——如果既有 codes 不夠用，先開 issue 討論
- [ ] Error messages 包含：error code + human-readable description + path to offending field

```typescript
// TypeScript 範例：validation error structure
interface AphelionValidationError {
  code: string;        // e.g. "E001_INVALID_UUID_FORMAT"
  message: string;     // human-readable description
  path: string;        // e.g. "claims[0].claim_id"
  layer: "syntax" | "schema" | "semantic";
}
```

---

## Step 4: Archive Security

你的 library 必須在 unpack/validation 階段阻擋以下 **malicious patterns**：

| 威脅 | 說明 | 處置 | Error code |
|------|------|------|-----------|
| Path traversal | Entry path 包含 `..` | **必須 reject** | — |
| Absolute paths | Entry path 以 `/` 開頭 | **必須 reject** | — |
| Symlinks | Symbolic link entries | **必須 reject** | — |
| Hardlinks | Hard link entries | **必須 reject** | — |
| Oversized archive (whole) | **> 100 MiB (104,857,600 bytes)** | **必須 reject** | `PX_E_6011` |
| Oversized single file | **> 25 MiB**（reference impl 上限；spec recommendation 為 50 MiB） | **必須 reject** | `PX_E_6010` |
| Too many entries | > 10,000 | **必須 reject** | — |

> 數字源於 `spec/packaging.md` Rule 7 + `src/aphelion/unpacker.py`：`PACKAGE_TOTAL_BYTES_LIMIT = 104_857_600`、`PACKAGE_SINGLE_FILE_BYTES_LIMIT = 25 * 1024 * 1024`。寫成 decimal MB 會在 100,000,001–104,857,600 byte 區間造成 4.86 MiB 的 interop cliff。

**強烈建議：使用 streaming validation。** 不要先將整個 archive unpack 到 disk 再檢查——在 streaming 讀取 entry headers 時就進行 validation。

```go
// Go 範例：streaming archive validation with per-entry + total size guards
const (
    maxArchiveBytes int64 = 104_857_600 // 100 MiB, PX_E_6011
    maxFileBytes    int64 = 25 << 20    // 25 MiB,  PX_E_6010
    maxEntries            = 10_000
)

tr := tar.NewReader(reader)
entryCount := 0
var totalBytes int64
for {
    header, err := tr.Next()
    if err == io.EOF { break }
    if err != nil { return err }

    entryCount++
    if entryCount > maxEntries {
        return ErrTooManyEntries
    }
    if strings.Contains(header.Name, "..") {
        return ErrPathTraversal
    }
    if path.IsAbs(header.Name) {
        return ErrAbsolutePath
    }
    if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
        return ErrDisallowedLinkType
    }
    if header.Size > maxFileBytes {
        return ErrFileTooLarge // PX_E_6010
    }
    totalBytes += header.Size
    if totalBytes > maxArchiveBytes {
        return ErrArchiveTooLarge // PX_E_6011
    }
    // ... continue streaming validation
}
```

---

## Step 5: Optional — Signer / Trust (v0.5)

Signing 是 **optional** 功能，但如果你選擇實作，必須遵守以下規則：

### 5.1 Supported Algorithms

| Algorithm | 用途 | Status |
|-----------|------|--------|
| HMAC-SHA256 | **TEST-ONLY**，不可用於 production | 必須在文件/API 中明確標示 `test-only` |
| Ed25519 (RFC 8032) | Production signing | 推薦 |

### 5.2 Algorithm Match Enforcement

這是 Codex P1 fix 中修復的問題：**signing algorithm 必須與 key type match**。如果 key 是 Ed25519，signature algorithm 也必須是 Ed25519——不可混用。

### 5.3 Signatures Log

所有 signatures 必須寫入 `signatures.jsonl`（append-only log）。每行一個 canonical JSON `SignatureEnvelope`（依 `spec/v0.5-signer-trust.md` §2.2），**簽章是 per-package 不是 per-claim**（per-claim signing 為 v0.6 future scope，§1.3 + §7.1 R7.1）：

```json
{"algorithm":"ed25519","package_canonical_hash":"<64-hex-sha256>","signature_b64":"<base64>","signed_at_iso":"2026-04-27T00:00:00.000Z","signer_id":"alice"}
```

欄位（spec §2.2 schema，以 ASCII 排序）：

| Field | Type | 說明 |
|---|---|---|
| `algorithm` | string | §3.1 algorithm registry name（`ed25519` 或 `hmac-sha256` test-only） |
| `package_canonical_hash` | string | sha256 hex lowercase, length 64（簽章綁定欄位，§2.1） |
| `signature_b64` | string | base64-standard 簽章 bytes |
| `signed_at_iso` | string | RFC 3339 UTC，**強制 millisecond** precision（`.sssZ`） |
| `signer_id` | string | §1.3，opaque non-empty UTF-8 |

**Implementor Checklist:**

- [ ] **不可** 加 `claim_id` / `key_id` / `timestamp` 等舊欄位 — 會觸發 `E_SIGNATURE_MALFORMED`
- [ ] `package_canonical_hash` 必須在 envelope 內 — 缺即 `E_SIGNATURE_MALFORMED`
- [ ] `signed_at_iso` 必須是 ms precision — second-only 觸發 `ERR-SYN-TIMESTAMP-NS`
- [ ] HMAC-SHA256 在 API 層標示 `test-only`，production code path 不允許使用
- [ ] Algorithm 必須與 `signers/<signer_id>.json` 一致（spec §5 confused-deputy 防護 → `E_SIGNER_ALGORITHM_MISMATCH`）
- [ ] `signatures.jsonl` lines **lex 排序** by `(signer_id, signed_at_iso)`，否則 `E_SIGNATURE_ORDER`

---

## Step 6: First Compatibility Release Checklist

在你宣稱自己的實作 "Aphelion-compatible" 之前，必須通過以下驗證：

### 6.1 Golden Fixture Testing

Python reference impl 的 `tests/fixtures/` 目錄包含一組 **golden fixtures**——預先計算好 hash 的 test cases。你的 library 必須通過所有 golden fixtures。

```bash
# 取得 golden fixtures
git clone https://github.com/Chris97924/Aphelion-Graph.git
ls Aphelion-Graph/tests/fixtures/
```

### 6.2 Hash Equivalence (Round-Trip)

**強制要求：** 你的 library 必須通過 round-trip test——pack → unpack → repack，三次的 content hash 必須 byte-equal。

```
pack(claim) → archive_A
unpack(archive_A) → claim'
pack(claim') → archive_B

hash(archive_A) == hash(archive_B)  # MUST be equal
```

### 6.3 Submit for Review

通過所有測試後，提交 PR 到 Aphelion-Graph repo，申請 `compatible impl` 標記。PR 必須附上：

1. 你的 test results（golden fixtures + round-trip）
2. Cross-platform hash equivalence evidence
3. 實作的 language / framework / version 資訊

---

## Step 7: 不要做的 ❌

以下是 **常見的 scope creep traps**——請明確避開：

| ❌ 不要做 | 為什麼 |
|-----------|--------|
| 實作 cross-source aggregation | 這是 **consumer's responsibility**（例如 Parallax）。Aphelion library 只負責 single-source package 的讀寫。 |
| 實作 retrieval API | Aphelion 是 **package format**，不是 memory service。不要在 library 中加入 HTTP server 或 retrieval endpoints。 |
| Fork canonical-serialization rules | 任何對 serialization 規則的偏差都會導致 **hash 分叉**，你的 output 將與其他 implementations 不相容。如果你認為 spec 有問題，開 issue 討論，不要自行修改。 |
| 自行發明 error codes | 使用 `error-codes.md` 既有 codes。新 codes 需要經過 spec review process。 |
| 使用 locale-dependent string comparison | Key sorting 必須是 ASCII byte order，不是 locale-dependent。 |

---

## Step 8: 提交貢獻流程

### 8.1 流程

```
GitHub Issue（描述你想實作的語言/平台）
    ↓
Discussion（與 maintainers 確認 scope、API 設計方向）
    ↓
Spec PR（如果需要 spec 變更或 clarification）
    ↓
Implementation PR（附測試結果）
    ↓
Maintainer Review → Merge → `compatible impl` 標記
```

### 8.2 License 要求

**必須使用 Apache 2.0。** 不接受 MIT、GPL、BSD、或任何 proprietary license。這是 Aphelion project 的整體 licensing policy，沒有例外。

### 8.3 Maintainer Review 標準

Maintainers 在 review 時會檢查：

| 項目 | 標準 |
|------|------|
| **Test coverage** | ≥ 90% line coverage，golden fixtures 全數通過 |
| **Spec compliance** | 所有 MUST/SHALL requirements 已實作，cross-platform hash equivalence 已驗證 |
| **Code quality** | Idiomatic code for target language、CI passing、no security warnings |
| **Documentation** | README 包含 quickstart、API reference、與 Python reference impl 的行為差異說明 |

---

## 推薦 Tools / References

| 資源 | 位置 |
|------|------|
| Python reference impl | `github.com/Chris97924/Aphelion-Graph` |
| Spec files | `spec/` |
| FAQ | `docs/m9-prep/spec-social-review-faq.md` |
| Crosswalk schema | `docs/m9-prep/crosswalk-schema-tristate.md` |
| Golden fixtures | `tests/fixtures/` (in Aphelion-Graph repo) |

### 各語言建議 Libraries

| 語言 | UUID v7 | Unicode NFC | Tar | JSON (sorted keys) |
|------|---------|-------------|-----|---------------------|
| **Go** | `github.com/google/uuid` (v1.3+) | `golang.org/x/text/unicode/norm` | `archive/tar` (stdlib) | `encoding/json` + custom marshaler |
| **TypeScript** | `uuidv7` npm package | `unorm` / built-in `Intl` | `tar-stream` | `JSON.stringify` + replacer |
| **Rust** | `uuid` crate (v1.6+) | `unicode-normalization` crate | `tar` crate | `serde_json` with `sort_keys` feature |
| **Java** | `java.util.UUID` (custom v7 gen) | `java.text.Normalizer` | `commons-compress` | `Jackson` with `ORDER_MAP_ENTRIES_BY_KEYS` |

---

> **最後提醒：** Aphelion 的價值在於 **interoperability**。你的 library 不需要功能豐富——它需要的是 **byte-level 的正確性**。寧可少做功能，也不要偏離 spec。有任何疑問，先開 issue，maintainers 很樂意協助。

---

*本文件以 Apache 2.0 授權釋出。Copyright 2025 Aphelion Contributors.*
