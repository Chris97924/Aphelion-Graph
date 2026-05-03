```markdown
# Aphelion — Decision Note Format & Toolchain

> **Aphelion** is an open-source decision note format and CLI toolchain that makes every decision traceable, verifiable, and portable.

**Aphelion** 是一套開源決策紀錄格式與工具鏈，讓每一個決策都有跡可循、可驗證、可攜帶。不同於散落在 Wiki、Slack thread 或 PDF 裡的 ADR，Aphelion 將決策結構化為可機器驗證的 canonical document，搭配六支 CLI 工具與三層 validator，確保從草稿到簽署的每一筆變更都可被獨立 audit。

---

## Quick Install

```bash
pip install aphelion-kit
```

Requires Python 3.10+. No external dependencies beyond the standard library.

---

## 5-Minute Quickstart

```bash
# 1. 初始化一個新的 decision note
aphelion init --title "Use PostgreSQL over MySQL" --id ADR-0042

# 2. 驗證 note 結構與 schema compliance
aphelion validate ./ADR-0042/

# 3. 打包為可分發的 canonical bundle
aphelion pack ./ADR-0042/ -o ADR-0042.aphelion

# 4. 解包收到的 bundle
aphelion unpack ADR-0042.aphelion -o ./restored/

# 5. 比較兩個版本的差異（claim-level diff）
aphelion diff ./ADR-0042/ ./ADR-0042-v2/

# 6. 驗證簽署與信任鏈完整性
aphelion verify ./ADR-0042.aphelion
```

Each command produces machine-readable output (exit codes + JSON on `--json`), making it CI-friendly.

---

## Why Aphelion?

| | Aphelion | JSON Schema | Pydantic | Proprietary formats |
|---|---|---|---|---|
| **Domain** | Decision notes | Generic validation | Data modelling | Varies |
| **Canonical serialization** | ✅ Deterministic bytes | ❌ | ❌ | ❌ |
| **Content-level hashing** | ✅ Per-claim `content_hash` | ❌ | ❌ | Rarely |
| **Polarity semantics** | ✅ supports / contradicts | ❌ | ❌ | ❌ |
| **Append-only provenance** | ✅ `provenance.jsonl` | ❌ | ❌ | ❌ |
| **Open standard** | ✅ Apache 2.0 | ✅ MIT | ✅ MIT | ❌ |

Aphelion 不是要取代 JSON Schema 或 Pydantic——它們解決 validation，Aphelion 解決 **decision traceability**。當你需要回答「為什麼做了這個決定？誰同意？誰反對？證據是什麼？」的時候，Aphelion 是為此設計的。

---

## Apache 2.0 — Why?

我們選擇 Apache License 2.0 而非 MIT 或 BSD，原因是 **explicit patent grant**（§3）。

企業採用開源工具時，最大的法律風險往往不是著作權，而是專利。Apache 2.0 的專利條款為使用者提供明確的授權保障：貢獻者自動授予使用者相關專利許可，且若發起專利訴訟則自動終止授權——這形成了一個自我強化的防禦機制。

對企業法務而言，Apache 2.0 是最「安全」的開源選項之一。

---

## Core Concepts

### Canonical Serialization

同一份 decision note，無論由誰、在哪個平台上序列化，產出的 bytes 完全一致。這是 diff、verify 與 trust chain 的基礎。

### Per-Claim Content Hash (Aphelion-ADR-0001)

每一個 claim（支持或反對的論點）都有獨立的 `content_hash`。這意味著你可以精確指出「第 3 條論點在 v2 中被修改了」，而非只能看到「檔案有變動」。

### Polarity-Explicit

每個 claim 必須標註 polarity：`supports` 或 `contradicts`。這不是情緒分析——這是結構化的語義標記，讓工具鏈能自動計算決策的淨支持度。

### Append-Only Provenance (`provenance.jsonl`)

所有變更以 JSONL 格式追加記錄，不可刪除、不可覆寫。每筆記錄包含 timestamp、actor、action 與前一筆的 hash，形成 tamper-evident chain。

---

## Roadmap to v1.0

| Milestone | Focus | Status |
|---|---|---|
| **M9** | PyPI publish (`aphelion-kit`) | 🔄 In progress |
| **M10** | 三方齊發：Aphelion spec + Parallax viewer + Lane C integration | 📋 Planned |
| **M11** | Plugin ecosystem & language SDKs (Go, Rust) | 📋 Planned |
| **v1.0** | Stable spec, backward-compat guarantee | 🎯 Target Q4 |

---

## Contributing

We welcome contributions at every level:

- **Bug reports** — Open an issue with `aphelion validate --json` output attached.
- **Spec discussion** — Propose changes to the format via ADR pull requests in the `spec/` directory.
- **Implementations in other languages** — We actively encourage ports. See `docs/porting-guide.md` for serialization test vectors and compliance criteria.

```bash
git clone https://github.com/aphelion-project/aphelion-kit.git
cd aphelion-kit
pip install -e ".[dev]"
pytest
```

---

## License

```
Copyright 2024 Aphelion Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
```

---

**字數約 1,050 字（zh-TW 正文 + English code block），結構完整、零 fluff。** 若套件名最終確定為 `decision-package`，只需替換 `pip install` 一行與標題即可。
