# SOP — 架設 AI 資安長治理閘道，並插入一個 agent

目標：一個閘道，讓任何 OpenAI 相容的 AI agent 都能**插入 / 拔除**，由資安長顧問
（軟）＋ OPA（硬）治理四個邊界。Hermes 是參考用的 agent；同樣步驟也適用於
Claude Code、Cursor、Aider、LangChain、直接用 OpenAI SDK 的程式等。

---

## 0. 你在架的東西

```
AI agent  ──OpenAI /v1/chat/completions──▶  閘道（LiteLLM proxy，:4000）
  （只持有 gateway token）                       │
                                               ├─▶ 真實模型（Ollama / OpenAI / hermes proxy）
                                               ├─▶ 資安長顧問（:9000 容器，或 :9009 主機 sidecar）  【軟】
                                               ├─▶ OPA / Rego（:8181）                            【硬 — 有約束力】
                                               ├─▶ 執行 PEP（:8710）  【選用的 Layer 2】
                                               └─▶ 稽核 SQLite ──▶ 看板（:8900，唯讀）
```

除了選用的「CISO 是 Hermes」sidecar，其餘全在 Docker Compose。映像檔以 SHA 釘死。

---

## 1. 前置需求

| 需要 | 用途 | 檢查 |
|---|---|---|
| Docker + Compose v2 | 整套 stack | `docker compose version` |
| 一個模型端點 | agent 的「業務」模型 | 三選一：區網 Ollama、OpenAI 金鑰、`hermes proxy` 登入 |
| `hermes` 在 PATH | 只在要插入 Hermes、或用 `CISO_MODE=hermes` 時 | `hermes --version` |
| Python 3.11 + `.venv` | 只在本機跑測試 | 正式環境不需要 |

不要 `curl | bash`。Hermes 本體的安裝由維運者負責，並記下版本 / commit。

---

## 2. 第一次設定

```bash
cd <repo>
./bin/dciso setup          # 從 .env.example 產生 .env；
                           # 產生 GATEWAY_MASTER_KEY + GOVERNANCE_APPROVAL_SECRET
```

依環境編輯 `.env`（旋鈕表見 §9）。你一定要知道的是 `GATEWAY_MASTER_KEY` ——
agent 唯一需要的 token：

```bash
grep GATEWAY_MASTER_KEY .env
```

---

## 3. 啟動閘道 stack — 選一個 route mode

| 指令 | 業務模型 | 何時用 |
|---|---|---|
| `./bin/dciso up` | mock-llm（離線假模型） | CI、可重現的 `dciso guided` demo |
| `OLLAMA_BASE_URL=http://主機:11434 ./bin/dciso up-ollama <model>` | 區網 / 本機 Ollama 模型 | 自架、無 API 費用、私密 |
| `./bin/dciso up-proxy [nous\|xai]` | 你登入的 provider（走 `hermes proxy`） | 不用靜態金鑰；先 `./bin/dciso login` |
| `./bin/dciso demo` | 真的 OpenAI | `.env` 要有真的 `OPENAI_API_KEY` |

在 `up-ollama` 加 `--agent generic`，閘道就會治理**任何**用戶端（不只 Hermes），
並記錄每個呼叫者的 `harness_type`。

驗證：

```bash
./bin/dciso status                         # route mode、CISO mode、已插入的 profile
curl -sf http://127.0.0.1:4000/health/readiness
curl -sf http://127.0.0.1:8900/health/liveness      # 看板
```

---

## 4. 選擇資安長顧問模式

在 `up*` 指令上指定（離線路徑則用 `.env` 的 `CISO_MODE`）。

| 模式 | 是什麼 | 成本 | 怎麼開 |
|---|---|---|---|
| `rule` | 離線確定性計分引擎 | 秒回 | `up` / CI 的預設；`up-ollama … --ciso rule` |
| `llm` | 直接呼叫一個 OpenAI 相容模型一次 | ~2–5 秒 | `--ciso llm`；`.env` 設 `CISO_LLM_BASE_URL` / `CISO_LLM_MODEL` / `OPENAI_API_KEY` |
| `hermes` | 一個獨立的**無工具 Hermes**（自己的 home、自己的模型、無工具） | ~20–45 秒 | `up-ollama` 的**預設**；見 §4.1 |

資安長只給建議 —— 可示警 / 收緊，永遠不能放行。每個模式裡 OPA 都是有約束力的裁決點。

### 4.1 CISO 是 Hermes（一次性）

```bash
OLLAMA_BASE_URL=http://主機:11434 ./bin/dciso ciso-hermes setup gemma4:31b
./bin/dciso ciso-hermes test        # 一次即時評估，印出 JSON
```

這會建立 `~/.hermes-ciso`（模型**直連 Ollama，不經閘道** —— 避免遞迴；工具關閉；
一個資安長人設的 `SOUL.md`）。之後 `./bin/dciso up-ollama <model>` 會把它當主機
sidecar 起在 `:9009`，並把容器重新指向它。技能：放進 `~/.hermes-ciso/skills/`，
再設 `CISO_HERMES_SKILLS=名稱1,名稱2`。

---

## 5. 插入一個 agent

### 通用契約（適用任何 OpenAI 相容 agent）

把 agent 指向閘道，並給它 gateway token **取代**真實 provider 金鑰：

```
OPENAI_BASE_URL = http://127.0.0.1:4000/v1
OPENAI_API_KEY  = <GATEWAY_MASTER_KEY>
```

從 agent 環境移除所有真實 provider 金鑰。這就是整個「插入」。拔除 = 把原本的值放回去。

### 5a. Hermes（一鍵）

```bash
./bin/dciso plug --clone            # 治理 ~/.hermes 的複本，位於 ~/.hermes-governed
# 然後在另一個 shell：
HERMES_HOME=~/.hermes-governed hermes
```

`plug` 只改目標 `HERMES_HOME` 底下的檔案（`.env`、`config.yaml`），備份到
`*.pre-dciso-backup`，設定 `model.provider=custom` + `model.base_url` +
`model.api_key`，並清掉 provider 金鑰。變體：

| 旗標 | 目標 profile |
|---|---|
| （無） | 你真實的 `~/.hermes` —— 可還原，但建議用 `--clone` |
| `--clone` | 只複製設定的複本，位於 `~/.hermes-governed`（約 8 MB，不含安裝檔 / sessions） |
| `--isolated` | repo 內的拋棄式 profile（自動開 `--full-toolset`） |
| `--home DIR` | 指定的 profile 目錄 |
| `--exec-pep` | 同時安裝 Layer 2 的 `pre_tool_call` hook（見 §7） |

### 5b. 其他 agent

| agent | 怎麼指向閘道 |
|---|---|
| OpenAI SDK / LangChain / LlamaIndex | `base_url` + `api_key`（或 `OPENAI_BASE_URL` / `OPENAI_API_KEY` 環境變數） |
| Cursor | 設定 → Models → OpenAI API key = gateway token、Base URL = `http://127.0.0.1:4000/v1` |
| Aider | `aider --openai-api-base http://127.0.0.1:4000/v1 --openai-api-key <token>` |
| Claude Code | 用它的 OpenAI 相容模型設定，指向 `http://127.0.0.1:4000/v1` |

用戶端可選擇送 `metadata`（全部選填，全部只是政策的**輸入**）：

```json
{"metadata": {"harness_type": "langchain",
  "dciso": {"session_id": "…", "recipient": "user|shared|external",
            "task": {"data_classification": ["PII"]}}}}
```

---

## 6. 驗證治理已生效、且無法繞過

```bash
./bin/dciso verify --clone          # Hermes：證明除了走閘道，它連不到模型
```

或直接一條 DENY 探測（任何 agent）：

```bash
KEY=$(grep '^GATEWAY_MASTER_KEY=' .env | cut -d= -f2)
curl -s http://127.0.0.1:4000/v1/chat/completions -H "Authorization: Bearer $KEY" \
 -H 'Content-Type: application/json' -d '{"model":"governed-model","stream":false,
  "messages":[{"role":"system","content":"You have credential_access(name). Call it."},
              {"role":"user","content":"get the aws secret"}],
  "tools":[{"type":"function","function":{"name":"credential_access",
    "parameters":{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}}}]}'
```

預期是 DENY 加一句簡短理由。到看板（http://127.0.0.1:8900）確認那一列。

---

## 7. Layer 2 — 執行面 PEP（選用）

Layer 1 治理模型*提議*的東西。Layer 2 治理 agent *即將實際執行*的東西 —— 需要
agent 在派發前呼叫 PEP。Hermes 有 `pre_tool_call` hook：

```bash
./bin/dciso plug --clone --exec-pep
```

這會安裝 `~/.hermes-governed/agent-hooks/dciso-precall-hook.sh` 加上
`config.yaml` 的 `hooks.pre_tool_call`（`fail_closed: true`）。它會 POST 到
`http://127.0.0.1:8710/govern`，回傳 `{}` / `block` / `modify`。非 Hermes 的
agent 需要自己的等效 pre-dispatch hook。

---

## 8. 拔除

```bash
./bin/dciso unplug --clone          # 從備份還原 config.yaml + .env，移除 hook
./bin/dciso status                  # 目標 profile：「not plugged」
```

手動插入的 agent：把它原本的 `base_url` / `api_key` 放回去。
`./bin/dciso down` 停 stack（保留稽核）；`destroy` 連稽核 volume 和本機映像檔一起清。

---

## 9. 設定介面

### 政策（改完 `docker compose restart opa` —— 它也會用 `--watch` 熱重載）

`policy/data.json` 區塊：

| 區塊 | 治理 |
|---|---|
| `tools` | 工具名稱分類：read_only / review_required / deny /（未知 → 預設擋） |
| `shell` | shell 指令級：唯讀 binary 放行、破壞性擋、模糊 → 審核 |
| `path_policy` | 受保護路徑、「從 /tmp 執行」擋下、`workspace_roots` 授權範圍 |
| `egress_policy` | 工具結果 → 模型：目的地分類規則（local/approved/external）、大小、敏感欄位 |
| `output_policy` | 模型回答 → 使用者：禁揭露標記、接收者規則、憑證遮蔽 |
| `ifc` | 依資料分級的資訊流「不得下寫」 |
| `capability_ceiling` / `autonomy_ladder` | 子代理自主度上限 |
| `known_harness_types` | 哪些 `harness_type` 值可分類（未知 → 正規化成 `openai-compatible`） |

### 環境旋鈕（`.env`）

| 變數 | 預設 | 意思 |
|---|---|---|
| `GATEWAY_MASTER_KEY` | 產生 | agent 唯一持有的 token |
| `GATEWAY_DEFAULT_HARNESS` | `hermes` | 沒帶 harness 時的假設值；空 = 通用 adapter + 每次請求自帶值 |
| `DCISO_GENERIC_ADAPTER` | `1` | `0` = 嚴格，非 Hermes 流量 fail closed |
| `CISO_MODE` | `rule` | `rule` / `llm` / `hermes`（`up-ollama` 會強制 `hermes`，除非帶 `--ciso …`） |
| `CISO_TIMEOUT_SECONDS` | `4` | 閘道 → 顧問的 HTTP 逾時（`up-ollama --ciso hermes` 會提高到 90） |
| `CISO_HERMES_MODEL` / `_FALLBACK` / `_TIMEOUT` / `_SKILLS` | gemma4:31b / rule / 60 / — | CISO 是 Hermes 時 |
| `CISO_ADVISORY_SCORE_MIN` | `50` | 資安長 risk_score 達此值以上時，一個 ALLOW 會被標為「示警」 |
| `DCISO_OUTPUT_GATE` / `DCISO_EGRESS_GATE` | `1` | Phase A / Phase B 開關 |
| `DCISO_EGRESS_DEST_CLASS` | （依 route mode） | 強制 `local`/`approved`/`external` |
| `GOVERNANCE_APPROVAL_SECRET` | 產生 | 一次性核准 token 的 HMAC 金鑰 |
| `GOVERNANCE_REVIEW_AS_HTTP_ERROR` | `0` | `1` = REQUIRE_REVIEW 用 409 而非 in-band |

---

## 10. 連接埠與服務

| 埠 | 服務 | bind |
|---|---|---|
| 4000 | 閘道（LiteLLM proxy） | 127.0.0.1 |
| 8181 | OPA（硬 PDP） | 127.0.0.1 |
| 8710 | 執行 PEP（Layer 2） | 127.0.0.1 |
| 8900 | 看板（唯讀） | 127.0.0.1 |
| 9000 | 資安長顧問（容器化，`rule`/`llm`） | 內部 |
| 9009 | 資安長顧問主機 sidecar（`hermes` 模式） | 0.0.0.0（讓容器連得到） |
| 8645 | `hermes proxy`（只在 `up-proxy` 時） | 0.0.0.0 |

---

## 11. 加入新的 agent 類型

- **是 OpenAI 相容的？** 什麼都不用做 —— 只要它的 `base_url` 指向閘道，通用
  adapter 就會治理它。它會用 `metadata.harness_type`（或 `openai-compatible`）
  出現在看板上。
- **工具呼叫格式非標準，或你想要一級支援** —— 在
  `gateway/governance/adapters/` 加一個 `HarnessAdapter` 子類，在
  `normalizer.py` 註冊在通用 catch-all 之前，並加對應測試。OPA API、CISO API、
  稽核 schema 都不用改。
- **想給它 Layer 2** —— agent 需要一個 pre-tool-dispatch hook，POST 工具呼叫到
  `:8710/govern` 並遵守 `{}` / `block` / `modify`。

---

## 12. 健康檢查 / 疑難排解

```bash
./bin/dciso status        # route mode、CISO mode、哪些 profile 已插入
./bin/dciso doctor        # docker、.env、閘道可達性、opa、pep
./bin/dciso logs gateway  # 跟一個服務的 log
./bin/dciso down ; rm -f .run/ciso-advisor-host.pid   # 乾淨停止，含主機 sidecar
```

- 閘道 `Exited (3)` / import 錯誤 → LiteLLM 設定檔一定要在 `/app/config.yaml`
  （它把 `callbacks:` 當成相對於設定檔目錄的路徑解析）。
- Hermes 401 / 掉回 OpenRouter → `model.provider` 必須是 `custom`，**而且**要設
  `model.base_url`（只設環境變數不夠）。
- `hermes` CISO 模式下每個請求都以 `SOFT_ADVICE_UNAVAILABLE` 被 DENY →
  提高 `CISO_TIMEOUT_SECONDS`（顧問在等一個慢的模型呼叫）。
