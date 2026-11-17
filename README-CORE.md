# DCISO CISO Core — AI 資安長完整工作鏈

精簡版，只包含 **AI 資安長（CISO Agent）的完整治理流程**。

## 📦 包含內容

```
dciso-ciso-core/
├── gateway/              ← 治理閘道核心
│   ├── governance/
│   │   ├── schemas.py              ✏️ [新增 AdviceConfidence, REQUIRE_HUMAN_REVIEW]
│   │   ├── decision_orchestrator.py
│   │   ├── enforcer.py             ✏️ [新增 _present_human_review_menu()]
│   │   ├── clients/
│   │   │   ├── ciso_advisor.py     ✏️ [新增 escalation 檢測]
│   │   │   └── opa.py
│   │   └── adapters/
│   │       └── hermes.py           (支持 Hermes Agent)
│   └── callbacks/
│       └── governance_callback.py   (LiteLLM 回調)
│
├── ciso-advisor/         ← CISO AI 顧問服務
│   ├── app.py            ✏️ [新增 confidence + escalation_reason]
│   ├── system-prompt.txt
│   ├── response-schema.json
│   ├── security-skill.md
│   └── Dockerfile
│
├── policy/               ← OPA 硬治理策略
│   ├── agent_governance.rego  ✏️ [新增 CISO_UNCERTAIN 檢測]
│   ├── data.json               (工具、數據分類、政策)
│   └── tests/
│       └── *_test.rego         (18 個 OPA 單元測試)
│
├── viewer/               ← 治理儀表板 UI
│   ├── app.py
│   ├── Dockerfile
│   └── templates/
│
├── docker-compose.yml    ← 一鍵啟動整個治理棧
├── Makefile              ← 開發命令
├── .env / .env.example   ← 環境設定
└── docs/                 ← 架構文檔
```

## 🚀 快速開始

### 1. 環境設定
```bash
cp .env.example .env
# 編輯 .env：設定 OPENAI_API_KEY 或 OLLAMA_BASE_URL
```

### 2. 啟動治理棧
```bash
docker-compose up
```

服務地址：
- **Gateway**（治理層）：http://127.0.0.1:4000
- **CISO 顧問**：http://127.0.0.1:8800/advise
- **儀表板**：http://127.0.0.1:8900
- **OPA**：http://127.0.0.1:8181

### 3. 連接 Hermes Agent
```bash
# Hermes 指向 Gateway
export HERMES_GATEWAY_URL=http://127.0.0.1:4000
export GATEWAY_TOKEN=<GATEWAY_MASTER_KEY from .env>

hermes chat -q "你的提示"
```

## 🔄 完整工作鏈

```
Hermes Agent
    ↓ (工具呼叫提議)
Gateway (LiteLLM 代理)
    ↓
governance_callback.py (攔截)
    ↓
GovernanceEvent (標準化)
    ↓
OPA 快速預檢 (hard_deny_reasons)
    ↓
├─ 有硬性拒絕? → 直接 DENY
└─ 沒有? → 調用 CISO
    ↓
CISO 顧問 (llm / rule / hermes 模式)
    ├─ 返回 advice + confidence + escalation_reason
    └─ confidence 可能是：
       ├─ CONFIDENT      → 有信心
       ├─ UNCERTAIN      → 需要人類審查 🔴
       └─ UNABLE_TO_ADVISE → 完全無法判斷
    ↓
OPA 最終決策
    ├─ 檢測 confidence == UNCERTAIN
    ├─ 如果是 → 升級為 REQUIRE_REVIEW
    └─ 優先級：DENY > REQUIRE_REVIEW > MODIFY > ALLOW
    ↓
Enforcer 執行決策
    ├─ ALLOW → 直接允許
    ├─ DENY → 拒絕 + 理由給 Hermes
    ├─ MODIFY → 修改參數後執行
    ├─ REQUIRE_REVIEW (無 UNCERTAIN) → 返回批准菜單
    └─ REQUIRE_REVIEW (有 UNCERTAIN) → 返回「人類決策菜單」🎯
        ├─ 允許
        ├─ 拒絕
        └─ 修改後執行
    ↓
返回結果給 Hermes
    ↓
審計日誌 + 儀表板記錄
```

## 🎯 關鍵改進（相比原版）

| 改進 | 位置 | 效果 |
|------|------|------|
| **信心度信號** | schemas.py | CISO 能表達「不確定」 |
| **Escalation 檢測** | ciso-advisor/app.py | 檢測模糊/邊界情況 |
| **OPA 升級邏輯** | agent_governance.rego | 不確定自動 escalate |
| **選項菜單** | enforcer.py | 人類決策而非自動化 |

## 📊 運作模式

### 模式 1：明確決策（自動化）
```
CISO: DENY (confidence=CONFIDENT)
  ↓
OPA: DENY
  ↓
Enforcer: 直接拒絕，Hermes 重新規劃 ⚡ 快速
```

### 模式 2：不確定決策（人類介入）
```
CISO: DENY/ALLOW/MODIFY (confidence=UNCERTAIN)
  ↓
OPA: 升級為 REQUIRE_REVIEW
  ↓
Enforcer: 顯示選項菜單
  ↓
人類選擇 → 批准令牌 → 執行決定 🤝 安全
```

## 🔌 支持的 Agent

目前內置支持：
- ✅ **Hermes** — 通過 adapters/hermes.py

擴展到其他 Agent（如 Claude Agent、LangChain）：
```
gateway/governance/adapters/
├── hermes.py        ← 現有
└── your_agent.py    ← 新加（實現 normalize() + enforce()）
```

## 📝 文件說明

- **docs/architecture.md** — 整體架構
- **docs/hard-policy-and-agt.md** — OPA 策略詳解
- **docs/governance-event.md** — 事件格式
- **docs/operating-sop.md** — 運維 SOP

## ❌ 不包含的內容

- `tests/` — 測試套件（可自行加回）
- `demo/` — Demo 腳本（可自行加回）
- `mock-llm/` — 模擬 LLM（使用真實 API）
- `pep/` — Layer 2 執行層（MVP 不需要）
- `.venv/` — 虛擬環境（需要時重建）

## 🆘 故障排查

```bash
# 查看 Gateway 日誌
docker-compose logs gateway

# 查看 CISO 日誌
docker-compose logs ciso-advisor

# 查看 OPA 日誌
docker-compose logs opa

# 訪問儀表板看完整流程
http://127.0.0.1:8900
```

---

**這是精簡版工作鏈，包含所有 AI 資安長治理的核心功能。**
