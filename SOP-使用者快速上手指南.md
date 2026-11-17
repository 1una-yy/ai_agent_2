# DCISO CISO 資安長 — 使用者快速上手 SOP

## 📋 目錄
1. [前置條件](#前置條件)
2. [安裝](#安裝)
3. [配置](#配置)
4. [啟動](#啟動)
5. [使用](#使用)
6. [常見問題](#常見問題)

---

## 前置條件

### 必須有：
- ✅ **Docker** — 運行治理系統
- ✅ **Hermes** — 被治理的 Agent（[下載連結](https://hermes.anthropic.com)）
- ✅ **Ollama 或其他 LLM** — 提供模型服務（本機或遠端）

### 可選：
- 📖 本 SOP 文件

---

## 安裝

### 1️⃣ 下載資安長系統

```bash
# 下載 dciso-ciso-core 資料夾
# 位置：/home/aii/Desktop/dciso-ciso-core

cd /home/aii/Desktop/dciso-ciso-core
```

### 2️⃣ 下載/安裝 Hermes

```bash
# 從官方下載 Hermes
# https://hermes.anthropic.com/download

# Linux/macOS:
wget https://github.com/anthropics/hermes/releases/download/v.../hermes
chmod +x hermes

# 或者用包管理器：
brew install hermes  # macOS
apt install hermes   # Ubuntu/Debian
```

### 3️⃣ 確認 Ollama 或 LLM 服務可用

```bash
# 如果用 Ollama（例如本機）：
ollama serve
# 應該在 http://localhost:11434 運行

# 如果用遠端 Ollama：
# 記下 URL，例如：http://192.168.47.77:11435
```

---

## 配置

### 1️⃣ 配置 Gateway 連接到你的 LLM

編輯 `.env` 檔案：

```bash
cd /home/aii/Desktop/dciso-ciso-core
nano .env  # 或用你偏好的編輯器
```

改這些行：

```env
# 改成 ollama（從 test 改成）
GATEWAY_ROUTE_MODE=ollama

# 改成你的 Ollama 地址
OLLAMA_BASE_URL=http://192.168.47.77:11435

# 改成你的模型名（可選）
OLLAMA_MODEL=gpt-oss:120b
```

**保存檔案** (Ctrl+S，然後 Ctrl+X 如果用 nano)

### 2️⃣ 啟動治理系統

```bash
cd /home/aii/Desktop/dciso-ciso-core

docker compose up -d
```

等待所有服務啟動（約 30 秒）

**驗證：**
```bash
docker compose ps
# 所有容器應該顯示 "Up (healthy)"
```

---

## 啟動

### 步驟 1：啟動 Hermes（新終端機）

```bash
hermes chat
```

### 步驟 2：選擇模型配置

Hermes 會要求選擇提供商，選擇：

```
→ (○) custom (direct API)
```

按 ENTER

### 步驟 3：輸入 Gateway 地址

```
API base URL: http://127.0.0.1:4000/v1
API key: gw-aeJSpNgLwAcK_QQr2sph4TMbHTDHH2AF
```

### 步驟 4：選擇相容模式

```
Choice [1-4]: 2
# 選擇 "Chat Completions"
```

### 步驟 5：選擇模型

```
Select model [1-7]: 1
# 選擇 "governed-model"
```

### 步驟 6：自動檢測 Context Length

按 ENTER（留空自動檢測）

---

**完成！** Hermes 現在已連接到治理系統 ✅

```
Welcome to Hermes Agent! Type your message or /help for commands.
✦ Tip: ...

>  # 準備好提問了
```

---

## 使用

### 正常提問（會被治理）

```
> 查詢病患資料庫中的所有 PHI 資訊
```

**可能的回應：**

| 情況 | 回應 |
|------|------|
| ✅ 合法操作 | 直接執行，返回結果 |
| ⚠️ 需要審核 | "這項操作需要人工審核才能進行" |
| ❌ 危險操作 | "無法完成：這項操作風險太高，已被擋下" |

### 打開儀表板查看決策過程

打開瀏覽器：

```
http://127.0.0.1:8900
```

**你會看到：**
- 📊 工具呼叫被攔截的時間點
- 🔍 CISO 的風險分析
- ⚖️ OPA 的決策邏輯
- 📋 完整的治理決策鏈

### 其他有用的命令

```
> /help           # 查看 Hermes 命令
> /model          # 切換模型
> /skills         # 查看可用的 Skills
> /exit           # 離開 Hermes
```

---

## 常見問題

### Q1: Hermes 連接失敗

**症狀：** "Connection refused" 或 "Invalid API key"

**解決：**
```bash
# 1. 確認 Gateway 在運行
docker compose ps

# 2. 確認 .env 中的 API key 正確
grep GATEWAY_MASTER_KEY .env

# 3. 重啟 Gateway
docker compose restart gateway
```

### Q2: 工具呼叫被自動拒絕

**症狀：** 所有操作都被攔截

**可能原因：**
- CISO 認為操作風險太高
- OPA 硬策略不允許

**檢查：**
```bash
# 1. 打開儀表板查看完整原因
http://127.0.0.1:8900

# 2. 查看 Gateway 日誌
docker compose logs gateway | tail -20
```

### Q3: 儀表板無法訪問

**症狀：** "Cannot connect to server"

**解決：**
```bash
# 確認 viewer 容器在運行
docker compose ps | grep viewer

# 如果沒有，重啟
docker compose restart viewer
```

### Q4: 治理系統不響應

**症狀：** Hermes 卡住或超時

**解決：**
```bash
# 1. 檢查所有服務狀態
docker compose ps

# 2. 查看日誌找錯誤
docker compose logs

# 3. 完整重啟
docker compose down
docker compose up -d
```

### Q5: 如何用不同的 LLM？

**選擇 Hermes 時：**
```
Select model [1-7]: 3
# 選擇任何可用的模型（例如 claude-sonnet-5）
```

所有模型都會通過 Gateway 被治理，效果相同 ✓

---

## 🚀 完整使用流程圖

```
使用者啟動 Hermes
    ↓
連接到 Gateway (http://127.0.0.1:4000)
    ↓
提問或讓 Hermes 執行工具
    ↓
Gateway 攔截工具呼叫
    ↓
CISO 分析風險
    ↓
OPA 做決策
    ↓
返回結果給 Hermes
    ├─ ✅ 允許 → 執行工具，返回結果
    ├─ ⚠️ 需審核 → 提示使用者
    └─ ❌ 拒絕 → 告訴使用者原因
    ↓
儀表板記錄決策過程
```

---

## 📞 故障排查檢查清單

```
□ Docker 在運行？                    docker compose ps
□ .env 配置正確？                    cat .env | grep OLLAMA
□ Ollama/LLM 服務可訪問？            curl http://你的ollama/api/tags
□ Hermes 指向正確的 Gateway？        hermes chat 時看 URL
□ 儀表板能訪問？                     http://127.0.0.1:8900
□ 查看 Gateway 日誌有沒有錯誤？      docker compose logs gateway
```

---

## 💡 小提示

1. **第一次使用時可能慢** — 系統需要載入 CISO 和 OPA，屬正常
2. **查看儀表板** — 最快的方式理解決策過程
3. **切換模型** — 不同模型可能有不同表現，自由嘗試
4. **保存 .env** — 改完後記得保存，重啟才能生效

---

**準備好了嗎？** 按照上面的步驟操作，現在就試試吧！🎯

如有任何問題，查看儀表板 (http://127.0.0.1:8900) 的完整決策鏈，通常能找到答案。
