# DCISO CISO 資安長 — 簡易版 SOP

> **核心原則：** 資安長系統一次安裝，使用者只需 Plug/Unplug Agent

---

## 📋 分角色 SOP

### 👨‍💼 Part 1: Admin（資安團隊）— 一次性安裝

#### 1️⃣ 下載資安長系統

```bash
# 下載 dciso-ciso-core 資料夾
# 位置：/home/aii/Desktop/dciso-ciso-core
cd /home/aii/Desktop/dciso-ciso-core
```

#### 2️⃣ 配置 .env（指向你的 LLM）

編輯 `.env`，改這三行：

```env
# 路由模式
GATEWAY_ROUTE_MODE=ollama

# 你的 Ollama/LLM 地址
OLLAMA_BASE_URL=http://192.168.47.77:11435

# 你的模型名
OLLAMA_MODEL=gpt-oss:120b
```

保存檔案

#### 3️⃣ 啟動資安長系統

```bash
cd /home/aii/Desktop/dciso-ciso-core

docker compose up -d
```

**驗證所有服務在運行：**
```bash
docker compose ps
# 所有容器應該顯示 "Up (healthy)"
```

#### 4️⃣ 驗證儀表板可訪問

打開瀏覽器：
```
http://127.0.0.1:8900
```

✅ **完成！資安長系統已啟動，之後不需要再動。**

---

### 👤 Part 2: 使用者 — 只需 Plug / Unplug

使用者可能用的 Agent：
- Hermes
- OpenClaw  
- 其他支持 OpenAI 相容端點的 Agent

#### 📌 步驟 A：Plug In（連接到治理層）

**以 Hermes 為例：**

```bash
# 1. 啟動 Hermes
hermes chat

# 2. 選擇模型時，選「custom endpoint」
# → 自動偵測 [current]
# → Chat Completions
# → custom (direct API)

# 3. 輸入 Gateway 地址
API base URL: http://127.0.0.1:4000/v1

# 4. 輸入 API key
API key: gw-aeJSpNgLwAcK_QQr2sph4TMbHTDHH2AF

# 5. 選模型
Select model: 1 (governed-model)

# 完成！Hermes 現在被治理
```

**或用環境變數（推薦）：**

```bash
export HERMES_GATEWAY_URL="http://127.0.0.1:4000"
export GATEWAY_TOKEN="gw-aeJSpNgLwAcK_QQr2sph4TMbHTDHH2AF"

hermes chat
```

#### 📌 步驟 B：使用 Agent（被治理）

```bash
# 在 Hermes 中正常提問
> 查詢患者資料庫中的所有敏感資訊

# 可能的回應：
✅ 合法 → 直接執行
⚠️ 需審核 → "需要人工審核"
❌ 危險 → "操作風險太高，已被擋下"
```

**實時查看決策過程：**
```
打開儀表板：http://127.0.0.1:8900
```

#### 📌 步驟 C：Unplug Out（恢復原狀）

**方式 1：恢復環境變數**
```bash
unset HERMES_GATEWAY_URL
unset GATEWAY_TOKEN

# 重新啟動 Hermes，選原來的 LLM provider
hermes chat
```

**方式 2：手動還原 Hermes 配置**
```bash
# 編輯 Hermes 設定檔，恢復原來的 API 端點
nano ~/.hermes/config.toml
# 改回原來的 model provider
```

✅ **Hermes 現在不再被治理。**

---

## 🎯 使用者完整流程

```
【使用前】
Plug：
  export HERMES_GATEWAY_URL="http://127.0.0.1:4000"
  export GATEWAY_TOKEN="gw-aeJSpNgLwAcK_QQr2sph4TMbHTDHH2AF"
  hermes chat

【使用中】
在 Hermes 中正常工作
所有工具呼叫會被資安長審查
查看 http://127.0.0.1:8900 了解決策過程

【使用後】
Unplug：
  unset HERMES_GATEWAY_URL
  unset GATEWAY_TOKEN
  重啟 Hermes 恢復原狀
```

---

## 📊 架構圖（使用者視角）

```
┌─────────────────────────────────────────────────────┐
│        Hermes / OpenClaw / 其他 Agent               │
│  (使用者的工作 Agent)                                │
└──────────────┬──────────────────────────────────────┘
               │
        ┌──Plug/Unplug──┐
        │               │
    【Plug】        【Unplug】
    ↓                   ↓
http://127.0.0.1:4000   直接用
    ↓                   LLM
┌─────────────────────┐
│  Gateway            │
│  (治理層)            │
│  CISO + OPA         │
└──────────┬──────────┘
           │
           ↓
     你的 LLM
   (Ollama/OpenAI)
```

---

## ⚙️ 各角色的責任

| 角色 | 負責 | 頻率 | 複雜度 |
|------|------|------|--------|
| **Admin** | 安裝資安長、配置 .env、啟動系統 | 一次 | 中 |
| **使用者** | Plug/Unplug Agent、正常工作 | 每次開始/結束 | 低 |

---

## 🆘 常見問題

### Q: Hermes 無法連接到 Gateway

**檢查：**
```bash
# 1. Gateway 在運行？
docker compose -f /home/aii/Desktop/dciso-ciso-core/docker-compose.yml ps

# 2. API key 正確？
grep GATEWAY_MASTER_KEY /home/aii/Desktop/dciso-ciso-core/.env

# 3. 重試連接
```

### Q: 所有操作都被拒絕

**原因：** 資安政策很嚴格

**查看原因：**
```
http://127.0.0.1:8900
→ 點擊最後一個決策
→ 查看 CISO 分析 + OPA 理由
```

### Q: 怎麼知道 Hermes 被治理了？

**檢查方式：**
1. 提問一個正常的操作
2. 打開儀表板 http://127.0.0.1:8900
3. 如果有新的決策記錄 → 說明被治理了 ✅

### Q: 可以用不同的 Agent 嗎？

**可以！** 只要 Agent 支持 OpenAI 相容的 API：

```bash
# OpenClaw
openclaw --api-endpoint http://127.0.0.1:4000/v1 \
         --api-key gw-aeJSpNgLwAcK_QQr2sph4TMbHTDHH2AF

# 其他 Agent
只要支持 OpenAI-compatible endpoint 即可
```

---

## 📝 Cheat Sheet（快速參考）

### Plug（連接治理層）
```bash
export HERMES_GATEWAY_URL="http://127.0.0.1:4000"
export GATEWAY_TOKEN="gw-aeJSpNgLwAcK_QQr2sph4TMbHTDHH2AF"
hermes chat
```

### Unplug（恢復原狀）
```bash
unset HERMES_GATEWAY_URL
unset GATEWAY_TOKEN
hermes chat
```

### 查看決策
```
http://127.0.0.1:8900
```

### 檢查系統狀態
```bash
docker compose -f /home/aii/Desktop/dciso-cisi-core/docker-compose.yml ps
```

---

## ✅ 完成檢查清單

### Admin 安裝檢查
- [ ] .env 配置完成
- [ ] `docker compose up -d` 執行
- [ ] 所有容器 healthy
- [ ] 儀表板可訪問 http://127.0.0.1:8900

### 使用者使用檢查
- [ ] 執行 Plug 命令
- [ ] Hermes 正常啟動
- [ ] 儀表板顯示新的決策記錄
- [ ] 操作完成後 Unplug

---

**就這麼簡單！** 🎉

**Admin：** 一次安裝，然後不動。
**使用者：** 只需 Plug/Unplug，享受被治理的 Agent。
