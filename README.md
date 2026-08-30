# carbon-cred-demo

跨組織碳足跡憑證選擇性揭露 demo:**越南紗廠 → 台灣布廠 → 歐洲品牌**,外包染整為 A/B 案的碳排差異來源。
憑證用 **SD-JWT VC**(`@sd-jwt/core` + `@sd-jwt/sd-jwt-vc`)簽發,授權用 **Cedar**,應用層撤銷用
**Token Status List**(`draft-ietf-oauth-status-list-21`),組織身分用 **vLEI Sandbox**,稽核用
**sha256 hash-chain**。

> 規格優先序(與 `CLAUDE.md` 一致):`docs/2026-08-26-專案架構決策.md` > `docs/demo情境設定與合成資料規格-v3.md` >
> `docs/製造貿易demo實作藍圖.html`。本檔是給操作/錄影用的說明書,規格衝突處一律以 `CLAUDE.md` 與上列文件為準。

---

## 1. 安裝與執行

### 1.1 前置需求

- **Node.js**:本檔 B-9 實測環境為 `v24.2.0`;`package.json` 未鎖 `engines`,建議 Node ≥ 20(需原生 ESM + `node:child_process`/`node:crypto` 支援)。
- **Python 3**:僅供 `.venv` 內 `blake3` + `cryptography`(vLEI sandbox 用;實測環境 Python 3.13.7)。
- **`vendor/vlei-sandbox/`**:第三方 vLEI sandbox 整包複製(唯讀,見該目錄 `VENDOR.md`);不得修改上游檔案,所有整合寫在 `server/`、`scripts/` 的包裝層。
- **`.vlei/`、`data/keys/`**:私鑰材料,執行 `make setup` 後產生,**永不進版控**(`.gitignore` 已排除)。
- 不需要 Docker、不需要任何鏈上/測試網帳號、不需要 API key——全部在本機 localhost 執行。

### 1.2 一鍵安裝

```bash
make setup   # venv + pip(blake3/cryptography)+ npm install + presign 7 呈現包 + seed
```

`make setup` 依序做:建 `.venv`、灌 `blake3`/`cryptography`、`npm install`、`bash scripts/presign-vlei.sh`
(vLEI sandbox 預簽 5 LE + 2 ECR,產出 `data/vlei/*.presentation.json` 共 7 張)、`npx tsx scripts/seed.ts`
(灌 `data/seed.json` 定義的參數表 + CB 先簽 `tc_rcs`/`ccs_scope_cert`)。

### 1.3 開發伺服器

```bash
make dev   # fastify(:3000)+ vite(:5173)並行,vite 已代理 /api、/status 到 :3000
```

開瀏覽器到 `http://localhost:5173/`。四分頁:紗廠(簽發)/ 誠紡閘道(聚合 · Cedar)/ Nordlicht 品牌 Agent(M2 · 查驗)/ 稽核與撤銷。

### 1.4 `make demo-reset` SOP

```bash
make demo-reset   # = npx tsx scripts/seed.ts;還原 DB 與 Status List 到 seed 狀態
```

**何時跑**:每次要重新錄影 / 交付前 / 前一輪操作留下已撤銷憑證或已放行 Dossier 而想從乾淨狀態重來時。

**跑完會回到什麼狀態**:

- `credentials`、`dossiers`、`audit_chain`、`credential_history` 等表清空重建。
- `data/status/credentials.jwt`、`data/status/mandates.jwt` 兩份 Status List 全部 bit 歸零重簽(無任何撤銷)。
- CB 簽的 `tc_rcs`(idx 9)、`ccs_scope_cert`(idx 10)重新入庫(沿用既有 sandbox 鑰,非重新 presign)。
- 案件 A/B/C/Cp 的定義維持在 `data/seed.json`,尚未簽發任何 `pcf_upstream`/`pcf_dyeing`/`pcf_aggregate`——需回到前端逐幕操作重新產生。
- **不會**重跑 `presign-vlei.sh`(sandbox AID/LEI/公私鑰維持不變,manifest 不變);要重新 presign 才需 `make presign`。

### 1.5 測試

```bash
make test   # npx tsx scripts/test.ts——498 項檢查(含本 phase 新增 20 項 deep-link/導覽狀態單元測試)
```

全綠通過才算過;`make test` 內建連跑相容性(不依賴前一次殘留狀態)、`make demo-reset` 後再跑 `make test` 亦全綠(見 §6 B-9 實測紀錄)。

### 1.6 其他指令

| 指令 | 用途 |
|---|---|
| `make presign` | 單獨重跑 vLEI sandbox 預簽(產生 7 張呈現包 + manifest) |
| `make seed` | 同 `make demo-reset` |
| `make revoke LIST=credentials\|mandates IDX=<n>` | 幕 6:翻某個 Status List bit 並以 FAB LE 鑰重簽該清單 JWT(前端「稽核與撤銷」分頁亦有同功能按鈕,不需重啟 `make dev`) |
| `make tamper N=<seq>` | 幕 6:竄改示範——備份 db 後改稽核鏈第 N 筆 `payload_json` |
| `make untamper` | 還原 `make tamper` 建立的備份 |
| `make verify-chain` | 幕 4/6:逐列重驗稽核鏈雜湊 + 簽章(竄改示範的對照組) |
| `make bench` | Phase 4 新增:實測 B-9 成本數字(presign 張數 + 簽發/驗證耗時),量測完自動以 `scripts/seed.ts` 歸位 |

---

## 2. 架構與信任邊界

### 2.1 五方(5 LE + 2 ECR)+ 2 把 workload 鑰

| 角色 | 組織 | 鑰種類 | 簽什麼 |
|---|---|---|---|
| `yarn` | Sợi Xanh Việt Co., Ltd.(越藍紗業,越南) | vLEI sandbox LE | `pcf_upstream`(幕 1) |
| `fab` | 誠紡實業股份有限公司(台灣) | vLEI sandbox LE | `pcf_aggregate`(幕 2)、Token Status List Token(閘道為清單發布方) |
| `dye` | 彩合染整股份有限公司(台灣彰化) | vLEI sandbox LE | `pcf_dyeing`、發票 invoice |
| `brand` | Nordlicht Sports AG(德國) | vLEI sandbox LE | 身分錨定(驗證側) |
| `cb` | Lowland Certification B.V.(荷蘭;虛構名,刻意避開真實 CB) | vLEI sandbox LE | `tc_rcs`(幕 1)、`ccs_scope_cert`(seed 時)、`slcp_dcc`(加映) |
| `fab_cfo` | 誠紡財務主管 Lin Hsiu-Feng | vLEI sandbox **ECR** | M1 委任狀、幕 5 人工放行(`release` JWS) |
| `brand_cso` | Nordlicht 永續長 Anna Schäfer | vLEI sandbox **ECR** | M2 委任狀 |
| `fab-workload` | app 產生(非 vLEI) | Ed25519 app 鑰 | 幕 2/5 內部 Dossier、跨組織 disclose 之閘道端簽章 |
| `brand-workload` | app 產生(非 vLEI) | Ed25519 app 鑰 | 跨組織 disclose request(M2 delegate_kid 綁定) |

不建立 `human.key`——人工放行一律用對應 ECR 鑰(`fab_cfo`/`brand_cso`),不是額外虛構的「人」身分。

### 2.2 信任邊界一覽

- **一方一鑰**:所有簽章鑰只經 `server/keys.ts` 自 `.vlei/state.json`(私鑰,700/600 權限、never 進版控)匯出;`server/routes/*` 不得直接讀鑰檔。
- **Cedar 不碰密碼學**:後端先驗完 mandate 簽章、`iss`/`aud`/`exp`/`jti`、`delegate_kid` 對 request 簽章、Token Status List、`request_nonce` 唯一性,才把 `mandate_status_ok`/`delegate_key_ok`/`replay_ok` 三個布林餵給 Cedar;政策本身不讀信任狀態,只讀布林與 mandate 資料欄位。
- **偽造高額放行的門檻**:偽造一筆幕 5 高額 Dossier 並讓它 RELEASED,需要同時持有 `fab-workload`(建卡)**與** `fab_cfo`(簽放行)兩把伺服端私鑰——這是本 demo「一方一鑰」設計下的信任邊界,不是漏洞。
- **無網路認證層**:localhost demo 對 `/api/human-sign`、`/api/mandates`、`/api/agent/run` 等一律無 auth 閘;唯一的 demo-mode 守門是 `/api/demo/sign-disclose-request`(瀏覽器不得持有 `brand-workload` 私鑰,由此 route 代簽,但仍完整走 `/api/disclose` 驗證管線,不繞過任何檢查)。詳見 §5 治理缺口。
- **H2 算術洩漏防線**:跨組織 presentation 只能有一個排放數字(`pcf_total`);`pcf_yarn`/`pcf_knitting`/`pcf_dyeing` 三段分項 `NEVER_DISCLOSABLE`,不進任何 `allowed_claims`,presenter 層再擋一次(政策 + 程式碼雙重拒絕)。

### 2.3 四分頁 × 六幕對照

| 分頁(URL `tab=`) | 對應幕次 |
|---|---|
| `yarn` — 紗廠 Sợi Xanh Việt(簽發) | 幕 1 |
| `gateway` — 誠紡閘道(聚合 · Cedar) | 幕 2、幕 4(Cedar 決策面板)、幕 5 |
| `brand` — Nordlicht 品牌 Agent(M2 · 查驗) | 幕 3、幕 4(觸發加碼索取) |
| `audit` — 稽核與撤銷 | 幕 6(+ 幕 5 Dossier 列表) |

---

## 3. 六幕劇本

| 幕 | 供應鏈位置 | 做什麼 | 看什麼 | 理由碼 |
|---|---|---|---|---|
| **1 簽發** | 紗廠(YARN) + 認證機構(CB) | CB 簽 `tc_rcs`(TE camelCase 欄位)→ 紗廠簽 `pcf_upstream`,公開層 `tc_ref` 綁定 TC | 兩張憑證卡(卡 1 TC、卡 2 三色碳憑證)、raw token、竄改 1 byte 後驗證失敗示範 | `CREDENTIAL_SIG_INVALID`、`CREDENTIAL_PARSE_ERROR`、`ISSUER_UNKNOWN`、（防呆）`TC_REF_MISMATCH` |
| **2 聚合** | 布廠(FAB) | FAB 驗三張外部憑證(`tc_rcs`/`pcf_upstream`/`pcf_dyeing`)+ 核對 `tc_ref` 與 SC 分包商清單 → 程式算三段聚合 → 簽 `pcf_aggregate` | 三段疊層熱點圖(紗/織布/染整;B 案染整段變紅並越過 9.5 門檻線)、`pcf_aggregate` 卡三個 `precursor_refs` 指紋、Scope Certificate 小卡 | `TC_REF_MISMATCH`、`CCS_SUBCONTRACTOR_NOT_LISTED`、`SCOPE_CERT_INVALID`、`VCT_ISSUER_UNAUTHORIZED`、`CREDENTIAL_REVOKED` |
| **3 委任查驗** ★ | 品牌(BRAND) Agent-2 | 持 M2 mandate 向 FAB 閘道發出查驗請求 → Cedar P1 允許 → presentation 只有六列(一個排放數字)→ Brand 端離線驗簽章/vLEI 鏈/Status List 三綠勾 | M2 委任狀卡、PERMIT 徽章 + `POLICY_P1_PERMIT`、六列 presentation、OFFLINE 驗證三綠勾 | `POLICY_P1_PERMIT`、`CLAIM_NOT_IN_MANDATE`、`MANDATE_EXPIRED`、`RECEIPT_INVALID`、`VLEI_CHAIN_BROKEN` |
| **4 越界攔截** ★ | 品牌(BRAND) Agent-2 | 加碼索取 `plant_total_output`(全廠產量)→ Cedar P2 一律 DENY,不看 mandate 寫什麼 | DENY 紅色徽章、Gateway 頁 P2 規則原文高亮 + DenyStamp 圖章、稽核帶多一行 | `POLICY_P2_CONFIDENTIAL` |
| **5 門檻+付款閘道** | 布廠(FAB)付染整廠(DYE) | Agent-1 持 M1 檢五要件(身分、SC 分包商、碳排 ≤ 9.5、發票、收款帳戶風險)→ 案 A 全過建 Dossier → 財務主管 ECR 鑰簽放行 → **mock USD 3,420 電匯指令**(FAB→DYE)→ RELEASED;案 B 碳超標轉人工;案 C 風險雙來源退回;案 C′ 單來源只記錄 | Agent-1 五項檢查列(✓/✗)、Dossier 卡、簽署確認對話框、放行後電匯指令卡 | `CARBON_OVER_THRESHOLD`、`CCS_SUBCONTRACTOR_NOT_LISTED`、`INVOICE_INVALID`、`AMOUNT_OVER_LIMIT`、`PAYER_NOT_ALLOWED`、`CURRENCY_MISMATCH`、`COUNTERPARTY_NOT_ALLOWED`、`MULTI_SOURCE_CONFIRMED`、`SINGLE_SOURCE_ONLY`、`POLICY_P3_PERMIT`、`RELEASE_APPROVED` |
| **6 稽核+撤銷** | 布廠(FAB)/ 稽核員 | 竄改一筆日誌 → `verify-chain` FAIL → 復原;**撤 `pcf_dyeing`(A)**(換燃料要重報)→ 重跑案 A 被拒 `CREDENTIAL_REVOKED`、既有 Dossier 標 `DEPENDS_REVOKED` → DYE 重簽新 `pcf_period` → FAB 重聚合 → 重驗綠;輔線撤 M1 → `MANDATE_REVOKED` | Status List bit 條(紅=已撤銷)、Dossier 列表狀態徽章、`verify-chain` 終端輸出 | `AUDIT_CHAIN_TAMPERED`、`CREDENTIAL_REVOKED`、`DEPENDS_REVOKED`、`AGGREGATE_STALE`、`MANDATE_REVOKED` |
| 加映(投影片,未寫程式) | — | 同一管線換 `slcp_dcc`(只揭露「零招募費=true」);鞋廠子集委任只答是/否 | — | — |

A/B 差異**只來自 `pcf_dyeing` 的 `heat_source`/`renewable_share`**(染整燃料);幕 5 mock USD 電匯固定 3,420(FAB → DYE);幕 6 撤銷主線是 `pcf_dyeing`。錄影優先序與保底(不得回退鋼鐵版):幕 3 → 幕 4 → 幕 6 → 幕 5(案 B)→ 幕 1–2 → 案 C → 加映(spec §7)。

---

## 4. deep-link 一覽

Phase 4 新增:`web/src/App.tsx` 的 `parseDeepLink(search)` 純函式解析 `?tab=…&case=…`,四分頁 key
(`yarn`/`gateway`/`brand`/`audit`)+ 四案件(`A`/`B`/`C`/`Cp`);不合法值一律回 `null`,呼叫端 fallback
現有預設。切分頁或切案件皆以 `history.pushState` 更新網址列(不整頁重載,瀏覽器上一頁/下一頁可回退)。

> `gateway` 分頁有兩個獨立案件選單:聚合步驟(僅 A/B)與幕 5 Agent-1 步驟(A/B/C/Cp)。`?case=` 帶入時兩個
> 選單都會嘗試套用,聚合選單只認 A/B(C/Cp 會 fallback 為 A)。

| 用途 | URL(接在 `http://localhost:5173/` 後) |
|---|---|
| 幕 1 · 紗廠簽發(案 A) | `?tab=yarn&case=A` |
| 幕 1 · 紗廠簽發(案 B) | `?tab=yarn&case=B` |
| 幕 2 · 聚合(案 A,綠;含 SC 小卡) | `?tab=gateway&case=A` |
| 幕 2 · 聚合(案 B,染整段紅、越過門檻) | `?tab=gateway&case=B` |
| 幕 3 · 委任查驗(案 A) | `?tab=brand&case=A` |
| 幕 4 · 越界攔截 | `?tab=brand&case=A`(到頁後按紅色「加碼索取」鈕) |
| 幕 5 · 案 A(五項全過 → 放行) | `?tab=gateway&case=A`(到頁後於「門檻與付款閘道」區塊操作) |
| 幕 5 · 案 B(碳超標轉人工) | `?tab=gateway&case=B` |
| 幕 5 · 案 C(風險雙來源退回) | `?tab=gateway&case=C` |
| 幕 5 · 案 C′(風險單來源只記錄) | `?tab=gateway&case=Cp` |
| 幕 6 · 稽核與撤銷 | `?tab=audit` |

---

## 5. A-2 逐幕截圖清單(手動操作指引)

專案未安裝 Playwright/無頭瀏覽器(brief 明文禁止為此加清單外重依賴),以下為**手動操作**指引;
每幕皆可在 30 秒內以「deep-link + 少數點擊」重現。開始前先 `make demo-reset`。

### 幕 1(紗廠簽發)

1. 開 `?tab=yarn&case=A`。
2. 點「載入 CB 簽發的 TC」→ 截圖卡 1(`tc_rcs`,TE camelCase 欄位)。
3. 點「簽發」→ 截圖卡 2(`pcf_upstream`,🟢🟡🔴 三色標示)。
4.(可選)點 `verify()` → 綠字通過;點「竄改 1 byte → 驗證失敗示範」→ 截圖紅字 `CREDENTIAL_SIG_INVALID`。

### 幕 2(聚合)

1. 開 `?tab=gateway&case=A`,點「聚合簽發」→ 截圖三段疊層熱點圖(全綠)+ `pcf_aggregate` 卡(三個 `precursor_refs` 指紋)+ Scope Certificate 小卡。
2. 換 `?tab=gateway&case=B`,點「聚合簽發」→ 截圖染整段變紅、總值越過門檻線。

### 幕 3(委任查驗)

1. 開 `?tab=brand&case=A`(頁面載入時自動簽 M2 mandate)→ 截圖 M2 委任狀卡(六個 `allowed_claims` 標籤)。
2. 點「發出查驗請求 ▶」→ 截圖 PERMIT 綠色徽章 + 六列 presentation + Brand 端 OFFLINE 三個綠勾。

### 幕 4(越界攔截)

1. 同上頁面,點紅色「加碼索取 全廠產量 plant_total_output ▶」→ 截圖 DENY 徽章 + `POLICY_P2_CONFIDENTIAL`。
2. 切到 `?tab=gateway` → 截圖「越界攔截判定」區塊:P2 規則原文紅框高亮 + DenyStamp 圖章;下方 `AuditStrip` 多一行。

### 幕 5(門檻+付款閘道,四案)

1. `?tab=gateway&case=A` → 點「執行 Agent-1」→ 截圖五項檢查全綠 ✓ → 點「以財務主管 ECR 金鑰簽署」→ 確認對話框 → 「確認簽署」→ 截圖 RELEASED + mock USD 3,420 電匯指令卡。
2. `?tab=gateway&case=B` → 「執行 Agent-1」→ 截圖 `carbon_threshold` 項紅色 ✗ `CARBON_OVER_THRESHOLD`(無放行按鈕渲染)。
3. `?tab=gateway&case=C` → 「執行 Agent-1」→ 截圖 `wallet_risk` 項紅色 ✗ `MULTI_SOURCE_CONFIRMED`(兩來源分數列表)。
4. `?tab=gateway&case=Cp` → 「執行 Agent-1」→ 截圖 `wallet_risk` 項仍為 ✓(單來源、`SINGLE_SOURCE_ONLY` 只記錄不升級),流程可續走放行。

### 幕 6(稽核+撤銷)

1. 竄改示範(終端):`make tamper N=<seq>`(seq 取自 `?tab=audit` 頁或 `/api/audit`)→ `make verify-chain` → 截圖終端 FAIL 輸出 → `make untamper` 復原 → 再跑 `make verify-chain` 截圖恢復綠。
2. 撤銷 `pcf_dyeing`(A)主線:開 `?tab=audit`,清單選「憑證(credentials)」、idx 選 `pcf_dyeing-A`(idx 4)→ 按「撤銷」→ 截圖該格變紅。
3. 回 `?tab=gateway&case=A`,點「執行 Agent-1」→ 截圖 `CREDENTIAL_REVOKED` 拒絕。
4. 回 `?tab=audit` → 截圖 Dossier 列表中舊案 A 的 Dossier 顯示「依據已撤銷,需重驗」（`DEPENDS_REVOKED`)。
5. DYE 重簽 + FAB 重聚合(目前無前端按鈕,終端執行,詳 §5 治理缺口):
   ```bash
   curl -X POST 'http://localhost:3000/api/issue/dyeing?case=A&reissue=1'
   curl -X POST 'http://localhost:3000/api/aggregate?case=A&reissue=1'
   ```
   完成後回 `?tab=gateway&case=A` 重新「聚合簽發」+「執行 Agent-1」→ 截圖重驗轉綠。
6. 輔線撤 M1:`?tab=audit`,清單選「委任狀(mandates)」、idx 選 `M1`(idx 0)→ 撤銷 → 回 `?tab=gateway` 任一案「執行 Agent-1」→ 截圖 `MANDATE_REVOKED`。

---

## 6. 治理缺口說明

(整合 `CLAUDE.md`「Codex 審查定案」三節 2026-08-30 之定案 + spec v3 §12;誠實列出哪些是 demo 邊界,非漏洞。)

- **無網路認證層**:`/api/human-sign`、`/api/mandates`(M1/M2 人簽)、`/api/agent/run` 等 route 皆無 auth 閘;唯一 demo-mode 守門在 `/api/demo/sign-disclose-request` 的 workload 簽章代簽 oracle(瀏覽器不持有 `brand-workload` 私鑰,但仍完整走 `/api/disclose` 全部驗證,不繞過任何檢查)。人核可 = UI 確認對話框 + 獨立 `fab_cfo` ECR 鑰簽章;偽造高額 Dossier 需同時持有伺服端的 `fab-workload`(建卡)與 `fab_cfo`(放行)兩把私鑰。此為既有單人 demo 設計,非漏洞。
- **vLEI 撤銷走 sandbox TEL**:身分憑證(法人 LE / ECR)不掛應用層 Token Status List;其撤銷狀態一律由 `verifyVleiChainSandbox`(child_process 呼叫 vLEI sandbox)查驗,不是本專案自建的撤銷機制。
- **CB(認證機構)為虛構身分**:Lowland Certification B.V. 不代表 Control Union 或任何真實 CB;`tc_rcs`/`ccs_scope_cert` 由虛構 CB 以 sandbox LE 鑰**真簽**(非 mock),欄位對照 Textile Exchange 鍵名,**不是** TE 授權 CB 簽發,`volume_reconciled` 為宣告示意,未實作 E2.1.8 勾稽演算;demo 簡化為同一家 CB 同時服務紗廠與布廠。
- **CCS 分包商型態單一**:只建模「列於布廠 SC 的 associated subcontractor」一種型態(CCS-101 C5.2.1);染整廠自持 SC(C5.2.2 獨立認證分包商)未建模。
- **單人 demo 併發邊角(LOW,不阻擋)**:①`human-sign` 晚檢查讀檔到同步 CAS 之間、與另一行程 revoke 之間有理論上的極短同步窗——但已提交之撤銷必被兩道檢查擋下(PoC 已證實不影響最終正確性);②`withStatusListLock` stale(>5s)回收時互斥可能短暫鬆動(owner-token 機制已確保不誤刪他人鎖)。二者屬 localhost 單一操作者 demo 可接受範圍,詳見 `CLAUDE.md`「Codex 審查定案(2026-08-30;Phase 3b)」章節。
- **幕 6 前端缺口**:目前無「重簽染整/重聚合」按鈕,§5 步驟 5 需以 `curl` 直接呼叫 `POST /api/issue/dyeing?case=A&reissue=1` 與 `POST /api/aggregate?case=A&reissue=1`——後端邏輯已完整且經 `make test` 覆蓋,純粹是前端尚未補這兩顆按鈕(deep-link 屬本 phase 範圍,新增業務按鈕不屬於「只碰前端路由」的授權範圍,留待下一輪)。
- **已設計、未實作(spec §12,只做投影片)**:鞋廠 SHOE 及其 M3 子集委任、幕 7、稽核層 P4/M4、月度承諾值開啟、送出前一致性檢查(`CONSISTENCY_FAILED` 未實作,故理由碼一覽刻意不列此碼)、品牌 Raw Data 方案的資安對策。
- **付款層為 mock**:USD 電匯指令為合成 JSON(付款人 FAB、收款人 DYE、USD 3,420),不做鏈上/穩定幣,不建立錢包或 RPC 連線;收款帳戶識別碼為合成字串,不對應任何鏈上位址。
- **可驗證 ≠ 可信賴**:ZK 未實作;憑證證明的是身分、授權與計算完整性,不證明單據反映物理真實。數值多為合成/推估(§8 附出處),染整外包為假設情境。

---

## 7. TC 鍵名對照(Textile Exchange,僅作 claims 欄位對照,不宣稱 TE 認證)

`tc_rcs`(CB 簽發之 Transaction Certificate)欄位採 Textile Exchange **ASR-104** 官方 camelCase 鍵名原樣。
**本 demo 不宣稱符合 W3C VC 2.0,也不宣稱通過 Textile Exchange 認證**——CB 為虛構身分,鍵名對照純供欄位語意參考。

| TC 欄位(TE camelCase) | 對照/用途 | 揭露層 |
|---|---|---|
| `tcNo` | Transaction Certificate 編號 | 公開層 |
| `tcStandard` | 認證標準(如 RCS) | 公開層 |
| `tcProductStandardLabelGrade` | 產品標籤等級(供 `pcf_aggregate` 推導 RCS 100 標示) | 公開層 |
| `tcProductCategoryCode` / `tcProductDetailCode` | 產品分類代碼(TE 代碼表核對屬 spec §13 尚未結案項) | 公開層 |
| `tcCertifiedRawMaterialCountryOrArea` | 認證原料產地國別 | 公開層 |
| `sellerTeId` / `buyerTeId` | 賣方/買方 TE 系統 ID | 公開層 |
| `seller_lei` / `buyer_lei` | 賣方(紗廠)/買方(布廠)LEI(我方延伸欄位,非 TE 原鍵名,由 manifest 取值不寫死) | 公開層 |
| `volume_reconciled` | 數量勾稽宣告(布林;未實作 E2.1.8 演算,僅宣告示意) | 公開層 |
| `tcShipmentInvoiceReferences_hash` | 出貨發票參照(僅 hash commitment) | 公開層(hash) |
| `tcProductRawMaterialCode` / `tcProductRawMaterialPercentage` | 原料代碼/比例(%;後者亦為 M2 六欄之一) | 品牌層(SD) |
| `tcProductCertifiedWeight` | 認證重量(供聚合前核對 ≥ `quantity_kg`) | 品牌層(SD) |
| `tcShipmentDate` / `tcShipmentNo` | 出貨日期/單號 | 品牌層(SD) |
| `inputTcNo` | 上游投入批次的 TC 編號(供應商重組追溯示意) | 品牌層(SD) |
| `tcProductLastProcessorName` / `tcProductLastProcessorCountry` | 最後加工廠名稱/國別 | 品牌層(SD) |

`pcf_upstream`(紗廠自簽)之 `tc_ref = { id, tcNo, issuer_lei, hash }` 為我方延伸欄位,以 `hash = sha256(tc_rcs 之 sd_jwt)`
鏈結上表的 TC——**TC 本身沒有碳數據**,碳只在紗廠簽的 `pcf_upstream`/`pcf_dyeing`/`pcf_aggregate`。

`ccs_scope_cert`(CB 簽發之布廠 Scope Certificate,對照 CCS-101 C5.2.1)欄位:`sc_no`、`holder_lei`/`holder_name`、
`standards`、`processes`、`associated_subcontractors[].{lei,name,process,audited}`、`cb_lei`/`cb_name`、`valid_from`/`valid_until`——
全部公開層(非 SD)。`pcf_dyeing`/`pcf_aggregate` 之 `ccs_scope_ref = { sc_no, hash }` 綁定本憑證。

---

## 8. 理由碼一覽(B-10)

以下 **40 個**理由碼逐一取自 `shared/codes.ts` 的 `CODES` 常數(全案唯一來源);**不含 `CONSISTENCY_FAILED`**
(一致性檢查僅設計、未實作,只做投影片,spec §12)。核對方法見本節末段。

| 理由碼 | 中文說明 | 出現幕次 |
|---|---|---|
| `INVALID_CASE_ID` | `case_id` 缺值或不是合法案件代碼,不得靜默塌成預設值 | 各幕 API 輸入驗證(泛用) |
| `INVALID_MANDATE_ID` | `POST /api/mandates` 的 `mandate` 欄位不是 `"M1"`/`"M2"` | 幕 3(M2)/幕 5(M1) |
| `DISCLOSE_REQUEST_INVALID` | `/api/disclose` 的 `request_jws` 無法解析或缺必要欄位 | 幕 3 |
| `MANDATE_NOT_FOUND` | `request_jws` 內 `mandate_id` 查無對應 mandate | 幕 3 |
| `PCF_AGGREGATE_NOT_ISSUED` | 該案 `pcf_aggregate` 尚未簽發(需先跑幕 2) | 幕 3 |
| `TC_REF_MISMATCH` | `tc_ref.hash` 對不上 `tc_rcs`、seller/buyer LEI 不符,或認證重量不足;`pcf_upstream` 簽發時入庫 `tc_rcs` 缺失亦回此碼 | 幕 1(簽發防呆)/幕 2(聚合前核對) |
| `CCS_SUBCONTRACTOR_NOT_LISTED` | 染整廠不在布廠 SC 分包商清單,或 `sc_no` 與 `ccs_scope_cert` 不一致 | 幕 2(聚合前核對)/幕 5(P3) |
| `SCOPE_CERT_INVALID` | `ccs_scope_cert` 驗章/效期/Token Status List 任一不通過 | 幕 2/幕 5 |
| `POLICY_P1_PERMIT` | Cedar P1 允許——請求欄位在 mandate 範圍內且三個可信布林皆通過 | 幕 3 |
| `POLICY_P2_CONFIDENTIAL` | Cedar P2 絕對禁止——請求機密標籤欄位(如 `plant_total_output`),不論 mandate 寫什麼 | 幕 4 |
| `CLAIM_NOT_IN_MANDATE` | 請求欄位不在 `mandate.allowed_claims` 範圍內 | 幕 3/4 |
| `MANDATE_REVOKED` | mandate 已被 Token Status List 標記撤銷 | 幕 6(輔線撤 M1) |
| `MANDATE_EXPIRED` | mandate 已過期或尚未生效 | 幕 3/幕 5(設計檢查項) |
| `MANDATE_SIG_INVALID` | mandate 簽章/`iss`/`aud`/`exp`/`jti` 不符,或 Dossier 內 mandate payload 與所依 mandate 列的 `jti` 不一致 | 幕 3/幕 5 |
| `DELEGATE_KEY_MISMATCH` | disclose/agent request 簽章非 `mandate.delegate_kid` 對應的 workload 鑰 | 幕 3/幕 5 |
| `QUERY_CAP_EXCEEDED` | mandate 查詢額度已用盡(交易內回滾,非靜默放行) | 幕 3 |
| `REPLAY_DETECTED` | 同一 `(mandate_id, request_nonce)` 已處理過 | 幕 4(輔)/幕 5 |
| `RECEIPT_INVALID` | 閘道簽章 receipt(key-binding)缺失、簽章壞、綁定不符或逾新鮮度 | 幕 3(Brand 端驗證) |
| `CREDENTIAL_REVOKED` | 被消費的憑證已被 Token Status List 標記撤銷 | 幕 6(主線撤 `pcf_dyeing`) |
| `CREDENTIAL_EXPIRED` | 被揭露憑證自身已過期或未生效 | 幕 3 |
| `CREDENTIAL_SIG_INVALID` | 簽章與 payload 內容不一致(竄改示範) | 幕 1 |
| `CREDENTIAL_PARSE_ERROR` | 不是合法的 compact SD-JWT | 幕 1 |
| `ISSUER_UNKNOWN` | 簽發者未登錄於 manifest(找不到對應公鑰) | 幕 1 |
| `VCT_ISSUER_UNAUTHORIZED` | 憑證型別(`vct`)與實際簽發者角色不符(型別/簽發者混淆防護) | 幕 2(聚合四輸入驗證) |
| `VLEI_CHAIN_BROKEN` | vLEI sandbox 鏈驗證(SAID/簽章/LEI 檢核碼/TEL 撤銷)失敗 | 幕 3(Brand 端 OFFLINE 三綠勾之一) |
| `CARBON_OVER_THRESHOLD` | 聚合碳排(含染整段)超過品牌合約門檻 9.5 kgCO₂e/kg | 幕 5(案 B) |
| `MULTI_SOURCE_CONFIRMED` | 收款帳戶風險兩來源皆確認高風險,升級為退回 | 幕 5(案 C) |
| `SINGLE_SOURCE_ONLY` | 收款帳戶風險僅一來源確認,只記錄不升級(自我約束) | 幕 5(案 C′) |
| `RELEASE_APPROVED` | 財務主管 ECR 鑰簽署放行成功(RELEASE) | 幕 5(案 A) |
| `POLICY_P3_PERMIT` | Cedar P3 五要件全過,整體 PERMIT 標記 | 幕 5(案 A) |
| `INVOICE_INVALID` | 發票驗章失敗、簽發者非 DYE,或 `vct` 型別不符 | 幕 5 |
| `AMOUNT_OVER_LIMIT` | 發票金額超過 `mandate.max_amount` | 幕 5 |
| `COUNTERPARTY_NOT_ALLOWED` | 收款方 LEI 不在 `mandate.allowed_counterparties` | 幕 5 |
| `DOSSIER_NOT_FOUND` | `dossier_id` 查無對應 Dossier | 幕 5 |
| `DOSSIER_NOT_RELEASABLE` | Dossier 狀態非 `PENDING_HUMAN`(已放行或依據已撤銷),不得再簽 | 幕 5/幕 6 |
| `AGGREGATE_STALE` | `pcf_aggregate.precursor_refs` 對不上現況憑證雜湊(重簽輸入後未重聚合) | 幕 6(reissue 後) |
| `PAYER_NOT_ALLOWED` | 發票 `payer_lei` 不是 FAB LEI | 幕 5 |
| `CURRENCY_MISMATCH` | 發票幣別與 M1 簽章約定幣別(USD)不符 | 幕 5 |
| `AUDIT_CHAIN_TAMPERED` | 稽核鏈雜湊/簽章重驗失敗(竄改示範) | 幕 6 |
| `DEPENDS_REVOKED` | Dossier 所依憑證已被撤銷(即使該 Dossier 已放行) | 幕 6 |

**核對方法**:`node -e "const s=require('fs').readFileSync('shared/codes.ts','utf-8');const a=s.indexOf('export const CODES = {');const b=s.indexOf('} as const;',a);console.log([...s.slice(a,b).matchAll(/^\s{2}([A-Z0-9_]+):/gm)].length)"`
於本次交付執行結果為 `40`,與上表列數一致;`DOSSIER_STATUS`(`PENDING_HUMAN`/`RELEASED`/`DEPENDS_REVOKED`)為
Dossier 狀態機常數,不是理由碼,故上表僅收其中作為理由碼重複出現的 `DEPENDS_REVOKED` 一次。

---

## 9. C-12 · 什麼是真的、什麼是模擬的

### 真的(真實執行,非 mock)

- `@sd-jwt/core` + `@sd-jwt/sd-jwt-vc` 簽章/驗章(RFC 9901 core + IETF SD-JWT VC profile;**不宣稱 W3C VC 2.0**)。
- Ed25519 簽章(sandbox LE/ECR 鑰經 `server/keys.ts` 自 `.vlei/state.json` 匯出;app 產生的 `fab-workload`/`brand-workload` 鑰)。
- vLEI sandbox 鏈驗證(`verifyVleiChainSandbox`:SAID 重算 + 簽章 + LEI 檢核碼 + TEL 撤銷狀態,真跑 child_process,非 mock)。
- Token Status List JWT 撤銷(`draft-ietf-oauth-status-list-21`;compact signed JWT,`typ: statuslist+jwt`,無裸 JSON bit array 退路)。
- Cedar 授權決策(`@cedar-policy/cedar-wasm`,真解析 `policies/*.cedar` 三條政策)。
- sha256 稽核鏈(`payload_hash`/`entry_hash` 雜湊鏈,逐列可重驗;`verify-chain.ts` 竄改偵測)。
- CB(Lowland Certification B.V.)雖為**虛構身分**,但 `tc_rcs`/`ccs_scope_cert` 是以其 sandbox LE 鑰**真簽**——身分虛構,簽章真實。

### 模擬的(demo 邊界,誠實標示)

- **USD 電匯指令**:mock JSON(付款人 FAB、收款人 DYE、金額 3,420 USD)——**不建立錢包、不連 RPC、無鏈上/穩定幣交易**。
- **收款帳戶識別碼**:合成字串(如 `ACCT-SYN-DYE-001`),不對應任何鏈上位址。
- **風險分數**:`data/seed.json` 合成資料,非真實風控 API 查詢結果。
- **部分係數為推估**:見 spec v3 §8 係數表「等級」欄(S3/推估),如 rPET 紗排碳、鍋爐效率、綠電覆蓋比。
- **鞋廠子集委任(M3)、幕 7、稽核層 M4、一致性檢查(`CONSISTENCY_FAILED`)**:僅設計、只做投影片,未寫程式(spec §12)。
- **CB 之 `volume_reconciled`**:宣告示意布林,未實作 TE ASR-104 E2.1.8 的實際勾稽演算。

---

## 10. B-9 成本側數字(實測)

> **不得杜撰**——以下數字皆為本機實測,方法與環境如下;非佔位值。

**量測環境**:`node v24.2.0` · `darwin/arm64`(Apple Silicon)· 量測時間 `2026-08-30T09:29:51Z`。

**量測方法**:`make bench`(= `npx tsx scripts/bench.ts`,本 phase 新增)——先 `scripts/seed.ts` 重置到乾淨狀態,
逐項呼叫既有簽發/驗證程式碼路徑量測(非另寫假路徑),量測完再次 `scripts/seed.ts` 歸位,不留污染態。

| 項目 | 方法 | 實測結果 |
|---|---|---|
| **presign 呈現包張數** | `ls data/vlei/*.presentation.json \| wc -l` | **7** |
| **簽發耗時**(`issuePcfUpstream` × 30,SD-JWT + Ed25519 簽章運算本身,不含 HTTP/DB 落庫) | `performance.now()` 前後測,30 次取 avg/min/max | avg **0.88 ms** · min 0.60 ms · max 3.74 ms |
| **單張憑證驗證耗時**(`verifyCompactSdJwt` × 30) | 同上,30 次取 avg/min/max | avg **0.25 ms** · min 0.23 ms · max 0.36 ms |
| **跨組織 presentation 驗證耗時**(`POST /api/verify` × 10;含簽章 + vLEI sandbox 鏈驗證 `child_process` + Status List 查驗) | 完整幕 1→3 管線後,對同一 presentation/mandate/receipt 重覆呼叫 `/api/verify`,10 次取 avg/min/max | avg **61.31 ms** · min 50.86 ms · max 110.06 ms |
| **一輪 `make test` 秒數**(498 項檢查,含本 phase 新增 20 項 deep-link/導覽狀態單元測試) | `time npx tsx scripts/test.ts`,`make demo-reset` 後實測兩次 | **約 10.1–10.3 秒**(10.312s / 10.123s,皆 498 通過 / 0 失敗) |

**重現方式**:

```bash
make bench          # 產生上列前三項數字(presign 張數、簽發/驗證耗時)
time make test       # 產生「一輪秒數」
```

單張憑證的簽發/驗證都在毫秒等級;跨組織 presentation 驗證因含真實 vLEI sandbox `child_process` 呼叫(非
記憶體內驗證),耗時明顯較高但仍在 100ms 內,對 demo 錄影的即時互動無感知延遲。

---

## 11. Phase 4 新增/改動檔案

- `web/src/App.tsx`:新增 `parseDeepLink`/`resolveNavState`/`DeepLink`/`NavState`/`TabId`/`DeepLinkCaseId` 匯出、掛載時解析 `?tab=&case=`、切換時 `pushState` 回寫網址列;**Codex 審查 P2-1 修復**:加 `popstate` 監聽,瀏覽器上一頁/下一頁時以 `resolveNavState(location.search)` 重新同步 `tab`/`urlCaseId`,並以遞增的 `navEpoch` 作子分頁 `key` 強制同分頁內重掛,讓案件選單隨網址列一起回退(否則同分頁內切案件後按上一頁,畫面會停在最新選擇、與網址不符)。
- `web/src/tabs/Yarn.tsx`、`web/src/tabs/Gateway.tsx`、`web/src/tabs/BrandAgent.tsx`:接受 `initialCase`/`onCaseChange` props,接上 deep-link 狀態(僅前端路由,未動任何伺服端授權/撤銷邏輯)。
- `scripts/test.ts`:新增 15 項 `parseDeepLink` + 5 項 `resolveNavState`(P2-1 回歸鎖)純函式單元測試,共 20 項。
- `scripts/bench.ts`(新):B-9 實測腳本;**Codex 審查 P2-2 修復**:量測本體包進 `try/finally`,任一步驟拋錯都保證先跑 `scripts/seed.ts` 歸位再把錯誤往外拋(已以暫時注入錯誤自測驗證,見交付回報)。
- `Makefile`:新增 `make bench` 目標。
- `README.md`(本檔,新)。
