# Demo 情境設定與合成資料規格 v2.0

> **建立**:2026-08-24|**狀態**:**[Implementation Baseline]**(文件優先序:**架構決策 > 本規格 > 實作藍圖**)|**修訂**:…;2026-08-28-d 狀態清單釘版;**2026-08-28-e 收尾** — §0 摘要用語更正、台驗鑰改經 server/keys.ts 載入 sandbox LE AID 鑰、DCC 改 claims 欄位對照
> **修訂依據**:《製造貿易命題研究報告》、《VC 選擇性揭露技術研究》、v1 審查意見
> **給誰**:Henry(合成資料/後端)、Yulia(講稿/錄影)、Quan(訪談驗證)
> **相關**:`2026-08-23-demo-day-簡報大綱-痛點對照矩陣.md`、`2026-08-22-hackathon-技術提案-01-02-06.md`

---

## 0. v1 → v2 修訂摘要(先看這裡)

| # | v1 的問題 | v2 的修正 |
|---|---|---|
| 1 | 選擇性揭露只做「三層視圖切換」(後端過濾欄位) | 改為 **SD-JWT(RFC 9901)密碼學揭露**:三層 = 同一張已簽名憑證的三種 presentation,驗證方直接驗簽發者簽章,**不經過鴻鋼後端** |
| 2 | 命題主線(跨組織查驗+最小揭露)沒有案件,demo 像 AML 付款閘道 | 新增 **幕 3(歐盟 Agent 持 mandate 查驗)與幕 4(越界索取機密 → 政策攔截)**,升格為主線 |
| 3 | USDC 付款佔 6 案中 3 案,Layer 3 被質疑硬湊的風險高 | 付款降為**可抽換末端**:Agent 產出「放行憑證」為止;C/C′ 合併為 15 秒一幕 |
| 4 | 缺鴻鋼自身的 PCF,命題「資料散落內部與供應商之間」沒被具象化 | 新增 **鴻鋼聚合 PCF VC(4.3)**:自身製程 + 前驅物內含排放;`carbon_price_paid` 填台灣碳費 → 直接命中痛點 7 |
| 5 | 撤銷 = DB 旗標、稽核 = DB 交易,第三方無法驗證 | **Token Status List**(公開可查)+ **hash-chain 稽核日誌**(可演「竄改一筆 → 驗證失敗」) |
| 6 | LEI 為 21 碼,不合 ISO 17442 | LEI 一律 **20 碼、由主辦方 vLEI Sandbox 產生**,不手打 |
| 7 | CBAM 鋼鐵類申報被寫成 direct + indirect | 法定申報**僅計 direct**(Reg. 2023/956 Annex II,引用前查現行版本);2.00 門檻改標示為**買方合約條款** |
| 8 | mandate 缺 nonce / policy_version / 資料範圍 / 簽發者角色 | 補齊,並新增第二張 mandate(M2,歐盟方) |
| 9 | 標題五幕實為六案,5 分鐘裝不下 | 重排為六幕 + 加映,附錄影秒數與優先序 |

---

## 1. 供應鏈與故事主軸

```
Thép Việt Wire Co.        鴻鋼精密扣件               Bruck & Söhne GmbH
(越南,線材 7213.91)  ──貨──▶ (台灣,扣件 7318.15) ──貨──▶ (歐盟進口商)──▶ 歐盟海關
                     ◀─付款──                      ◀─要可驗證碳排──
                     ◀─要碳憑證──
```

**兩股壓力落在同一家台灣廠身上**:
- **對下游**:Bruck 因 CBAM(2026 正式期)要申報扣件的內含碳排,而扣件(CN 7318)的內含碳排**必須把前驅物(7213 線材)的排放算進來** → 鴻鋼被迫向上游要數據。
- **對上游**:鴻鋼要付 Thép Việt 貨款,同時要拿到對方的碳足跡憑證——碳排壓力與付款動作在同一筆交易上,故事不用硬接。

**命題三條件的對應**:
1. 跨組織查驗成立 → 幕 3(SD-JWT 出示 + 離線驗簽)
2. 只揭露必要數據 → M2 mandate 的 `allowed_claims` + SD-JWT 選擇性揭露
3. 不外洩製程機密 → 幕 4 攔截 + 機密欄位僅留 commitment hash

> ✅ **[已結案 2026-08-28] USDC 假設經訪談證偽**:跨境付款現行以美金電匯為主、穩定幣未普及(訪談對照表 Q6)。v2 的保險絲奏效——demo 主線只到「放行憑證」,付款軌道為 **mock 指令(可抽換)**,真實 testnet 列 out of scope;簡報以「訪談證偽自家假設 → 誠實降級」呈現(吃 25% 誠實邊界)。

---

## 2. 角色設定

| 角色 | 設定 | 身分錨定 |
|---|---|---|
| **Principal** | 鴻鋼精密扣件股份有限公司(台灣,虛構),財務部 3 人 + 永續課 1 人 | vLEI(Sandbox 預簽)|
| **上游/收款方** | Thép Việt Wire Co.(越南,虛構),鋼線材供應商 | vLEI(Sandbox 預簽;金鑰匯出失敗 → 全域 Plan B,見架構 §0) |
| **下游/查驗方** | Bruck & Söhne GmbH(德國,虛構)進口商;其**永續長持 ECR 角色憑證** | vLEI + ECR |
| **Agent-1** | Trade Settlement & Compliance Agent(鴻鋼側)。**不簽交易、不持付款私鑰**;持 workload 金鑰簽 Dossier/建議 | workload id = {build_hash, version} |
| **Agent-2** | CBAM Declaration Agent(Bruck 側),**新增,主線角色** | 持 M2 mandate |
| **驗證者** | 歐盟海關 / 查證機構 | **直接驗簽發者簽章與身分鏈,不信任、也不經過鴻鋼的伺服器** |
| **查證機構** | 台驗國際股份有限公司(台灣,虛構);第三方查驗示意,簽發 `rba_dcc` 與(選配)查證聲明 VC | vLEI(Sandbox 預簽);CBAM 正式查驗須歐盟認可查驗員,見 §11 |

---

## 3. 交易與產品設定

| 項目 | 值 | 備註 |
|---|---|---|
| 上游批次貨品 | 低碳鋼線材 SWRCH22A | |
| 上游 CN code | **7213.91**(CBAM Annex I) | |
| 數量 / 單價 / 金額 | 40 公噸 × USD 650 = **USDC 26,000** | USDC 為**合成幣別**,僅出現於 mock 付款指令;不建立錢包、RPC 或鏈上交易 |
| 生產國 | 越南 | |
| **下游產品** | 六角螺栓 M12(鴻鋼) | **新增** |
| 下游 CN code | **7318.15**(CBAM Annex I 下游鋼品) | 使鴻鋼自身出口即受 CBAM 規範 |
| 合約碳排門檻 | **≤ 2.00 tCO₂e/公噸(direct + indirect)** | **買方合約條款,非法定** |

> **法遵註記(Q&A 必考)**:CBAM 正式期對鋼鐵、鋁、氫的申報**僅計直接排放**(Reg. 2023/956 Annex II;demo 前查現行條文版本)。indirect 屬於**客戶層/合約欄位**。因此案 B 對海關合法、對合約不合——「我們攔的是商業政策,不是法規」是 Q&A 的加分答案,不是漏洞。

---

## 4. 憑證清單(5 張)

### 4.1 `identity_vlei` × 4 — 四家法人身分(含查證機構台驗)
- 信任鏈:GLEIF → QVI → 法人(LE)→ 角色(OOR/ECR)
- 欄位:`subject_lei(20 碼)`、`legal_name`、`role`、`valid_until`、`tel_ref`(**vLEI TEL 參照**;撤銷狀態由 sandbox `verify` 經 TEL 查驗,**不掛應用層 Token Status List**)
- **由主辦方 vLEI Sandbox 預簽**;demo 現場只做驗證與撤銷連鎖,不現場跑 KERI 全流程。

### 4.2 `pcf_upstream` — Thép Việt 產品碳足跡 VC(核心)
- **格式**:SD-JWT core = **RFC 9901**;憑證 profile = **SD-JWT VC(IETF Internet-Draft)**(`@sd-jwt/core` + `@sd-jwt/sd-jwt-vc`)。**不宣稱符合 W3C VC 2.0**(Codex 審查 #1);簽章鑰 = Thép Việt 的 sandbox LE AID 鑰(Codex #2)
- **claims 欄位對照**(非 schema 符合):UNTP DPP 0.6 欄位命名,附 **PACT v3.0.3 ↔ CBAM 欄位對照表**(README 一頁,換「對齊聯合國規格詞彙」+「算一次報多處」兩句話)

| 欄位 | 揭露層級 |
|---|---|
| `cn_code`、`quantity_t`、`country_of_origin`、簽發者、簽發日、`status.status_list`(`{idx, uri}`) | 公開層 |
| **`specific_direct_embedded_emissions`(tCO₂e/t)**、`production_route`(EAF/BF-BOF)、`carbon_price_paid_origin` | **海關層(法定)** |
| `specific_indirect_embedded_emissions`、`electricity_mix_ref`、`installation_unlocode`、`dqr`、`primary_data_share` | 客戶層(合約) |
| 機台級能耗結構、電力採購合約(PPA)、配方、其他客戶名單、**產能利用率(`capacity_utilization`,依 2026-08 產業訪談 Q5 增列)** | **永不揭露** → 僅留 `commitment_hash`(SHA-256)+ **`emission_factor_table_hash`(排放係數表雜湊)** |

- **[可選] ZK 模組**:RISC Zero dev mode guest(~50 行 Rust):證明「Σ(活動數據 × 係數) = direct 排放,且係數表 hash = 公開值」;journal 只含總量與 hash;proof 參照放 VC 的 `evidence`。沒時間 → 不做,**在治理缺口誠實列出**。

### 4.3 `pcf_aggregate` — 鴻鋼扣件 PCF VC(**新增,中間層**)
- 邏輯:**自身製程排放 + 前驅物內含排放 × 投入係數**
- 範例值 [Assumption,引用前查正式期預設值表]:前驅物 1.05 t 線材/t 扣件 × 1.05 tCO₂e/t + 自身 direct 0.08 + 自身 indirect 0.33(台電網約 0.494 kg/kWh × ~0.67 MWh/t)≈ **1.51 tCO₂e/t 扣件**
- `carbon_price_paid_origin` = **台灣碳費**(一般費率 300 元/噸級距)→ 痛點 7「碳費 ↔ CBAM 扣抵」的現成素材
- 歐盟 Agent **只看得到聚合值,看不到上游明細** → Tier-N 最小揭露傳遞,一張圖講完。

### 4.4 `invoice` — 發票 VC
`invoice_no`|`amount`|`currency`|`quantity`|`payee_wallet`|`issued_at`(同 v1)

### 4.5 `rba_dcc` — RBA 合規憑證(Track 06 加映)
- claims 欄位對照:UNTP **DCC** 詞彙(非 schema 符合)
- 揭露 claim 僅一項:`recruitment_fee_policy_compliant = true`(Employer Pays);另含 `assessment_level: Gold`、**簽發者 = 台驗國際(§2 查證機構;由 `server/keys.ts` 載入其 sandbox LE AID 鑰簽發,manifest 參照其法人憑證)**、效期
- **共用同一套 Token Status List** → 稽核方撤銷 → 下游採購 Agent 即時擋下(機制可遷移的證明)。

### 4.6 [選配] `verification_attestation` — 台驗對 `pcf_aggregate` 的查證聲明 VC
- 單一 claim:`verified_against_methodology = true`(附方法學代碼);由 `server/keys.ts` 載入台驗 sandbox LE AID 鑰簽發,參照掛入 `pcf_aggregate` 的 `evidence`。
- 前端呈現:憑證卡「已第三方查證 ✓」徽章——「供應商造假怎麼辦」Q&A 的畫面落點(查證方自己也有 vLEI、也在撤銷清單上,可撤可追)。
- **Phase 3 選配(≤1 小時),時間不足即砍,不影響主線。**

---

## 5. 兩張 Mandate(委任狀)

### 5.1 M1:鴻鋼財務部 → Agent-1(修訂版)

```
issuer                 : 財務部主管之 ECR 憑證(鏈回鴻鋼 vLEI;以其 sandbox ECR 鑰簽)
jti                    : <mandate 唯一 ID>                        ← Codex #3
aud                    : hunggang-gateway(mandate 受眾)          ← 後端驗 iss/aud/exp/jti
principal_lei          : <vLEI Sandbox 產生,20 碼>
agent_id               : agent-stable-001
delegate_kid           : <hunggang-workload 公鑰 kid>             ← Codex 規則 6:綁定執行者
agent_workload         : { build_hash: <sha256>, version: v0.3 }
scope_tools            : ["verify_vc", "check_wallet_risk", "emit_release_credential"]
                         # 沒有 sign_transaction —— 維持 v1 設計
allowed_claims         : 各憑證之「公開層 + 海關層」欄位
max_granularity        : batch
max_amount             : 50000 USDC
allowed_counterparties : [<Thép Việt LEI,20 碼>]
policy_thresholds      : { carbon_max: 2.00, wallet_risk_max: 40, min_sources: 2 }
policy_version         : pol-2026-08-v2
mandate_nonce          : <簽發時隨機;使 mandate 內容唯一>          ← 原 nonce 更名
valid_from / until     : 2026-08-01 → 2026-09-30
status.status_list     : { idx, uri }   # draft-ietf-oauth-status-list-21;撤銷 = 翻一個 bit,第三方可查
```

> **重放防護(Codex #3,mandate 層之外)**:每次 disclose request 由 workload 鑰簽章並附**新的 `request_nonce`**;閘道對 `(mandate_id, request_nonce)` 加 UNIQUE,重複 → `REPLAY_DETECTED`;`query_cap` 扣次與 presentation、audit 寫入**同一筆交易**。mandate_nonce 只保 mandate 唯一,**不視為防重放完成**。
> **後端驗序(進 Cedar 前必須完成)**:mandate 簽章 → iss/aud/exp/jti → delegate_kid 對 request 簽章 → Token Status List → request_nonce UNIQUE → 產出 `context.mandate_status_ok / delegate_key_ok / replay_ok` 三個可信布林,再進 §6 政策。

### 5.2 M2:Bruck 永續長(ECR)→ Agent-2(**新增,主線**)

```
issuer            : Bruck 永續長之 ECR 憑證(鏈回 Bruck vLEI;以其 sandbox ECR 鑰簽)
jti               : <mandate 唯一 ID>
aud               : hunggang-gateway(揭露閘道為受眾)
purpose           : CBAM_quarterly_declaration
delegate_kid      : <bruck-workload 公鑰 kid>   # disclose request 必以此鑰簽章
allowed_claims    : [cn_code, quantity_t, country_of_origin,
                     specific_direct_embedded_emissions,
                     production_route, carbon_price_paid_origin]
max_granularity   : batch            # 明文禁止 machine-level
query_cap         : 10 次(原子扣次,見上方重放防護)
valid_from/until  : 2026-08-01 → 2026-09-30
mandate_nonce / policy_version / status.status_list : 同 M1 結構
```

---

## 6. 政策(Cedar 風格,三條肉眼可讀)

```cedar
// ⚠ 硬性關卡優先:Cedar 不做密碼學。後端先完成——
//   mandate 簽章、iss/aud/exp/jti、delegate_kid 對 request 簽章、
//   Token Status List、request_nonce UNIQUE——
//   再以三個可信布林餵入 context。
//   政策只讀布林與 mandate 的資料欄位,絕不直接信任 mandate.status。

// P1 允許:mandate 範圍內的欄位揭露
permit (action == DiscloseClaim)
when  { resource.claim in principal.mandate.allowed_claims
     && resource.granularity <= principal.mandate.max_granularity
     && context.mandate_status_ok      // 簽章 + iss/aud/exp/jti + Token Status List 皆通過
     && context.delegate_key_ok        // request 確由 mandate.delegate_kid 簽章
     && context.replay_ok };           // request_nonce 未重複

// P2 絕對禁止:機密標籤欄位(不論 mandate 寫什麼)
forbid (action == DiscloseClaim)
when  { resource.claim.tag == "confidential" };
// confidential = machine_energy, ppa_contract, recipe, customer_list, capacity_utilization

// P3 放行憑證要件(Agent-1)
permit (action == EmitReleaseCredential)
when  { context.mandate_status_ok
     && context.identity_ok
     && context.carbon_total <= principal.mandate.policy_thresholds.carbon_max
     && context.invoice_ok
     && (context.wallet_risk <= 40 || context.risk_sources_confirming < 2)
     && context.amount <= principal.mandate.max_amount };
// sign_transaction 永遠不在任何 agent scope → 由財務主管以其 ECR 金鑰簽署放行
```

---

## 7. 六幕與案件

「幕」= 錄影敘事順序;「案」= 幕 5 內的資料變體。

| 幕 | 內容 | 技術 | 秒數 |
|---|---|---|---|
| **1 簽發** | Thép Việt 簽發 `pcf_upstream`(SD-JWT VC)+ [可選] zk proof | @sd-jwt/*(server/creds)、sandbox LE 鑰、(ZK out of scope) | 20 |
| **2 聚合** | 鴻鋼產出 `pcf_aggregate`(前驅物 + 自身 + 台灣碳費) | UNTP DPP、PACT 對照 | 15 |
| **3 委任查驗** | Agent-2 持 M2 出示請求 → 鴻鋼閘道回 **SD-JWT presentation(只含 M2 欄位)** → Agent-2 **離線**驗簽發者簽章與身分鏈 | M2、Cedar P1、SD-JWT verify | 30 |
| **4 越界攔截** ★ | Agent-2 加碼索取 `machine_energy` → **Cedar P2 Deny** → 拒絕事件本身寫入稽核鏈 | Cedar P2、hash-chain | 20 |
| **5 門檻+付款閘道** | 案 B:2.10 > 2.00 → `CARBON_OVER_THRESHOLD` 轉人工補件;案 A:四項全過 → Dossier(hunggang-workload 鑰簽)→ **財務主管以 ECR 鑰**簽署 mock 付款指令(USDC 26,000,合成幣別);案 C(合併):雙來源 `peel_chain` → 退回;單來源 → 只記錄不升級 | P3、放行憑證、帳戶風險雙來源 | 35 |
| **6 稽核+撤銷** | 竄改一筆日誌 → 驗證失敗;翻 Status List 一個 bit → 重跑案 A 被拒 `MANDATE_REVOKED`;帶一句 vLEI 撤銷向下連鎖 | hash chain + Ed25519 收據、Token Status List(JWT) | 30 |
| **加映 D** | 同一 Agent,憑證換成 `rba_dcc`,只揭露「零招募費 = true」 | UNTP DCC、同一 Status List | 20 |

**合計約 170 秒 + 20 秒**,其餘留給問題陳述與架構圖。**錄影優先序(時間不夠先砍後面)**:幕 3 → 幕 4 → 幕 6 → 幕 5(案 B)→ 幕 1-2 → 案 C → 加映 D。

### 案件碳排數值(修正)

| 案 | 路線 | direct | indirect | 合計 | 法定申報(僅 direct) | 合約門檻 2.00 | 結果 |
|---|---|---|---|---|---|---|---|
| **A** | EAF 電弧爐 | 0.42 | 0.63 | **1.05** | 0.42 | ✓ | 放行 → 人簽 |
| **B** | BF-BOF 高爐轉爐 | 1.98 | 0.12 | **2.10** | 1.98(海關仍可收) | ✗ | 轉人工補件 |

- A/B 差異來自**生產路線**,不是隨機數字——被問答得出理由。
- v1 的 EAF indirect 1.43 偏高(EAF 用電約 0.5–0.7 MWh/t,越南電網係數約 0.6–0.7 kg/kWh),修正為 0.63;BF-BOF 幾乎不外購電,indirect 修正為 0.12。
- [Assumption] 量級為合理推估,**引用前查歐盟執委會正式期預設值表**,講稿要說得出出處。

---

## 8. 收款帳戶與風險資料(合併 C/C′,一幕 15 秒)

```
payee_wallet (A/B)  : 0xA7f3...9C21   風險 12   labels: []
payee_wallet (C)    : 0x4Bd8...17Fe   風險 78
    provider_a : 78  ["peel_chain", "rapid_passthrough"]
    provider_b : 71  ["peel_chain"]
    → 兩來源一致 → MULTI_SOURCE_CONFIRMED → 升級 → 退回
payee_wallet (C′)   : 0x9Ee2...4A08   風險 74
    provider_a : 74  ["rapid_passthrough"]
    provider_b : 18  []
    → 僅一來源 → SINGLE_SOURCE_ONLY → 只記錄不升級(自我約束)
```
識別碼皆為**合成字串,不對應任何鏈上位址**;不建立錢包、RPC 或鏈上交易。所有資料為合成資料(比賽規則第十四節)。

---

## 9. 技術堆疊與備援

| 元件 | 首選 | 備援 |
|---|---|---|
| 憑證格式 | **IETF SD-JWT VC**:`@sd-jwt/core` + `@sd-jwt/sd-jwt-vc` | —(不宣稱 W3C VC 2.0) |
| claims 欄位對照 | UNTP DPP/DCC 0.6 + PACT v3.0.3 對照表 | — |
| 簽發/驗證 | 自建於 `server/creds/`(@sd-jwt/* + jose) | — |
| 組織身分 | vLEI Sandbox 預簽(現場只驗證);**簽章鑰自 state.json 匯出** | 全域 Plan B:app 鑰 + 綁定聲明 + 缺口標注 |
| 計算證明 | —(out of scope) | 治理缺口列出 |
| 政策 | Cedar(cedar-wasm) | policy.ts 純函式 + 前端顯示 .cedar 原文 |
| 稽核 | 自建 hash chain + Ed25519 收據 | — |
| 撤銷(應用層) | **Token Status List `draft-ietf-oauth-status-list-21`**:compact signed JWT(typ=`statuslist+jwt`,`status_list={bits:1, lst}`);vLEI 層 = sandbox TEL | 裸 JSON bit array(明確標示 fallback) |
| 付款(可抽換) | 銀行/USDC 指令 **mock** | — |

> **範圍鐵則(Codex 審查)**:vckit、walt.id、OPA、APL、RISC Zero、did:web、真實 testnet 皆 **out of core scope**,僅 Phase 0–3 核心全數通過後考慮。

---

## 10. Henry 的最小可行清單(v2)

1. 7 張表照舊,**新增** `status_list`(bit array)與 `audit_chain`(`prev_hash`、`receipt_sig`)兩張。
2. 憑證簽發改 SD-JWT;**presentation 由持有端組裝,不是後端過濾**——驗收標準:驗證頁在斷網下仍能驗簽成功。
3. Cedar 三條政策接上閘道;**Deny 事件也寫入稽核鏈**。
4. **Status List JWT endpoint**(`draft-ietf-oauth-status-list-21`):header.typ=`statuslist+jwt`;payload 含 `sub`、`iat`(建議 `exp`、`ttl`)與 `status_list = { bits: 1, lst: base64url(zlib 位元陣列) }`;回應 `Content-Type: application/statuslist+jwt`(裸 JSON 僅為明確標示的 fallback)+ 翻 bit 的 UI 開關。
5. 撤銷後重跑腳本;竄改示範腳本 `tamper.sh`(改一筆 → 全鏈驗證失敗)。
6. [可選] risc0 guest ~50 行:輸入活動數據 × 係數表,journal 輸出總量 + 係數表 hash。
7. seed 時所有 PCF 憑證的 `issued_at` 回填約三個月前(效期涵蓋 2026-Q3)——錄影要拍「不是稽核當天才生資料」。
8. **重放防護**:presentations 表 `(mandate_id, request_nonce)` UNIQUE;重複 → `REPLAY_DETECTED`(理由碼入 `shared/codes.ts`);`query_cap` 扣次與 presentation、audit 同一交易(Codex #3)。

---

## 11. 治理缺口說明(簡報必附一頁,誠實列出反而加分)

- vLEI 為 Sandbox 預簽,非正式 QVI 簽發(台灣目前無 QVI)。
- ZK 為 dev mode 或未實作(照實標注)。
- **可驗證 ≠ 可信賴**(GLEIF 原話):憑證證明身份、授權與計算完整性,**不證明感測器讀值反映物理真實**。
- ~~USDC 前提待 Quan 訪談~~ → **已由 2026-08 訪談證偽**(跨境結算現行以美金電匯為主):付款層降為可抽換末端、穩定幣列前瞻選項;供應商重組/轉包風險未涵蓋。
- indirect 排放的法遵定位(合約 vs 法定)已於 §3 註記。
- **CBAM 查驗須歐盟認可之查驗員**;demo 以合成之台灣查證機構(台驗)示意,不表示其具 CBAM 查驗資格。

---

## 12. Quan 訪談待驗證(v1 保留 + 新增)

- [ ] 台灣扣件廠是否真的被下游要求提供上游碳排資料?
- [ ] 目前用什麼格式給?(假設是 Excel)
- [x] ~~哪些欄位是他們不想給的?~~ **部分已答(訪談 Q1/Q5)**:原始水電/過磅單據 → 產能、量能、成本結構被反推
- [x] ~~付東南亞供應商目前怎麼付?有沒有人在收 USDT?~~ **已答(訪談 Q6)**:美金電匯為主、加密未普及 → 假設證偽,付款降為 mock 可抽換
- [ ] 碳排數值與門檻的合理量級
- [ ] **[新] 上游是否願意給「只含總量 + 證明」的憑證?**
- [ ] **[新] 台灣碳費繳費證明,目前如何提供給歐盟客戶?**

---

## 13. 評分對齊檢查

| 評分項 | 權重 | 對應 |
|---|---|---|
| 場景契合度 | 35% | CN 7318 扣件 × CBAM 2026 正式期;三層揭露照官方簡報;台灣碳費扣抵;Tier-N 上游卡死 |
| 可信技術可行性 | 25% | mandate / workload / transaction 三支柱逐一對映(M1、M2、workload id、雙來源佐證、Status List) |
| 簡報與 Demo | 25% | 六幕 170 秒 + 加映 20 秒;錄影預留半天;優先序已定 |
| 洞察與創意 | 15% | Tier-N 聚合傳遞;「攔的是商業政策不是法規」;治理缺口誠實列出 |

---

## 來源

- v1:`痛點1_製造貿易_高崎鈞.pdf`(三層揭露、四層架構、CBAM 時程)、EU CBAM 過渡期報告欄位規格(待查原始範本)、vault `context/product-overview.md`
- 新增:《製造貿易命題研究報告》(2026-08-23)、《VC 選擇性揭露技術研究》(2026-08-23)、Reg. (EU) 2023/956 Annex II(demo 前查現行版本)、歐盟執委會 CBAM 預設值表(待查)
