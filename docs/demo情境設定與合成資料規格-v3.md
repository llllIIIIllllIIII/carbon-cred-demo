# Demo 情境設定與合成資料規格 v3.0(紡織版)

> **建立**:2026-08-29|**狀態**:**[Implementation Baseline]**(文件優先序:**架構決策 > 本規格 > 實作藍圖**;本檔取代 `demo情境設定與合成資料規格-v2.md`,v2 僅留歷史)|**修訂**:2026-08-29-a — 依 Quan《260830 交接檔二 製造貿易demo實作藍圖v3(紡織版)》落成規格,並以 Henry 8/29 四項拍板覆寫其衝突處(見 §0)
> **修訂依據**:《260829 交接檔一 為什麼可以做紡織業》、《260830 交接檔二》、《260826 Martin(鎰呈行)訪談紀錄 整理版》(S1)、《260829 紡織業標準機構與廠商》《260829 紡織業應用場景案例》(S3/S4)
> **給誰**:Henry(合成資料/後端)、Claude Code(遷移與 Phase 3)、Yulia(講稿/錄影)、Quan(出處與訪談)
> **合成資料聲明**:本檔所有公司名、LEI、人名、帳戶識別碼、數值皆為**合成資料**(比賽規則第十四節),以受訪廠鎰呈行為**原型**;簡報引述訪談才具名,demo 畫面一律虛構名。

---

## 0. v2 → v3 變更摘要與對交接檔二的覆寫(先看這裡)

### 0.1 技術層不變

vLEI 預簽與 TEL、SD-JWT VC 三分法(明文 / 可撕 / 僅指紋)、M1/M2 與三層 nonce、delegate_kid、Cedar P1–P3 只消費可信布林、Token Status List(`draft-ietf-oauth-status-list-21`)、audit_chain、tamper/verify-chain、四分頁、疊層熱點圖綁真值——**全部沿用 v2 與現有程式(Phase 0–2)**。要換的只有:角色、憑證欄位、數值、劇本。

### 0.2 v2 → v3 差異清單

| # | 項目 | v2(鋼鐵扣件) | v3(紡織,鞋用聚酯布) |
|---|---|---|---|
| 1 | 供應鏈 | 越南線材廠 → 台灣扣件廠 → 德國進口商 → 海關 | **越南紗廠 → 台灣布廠(Principal,自家織布、染整外包)→ 歐洲運動品牌(規格方)**;付款方為鞋廠(僅敘事) |
| 2 | 壓力來源 | CBAM 硬法規 | **品牌合約**(Scope 3 目標、供應商評比「Right the first time」、去煤要求)+ TE TC V4.0(2026-10)+ ESPR/DPP 紡織(2027–29) |
| 3 | 法人 | 4 LE + 2 ECR | **5 LE(紗廠/布廠/染整廠/品牌/認證機構)+ 2 ECR(布廠財務主管、品牌永續長)**;workload 鑰仍兩把 |
| 4 | 上游憑證 | `pcf_upstream`(CBAM 欄位) | **`tc_carbon_upstream`**:Textile Exchange TC camelCase 欄位 + `pcf_*` 延伸(TC 本身無碳數據,S3) |
| 5 | 聚合來源 | 上游 + 自製 direct/indirect | **紗(外部)+ 織布(自家用電)+ 染整(外部 `pcf_dyeing`)** 三段 |
| 6 | A/B 差異 | 電弧爐 vs 高爐 | **外包染整廠鍋爐:天然氣 + 30% 綠電 vs 燃煤** |
| 7 | 揭露三層 | 公開 / 海關 / 客戶 | **公開 / 品牌 / 稽核**(tag:`public` / `brand` / `audit`) |
| 8 | 幕 4 被擋欄位 | `machine_energy` | **`plant_total_output`(全廠產量)**;機密名單見 §4.4 |
| 9 | 幕 5 門檻與付款 | ≤ 2.00 tCO₂e/t;鴻鋼付線材廠 | **≤ 9.5 kgCO₂e/kg 布(品牌合約)**;**布廠付染整廠**染整費(mock USD 電匯) |
| 10 | 幕 6 撤銷主線 | 撤 M1 → `MANDATE_REVOKED` | **撤 `pcf_dyeing`(換燃料要重報,Fact)→ Dossier `DEPENDS_REVOKED` → 重簽重驗**;撤 M1 為輔 |
| 11 | 加映 | `rba_dcc`(台驗) | **`slcp_dcc`**(認證機構 CB 簽;SLCP/FSLM),claim 同名 |
| 12 | 單位 | tCO₂e/t;CBAM 預設值 | **kgCO₂e/kg 布**;係數 Ecobalyse / IPCC / 能源署 / MONRE(§8);Cedar 以整數 **gCO₂e/kg** 比較 |

### 0.3 對《交接檔二》的覆寫(Henry 8/29 拍板,衝突時以本節為準)

| 交接檔二寫法 | 本規格定案 | 理由 |
|---|---|---|
| 6 家法人(含鞋廠 SHOE)+ 3 ECR + 3 workload + 第五分頁 + 幕 7(M3 子集委任)+ P4 | **5 LE + 2 ECR + 2 workload、四分頁、六幕**;鞋廠、幕 7、M3、P4 **只做投影片**(治理缺口頁「已設計、未實作」) | 8/30 23:59 交件,幕 5/6 尚未寫;鞋廠是敘事角色不需 vLEI |
| M2 六欄含 `pcf_total`、`pcf_yarn`、`pcf_dyeing` | **維持 Codex H2:跨組織 presentation 只含一個排放數字(`pcf_total`)**;三段拆解只在 Tab 2 布廠自己的熱點圖(伺服端真值),`pcf_yarn / pcf_knitting / pcf_dyeing` 為 NEVER_DISCLOSABLE | 三段任兩段相減即還原第三段(布廠自家織布強度),正是 H2 擋的算術洩漏 |
| `brand_allocation_share = 0.40` 在品牌層 | **移入永不揭露(僅 hash)** | 品牌以自己訂單量 ÷ 0.40 = 全廠產量,正是受訪者最怕被反推的欄位(訪談 §4),與交接檔二 §3.4 自相矛盾 |
| 幕 5「布廠內部付款前檢查」但付款方鞋廠 | **幕 5 = 布廠付染整廠**:Agent-1 在付染整費前驗 `pcf_dyeing` + 聚合門檻;人簽 = 布廠財務主管 ECR;mock 指令付款人 FAB、收款人 DYE | 檢查者、付款者、被檢查憑證回到同一條交易線(同 v2 結構);Quan 拍板的「差異來源 = 染整燃料」完整保留 |
| 送出前一致性檢查(`CONSISTENCY_FAILED`)、稽核層 M4 與 12 個月度承諾值開啟 | **不實作**;`monthly_utility_commitments` 只留單一 hash 於憑證,投影片講 | 新程式;不影響三面向評分 |
| 速查矩陣「保底:裸 bit JSON」 | **刪除**;Status List 一律簽章 JWT | 與架構決策 §0 一致 |
| 付款「PAID」 | 狀態 **RELEASED**,產 mock 電匯指令(instruction id) | 不做鏈上/銀行交易 |
| `tcShipmentDate 2026-08-12`、`pcf_period 2026-07` | 憑證 `issued_at` **回填約三個月前**(§9),`pcf_period = 2026-05` | 沿用 v2 §10.7「不是稽核當天才生資料」 |

---

## 1. 供應鏈與故事主軸

```
Sợi Xanh Việt(越南紗廠 YARN)──tc_carbon_upstream──▶ 誠紡實業(台灣布廠 FAB,Principal)
                                                       │ 自家織布(用電)
彩合染整(台灣外包染整 DYE)──pcf_dyeing───────────────▶ │ 聚合 → pcf_aggregate
                                          ◀─染整費(mock USD 電匯)─┘
                                                       ▼
                      Nordlicht Sports(德國品牌 BRAND)Agent 持 M2 查驗 ◀──▶ FAB 閘道(Cedar P1/P2)
                      Lowland Certification(認證機構 CB):簽 slcp_dcc、[選配] 查證聲明
                      鞋廠(付款方,越南台商廠):僅敘事與投影片,不入 demo 程式
```

**兩股壓力落在同一家台灣布廠身上**(訪談 Fact):
- **對下游**:品牌每月要 Higg FEM / 自建系統雙軌填報、每年第三方到廠核單據、真實性缺陷直接零分(「Right the first time」);訪談前一天品牌更提出未來直接收原始單據給品牌 AI 算——供應商最怕的是**全廠產量與帳單被反推產能利用率與成本結構**。
- **對上游**:布廠每批貨都要交代來源與成分(TC 交易證書,半紙本半 PDF);付染整費、付紗款時就是拿憑證的時點。

**命題三條件的對應**:
1. 跨組織查驗成立 → 幕 3(SD-JWT 出示 + 離線驗簽)
2. 只揭露必要數據 → M2 `allowed_claims`(品牌層六欄,只有一個排放數字)+ SD-JWT 選擇性揭露
3. 不外洩製程機密 → 幕 4 攔截 `plant_total_output` + 機密欄位僅留 commitment hash

> **為什麼是紡織**(交接檔一 §0):唯一同時擁有一手訪談(可具名)、真實公司與真實認證體系(RCS 100 / Control Union SC / ZDHC / SLCP / Higg)、以及官方文件背書的缺口(TC 無碳數據;FEM 原始單據留廠只交總量)的場景。CBAM 不含紡織,受訪者「慢三年」為【受訪者觀察】,簡報不引用。

---

## 2. 角色設定

| 代號 | 角色 | 虛構名(demo 用) | 原型 / 依據 | 身分錨定 |
|---|---|---|---|---|
| **YARN** | 上游 Tier 2 | Sợi Xanh Việt Co., Ltd.(越藍紗業;越南同奈) | 訪談:上游聚酯紗 / 回收聚酯粒供應商 | vLEI LE(Sandbox 預簽) |
| **FAB** | **Principal**,Tier 1 布廠 | 誠紡實業股份有限公司(台灣台中);永續/驗證部 2 人 + 財務部 | 鎰呈行(自家織布、RCS 100、鞋用聚酯布) | vLEI LE + **財務主管 ECR**(簽 M1、幕 5 人簽) |
| **DYE** | 外包染整工段 | 彩合染整股份有限公司(台灣彰化) | 【假設】訪談未明說染整是否在自家;若 Martin 回覆在自家 → DYE 併入 FAB 自簽(§13) | vLEI LE |
| **BRAND** | 下游查驗方(規格方,不付款) | Nordlicht Sports AG(德國) | 訪談:十幾二十個歐美運動品牌;品牌下規格、鞋廠付款 | vLEI LE + **永續長 ECR**(簽 M2) |
| **CB** | 第三方認證機構 | Lowland Certification B.V.(荷蘭;名稱刻意避開真實 CB) | Control Union 型 TE 授權 CB | vLEI LE;簽 `slcp_dcc`、[選配] 查證聲明 |
| **Agent-1** | Settlement & Compliance Agent(FAB 側) | — | **不簽交易、不持付款私鑰**;持 `fab-workload` 鑰簽 Dossier | delegate_kid = fab-workload |
| **Agent-2** | Supplier Carbon Reporting Agent(BRAND 側,主線) | — | 持 M2;以 `brand-workload` 鑰簽查驗請求 | delegate_kid = brand-workload |
| 鞋廠 | 付款方(敘事) | Bình Minh Footwear(越南台商廠) | 訪談:「付錢的不是品牌,是鞋廠」 | **不入 demo**;投影片講「子集委任只答是/否」 |

**實作別名對照**(程式內部 alias;manifest key 同):

| 代號 | alias(v3) | v2 alias | ECR / workload |
|---|---|---|---|
| YARN | `yarn` | `thepviet` | — |
| FAB | `fab` | `hunggang` | `fab_cfo`(v2 `hunggang_cfo`)、`fab-workload`(v2 `hunggang-workload`) |
| DYE | `dye` | (新增) | — |
| BRAND | `brand` | `bruck` | `brand_cso`(v2 `bruck_cso`)、`brand-workload`(v2 `bruck-workload`) |
| CB | `cb` | `taiwanverify` | — |

LEI 字首(`lei make` 補檢核碼):`984500SOIXANHVN001` / `984500CHENGFANG001` / `984500CAIHEDYE0001` / `984500NORDLICHT001` / `984500LOWLANDCB001`;QVI 不變。ECR 人名沿用合成:FAB 財務主管 Lin Hsiu-Feng(Finance Director)、BRAND 永續長 Anna Schäfer(Chief Sustainability Officer)。

---

## 3. 交易與產品設定

| 項目 | 值 | 備註 |
|---|---|---|
| 上游貨品 | rPET DTY 長絲紗,**RCS 100** | TE 代碼 PC0027 Yarns / PD0059 Filament yarn / RM0186 Recycled polyester 100% |
| 紗數量 | **3,000 kg** | `tcProductCertifiedWeight` |
| 生產國 | 越南(VN) | |
| **下游產品** | 回收聚酯針織網布(鞋面用) | `product = "Recycled polyester knitted mesh, shoe upper"` |
| 下游 HS | **6006.32**【待查證】 | 合成纖維染色針織布 |
| 布數量 | **2,850 kg** | 3,000 kg 紗 → 針織損耗 5.45%(Ecobalyse)≈ 2,837,取整 2,850 |
| **幕 5 交易** | FAB 付 DYE 染整費:2,850 kg × USD 1.20 = **USD 3,420** | mock 電匯指令(付款人 FAB、收款人 DYE);USD 為訪談證實之現行幣別;**不建立錢包、RPC 或鏈上交易** |
| 合約碳排門檻 | **≤ 9.5 kgCO₂e/kg 布**(cradle-to-gate:紗 + 織 + 染整) | **品牌(BRAND)對布廠的合約條款,非法規**;Cedar 以 **9500 gCO₂e/kg** 整數比較 |

> **Q&A 註記**:門檻 9.5 為【推估】——燃煤 + 電網情境(B 案 10.9)視為 PEF 預設情境 × 0.87 ≈ 9.5,對應品牌 2025 供應鏈減量 13–15%;A 案低於門檻 17%、B 案高於 15%,錄影可看出差距。若要更保守可改 9.0。染整段的隱含上限 = 9.5 − 3.16 − 1.14 = **5.20 kgCO₂e/kg**,B 案染整 6.60 超過——「染整段把整批推過門檻」是口白。

---

## 4. 憑證清單(6 張)

### 4.1 `identity_vlei` × 5 — 五家法人身分
- 信任鏈:GLEIF → QVI → 法人(LE)→ 角色(ECR)
- 欄位:`subject_lei(20 碼)`、`legal_name`、`role`、`valid_until`、`tel_ref`(**vLEI TEL 參照**;撤銷狀態由 sandbox `verify` 經 TEL 查驗,**不掛應用層 Token Status List**)
- 由主辦方 vLEI Sandbox 預簽;demo 現場只做驗證與撤銷連鎖。

### 4.2 `tc_carbon_upstream` — YARN 紗廠「TC + 碳」憑證(幕 1)
- **格式**:SD-JWT core = RFC 9901;profile = SD-JWT VC(IETF Internet-Draft);`@sd-jwt/core` + `@sd-jwt/sd-jwt-vc`;簽章鑰 = YARN 的 sandbox LE AID 鑰。
- **欄位原則**:TC 有的欄位用 Textile Exchange 官方 camelCase 鍵名原樣(ASR-104 V3.1 / V4.0);碳欄位為我方延伸,`pcf_` 前綴(**TC 本身沒有碳數據**,S3)。不宣稱 TE 認證,只做「欄位對照」。
- A/B 兩案**紗憑證相同**(差異在染整段)。

| 層 | claim | 對應 TC 鍵名 | 值(A=B) |
|---|---|---|---|
| 🟢 公開(非 SD) | `tcNo` | tcNo(V4.0 格式) | `CB-LLC-TC-20260529-00417` |
| 🟢 | `tcStandard` / `tcProductStandardLabelGrade` | 同名 | `RCS` / `RCS 100` |
| 🟢 | `tcProductCategoryCode` / `tcProductDetailCode` | 同名 | `PC0027` / `PD0059` |
| 🟢 | `tcCertifiedRawMaterialCountryOrArea` | 同名 | `VN` |
| 🟢 | `sellerTeId` / `buyerTeId` | 同名 | `TE-VN-01924` / `TE-TW-00731` |
| 🟢 | `tcShipmentInvoiceReferences_hash`、`unit_price_hash`、`energy_invoice_hash`、`recycler_name_hash`、`emission_factor_table_hash` | — | SHA-256(僅指紋) |
| 🟢 | `iss`、`iat`、`nbf`、`exp`、`status.status_list {idx, uri}` | — | idx 0 = A、1 = B |
| 🟡 品牌層(SD) | `tcProductRawMaterialCode` / `tcProductRawMaterialPercentage` | 同名 | `RM0186` / `100` |
| 🟡 | `tcProductCertifiedWeight`(kg) | 同名 | `3000` |
| 🟡 | `tcShipmentDate` / `tcShipmentNo` | 同名 | `2026-05-28` / `SH-0528-07` |
| 🟡 | `inputTcNo` | inputTcNo(Box 8) | `CB-LLC-TC-20260415-00388`(回收粒供應商 TC → **上游鏈結**) |
| 🟡 | `tcProductLastProcessorName` / `tcProductLastProcessorCountry` | 同名 | YARN / `VN` |
| 🟡 | `pcf_total`(kgCO₂e/kg 紗) | 延伸 | **3.00**(計算值 2.9975) |
| 🟡 | `pcf_period` / `pcf_method` | 延伸 | `2026-05` / `activity×factor` |
| 🟡 稽核層(SD) | `pcf_direct` / `pcf_indirect` | 延伸 | `0.42` / `2.58`(3.91 kWh × 0.6592) |
| 🟡 | `electricity_kwh_per_kg` / `pcf_factor_source` | 延伸 | `3.91` / `MONRE CV 1726/2023; TE Polyester LCA 2026` |
| 🔴 永不揭露 | 發票號、單價、電費/燃料帳單原件、回收粒供應商名(每批可能換,Fact) | — | 僅上列 hash |

### 4.3 `pcf_dyeing` — DYE 染整工段憑證(幕 2 輸入;幕 5 付款對象;幕 6 撤銷主線)
- 簽章鑰 = DYE 的 sandbox LE AID 鑰;A/B 差異**全部來自此憑證**。

| 層 | claim | A 案 | B 案 |
|---|---|---|---|
| 🟢 | `process` / `facility_country` / `zdhc_incheck_level` | `dyeing_finishing` / `TW` / `Progressive` | 同 |
| 🟢 | `boiler_model_hash`、`fuel_contract_hash`、`chemical_inventory_hash`、`ppa_price_hash`、`emission_factor_table_hash` | hash | hash |
| 🟢 | `status.status_list` | idx 4 | idx 5 |
| 🟡 品牌層 | `pcf_total`(kgCO₂e/kg 布) | **3.63**(3.6266) | **6.60**(6.6002) |
| 🟡 | `heat_source` | `natural_gas` | **`coal`** |
| 🟡 | `renewable_share` | `0.30` | `0.00` |
| 🟡 | `pcf_period` / `pcf_method` | `2026-05` / `activity×factor` | 同 |
| 🟡 稽核層 | `heat_mj_per_kg` / `electricity_kwh_per_kg` | `48.6` / `1.8` | 同 |
| 🟡 | `boiler_efficiency` | `0.90` | `0.80` |
| 🟡 | `pcf_direct` / `pcf_indirect` | `3.03` / `0.60` | `5.75` / `0.85` |
| 🟡 | `pcf_factor_source` | IPCC 2006 Vol.2 Table 2.2;環境部 113-02-05 公告;能源署 113 年度電力係數 | 同 |
| 🔴 | 鍋爐型號、燃料採購合約、化學品清冊(CIL)、PPA 價格 | 僅 hash | 僅 hash |

計算(程式執行,不寫死):`pcf_direct = heat_mj_per_kg ÷ boiler_efficiency × 燃料係數`;`pcf_indirect = electricity_kwh_per_kg × 台灣電網 0.474 × (1 − renewable_share)`。

### 4.4 `pcf_aggregate` — FAB 布廠聚合 PCF 憑證(幕 2 產出;幕 3 查驗對象)
- 邏輯:**紗(外部)× 損耗加成 + 自家織布用電 + 染整(外部)**;簽章鑰 = FAB sandbox LE AID 鑰。
- `precursor_refs` 只留兩張外部憑證的 id + sha256(sd_jwt),**不含任何上游明細**。

| 層 | claim | A 案 | B 案 |
|---|---|---|---|
| 🟢 | `product` / `hs6` / `origin` | `Recycled polyester knitted mesh, shoe upper` / `6006.32` / `TW` | 同 |
| 🟢 | `tcProductStandardLabelGrade` / `zdhc_incheck_level` | `RCS 100` / `Progressive` | 同 |
| 🟢 | `precursor_refs[]` | `[{id: tc_carbon_upstream-A, hash}, {id: pcf_dyeing-A, hash}]` | B |
| 🟢 | `plant_total_output_hash`、`capacity_utilization_hash`、`other_customers_hash`、`brand_allocation_share_hash`、`monthly_utility_commitments_hash` | hash | hash |
| 🟢 | `status.status_list` | idx 2 | idx 3 |
| 🟡 **品牌層(= M2 六欄)** | `pcf_total`(kgCO₂e/kg 布) | **7.93**(7.9251) | **10.90**(10.8987) |
| 🟡 | `pcf_period` | `2026-05` | 同 |
| 🟡 | `pcf_method` | `activity×factor; cradle-to-gate(PEFCR A&F v3.1 邊界對照)` | 同 |
| 🟡 | `tcProductRawMaterialPercentage` | `100`(RM0186) | 同 |
| 🟡 | `verification` | `vFEM 2025 completed; RCS scope certificate valid` | 同 |
| 🟡 | `quantity_kg` | `2850` | 同 |
| 🟡 稽核層(SD;**NEVER_DISCLOSABLE**,布廠自持) | `pcf_yarn` / `pcf_knitting` / `pcf_dyeing` | `3.16` / `1.14` / `3.63` | `3.16` / `1.14` / `6.60` |
| 🟡 | `yarn_loss_factor` / `knitting_electricity_kwh_per_kg` / `pcf_factor_source` | `1.0545` / `2.4` / 能源署 113 年度 0.474 | 同 |
| 🔴 永不揭露 | 全廠產量(月 95 t)、產能利用率、其他客戶佔比、**品牌別分配比(0.40)**、12 個月度帳單承諾值、原始帳單 | 僅 hash | 僅 hash |

- **算術洩漏防線(Codex H2,沿用)**:跨組織 presentation 只能有一個排放數字(`pcf_total`);`pcf_yarn / pcf_knitting / pcf_dyeing` 任兩項相減即還原第三項與布廠自家強度,故三者既不進 M2.allowed_claims,presenter 亦硬拒。三段疊層熱點圖走 Tab 2 伺服端真值,不經 presentation。
- 品牌 Agent **只看得到聚合值,看不到紗廠是誰、染整廠帳單** → Tier-N 最小揭露傳遞;紡織版更強:整個產業填報制度本來就不流動上游製程數據(Higg FEM 只收設施 Scope 1+2、TC 只追來源與成分)。

### 4.5 `invoice` — 發票 VC(DYE → FAB,染整費)
`invoice_no` | `amount: 3420` | `currency: "USD"` | `quantity_kg: 2850` | `payee_wallet`(欄位名沿用程式;值為**合成帳戶識別碼**如 `ACCT-SYN-DYE-001`,介面文案「收款帳戶」)| `issued_at`;簽章鑰 = DYE LE 鑰。

### 4.6 `slcp_dcc` — SLCP/FSLM 勞權合規憑證(加映,投影片為主)
- claims 欄位對照 UNTP DCC 詞彙;揭露 claim 僅一項:`recruitment_fee_policy_compliant = true`;另含 `assessment_level`、簽發者 = **CB**(`server/keys.ts` 載入其 sandbox LE AID 鑰)、效期;共用 `credentials` Token Status List(idx 6)。
- 口白:「受訪廠掛 SLCP;Higg 的勞工模組就是 SLCP,一份驗證多品牌查驗——跟 RBA 相關但不一樣」;素材:東南亞廠移工招募費、UFLPA 棉花溯源。**保底:不寫程式,一頁投影片。**

### 4.7 [選配] `verification_attestation` — CB 對 `pcf_aggregate` 的查證聲明 VC
單一 claim `verified_against_methodology = true`;CB LE 鑰簽,掛入 `pcf_aggregate.evidence`;前端「已第三方查證 ✓」徽章(idx 7)。Phase 3 選配(≤1 小時),時間不足即砍。

---

## 5. 兩張 Mandate(委任狀)

### 5.1 M1:FAB 財務部 → Agent-1(付染整費前檢查)

```
issuer                 : FAB 財務主管之 ECR 憑證(鏈回 FAB vLEI;以其 sandbox ECR 鑰簽)
jti / aud              : <唯一 ID> / fab-gateway                      ← 後端驗 iss/aud/exp/jti
principal_lei          : <FAB LEI,20 碼,讀 manifest>
agent_id               : agent-settlement-001
delegate_kid           : <fab-workload 公鑰 kid>                       ← 綁定執行者
agent_workload         : { build_hash: <sha256>, version: v0.3 }
scope_tools            : ["verify_vc", "check_wallet_risk", "emit_release_credential"]
                         # 沒有 sign_transaction —— 放行簽名權在財務主管 ECR 鑰
allowed_claims         : pcf_dyeing 之公開層 + 品牌層;pcf_aggregate 之品牌層
max_granularity        : batch
max_amount             : 50000 USD
allowed_counterparties : [<DYE LEI,20 碼>]
policy_thresholds      : { carbon_max: 9.5, wallet_risk_max: 40, min_sources: 2 }   # kgCO₂e/kg;Cedar 用 9500 gCO₂e/kg
policy_version         : pol-2026-08-v3
mandate_nonce / valid_from / valid_until / status.status_list : 同 v2(mandates list idx 0)
```

### 5.2 M2:BRAND 永續長(ECR)→ Agent-2(主線)

```
issuer            : BRAND 永續長之 ECR 憑證(以其 sandbox ECR 鑰簽)
jti / aud         : <唯一 ID> / fab-gateway
purpose           : brand_scope3_supplier_reporting        # 取代 CBAM_quarterly_declaration
delegate_kid      : <brand-workload 公鑰 kid>              # 查驗請求必以此鑰簽章
allowed_claims    : [pcf_total, pcf_period, pcf_method,
                     tcProductRawMaterialPercentage, verification, quantity_kg]   # 品牌層六欄;排放數字恰一個
max_granularity   : batch                                   # 明文禁止 plant-level / machine-level
query_cap         : 10 次(原子扣次)
valid_from/until  : 2026-08-01 → 2026-09-30
mandate_nonce / policy_version / status.status_list : 同 M1 結構(mandates list idx 1)
```

> **重放防護與後端驗序**:同 v2(`jti` / `mandate_nonce` / `request_nonce`;`(mandate_id, request_nonce)` UNIQUE → `REPLAY_DETECTED`;後端先驗 mandate 簽章 → iss/aud/exp/jti → delegate_kid 對 request 簽章 → Token Status List → request_nonce,再以 `context.mandate_status_ok / delegate_key_ok / replay_ok` 進 Cedar)。**程式零改動。**

---

## 6. 政策(Cedar,三條肉眼可讀;結構同 v2,只換常數與註解)

```cedar
// P1 允許:mandate 範圍內的欄位揭露(只讀可信布林與 mandate 資料欄位)
permit (principal, action == Action::"DiscloseClaim", resource)
when {
  principal.mandate.allowed_claims.contains(resource.claim) &&
  resource.granularity_rank <= principal.mandate.max_granularity_rank &&
  context.mandate_status_ok && context.delegate_key_ok && context.replay_ok
};

// P2 絕對禁止:機密標籤欄位(不論 mandate 寫什麼;forbid 優先於 permit)
// confidential = plant_total_output, capacity_utilization, other_customers,
//                brand_allocation_share, utility_invoice_ref, monthly_utility_commitments,
//                chemical_inventory, fuel_contract, boiler_model, ppa_price, recycler_name, unit_price
forbid (principal, action == Action::"DiscloseClaim", resource)
when { resource.tag == "confidential" };

// P3 放行要件(Agent-1,付染整費前):碳排以整數 gCO₂e/kg 布比較(9.5 → 9500)
permit (principal, action == Action::"EmitReleaseCredential", resource)
when {
  context.mandate_status_ok &&
  context.identity_ok &&                                   // DYE 的 vLEI 鏈 + pcf_dyeing 簽章/狀態
  context.carbon_total_g <= principal.mandate.carbon_max_g && // pcf_aggregate.pcf_total(含染整段)
  context.invoice_ok &&
  (context.wallet_risk <= 40 || context.risk_sources_confirming < 2) &&
  context.amount <= principal.mandate.max_amount
};
// sign_transaction 永遠不在任何 agent scope → 由財務主管以其 ECR 金鑰簽署放行
```

`GRANULARITY_RANK = { batch: 0 }` 不變;`NEVER_DISCLOSABLE_CLAIMS = [pcf_yarn, pcf_knitting, pcf_dyeing]`。

---

## 7. 六幕與案件

| 幕 | 內容 | 技術 | 秒數 |
|---|---|---|---|
| **1 簽發** | YARN 簽發 `tc_carbon_upstream`:表單欄位名就是 TE 的 camelCase,旁註「TC 本身沒有碳數據,`pcf_*` 是我們補的」→ 憑證卡三色 → raw token | @sd-jwt/*、YARN LE 鑰 | 20 |
| **2 聚合** | FAB 讀紗憑證 + 自家織布用電 + DYE 的 `pcf_dyeing` → 程式算 `3.00×1.0545 + 2.4×0.474 + 染整` → 簽 `pcf_aggregate`;熱點圖三段(紗/織/染整),B 案染整段變紅、越過 9.5 門檻線;鏡頭句「下游拿到的憑證裡沒有紗廠是誰、沒有染整廠帳單,只有兩個參照指紋」 | 三輸入聚合、StackChart 三段 | 20 |
| **3 委任查驗** | Agent-2 持 M2 → FAB 閘道 `PERMIT · P1` → presentation **只有六列**(一個排放數字)→ BRAND 端離線驗簽章 / vLEI 鏈 / Status List 三綠勾 + OFFLINE;口白「品牌今天在 Worldly 看到的是總量;我們讓總量帶著證明,而且品牌拿不到能反推產能的欄位」 | M2、Cedar P1、SD-JWT verify | 30 |
| **4 越界攔截** ★ | Agent-2 加碼索取 **`plant_total_output`** → Cedar P2 DENY `POLICY_P2_CONFIDENTIAL` + 規則原文高亮 + 稽核帶多一行;口白引訪談:「供應商最怕的就是全廠產量被拿去反推產能利用率——這一欄連委任狀都寫不進去」 | Cedar P2、hash-chain | 20 |
| **5 門檻+付款閘道** | 案 B:染整燃煤 → 聚合 **10.90 > 9.5** → `CARBON_OVER_THRESHOLD` 轉人工(要求染整廠補件/重報);案 A:四項全過 → Dossier(fab-workload 簽)→ **財務主管以 ECR 鑰**簽放行 → mock USD 電匯指令(FAB → DYE,USD 3,420)→ 狀態 RELEASED;案 C/C′:收款帳戶風險雙來源 → 退回 / 單來源 → 只記錄 | P3、放行憑證、風險雙來源 | 35 |
| **6 稽核+撤銷** | 竄改一筆日誌 → verify-chain FAIL;**撤 `pcf_dyeing`(A)**(換燃料要重報,Fact)→ 重跑案 A 被拒 `CREDENTIAL_REVOKED`、已放行 Dossier 標 `DEPENDS_REVOKED` → DYE 重簽(新 `pcf_period`)→ FAB 重聚合 → 重驗綠;輔線撤 M1 → `MANDATE_REVOKED`;帶一句 vLEI TEL 撤銷向下連鎖 | hash chain、Token Status List(JWT)、revoke.ts | 35 |
| **加映** | 同一管線換 `slcp_dcc`,只揭露「零招募費 = true」;鞋廠子集委任「只答是/否」以投影片講 | 投影片為主 | 20 |

**合計約 160 秒 + 20 秒**。**錄影優先序**:幕 3 → 幕 4 → 幕 6 → 幕 5(案 B)→ 幕 1–2 → 案 C → 加映。

### 案件數值(kgCO₂e/kg 布;程式計算,顯示 2 位小數)

| 案 | 染整熱源 | 綠電比 | 紗 | 織布 | 染整 | **合計** | 門檻 9.5 | 結果 |
|---|---|---|---|---|---|---|---|---|
| **A** | 天然氣 | 0.30 | 3.16 | 1.14 | **3.63** | **7.93** | ✓ | 放行 → 人簽 → RELEASED |
| **B** | 燃煤 | 0.00 | 3.16 | 1.14 | **6.60** | **10.90** | ✗ | `CARBON_OVER_THRESHOLD` 轉人工 |
| C / C′ | 同 A | 同 A | 同 A | 同 A | 同 A | 7.93 | ✓ | 收款帳戶風險:雙來源退回 / 單來源只記錄 |
| E(狀態轉換) | 撤銷 A 的 `pcf_dyeing` 後重跑 A | — | — | — | — | — | — | `CREDENTIAL_REVOKED` + Dossier `DEPENDS_REVOKED` → 重簽重驗 |

- A/B 差異**只來自染整熱源**(+2.97 全在染整段),被問答得出理由:燃煤 94.6 vs 天然氣 56.1 kgCO₂/GJ、鍋爐效率 0.80 vs 0.90、綠電 30%。
- **seed 只有 A/B/C/Cp 四組**;E 不是 fixture。

---

## 8. 數值與係數表(程式計算用,不寫死結果;擷取日期 2026-08-29)

| 係數 | 值 | 單位 | 出處 | 等級 |
|---|---|---|---|---|
| 台灣電網(113 年度公用售電) | **0.474** | kgCO₂e/kWh | 經濟部能源署 113 年度電力排碳係數 | S3(114 年度 0.467,口白可提) |
| 越南電網(2023) | **0.6592** | kgCO₂/kWh | MONRE CV 1726/BĐKH-PTCBT(IKI Vietnam 轉載) | S3 |
| 天然氣 | **0.0561** | kgCO₂/MJ | IPCC 2006 Vol.2 Ch.2 Table 2.2;環境部 113-02-05 公告 | S3 |
| 煙煤 | **0.0946** | kgCO₂/MJ | 同上 | S3 |
| 鍋爐效率(天然氣 / 燃煤) | 0.90 / 0.80 | — | 【推估】產業常用值 | 推估 |
| 染整熱能(前處理 + 染色 + 後整理) | **48.6** | MJ/kg 布 | Ecobalyse 法規版方法說明 Table 20 | S3 |
| 染整電力 / 針織電力 | **1.8** / **2.4** | kWh/kg 布 | Ecobalyse | S3 |
| 針織損耗率 | 5.45%(加成 1.0545) | — | Ecobalyse Table 18 | S3 |
| rPET DTY 紗(越南) | **3.00**(0.42 direct + 3.91 kWh × 0.6592) | kgCO₂e/kg 紗 | 【推估】TE Polyester LCA 2026:東南亞機械回收 rPET 粒 1.31 + 紡絲 ≈ 1.7 | S3 底層/推估 |
| (對照)原生聚酯 DTY | 5.83 | kgCO₂e/kg 紗 | 同上 §5.5 | S3 |
| 綠電覆蓋比(A 案) | 0.30 | — | 【推估】PUMA 核心供應商 2025 目標 25% + 自建太陽能 | S4/推估 |
| 合約門檻 | **9.5** | kgCO₂e/kg 布 | 【推估】B 案 10.9 × 0.87;見 §3 註記 | 推估 |

**合理性錨點(Q&A 用)**:織布 + 染整的範疇 1+2 強度 A 4.77 / B 7.74 kgCO₂e/kg,對照儒鴻布料事業部公開實績 3.89(含針織 + 染整,自建太陽能 + 天然氣,S4)——A 同量級、B 為燃煤情境約 2 倍;含紗全值 7.93 / 10.90 落在文獻「染色聚酯針織布 9–14(原生紗)」扣除 rPET 差異 ≈2.5 的區間。一句話:「係數來源與品牌平台(Worldly)同一等級,結果與台灣一線布廠公開實績同量級;差異情境是燃煤 vs 天然氣,正是 H&M、PUMA 供應鏈去煤要求的內容。」完整 URL 見《260830 交接檔二》§4.1。

---

## 9. 收款帳戶與風險資料(合併 C/C′,一幕 15 秒)

```
payee_wallet (A/B)  : ACCT-SYN-DYE-001    風險 12   labels: []
payee_wallet (C)    : ACCT-SYN-DYE-7F2C   風險 78
    provider_a : 78  ["peel_chain", "rapid_passthrough"]
    provider_b : 71  ["peel_chain"]
    → 兩來源一致 → MULTI_SOURCE_CONFIRMED → 升級 → 退回
payee_wallet (C′)   : ACCT-SYN-DYE-9E04   風險 74
    provider_a : 74  ["rapid_passthrough"]
    provider_b : 18  []
    → 僅一來源 → SINGLE_SOURCE_ONLY → 只記錄不升級(自我約束)
```
識別碼皆為**合成字串,不對應任何鏈上位址**;不建立錢包、RPC 或鏈上交易。憑證 `issued_at` 回填:紗 2026-05-29、染整 2026-06-05、聚合 2026-06-12(`pcf_period` 皆 2026-05,對應每月 24/25 號結帳,Fact);效期至 2026-12-31。

---

## 10. 技術堆疊與備援(同 v2,只列差異)

| 元件 | 首選 | 備援 |
|---|---|---|
| 憑證格式 | IETF SD-JWT VC(`@sd-jwt/core` + `@sd-jwt/sd-jwt-vc`) | — |
| claims 欄位對照 | **Textile Exchange TC(ASR-104)鍵名 + PACT v3 / PEFCR A&F 邊界對照** | — |
| 組織身分 | vLEI Sandbox 預簽 **5 LE + 2 ECR**;鑰自 state.json 匯出 | 全域 Plan B(app 鑰 + 綁定聲明 + 缺口標注) |
| 政策 | Cedar(cedar-wasm,已可用) | policy.ts 純函式 |
| 撤銷(應用層) | Token Status List `draft-ietf-oauth-status-list-21` 簽章 JWT;**無裸 JSON 退路** | — |
| 撤銷(vLEI 層) | sandbox TEL | — |
| 付款(可抽換) | **mock USD 電匯指令**(FAB → DYE) | — |

> **範圍鐵則**:vckit、walt.id、OPA、APL、RISC Zero、did:web、任何鏈上/測試網實作、鞋廠 M3/幕 7/P4、稽核層 M4、一致性檢查 皆 **out of core scope**。

---

## 11. Henry 的最小可行清單(v3;程式面對照見《2026-08-29-v2→v3遷移清單》)

1. presign 多一家 LE(`dye`);manifest 7 個角色(5 LE + 2 ECR);LEI 字首與虛構名換紡織版。
2. seed.json 換 v3(§3、§7–9 全部數值 + 係數表);**所有結果由程式算**(`pcf_dyeing`、`pcf_aggregate`)。
3. 三張憑證的欄位常數:`tc_carbon_upstream`(TC 鍵名)、`pcf_dyeing`(新)、`pcf_aggregate`(三段);tag 改 `public / brand / audit / confidential`。
4. `claims.ts`:機密名單換 §6 清單;`NEVER_DISCLOSABLE = [pcf_yarn, pcf_knitting, pcf_dyeing]`;`M2_ALLOWED_CLAIMS` = 品牌層六欄。
5. mandate:M2 `purpose`、`aud = fab-gateway`;M1 `allowed_counterparties = [DYE]`、`carbon_max 9.5`、幣別 USD。
6. Cedar:P2 註解清單、P3 常數 `carbon_max_g = 9500`;整數換算 kgCO₂e/kg × 1000。
7. 前端:分頁名(紗廠 / 布廠閘道 / 品牌 Agent / 稽核撤銷)、憑證卡標籤、熱點圖三段、幕 4 按鈕「加碼索取 全廠產量 plant_total_output」。
8. 測試:寫死值改 `6006.32`、`7.9251`、`natural_gas`、機密名;H2 檢查對象換三段;新增 `dye` LE verify 與 manifest 7 角色。
9. 幕 5/6(Phase 3):P3 管線、人簽(財務主管 ECR)、mock 電匯指令、撤 `pcf_dyeing` → `DEPENDS_REVOKED` → 重簽重驗。

---

## 12. 治理缺口說明(簡報必附一頁)

- vLEI 為 Sandbox 預簽,非正式 QVI 簽發;認證機構 CB 為虛構,不代表 Control Union 或任何真實 CB。
- TC 欄位為**對照 Textile Exchange 鍵名**,非 TE 認證系統簽發;碳欄位 `pcf_*` 為我方延伸(TC 本身無碳數據,S3)。
- 數值為合成/推估(§8 附出處);染整外包為【假設】,待受訪者確認工段切分。
- ZK 未實作;**可驗證 ≠ 可信賴**:憑證證明身份、授權與計算完整性,不證明單據反映物理真實(訪談:「單據造假,我相信他應該看不出來」【受訪者觀察】)。
- 付款層為 mock USD 電匯(訪談證實現行方式);不做鏈上/穩定幣。
- **已設計、未實作**:鞋廠子集委任(只答是/否)、稽核層開啟月度承諾值、送出前一致性檢查(Right the first time)、品牌 Raw Data 方案的資安對策。
- 供應商重組/轉包、上游回收粒供應商每批更換的追溯,僅以 `inputTcNo` 鏈結示意。

---

## 13. 尚未結案(不阻擋)

- [ ] 染整是否在自家(Martin LINE):若在自家 → DYE 併入 FAB,`pcf_dyeing` 改為 FAB 自簽的內部段憑證;熱點圖與 A/B 差異不變,幕 5 付款對象改回紗廠。
- [ ] 向上游要碳數據的經驗(Martin):制度面已由研究補齊(FEM 不收上游、TC 無碳)。
- [x] TC 是否含碳:研究確認**無**(S3)。
- [ ] HS 6006.32 查證;`tcProductCategoryCode / DetailCode / RawMaterialCode` 對 TE 代碼表核對。

---

## 14. 評分對齊檢查

| 評分項 | 權重 | 對應 |
|---|---|---|
| 場景契合度 | 35% | 一手訪談(具名)、真實認證體系(RCS/SC/ZDHC/SLCP/Higg)、品牌合約硬要求(Nike/On/PUMA/adidas/H&M 有名字年份)、填報制度縫隙(FEM 單據留廠只交總量、TC 無碳)與 demo 主張精準對位 |
| 可信技術可行性 | 25% | mandate / workload / transaction 三支柱逐一對映(M1、M2、workload id、雙來源佐證、Token Status List、TEL);憑證 schema 對映 TE TC 官方鍵名 |
| 簡報與 Demo | 25% | 六幕 160 秒 + 加映 20 秒;開場用受訪者原話;PASS → 撤銷 → FAIL 對應「換燃料要重報」 |
| 洞察與創意 | 15% | TC 無碳數據(S3)、原始單據留廠只交總量、追溯平台碎片化;Tier-N 卡死在紡織是制度性的 |

---

## 來源

《260826 Martin(鎰呈行)訪談紀錄 整理版》(S1;受訪者已同意具名);《260829 交接檔一》《260830 交接檔二》(數值與係數 §4、出處總表 §9);《260829 紡織業標準機構與廠商》(A-4 TC 欄位、B-2/B-8 FEM、§C 品牌目標、§D 法規時程);Textile Exchange ASR-104 V3.1 / TE-TXL-POL-203 V4.0;TE Polyester LCA Technical Report 2026-06;Ecobalyse 法規版方法說明(2025-10-01);IPCC 2006 Vol.2 Ch.2;環境部 113-02-05 排放係數公告;能源署 113/114 年度電力排碳係數;MONRE CV 1726/BĐKH-PTCBT;Cascale Higg FEM 2025;PUMA AR2023;MIT Cheah et al. 2013。
