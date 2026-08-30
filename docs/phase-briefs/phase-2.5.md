# Phase 2.5 brief — v3.0 → v3.1 遷移完成(紡織版)

> 規格:CLAUDE.md(v3.1)> docs/2026-08-26-專案架構決策.md > docs/demo情境設定與合成資料規格-v3.md(§0.4/§0.5、§4.2a/§4.2b/§4.5)> docs/2026-08-29-v2→v3遷移清單.md(Step 2–8 已更新為 v3.1,為程式面逐檔對照)。seed 唯一來源:docs/seed.v3.json(不得手改數值)。

## 0. 現況(branch v3-textile @ 77453f0)

v3.0 遷移已完成並全綠(201 項):alias 改名(yarn/fab/dye/brand/cb)、presign 7 角色、seed v3.0、`tcCarbonUpstream.ts` / `pcfDyeing.ts` / `pcfAggregate.ts` 三段公式、前端紡織版、test.ts 七組 v3 檢查。
**本 phase = 補 v3.1 delta**:TC 改由 CB 簽發(`tc_rcs`)、新增 `ccs_scope_cert`(CB 簽)、`pcf_upstream` 恢復檔名並帶 `tc_ref`、`hs6` 全面移除、三個新理由碼、p3.cedar 加 `subcontractor_listed`。
程式現況佐證:`server/creds/tcCarbonUpstream.ts` 存在;`shared/codes.ts` 無 `TC_REF_MISMATCH` 等;`data/seed.json` 無 `tc_rcs`/`ccs_scope_cert`;`hs6`/`6006.32` 出現於 types.ts、pcfAggregate.ts、test.ts。

## 1. 範圍(只能動這些檔)

1. **`data/seed.json`** ← 整檔覆蓋為 `docs/seed.v3.json`(v3.1;含 `tc_rcs`、`ccs_scope_cert`、`status_list_idx` 新表:pcf_upstream 0/1、aggregate 2/3、dyeing 4/5、slcp 6、attestation 7、dyeing-reissue 8、**tc_rcs 9、ccs_scope_cert 10**)。
2. **`shared/types.ts`**(遷移清單 Step 3 v3.1 版):
   - `TC_RCS_PUBLIC_FIELDS` / `TC_RCS_BRAND_SD_FIELDS`(新);`interface TcRef { id; tcNo; issuer_lei; hash }`;`interface CcsScopeRef { sc_no; hash }`;`CCS_SCOPE_CERT_FIELDS` 與 `interface AssociatedSubcontractor { lei; name; process; audited }`。
   - `TC_UPSTREAM_*` → `PCF_UPSTREAM_*`(公開層 = `tc_ref, product_code, country_of_origin, unit_price_hash, energy_invoice_hash, recycler_name_hash, emission_factor_table_hash`;品牌層 = `pcf_total, pcf_period, pcf_method, quantity_kg`;稽核層與機密層照遷移清單)。
   - `PCF_DYEING_PUBLIC_FIELDS` 加 `ccs_subcontractor_status`、`ccs_scope_ref`。
   - `PCF_AGGREGATE_PUBLIC_FIELDS`:**移除 `hs6`**、加 `ccs_scope_ref`。
   - Payload interfaces:`TcRcsPayload` / `PcfUpstreamPayload(tc_ref)` / `PcfDyeingPayload(ccs_scope_ref)` / `PcfAggregatePayload(ccs_scope_ref; precursor_refs 三筆)` / `CcsScopeCertPayload`。
3. **`shared/codes.ts`**:新增 `TC_REF_MISMATCH`、`CCS_SUBCONTRACTOR_NOT_LISTED`、`SCOPE_CERT_INVALID`。
4. **`server/creds/`**(遷移清單 Step 4 v3.1 版):
   - `git mv tcCarbonUpstream.ts pcfUpstream.ts`:`vct = .../pcf_upstream`;store id `pcf_upstream-A/B`(idx 0/1);簽發前先取入庫 `tc_rcs`(不存在 → 拒簽 `TC_REF_MISMATCH`),公開層 `tc_ref = { id:'tc_rcs', tcNo, issuer_lei, hash: sha256(tc_rcs.sdJwt) }`;三個機密項 → `*_hash`;A/B 同 `upstream_defaults`。
   - 新 **`tcRcs.ts`**(CB LE 鑰簽):`vct = .../tc_rcs`;讀 `seed.tc_rcs`;`seller_lei/buyer_lei` 自 manifest(yarn/fab);`tcShipmentInvoiceReferences` → hash;disclosureFrame `_sd = TC_RCS_BRAND_SD_FIELDS`;idx 9;id `tc_rcs`;A/B 同一張;issuerParty 'cb'、holderParty 'fab'。
   - 新 **`ccsScopeCert.ts`**(CB LE 鑰簽):`vct = .../ccs_scope_cert`;讀 `seed.ccs_scope_cert`;`holder_lei/cb_lei/associated_subcontractors[].lei` 自 manifest;**全部非 SD**;idx 10;id `ccs_scope_cert`;並輸出 `verifyScopeCert(sdJwt)`(驗章 + 效期 + Status List → 不過即 `SCOPE_CERT_INVALID`)與 `isSubcontractorListed(payload, dyeLei, process)`。
   - `pcfDyeing.ts`:公開層加 `ccs_scope_ref = { sc_no, hash: sha256(ccs_scope_cert.sdJwt) }`(自入庫 SC 計算)與 `ccs_subcontractor_status`;其餘不動(computeDyeing、idx A=4/B=5/reissue=8 照舊)。
   - `pcfAggregate.ts`:`ensureInputs(case)` 改取 `tc_rcs`、`pcf_upstream-<case>`、`pcf_dyeing-<case>`、`ccs_scope_cert`;**三張外部憑證(tc_rcs、pcf_upstream、pcf_dyeing)消費前以 manifest 公鑰驗章**(不過丟 `UpstreamVerificationError` → `CREDENTIAL_SIG_INVALID`);v3.1 核對:①`pcf_upstream.tc_ref.hash == sha256(tc_rcs.sdJwt)` ②`tc_rcs.seller_lei == manifest.yarn.lei` ③`tc_rcs.buyer_lei == manifest.fab.lei` ④`tc_rcs.tcProductCertifiedWeight >= pcf_upstream.quantity_kg`(任一不符 → `TC_REF_MISMATCH`);⑤`verifyScopeCert` 通過(否則 `SCOPE_CERT_INVALID`)⑥`pcf_dyeing.ccs_scope_ref.sc_no == sc_no` 且 DYE LEI ∈ `associated_subcontractors`(否則 `CCS_SUBCONTRACTOR_NOT_LISTED`);`tcProductStandardLabelGrade` 取自 tc_rcs(不自填);`precursor_refs = [tc_rcs, pcf_upstream, pcf_dyeing]` 三筆;公開層加 `ccs_scope_ref`、**移除 hs6**。這三個新理由碼的 DENY 一律經 server/audit.ts 入鏈(與其他 DENY 相同)。
5. **`server/routes/issue.ts`**:新 `POST /api/issue/tc`(CB 簽 tc_rcs)、新 `POST /api/issue/scope-cert`;`/api/issue/upstream` TC 缺 → 400 + `TC_REF_MISMATCH`。**seed 流程**(server/seed.ts 或現行對應檔):灌案件前先簽 `ccs_scope_cert` 與 `tc_rcs`。`routes/aggregate.ts` 改呼叫 `ensureInputs`。
6. **`policies/p3.cedar`**:在 `context.identity_ok` 後加 `context.subcontractor_listed &&`(後端算好的可信布林,Cedar 不得讀狀態);`policies/p2.cedar` 註解列 12 個機密名;`server/policy/cedar.ts` 同步 context/entity(carbon_max_g 9500 照舊)。`server/policy/claims.ts` 依新欄位常數對照(M2 六欄不變)。
7. **前端**(遷移清單 Step 6 v3.1 版):
   - `Yarn.tsx` 幕 1 **兩張卡**:卡 1「Transaction Certificate — 認證機構簽發」(TE camelCase、`volume_reconciled ✓`、seller/buyer;按鈕「載入 CB 簽發的 TC」);卡 2「碳足跡憑證 — 紗廠簽發」(簽發後出現;公開層 `tc_ref` 旁鏈結圖示指向卡 1;旁註「TC 是認證機構開的但沒有碳;碳只有紗廠有帳單能證明」;三色 🟢 tc_ref/產品/產地、🟡 pcf_total/pcf_period/稽核層、🔴 單價/帳單/供應商名)。
   - `Gateway.tsx`:鏈結圖示三個參照指紋(TC、紗、染整)+ SC 小卡(sc_no、CB 簽、製程、associated subcontractor ✓);StackChart 三段照舊。
   - 其他分頁文案不動(BrandAgent 六 chips 已是 v3)。
8. **`scripts/test.ts`**(Step 7 v3.1 版):改寫既有第 3 組(precursor_refs 兩筆 → **三筆**)、新增 **3a/3b** 兩組(見 §3);移除所有 `hs6`/`'6006.32'`(改斷言 `product` 字串);守門 grep 名單加 `6006`。
9. 若 `Makefile` 的 setup/demo-reset 流程需帶入新憑證簽發順序,允許小改。

## 2. DoD(逐條,全過才算)

1. `make setup` 乾淨環境一鍵成功(rm -rf .vlei data/vlei/* data/keys/* db/*.sqlite* 後重跑)。
2. `make test` 全綠,且含九組 v3/v3.1 檢查(§3)。
3. 守門 grep 為 0 行。**規格疑義裁定(Opus 驗證揭出、記入 CLAUDE.md 定案)**:原完成條件的 `git grep -iE "…EAF…|6006…" -- server web scripts data policies CLAUDE.md` 掃到 `data/` 時,會機率性(實測約 25%)誤中 `data/vlei/manifest.json`(tracked 公開材料)裡隨機 CESR AID/SAID 的 `EAF`/`eaf` 子字串、與 `data/status/*.jwt` 的 ISO 時間戳裡的 `6006`——這些是生成的密碼學材料,非人寫的鋼鐵術語。故:**權威守門 = scripts/test.ts 的 case-sensitive `STEEL_RE`**(掃 authored 檔:server/shared/scripts/web/src/policies/CLAUDE.md 與 `data/seed.json`,不掃 data/vlei|data/status),它穩定、`make test` 不 flaky;**完成條件的外部 grep 對齊其檔案集**——排除生成材料:`git grep -iE "鴻鋼|Thép Việt|Bruck|台驗|扣件|線材|CBAM|海關|EAF|BF-BOF|USDC|6006" -- server web scripts policies CLAUDE.md data/seed.json`(即 `data` 只掃 `data/seed.json`)輸出為 0 行。
4. `git status` 乾淨:`.vlei/`、`data/keys/`、`db/*.sqlite*` 未被追蹤。
5. `make dev` 幕 1–4 可走通:幕 1 為兩張卡(TC 卡 + 碳憑證卡)、Tab 2 有 SC 小卡、無鋼鐵字樣;web build 通過(`cd web && npx vite build`;無 `npm run build` script)。
6. Cedar:`checkParsePolicySet` 三條可解析;mandate entity `carbon_max_g == 9500`;A `carbon_total_g 7925` 過、B `10899` 不過;`context.subcontractor_listed = false` 時 p3 DENY。

## 3. 要新增/改寫的回歸測試(scripts/test.ts)

1. manifest 7 角色(5 le + 2 ecr)、dye presentation sandbox verify 通過(既有,保留)。
2. computeDyeing A/B 交叉驗證 = `expected_pcf_dyeing`;B ≠ A 且差異僅來自 heat_source/renewable_share(既有,保留)。
3. pcf_aggregate A/B = `expected_pcf_total`;`precursor_refs` 恰**三筆**(tc_rcs、pcf_upstream、pcf_dyeing)且 hash 對得上入庫 sd_jwt;消費前驗章失敗路徑回 `CREDENTIAL_SIG_INVALID`(改寫)。
4. **3a(新)**:`tc_rcs` 以 CB 公鑰驗章通過、`volume_reconciled === true`;竄改入庫 tc_rcs 一個 byte 後重簽 pcf_upstream → 聚合回 `TC_REF_MISMATCH`;`tc_rcs.buyer_lei` 改別家 → `TC_REF_MISMATCH`(兩條失敗路徑;測後還原)。
5. **3b(新)**:`ccs_scope_cert` 以 CB 公鑰驗章通過;`pcf_dyeing.ccs_scope_ref.sc_no` 一致;`associated_subcontractors` 清空重灌 → 聚合回 `CCS_SUBCONTRACTOR_NOT_LISTED`;撤 idx 10 → `SCOPE_CERT_INVALID`(測後還原 bit)。
6. H2:M2 presentation 排放數字恰一個;pcf_yarn/pcf_knitting/pcf_dyeing 任一 → `CLAIM_NOT_IN_MANDATE` 且 presenter 硬拒;`brand_allocation_share` 不出現於任何 presentation 明文(既有,保留)。
7. 幕 4:`plant_total_output` → `POLICY_P2_CONFIDENTIAL` 且 deny 入鏈(既有,保留)。
8. Cedar 單位與 `subcontractor_listed=false` DENY(§2 第 6 條)。
9. 一致性守門 grep(名單加 `6006`;原有守門 human.key/workload.key/status_list_ref/encodedList/testnet 照舊)。

## 4. 禁止事項

- 不動 `vendor/`;不加遷移清單未列的依賴;不建錢包/RPC/鏈上;不宣稱 W3C VC 2.0 或 TE 認證。
- 密碼學不可造假:tc_rcs 與 ccs_scope_cert 必須真簽真驗(CB LE 鑰經 server/keys.ts);任何 mock 驗證視為 bug。
- 取鑰只經 server/keys.ts;route 不得讀鑰檔或 .vlei/state.json。
- 所有數值由 seed 係數表計算;`expected_*` 只供 test;seed 數值不得手改。
- Cedar 不得直接讀 mandate/SC 狀態,只消費後端算好的布林。
- 不動 `statuslist.ts`、`audit.ts`、`db.ts`/`schema.sql`、`discloseGateway.ts` 驗證順序、`verifyPresentation.ts` 檢查項、`presenter.ts` 硬拒機制、`verify-chain.ts`、`verify-offline.ts`、`tamper.ts`(除非 DoD 需要且說明理由)。
- H2 防線與 M2 六欄不得鬆動。
