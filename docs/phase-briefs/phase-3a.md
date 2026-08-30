# Phase 3a brief — 幕 5:門檻與付款閘道(Agent 開單、財務主管簽字、付染整費)

> 規格:CLAUDE.md(v3.1)> spec v3 §5.1(M1)、§4.6(invoice)、§6(P3)、§7 幕 5、§9(風險資料)> 遷移清單 §10 > 藍圖 v3 幕 5 節。前置:Phase 2.5 已完成(tc_rcs / ccs_scope_cert / verifyScopeCert / isSubcontractorListed 已存在)。
> 規格疑義(已裁定):藍圖幕 5 寫「Dossier 含四項檢查結果」為 v2 殘留;v3.1 P3 為**五要件**,Dossier 含**五項結果**(runbook 與 CLAUDE.md 優先)。

## 0. 現況

幕 5 為全新開發:repo 無 `/api/agent/run`、`/api/human-sign`、invoice 簽發、Dossier。已存在可複用:M1 常數(mandate.ts:max_amount 50000、USD、allowed_counterparties=[DYE LEI]、thresholds {carbon_max 9.5, wallet_risk_max 40, min_sources 2}、policy_version pol-2026-08-v3、delegate_kid=fab-workload)、p3.cedar(carbon_max_g 9500 + subcontractor_listed)、server/audit.ts、server/keys.ts(fab_cfo ECR、dye LE、fab-workload)、discloseGateway.ts 的 mandate 驗證順序(M2 流程,照抄結構)。

## 1. 範圍(要動的檔)

1. **`server/creds/invoice.ts`(新)**:DYE LE 鑰簽發票 VC(經 server/keys.ts)。內容依 spec §4.6 與 `seed.transaction.dyeing_service`:USD 3,420、quantity 2,850 kg、payer FAB、payee DYE、收款帳戶識別碼(合成字串,依 case 取 seed §9:A/B=ACCT-SYN-DYE-001、C=…7F2C、Cp=…9E04)。提供驗章函式。
2. **`server/routes/agent.ts`(新)**:`POST /api/agent/run?case=A|B|C|Cp`:
   - 先驗 M1(簽章=財務主管 ECR、iss/aud/exp/jti、delegate_kid 對 request(fab-workload)簽章、Token Status List、request_nonce)→ `mandate_status_ok / delegate_key_ok / replay_ok` 三布林進 Cedar(結構照 discloseGateway 之 M2 驗序;Cedar 不得直接讀狀態)。
   - **P3 五要件**(每項結果+理由碼經 server/audit.ts 與 decisions **同一交易**入鏈):
     ① `identity_ok`:DYE vLEI 鏈 sandbox verify + `pcf_dyeing-<case>` 簽章/效期/Status List;
     ② `subcontractor_listed`:`verifyScopeCert(ccs_scope_cert)` 通過 ∧ `pcf_dyeing.ccs_scope_ref.sc_no == sc_no` ∧ DYE LEI ∈ `associated_subcontractors`(SC 失效 → `SCOPE_CERT_INVALID`;不在清單 → `CCS_SUBCONTRACTOR_NOT_LISTED`);
     ③ 門檻:`carbon_total_g = round(pcf_aggregate.pcf_total × 1000)` ≤ `carbon_max_g 9500`(Cedar P3 判;A 7925 過、B 10899 不過 → `CARBON_OVER_THRESHOLD`);
     ④ `invoice_ok`:invoice 驗章(DYE 公鑰)+ `amount ≤ max_amount` + payee ∈ `allowed_counterparties`;
     ⑤ 帳戶風險:讀 `seed.risk_signals[case]`;兩來源皆 > wallet_risk_max 40 → `MULTI_SOURCE_CONFIRMED`(升級、退回);僅一來源 → `SINGLE_SOURCE_ONLY`(只記錄不升級,不阻擋);A 風險 12 → 過。
   - 全過(A/Cp)→ 建 **Dossier**:JWS by **fab-workload 鑰**,payload = `{ build_hash(git commit)、version、五項結果、三張輸入憑證 hash(pcf_dyeing、pcf_aggregate、invoice)、case、mandate_jti }`,狀態 `PENDING_HUMAN`,存 DB(新表或 store,schema 小改允許)。
   - 案 B:第 3 項 FAIL → `CARBON_OVER_THRESHOLD` DENY 入鏈,不建可放行 Dossier;案 C:第 5 項 `MULTI_SOURCE_CONFIRMED` → 退回,不放行。
3. **`POST /api/human-sign`**(同檔或 routes/humanSign.ts):輸入 dossier id;僅五項全過之 Dossier 可放行;以**財務主管 ECR 鑰**(server/keys.ts)簽 release;產 `mock_payment_instruction = { instruction_id, payer: fab, payee: dye, amount: 3420, currency: 'USD', rail: 'mock_wire' }` → 狀態 `RELEASED`,`RELEASE` 事件經 audit.ts 入鏈。對 FAIL 案(B/C 或 subcontractor_listed=false)呼叫 → 4xx 拒絕。
4. **`web/src/tabs/Gateway.tsx`**(幕 5 區塊,Tab 2):案件切換 A/B/C/Cp;五檢查逐列亮綠/紅;Dossier 卡(workload 簽章 + build_hash);「以財務主管 ECR 金鑰簽署」不同配色確認對話框 → RELEASED(顯示 instruction id);**案 B/C 放行按鈕不渲染(不是 disabled)**,案 B 只剩「轉人工/要求染整廠補件」;案 C 風險表兩列 provider 並排紅、Cp 一列灰「只記錄」。文案繁中,理由碼用 shared/codes.ts 常數。
5. **`shared/codes.ts`**:補 `CARBON_OVER_THRESHOLD`、`MULTI_SOURCE_CONFIRMED`、`SINGLE_SOURCE_ONLY`、`RELEASED` 等幕 5 常數(若缺)。
6. **`scripts/test.ts`**:§3 回歸鎖。
7. `db/schema.sql` 允許新增 dossiers 表(僅新增,不動既有表);`Makefile` 不動(demo-reset 需能清 Dossier 狀態——若 demo-reset 重建 DB 即天然滿足,說明即可)。

## 2. DoD(逐條)

1. `POST /api/agent/run?case=A|B|C|Cp` 走 P3 五要件,每項檢查結果與理由碼入 decisions + audit_chain 同一交易。
2. Dossier 為 fab-workload 簽之 JWS,payload 含 build_hash、五項結果、三張輸入憑證 hash;可用 manifest 內 fab-workload 公鑰驗章。
3. `POST /api/human-sign` 以財務主管 ECR 鑰簽放行,產 mock USD 電匯指令(payer fab、payee dye、3,420)→ RELEASED,入鏈。
4. 案 B 回 `CARBON_OVER_THRESHOLD` 且 UI 不渲染放行按鈕;對 B 呼叫 human-sign 被拒。
5. 案 C `MULTI_SOURCE_CONFIRMED`(退回)、案 Cp `SINGLE_SOURCE_ONLY`(只記錄,可放行)。
6. `subcontractor_listed=false`(撤 idx 10 或清空清單重灌)時不放行,理由碼正確。
7. `make test` 全綠(新回歸鎖 + 既有 201+ 項);守門 grep 0;git status 乾淨。

## 3. 要新增的回歸測試(scripts/test.ts)

1. 案 A:agent/run 五項全綠;Dossier JWS 以 fab-workload 公鑰驗章通過;payload 含 build_hash、五項結果、三張 hash 且 hash 對得上入庫 sd_jwt/invoice;human-sign → RELEASED;release 簽章以財務主管 ECR 公鑰驗過;payment_instruction 欄位正確(payer fab、payee dye、3420、USD、mock_wire);RELEASE 入鏈(verify-chain 通過)。
2. 案 B:`CARBON_OVER_THRESHOLD`;deny 入鏈;human-sign 對 B 的 dossier(或無 dossier)→ 4xx。
3. 案 C:`MULTI_SOURCE_CONFIRMED` 且不放行;案 Cp:`SINGLE_SOURCE_ONLY` 且可放行(或依 spec 只記錄後放行)。
4. SC 失效路徑:撤 credentials idx 10 → agent/run 回 `SCOPE_CERT_INVALID` 且不放行(測後還原 bit);清單不含 DYE → `CCS_SUBCONTRACTOR_NOT_LISTED`(測後還原)。
5. 重放:同一 (mandate_id, request_nonce) 重送 agent/run → `REPLAY_DETECTED`。
6. Cedar:P3 evaluate 以 `subcontractor_listed=false` → DENY(2.5 已鎖,保留)。

## 4. 禁止事項

- 不建錢包、RPC、testnet 位址、任何鏈上交易;付款永遠停在 mock JSON;收款帳戶為合成字串。
- 放行簽名權只在財務主管 ECR 鑰;fab-workload 只簽 Dossier;scope_tools 不含 sign_transaction。
- 取鑰只經 server/keys.ts;Cedar 只消費後端算好的布林;所有 DENY/RELEASE 經 server/audit.ts 同交易入鏈。
- 不動 vendor/、不加依賴;H2 防線不得鬆動;數值由 seed 計算不寫死(3420/2850/風險分數等皆讀 seed)。
- 不動 Phase 2.5 已驗過的檔案行為(pcfAggregate 核對、H2、Cedar 常數),除非 DoD 需要且說明。
