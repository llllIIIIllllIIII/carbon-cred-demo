# carbon-cred-demo — 專案硬規則(每個 phase 都遵守)

跨組織碳足跡憑證選擇性揭露 demo(**紡織:越南紗廠 → 台灣布廠 → 歐洲品牌;外包染整為 A/B 差異來源**)。文件優先序:
**docs/2026-08-26-專案架構決策.md(2026-08-29-f)> docs/demo情境設定與合成資料規格-v3.md > docs/製造貿易demo實作藍圖.html(技術細節與 DoD)**;程式面對照見 docs/2026-08-29-v2→v3遷移清單.md。
(藍圖之檔案路徑僅為示意,目錄一律以架構決策 §2 為準;Quan《260830 交接檔二》為敘事參考,與規格衝突處以 spec v3 §0.3 為準。)

## 範圍鐵則(優先於文件中任何相反描述)

- 憑證格式:@sd-jwt/core + @sd-jwt/sd-jwt-vc——**SD-JWT core = RFC 9901,SD-JWT VC = IETF Internet-Draft profile**。不得宣稱符合 W3C VC 2.0;UNTP DPP/PACT/**Textile Exchange TC 鍵名**僅作 claims 欄位對照,不宣稱 TE 認證。
- 應用層撤銷 = **Token Status List(draft-ietf-oauth-status-list-21)**:Status List Token 為 compact signed JWT,header.typ="statuslist+jwt",payload 含 sub、iat(建議含 exp、ttl)與 status_list = { bits: 1, lst: "<base64url(zlib 壓縮位元陣列)>" };credential 與 mandate 一律以 **status.status_list = { idx, uri }** 引用;正式檔案為 **data/status/mandates.jwt 與 data/status/credentials.jwt**,GET /status/* 必須回 compact signed JWT、Content-Type: application/statuslist+jwt;**驗證方必先驗 compact JWS 簽章,再解碼 payload.status_list.bits/lst**。vLEI 撤銷由 sandbox TEL 驗證。裸 JSON bit array 不得出現於正式流程。idx 固定表在 data/seed.json `status_list_idx`。
- 簽章金鑰(**5 LE + 2 ECR**,皆經 server/keys.ts 自 .vlei/state.json 匯出):**CB 認證機構 LE 鑰簽 tc_rcs(Transaction Certificate,CCS-102 E2.1 由賣方 CB 簽發)與 ccs_scope_cert(布廠 Scope Certificate,列染整廠為 associated subcontractor,D3.4)**、加映 slcp_dcc/查證聲明;YARN 紗廠 LE 鑰簽 pcf_upstream(公開層 tc_ref {id, hash} 綁定 tc_rcs;TC 不存在則拒簽);DYE 染整廠 LE 鑰簽 pcf_dyeing(公開層 ccs_scope_ref)與 invoice;FAB 布廠 LE 鑰簽 pcf_aggregate(ccs_scope_ref;precursor_refs 三筆;tcProductStandardLabelGrade 由 tc_rcs + SC 推導)與 Status List Token;M1 與幕 5 人工放行用 **FAB 財務主管 ECR 鑰**;M2 用 **BRAND 永續長 ECR 鑰**。不建立 human.key。**紗廠不得自簽 TC 欄位;染整廠不得在沒有 SC 參照下撐起 RCS 宣告。**
- 另建兩把 app 產生的 workload 鑰:**fab-workload、brand-workload**。M1/M2 必須含 delegate_kid 綁定對應 workload 公鑰;跨組織 disclose request 必須由對應 workload 鑰簽章,閘道先驗簽再進 Cedar。
- 防重放:mandate 含 jti 與 mandate_nonce;每次 disclose request 帶新 request_nonce;(mandate_id, request_nonce) 加 UNIQUE;重複 → REPLAY_DETECTED;query_cap 扣次與 presentation、audit 寫入同一筆交易。
- seed 只有 A/B/C/Cp 四組;A/B 差異**只來自 pcf_dyeing 的 heat_source/renewable_share**;E 不是 fixture,是「撤銷 pcf_dyeing(A)後重跑 A」的狀態轉換(CREDENTIAL_REVOKED + 既有 Dossier DEPENDS_REVOKED → DYE 重簽 → 重聚合 → 重驗);撤 M1 為輔線(MANDATE_REVOKED)。
- Cedar 不得直接讀取 mandate 狀態:後端先驗 mandate 簽章、iss/aud/exp/jti、delegate_kid 對 request 簽章、Token Status List、request_nonce,再以 context.mandate_status_ok / delegate_key_ok / replay_ok 三個可信布林傳入;政策僅消費布林與 mandate 之資料欄位(allowed_claims 等)。
- **H2 算術洩漏防線(維持)**:跨組織 presentation 只能有一個排放數字(pcf_total);pcf_yarn / pcf_knitting / pcf_dyeing 為 NEVER_DISCLOSABLE(不進任何 allowed_claims,presenter 硬拒);三段熱點圖走 Tab 2 伺服端真值。brand_allocation_share、plant_total_output、capacity_utilization、other_customers、monthly_utility_commitments、原始帳單、化學品清冊、燃料合約、鍋爐型號、PPA 價格、回收粒供應商名、單價 一律 confidential(僅 hash)。M2 allowed_claims 恰為 pcf_total、pcf_period、pcf_method、tcProductRawMaterialPercentage、verification、quantity_kg 六欄。
- identity_vlei(法人/ECR)不掛應用層 Token Status List;其撤銷狀態一律以 vLEI TEL 參照、由 sandbox verify(child_process)查驗。
- 聚合前核對(v3.1):pcf_upstream.tc_ref.hash == sha256(tc_rcs)、tc_rcs.seller_lei/buyer_lei = 紗廠/布廠、tcProductCertifiedWeight ≥ quantity_kg,不符 → TC_REF_MISMATCH;ccs_scope_cert 驗章/效期/Status List 通過(否則 SCOPE_CERT_INVALID)且 pcf_dyeing.ccs_scope_ref.sc_no 一致、DYE LEI ∈ associated_subcontractors(否則 CCS_SUBCONTRACTOR_NOT_LISTED)。這三個理由碼與其他 DENY 一樣入稽核鏈。
- 幕 5 = **布廠(FAB)付染整廠(DYE)**染整費:P3 檢查 DYE 身分、**染整廠在布廠 SC 分包商清單(context.subcontractor_listed,後端算好的布林)**、pcf_aggregate.pcf_total ≤ 9500 gCO₂e/kg(品牌合約 9.5 kgCO₂e/kg × 1000)、發票、收款帳戶風險雙來源;Dossier 由 fab-workload 簽;人簽 = 財務主管 ECR;產 **mock USD 電匯指令**(付款人 FAB、收款人 DYE、USD 3,420)→ 狀態 RELEASED。不得建立錢包、RPC 連線、testnet 位址或任何鏈上交易;收款帳戶識別碼為合成字串。
- **只做投影片、不寫程式**:鞋廠 SHOE 與其 M3 子集委任/幕 7/P4、稽核層 M4 與月度承諾值開啟、送出前一致性檢查(CONSISTENCY_FAILED)、slcp_dcc 加映(seed 一段即可)。
- out of scope:ZK/RISC Zero、鏈上/穩定幣、did:web、vckit、walt.id、OPA、APL。

## 硬規則

- docs/ 為唯一規格來源;禁止讀取 workspace 其他同名或舊版文件(含 v2 spec、鋼鐵版 seed)。
- 密碼學不可造假:簽章與驗章一律真實執行(@sd-jwt/*、Ed25519、sandbox verify);任何 mock 驗證視為 bug。
- 一方一鑰:取鑰只經 server/keys.ts;route 不得直接讀鑰檔或 .vlei/state.json。
- BRAND 端驗證(server/routes/verify 與 scripts/verify-offline.ts)只讀 token、manifest 公鑰、data/vlei/、data/status/;不得呼叫閘道 API 或讀他方 DB 資料。
- 所有 PERMIT/DENY/RELEASE/REPLAY_DETECTED 經 server/audit.ts 唯一入口,decisions 與 audit_chain 同一筆 transaction;DENY 與重放也入鏈。
- vendor/ 唯讀;.vlei/ 與 data/keys/ 永不進版控。
- 介面文案繁體中文;理由碼用 shared/codes.ts 的英文常數。
- 所有數值由程式以 data/seed.json 係數表計算,不得寫死結果;seed 的 expected_* 只供 make test。
- 每幕完成即執行 docs 藍圖對應的 DoD 檢查。
- **保底 = 紡織版少一幕(幕 3 → 4 → 6),不得回退鋼鐵版**;錄影總長 ≤ 2:30、分幕輸出獨立檔並附時間碼表。幕 1 保底 (a):tcRcs.ts 未完成時 pcf_upstream.tc_ref 的 hash 改為 sha256(seed.tc_rcs JSON)、治理缺口註明 CB 憑證未真簽。
- **Phase 收尾流程(使用者 2026-08-29 指定)**:每完成一個大 phase,**push 之前必經 `/codex:review`**——提示使用者執行(或經使用者同意後代跑 codex 審查);逐項評估審查發現:需修正/優化者修完並使 `make test` 全綠(必要時加回歸鎖入 test.ts),不修者在回覆中寫明理由。**審查發現處理完畢,該 phase 才算結束、才可 push。**審查定案(影響後續 phase 的約束)一律追記到本檔「Codex 審查定案」章節。
  **遞補規則**:若 `/codex:review` 回報「無變更可審」或跑完零發現,改跑 **`/codex:adversarial-review`**,以其結果作為收尾依據。

## Phase 0 環境判定(2026-08-29 實測)

- **金鑰 Plan A 成立**:`.vlei/state.json` 之 `actors[alias].seed/verkey` 為 CESR qb64(code `A`/`D`,44 字元);解碼 = base64url("A"×1 + qb64[1:]) 去前 1 byte → 32B Ed25519 seed/公鑰。server/keys.ts 照此實作;v3 新增 `dye` 同法。
- **cedar-wasm 可用**:`@cedar-policy/cedar-wasm/nodejs` import 成功;policy.ts 純函式退路暫不需要,前端仍顯示 policies/*.cedar 原文。
- Status List Token 由 FAB LE 鑰簽署(閘道為 data/status/ 兩份清單的發布方);套件 @owf/token-status-list。
- blake3 已裝:sandbox 識別碼為 `E` 開頭。
- 常用指令:`make setup` / `make dev` / `make demo-reset` / `make test`。

## Codex 審查定案(2026-08-29;Phase 2.5/3 實作必須遵守)

- **Cedar 字串集合**:成員判斷用 `.contains()`,不得用 `in`。
- **Cedar 數值單位**:Cedar 不支援浮點、decimal 擴充無 `<=`——碳排一律以**整數 gCO₂e/kg 布**傳入政策(mandate 資料欄位維持 9.5 kgCO₂e/kg,後端 ×1000 轉 `carbon_total_g` / `carbon_max_g`)。make test 以 checkParsePolicySet 鎖住三條政策可解析。
- **稽核雜湊**:`payload_hash = sha256(event_type ‖ '\n' ‖ payload_json)`,`entry_hash = sha256(prev_hash ‖ payload_hash ‖ ts)`——event_type 必須在被簽章的序列化內;verify-chain.ts 照此公式驗證。
- **私鑰檔權限**:presign 以 `umask 077` 執行;`.vlei/` 700、`state.json` 600(make test 檢查);`data/vlei/*.json` 為公開材料,放寬 644。
- **稽核帶輪詢**:前端以最後收到的 seq 為游標(`/api/audit?after=<lastSeq>`)附加新事件,不得固定 after=0。
- **H2(Phase 2 總驗收)**:跨組織 presentation 內只能有一個排放數字;分項欄位 NEVER_DISCLOSABLE 由政策層與 presenter 層雙重拒絕。v3 對象為 pcf_yarn / pcf_knitting / pcf_dyeing。
- **F3/F4**:disclose 前驗被揭露憑證自身效期(CREDENTIAL_EXPIRED);presentation 由閘道簽章 receipt 綁定 presentation_hash + mandate_jti + request_nonce + aud + iat(RECEIPT_INVALID)。
