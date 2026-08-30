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

## Codex 審查定案(2026-08-30;Phase 2.5 v3.1 遷移;Phase 3a/3b 實作必須遵守)

- **簽發者角色釘住(消費端)**:凡消費外部憑證(聚合、P3、驗證)一律在 `verifyCompactSdJwt` 之後斷言 `verifyResult.kid === manifest[expectedRole].aid`——`tc_rcs`/`ccs_scope_cert`→`cb`、`pcf_upstream`→`yarn`、`pcf_dyeing`→`dye`;不符即拒(`VCT_ISSUER_UNAUTHORIZED` 或該憑證的失敗碼)。只按 `header.kid` 解析「任一」manifest 角色 = 型別/簽發者混淆漏洞(FAB/YARN 可自鑄 TC/SC 使偽造欄位流進 M2 六欄)。
- **憑證型別釘住**:`verifyScopeCert` 等「專驗某一種憑證」的函式,除簽發者角色外必須斷言 `payload.vct === <該 VCT>` 且 `payload.iss === verifyResult.kid`。因 CB 同時簽 `tc_rcs` 與 `ccs_scope_cert`,只驗角色會讓 `tc_rcs` 被誤當有效 SC。
- **狀態清單消費端 fail-closed(禁 fail-open)**:消費端查撤銷一律經 `server/creds/statusGuard.ts` 的 `safeReadOrRefreshStatusListToken`——清單檔缺失/簽章或 typ 不符/bits 解碼失敗 → 回 `null` → 呼叫端 fail-closed(`CREDENTIAL_REVOKED` / `SCOPE_CERT_INVALID`);成功解碼且驗章通過才續用,**陳舊時保留既有 bits、只換新 iat 續簽**(不得重建為全 0)。禁止在缺/壞時回傳全 0 清單(= 抹除撤銷狀態的 fail-open)。續簽只在 FAB 信任邊界內(FAB 為清單發布方);**Brand 端驗證(verifyPresentation / verify 路由 / verify-offline)維持純 `readStatusListToken`,不簽不寫檔**。
- **聚合消費端四輸入全驗**:`pcfAggregate.ensureInputs` 消費 `tc_rcs`(idx9)、`pcf_upstream`(idx0/1)、`pcf_dyeing`(idx4/5)、`ccs_scope_cert`(idx10)——四張皆驗簽 + 角色釘住 + 查撤銷位;`ccs_scope_ref` 除 `sc_no` 外必比 `hash === sha256(ccs_scope_cert.sdJwt)`(SC 以同 sc_no 重簽會遮蔽斷鏈)。
- **三+二理由碼 DENY 入鏈**:`TC_REF_MISMATCH`/`CCS_SUBCONTRACTOR_NOT_LISTED`/`SCOPE_CERT_INVALID` 與新增之 `VCT_ISSUER_UNAUTHORIZED`/`CREDENTIAL_REVOKED`,凡在聚合路徑(含 `routes/aggregate.ts` catch 的 `TcRefMissingError`)觸發 DENY,一律經 `server/audit.ts` `recordDecision`(decisions 與 audit_chain 同交易);不得落到未入鏈的 500。
- **守門 grep 排除生成密碼學材料**:完成條件的禁詞 grep 掃 `data/` 時只掃 `data/seed.json`,**排除 `data/vlei`(manifest 隨機 CESR AID/SAID 之大小寫不敏感子字串會誤中鋼鐵爐別縮寫)與 `data/status`(ISO 時間戳數字子字串誤中禁詞數列)**;權威守門 = `scripts/test.ts` 的 case-sensitive `STEEL_RE`(掃 authored 檔含 `data/seed.json`,不掃生成材料,並以 NEG 排除文件自我引用),`make test` 據此不 flaky。完成條件外部 grep 檔案集:`server web scripts policies CLAUDE.md data/seed.json`(即 `data` 只掃 seed)。

## Codex 審查定案(2026-08-30;Phase 3a 幕 5 付款閘道;兩輪 Codex adversarial;Phase 3b/4 必須遵守)

- **付款須源自已驗發票,不得讀 seed**:agent/run 的 `checkInvoiceOk` 回傳已驗發票 facts(`amount/currency/payer_lei/payee_lei`)寫入 **Dossier JWS payload(`dossier.invoice`,fab-workload 簽保護)**;`human-sign` 的 mock 電匯指令一律由 `dossier.invoice` 建構(`rail` 非發票欄位,讀 seed),**不得**直接讀 `seed.transaction.dyeing_service`——否則核准金額與付款金額可分歧(合法低額發票→付出 seed 高額)。
- **限額/幣別一律來自已簽 M1 payload,不讀 DB 未簽欄位**:`max_amount`/`allowed_counterparties`/`policy_thresholds`(含 `min_sources`)/`currency` 由 `mandate.ts` 簽進 M1 JWT(僅 `id==='M1'` 注入,M2 恆 undefined 故 token 不變);agent/run 的 `extractM1Limits()` 只從 `verifyMandate` 回傳的**已驗 payload** 讀,不讀 `mandates.extra_json`。`checkInvoiceOk` 另斷言 `payer_lei===manifest.fab.lei`(`PAYER_NOT_ALLOWED`)、`currency===M1.currency`(`CURRENCY_MISMATCH`)。並斷言 `mandatePayload.jti===mandateRow.jti`(不符→`MANDATE_SIG_INVALID`)。
- **聚合新鮮度(與幕 6 reissue 相關)**:agent/run 消費 `pcf_aggregate` 前以 `checkAggregateFreshness()` 斷言其 `precursor_refs[tc_rcs|pcf_upstream|pcf_dyeing].hash === sha256(當前入庫憑證 sd_jwt)`,不符→`AGGREGATE_STALE`。**幕 6 reissue pcf_dyeing 後必須重聚合 pcf_aggregate**,否則 agent/run 會(正確地)以 AGGREGATE_STALE 拒絕。
- **風險按 distinct provider 計數**:`checkWalletRisk` 以 `Map<provider,maxScore>` 聚合後才計 confirming,並以已驗 invoice 之 `payee_wallet` 查 `risk_signals.account_ref`(非 case_id)、套 M1 簽章之 `min_sources`。同 provider 多列不得灌成多來源。
- **放行原子化 + 綁定 + 完整性**:`human-sign` 以 CAS(`UPDATE ... WHERE id=? AND status='PENDING_HUMAN'`)於單一 immediate transaction 轉移狀態,只有勝者記 `RELEASE`;驗 Dossier JWS 後斷言 `payload.dossier_id/case_id/mandate_jti===row.*`(跨列複製 JWS→拒);`checksAllPassed` 要求恰為五個預期 check id、無缺無重複、皆 ok;release payload 含 `payment_instruction_hash=sha256(canonical(instruction))` 由 fab_cfo 簽;對已 RELEASED dossier 再簽→409 且 `recordDecision(REPLAY_DETECTED)` 入鏈。
- **治理缺口(記入 README「什麼是真的/模擬的」)**:全站 localhost demo **無網路認證層**——`/api/human-sign`、`/api/mandates`(M1/M2 人簽)、`/api/agent/run` 等皆無 auth 閘(唯一 demo-mode 守門在 `/api/demo/sign-disclose-request` 的 workload 簽章 oracle)。人核可 = UI 確認對話框 + 獨立 `fab_cfo` ECR 鑰簽章;偽造高額 Dossier 需同時持 `fab-workload`(建卡)與 `fab_cfo`(放行)兩把伺服端私鑰(即「一方一鑰」信任邊界)。此為既有單人 demo 設計,非漏洞。
- **幕 6 待辦(Phase 3b 必補)**:`human-sign` 目前只重驗凍結 Dossier 自洽,**不對現況重跑撤銷檢查**;PENDING_HUMAN → 放行之間若底層 `pcf_dyeing` 被撤仍會放行。幕 6 須在 human-sign 端補撤銷重驗(或標 `DOSSIER_STATUS.DEPENDS_REVOKED`,schema 已預留),使已撤依據無法放行。
- **既有測試容量上限(LOW,非阻擋)**:`GET /api/audit?after=0` 有 `LIMIT 200`;連跑 3+ 次 `make test` 未 `demo-reset` 時累積稽核列破 200,以 after=0 計數差的測項會假失敗。DoD 契約(2 連跑 / demo-reset 後全綠)成立;若後續要根治,測試改以「操作前 seq 當游標」或測前自帶 reset。

## Codex 審查定案(2026-08-30;Phase 3b 幕 6 稽核與撤銷;兩輪 Codex adversarial 共 15 發現;Phase 4 必須遵守)

- **撤銷不重啟即生效**:撤銷一律翻 `data/status/*.jwt` 的 bit 並以 FAB LE 鑰重簽(`server/statuslist.ts` `revokeStatusIndex`);消費端每次現讀檔(經 `statusGuard.safeReadOrRefreshStatusListToken` fail-closed),無記憶體快取。裸 JSON bit array 不得出現。
- **Dossier 撤銷重驗查凍結依據,非現況 case rows**:`human-sign`/`/api/dossiers` 的 `checkDossierInputsCurrent` 以 Dossier JWS **凍結的 `credential_hashes`** 查 `credential_history`(append-only 表,`hash` PK;`openDb()` 每次 `backfillCredentialHistory` 補既有列)取回「建卡當下那一版」sd_jwt,**且驗 `sha256(sd_jwt)===凍結 hash`(防換版)** 後才重驗其現況撤銷位;並驗 aggregate 之 `precursor_refs`(tc_rcs/pcf_upstream/pcf_dyeing)凍結版本+撤銷位。任一已撤 → `DEPENDS_REVOKED`(即使案件已 reissue supersede)。禁止改看現況 case rows(reissue 後會讓舊 Dossier 假性轉綠放行)。
- **狀態清單發布端 fail-closed + 綁清單**:`revokeStatusIndex` 讀既有清單須驗 FAB 簽章、`header.typ==='statuslist+jwt'`、**`payload.sub===statusListUri(name)`**(防 credentials/mandates token 因共用簽章鑰而互換抹除撤銷);缺/壞/簽驗不過 → 拋錯不寫檔(不得從全 0 重建)。read-modify-write 經 `withStatusListLock`(owner-token = pid+uuid,釋放前重讀確認 owner 未被接管才刪)序列化,防並發覆蓋丟失撤銷位。
- **重簽必重聚合(supersede)**:幕 6 reissue `pcf_dyeing`(idx8/新 period)後**必**重聚合 `pcf_aggregate`(翻舊 idx2 + 新 idx11),否則 agent/run 以 `AGGREGATE_STALE` 拒(3a 定案)。
- **撤銷/稽核留痕**:所有 `revokeStatusIndex` 呼叫端(CLI `revoke.ts`、reissue supersede、`/api/audit/revoke`)一律 `appendAudit('admin:revoke', …)` 入鏈;`appendAudit` 本體(SELECT prev + INSERT)包在 `db.transaction().immediate()`,防並發分叉鏈(巢狀 immediate 於 better-sqlite3 不拋錯)。`recordCredentialHistory` 與 credential upsert 共用同一 immediate transaction(防半寫入使 Dossier 永久解不回)。
- **tamper 備份可逆**:`tamper.ts` row-level JSON 側車備份以 `wx` 原子建立(已存在即拒、防覆寫破壞可逆性);先確認目標列存在才備份;無效 seq 報錯不動備份。
- **殘留 LOW(單人 demo 邊角,需本機檔案寫入權,不阻擋)**:①`human-sign` 晚檢查讀檔到同步 CAS 之間,另一行程 revoke 的極短同步窗口理論競態——但只是 revoke/release 平手,已提交之撤銷必被兩道檢查擋下(PoC 證);②`withStatusListLock` stale(>5s)回收時互斥可能短暫鬆動(owner-token 已確保不誤刪他人鎖)。二者屬 localhost 單一操作者 demo 可接受範圍。

## Codex 審查定案(2026-08-30;Phase 4 交付;末 phase 無後續約束,備查)

- **deep-link 契約**:`web/src/App.tsx` `parseDeepLink`/`resolveNavState` 為純函式,只讀寫 URL 的 `tab`(yarn/gateway/brand/audit)與 `case`(A/B/C/Cp);**不得**把任何 claims、分項排放數字或 M2 六欄放進 URL(H2 防線)。掛載初始化與 `popstate`(上一頁/下一頁)共用 `resolveNavState` fallback,`navEpoch` 於 popstate 遞增以 `key` 強制子分頁重掛使案件選單同步網址。
- **B-9 成本為實測**:`scripts/bench.ts`(`make bench`)實跑 `issuePcfUpstream`/`verifyCompactSdJwt`/`POST /api/verify` 量測,前後自動 seed 歸位(reset 置於外層 `finally`,任何拋錯路徑皆還原);README 數字附量測環境與方法,不得杜撰。
- **理由碼一覽權威**:README B-10 表須與 `shared/codes.ts` 完全一致(現 40 碼),**不含 CONSISTENCY_FAILED**(一致性檢查只做投影片);新增/改碼時同步更新。
- **交付誠信**:README C-12 誠實分「真(密碼學/vLEI/Status List/Cedar/稽核鏈皆真跑)」與「模擬(USD 電匯 mock JSON、合成帳戶、風險分數、推估係數、鞋廠/幕7/M4/一致性檢查只投影片)」;不宣稱 W3C VC 2.0 或 TE 認證;out-of-scope 一律標「未實作」。
