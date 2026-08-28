# carbon-cred-demo — 專案硬規則(每個 phase 都遵守)

跨組織碳足跡憑證選擇性揭露 demo(台灣扣件廠情境)。文件優先序:
**docs/2026-08-26-專案架構決策.md > docs/demo情境設定與合成資料規格-v2.md > docs/製造貿易demo實作藍圖.html**
(藍圖之檔案路徑僅為示意,目錄一律以架構決策 §2 為準。)

## 範圍鐵則(優先於三份文件中任何相反描述)

- 憑證格式:@sd-jwt/core + @sd-jwt/sd-jwt-vc——**SD-JWT core = RFC 9901,SD-JWT VC = IETF Internet-Draft profile**。不得宣稱符合 W3C VC 2.0;UNTP DPP/PACT 僅作 claims 欄位對照。
- 應用層撤銷 = **Token Status List(draft-ietf-oauth-status-list-21)**:Status List Token 為 compact signed JWT,header.typ="statuslist+jwt",payload 含 sub、iat(建議含 exp、ttl)與 status_list = { bits: 1, lst: "<base64url(zlib 壓縮位元陣列)>" };credential 與 mandate 一律以 **status.status_list = { idx, uri }** 引用(移除任何自訂 status_list_ref);正式檔案為 **data/status/mandates.jwt 與 data/status/credentials.jwt**,GET /status/* 必須回 compact signed JWT、Content-Type: application/statuslist+jwt;**驗證方必先驗 compact JWS 簽章,再解碼 payload.status_list.bits/lst**。vLEI 撤銷由 sandbox TEL 驗證。裸 JSON bit array 僅可作為明確標示的 fallback,不得出現於正式流程。
- 簽章金鑰:Thép Việt、鴻鋼的 SD-JWT 分別以其 sandbox LE AID 金鑰簽署;M1 與幕 5 人工放行用鴻鋼財務主管 ECR 鑰;M2 用 Bruck 永續長 ECR 鑰;以上皆經 server/keys.ts 自 .vlei/state.json 匯出。
- 另建兩把 app 產生的 workload 鑰:hunggang-workload、bruck-workload。M1/M2 必須含 delegate_kid 綁定對應 workload 公鑰;跨組織 disclose request 必須由對應 workload 鑰簽章,閘道先驗簽再進 Cedar。
- 防重放:mandate 含 jti 與 mandate_nonce;每次 disclose request 帶新 request_nonce;(mandate_id, request_nonce) 加 UNIQUE;重複 → REPLAY_DETECTED;query_cap 扣次與 presentation、audit 寫入同一筆交易。
- seed 只有 A/B/C/Cp 四組;E 不是 fixture,是「撤銷後重跑 A」的狀態轉換。
- Cedar 不得直接讀取 mandate 狀態:後端先驗 mandate 簽章、iss/aud/exp/jti、delegate_kid 對 request 簽章、Token Status List、request_nonce,再以 context.mandate_status_ok / delegate_key_ok / replay_ok 三個可信布林傳入;政策僅消費布林與 mandate 之資料欄位(allowed_claims 等)。
- identity_vlei(法人/ECR)不掛應用層 Token Status List;其撤銷狀態一律以 vLEI TEL 參照、由 sandbox verify(child_process)查驗。
- USDC 僅作 mock 付款指令中的合成幣別;不得建立錢包、RPC 連線、testnet 位址或任何鏈上交易;收款帳戶識別碼為合成字串。
- out of scope(除非 Phase 0–3 核心全數通過):ZK/RISC Zero、RBA 程式、真實 testnet USDC、did:web、vckit、walt.id、OPA、APL。

## 硬規則

- docs/ 三份為唯一規格來源;禁止讀取 workspace 其他同名或舊版文件。
- 密碼學不可造假:簽章與驗章一律真實執行(@sd-jwt/*、Ed25519、sandbox verify);任何 mock 驗證視為 bug。
- 一方一鑰:取鑰只經 server/keys.ts;route 不得直接讀鑰檔或 .vlei/state.json。
- Bruck 端驗證(server/routes/verify 與 scripts/verify-offline.ts)只讀 token、manifest 公鑰、data/vlei/、data/status/;不得呼叫閘道 API 或讀他方 DB 資料。
- 所有 PERMIT/DENY/RELEASE/REPLAY_DETECTED 經 server/audit.ts 唯一入口,decisions 與 audit_chain 同一筆 transaction;DENY 與重放也入鏈。
- vendor/ 唯讀;.vlei/ 與 data/keys/ 永不進版控。
- 介面文案繁體中文;理由碼用 shared/codes.ts 的英文常數。
- 每幕完成即執行 docs 藍圖對應的 DoD 檢查(藍圖路徑僅示意,目錄以架構 §2 為準)。

## Phase 0 環境判定(2026-08-29 實測)

- **金鑰 Plan A 成立**:`.vlei/state.json` 之 `actors[alias].seed/verkey` 為 CESR qb64(code `A`/`D`,44 字元);解碼 = base64url("A"×1 + qb64[1:]) 去前 1 byte → 32B Ed25519 seed/公鑰。server/keys.ts 照此實作。
- **cedar-wasm 可用**:`@cedar-policy/cedar-wasm/nodejs` import 成功(isAuthorized 存在);policy.ts 純函式退路暫不需要,前端仍顯示 policies/*.cedar 原文。
- Status List Token 由鴻鋼 LE 鑰簽署(閘道為 data/status/ 兩份清單的發布方);首選套件 @owf/token-status-list。
- blake3 已裝:sandbox 識別碼為 `E` 開頭(與 production 相同)。
- 常用指令:`make setup` / `make dev` / `make demo-reset` / `make test`。

## Codex 審查定案(2026-08-29;Phase 2/3 實作必須遵守)

- **Cedar 字串集合**:成員判斷用 `.contains()`,不得用 `in`(`in` 僅限 entity 階層,對字串會 error 而非 deny)。
- **Cedar 數值單位**:Cedar 不支援浮點、decimal 擴充無 `<=`——碳排一律以**整數 kgCO2e/t** 傳入政策(mandate 資料欄位維持 2.00 tCO2e/t,後端 ×1000 轉 `carbon_total_kg` / `carbon_max_kg`)。make test 以 checkParsePolicySet 鎖住三條政策可解析。
- **稽核雜湊**:`payload_hash = sha256(event_type ‖ '\n' ‖ payload_json)`,`entry_hash = sha256(prev_hash ‖ payload_hash ‖ ts)`——event_type 必須在被簽章的序列化內;Phase 3 的 verify-chain.ts 照此公式驗證。
- **私鑰檔權限**:presign 以 `umask 077` 執行;`.vlei/` 700、`state.json` 600(make test 檢查);`data/vlei/*.json` 為公開材料,放寬 644。
- **稽核帶輪詢**:前端以最後收到的 seq 為游標(`/api/audit?after=<lastSeq>`)附加新事件,不得固定 after=0。
