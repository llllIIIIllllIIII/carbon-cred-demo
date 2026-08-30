# Phase 3b brief — 幕 6:稽核與撤銷(換燃料要重報)

> 規格:CLAUDE.md(v3.1)> spec v3 §7 幕 6 > 遷移清單 §10 > 藍圖 v3 幕 6 節。前置:Phase 2.5 + 3a 完成(agent/run、Dossier、human-sign、verifyScopeCert 已存在)。
>
> **規格疑義(已裁定,記入 phase 報告)**:runbook/藍圖 DoD 要求「重簽後 verify-offline 對新 presentation 通過、對舊的失敗」,而 verifyPresentation 的撤銷檢查走「被呈現憑證自身的 status idx」——新舊 pcf_aggregate 若共用 idx 2 則無法同時滿足。裁定:**重聚合(reissue 路徑)時 FAB 撤銷舊 aggregate(翻 idx 2)並以新 slot `pcf_aggregate-A-reissue: 11` 簽發新 aggregate**(supersede 語意)。idx 表依 CLAUDE.md 本就住在 seed:於 `docs/seed.v3.json` 與 `data/seed.json` 的 `status_list_idx.credentials` **各加一列** `"pcf_aggregate-A-reissue": 11`(兩檔保持一致;不動任何係數/expected 數值)。

## 0. 現況

已存在:`server/statuslist.ts`(bit 翻轉與重簽能力視實作)、`scripts/verify-chain.ts`、`server/creds/tamper.ts`、`make demo-reset`、Audit.tsx(稽核帶)、3a 的 Dossier(含輸入憑證 hash)。缺:`make revoke` / `make tamper` / `make untamper` 目標、`scripts/revoke.ts`、reissue 流程、DEPENDS_REVOKED 標記、Audit 分頁 bit 條與撤銷開關 UI。

## 1. 範圍(要動的檔)

1. **`scripts/revoke.ts`(新)+ Makefile 目標**:`make revoke LIST=credentials|mandates IDX=<n>`——翻對應 bit 並以 FAB LE 鑰**重簽**該清單 JWT(經 server/keys.ts;寫 `data/status/credentials.jwt` / `mandates.jwt`);**不重啟服務即生效**(驗證方每次現抓 JWT——確認現行讀取路徑無快取,有就移除)。裸 JSON bit array 不得出現。
2. **撤銷語意(server)**:重跑 `agent/run?case=A` 時 `pcf_dyeing-A`(idx 4)已撤 → 檢查①失敗 → `CREDENTIAL_REVOKED` DENY 入鏈;既有 RELEASED Dossier 依其輸入憑證 hash 對應之憑證撤銷狀態,查詢時標 **`DEPENDS_REVOKED`**(shared/codes.ts 補常數;不竄改 Dossier 原 JWS,狀態為衍生欄位)。
   - **幕 6 待辦(Phase 3a 定案指定,本 phase 必補)**:`/api/human-sign` 目前只重驗凍結 Dossier 自洽,不對現況重跑撤銷檢查——PENDING_HUMAN → 放行之間若底層 `pcf_dyeing` 被撤仍會放行。本 phase 須在 human-sign 端補「放行前重驗 Dossier 三張輸入憑證(pcf_dyeing/pcf_aggregate + 其 precursor)之現況撤銷狀態」,任一已撤 → 拒放行(`DEPENDS_REVOKED`,入鏈),使已撤依據無法放行。回歸鎖:對 A 建 PENDING_HUMAN Dossier → 撤 idx 4 → human-sign 被拒 `DEPENDS_REVOKED`;重簽重聚合後新 Dossier 可放行。
3. **重簽 + 重聚合**:`POST /api/issue/dyeing?case=A&reissue=1` → id `pcf_dyeing-A-reissue`、idx 8、新 `pcf_period`(2026-06,自 seed 讀,不寫死);`POST /api/aggregate?case=A`(reissue 路徑)→ 消費 reissue 後的 dyeing、**翻舊 aggregate idx 2 + 以 idx 11 簽新 aggregate**(見上方裁定);重跑 `agent/run?case=A` → 五項全綠。
4. **verify-offline**:對重聚合後新產出的 presentation 通過;對撤銷前留存的舊 presentation 失敗(`CREDENTIAL_REVOKED`)。scripts/verify-offline.ts 本身不應需要改(檢查邏輯已含 status);若需改,說明理由。
5. **輔線**:`make revoke LIST=mandates IDX=0`(撤 M1)→ `agent/run` 回 `MANDATE_REVOKED`。
6. **tamper**:`make tamper N=42`(或 `scripts/tamper.sh`,內部可呼叫既有 server/creds/tamper.ts 邏輯:一行 sqlite UPDATE 改歷史第 N 筆,先備份 db)→ `make verify-chain` 自該筆起 FAIL;`make untamper` 還原備份 → 重驗全綠。
7. **`web/src/tabs/Audit.tsx`**:Status List **bit 條**(credentials …0 0 0 0 [1] 0…,idx 4 高亮標 pcf_dyeing-A;mandates 同理)+ **撤銷開關**(憑證/mandate 各一,呼叫後端 revoke API 或指示終端指令——若走 API,新 route 同樣經 audit.ts 入鏈)+ **Dossier 列表**(dossier-A · RELEASED → 撤銷後黃 badge「依據已撤銷,需重驗」→ 重簽重聚合後重跑 → 綠)。文案繁中。
8. **`make demo-reset`**:一鍵還原全部幕 6 狀態(bits 歸零重簽、DB 重建、Dossier 清空、reissue 憑證移除),還原後 `make test` 全綠。
9. **`scripts/test.ts`**:§3 回歸鎖。

## 2. DoD(逐條)

1. `make revoke LIST=credentials IDX=4` 翻 bit 並重簽 credentials.jwt,不重啟即生效。
2. 重跑案 A → `CREDENTIAL_REVOKED`(入鏈)。
3. 既有 Dossier 標 `DEPENDS_REVOKED`(UI 黃 badge)。
4. `POST /api/issue/dyeing?case=A&reissue=1`(idx 8、新 pcf_period)→ 重聚合 → 重跑 A 綠。
5. verify-offline 對新 presentation 通過、對舊的失敗。
6. 撤 M1 → `MANDATE_REVOKED`。
7. `make tamper` → verify-chain FAIL;`make untamper` 還原後全綠。
8. Audit 分頁有 bit 條與撤銷開關、Dossier 黃 badge。
9. `make demo-reset` 一鍵還原;之後 `make test` 全綠;守門 grep 0;git status 乾淨。

## 3. 要新增的回歸測試(scripts/test.ts)

1. 撤 idx 4 → agent/run A 回 `CREDENTIAL_REVOKED` 且 deny 入鏈;Dossier 查詢帶 `DEPENDS_REVOKED`。
2. reissue(idx 8、新 pcf_period)→ 重聚合(舊 idx 2 翻 1、新 aggregate idx 11)→ agent/run A 全綠;新 presentation verify-offline 通過、舊 presentation 失敗(`CREDENTIAL_REVOKED`)。
3. 撤 mandates idx 0 → `MANDATE_REVOKED`;還原後恢復。
4. tamper 第 N 筆 → verify-chain 自該筆 FAIL;untamper → 全綠。
5. demo-reset 後:bits 全 0、Dossier 清空、`make test` 既有全部檢查仍綠(等冪性)。
6. Status List Token 重簽後仍為 compact JWS、header.typ=statuslist+jwt、以 FAB 公鑰驗章通過(既有檢查保留)。

## 4. 禁止事項

- 撤銷一律走 Token Status List(JWT 重簽);不得出現裸 JSON bit array;identity_vlei 不掛應用層清單(vLEI 走 sandbox TEL,口白層次,不寫程式)。
- 不動 audit 雜湊公式、verifyPresentation 檢查順序;verify-offline 只讀 token/manifest/data/vlei/data/status。
- Dossier 原 JWS 不可竄改;DEPENDS_REVOKED 為查詢時衍生狀態。
- seed 僅允許在 `status_list_idx.credentials` 加 `pcf_aggregate-A-reissue: 11` 一列(docs 與 data 同步);其他任何數值不得改。
- 不加依賴、不碰 vendor/;取鑰只經 server/keys.ts;所有 DENY/撤銷事件經 server/audit.ts 同交易入鏈。
