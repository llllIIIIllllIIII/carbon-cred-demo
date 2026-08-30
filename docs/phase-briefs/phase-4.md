# Phase 4 brief — 錄影支援與交付素材

> 規格:CLAUDE.md > docs/製造貿易demo實作藍圖-v3紡織版.html「素材交付」節(B-9 成本、B-10 理由碼、A-2 逐幕截圖、C-12 真/模擬)> spec v3 §7(六幕)、§12(治理缺口)。前置:Phase 2.5/3a/3b 已完成並 commit(HEAD fafde56,make test 478/0)。
> 性質:交付/文件為主 + 一個小功能(deep-link)。所有數值(B-9 成本)必須**實測**,不得杜撰;理由碼/TC 鍵名對照必須與程式一致。

## 0. 現況

無 README;無 Playwright。四分頁 + 六幕已可跑(make dev)。理由碼定義在 shared/codes.ts(38 個,**無 CONSISTENCY_FAILED**——一致性檢查只做投影片)。Makefile 目標:setup/dev/demo-reset/seed/presign/test/revoke/tamper/untamper/verify-chain。

## 1. 範圍(要動/新增的檔)

1. **deep-link(小功能)**:`web/src/App.tsx`(或分頁路由處)支援以 URL query/hash 深連到指定分頁與案件,例 `?tab=gateway&case=B`、`?tab=audit`。四分頁(yarn/gateway/brand/audit,以現有分頁 key 為準)+ 案件(A/B/C/Cp)。載入時解析、切換時更新 URL(pushState 或 hashchange 皆可)。不得破壞現有分頁切換。回歸:vite build 過;可加一個純函式(parseDeepLink)單元測試到 scripts/test.ts。
2. **`README.md`(新,繁中為主)**,至少含下列節:
   - **安裝與執行**:前置(node 版本、vendor/ 說明)、`make setup`(乾淨環境一鍵:presign 7 呈現包 + seed)、`make dev`、`make demo-reset`、`make test`。demo-reset SOP(何時跑、跑完回到什麼狀態)。
   - **六幕劇本**:幕 1–6 各一段(供應鏈位置、做什麼、看什麼、理由碼);對照 spec §7 與藍圖 v3.1。標明幕 5=布廠付染整廠 mock USD 3,420、A/B 差異只在染整燃料、幕 6 撤 pcf_dyeing 主線。
   - **deep-link 一覽**:每幕對應的 `?tab=…&case=…` 連結(供錄影快速跳轉)。
   - **A-2 逐幕截圖清單**:每幕要截的畫面 + 如何 30 秒內重現(deep-link + 按哪顆鈕 → 看什麼變色/理由碼)。因無 Playwright,寫**手動操作指引**(若你能裝無頭瀏覽器截圖則附上,但不得為此加清單外重依賴)。
   - **治理缺口**:整合 CLAUDE.md 三節「Codex 審查定案」與 spec §12——localhost 無網路認證層(人核可=UI 對話框+fab_cfo ECR)、vLEI 撤銷走 sandbox TEL(口白層)、身分憑證不掛應用層 Status List、單人 demo 併發邊角(P1-4 同步窗、鎖 stale)、CB 憑證真簽狀態。誠實列出「哪些是 demo 邊界」。
   - **TC 鍵名對照**:Textile Exchange TC camelCase 鍵名(tcNo/tcStandard/tcProductStandardLabelGrade/tcProductCertifiedWeight/tcProductRawMaterialPercentage/inputTcNo…)對照我方欄位與用途;註明「僅作 claims 欄位對照,不宣稱 TE 認證」。
   - **理由碼一覽(B-10)**:列 shared/codes.ts 全部理由碼 + 一句中文說明 + 出現幕次;**明確不含 CONSISTENCY_FAILED**。必須與 shared/codes.ts 一致(建議由程式或人工核對,漏一個算 bug)。
   - **C-12 什麼是真的、什麼是模擬的**:真——@sd-jwt 簽/驗、Ed25519、vLEI sandbox 鏈驗證、Token Status List JWT 撤銷、Cedar 授權、sha256 稽核鏈、cedar-wasm。模擬——USD 電匯(mock JSON,無鏈上/錢包/RPC)、收款帳戶識別碼(合成字串)、風險分數(seed 合成)、部分係數為推估(標 S3/推估)、鞋廠/幕7/M4/一致性檢查(只投影片)。
   - **B-9 成本側數字(實測)**:presign 呈現包張數(=7)、單張憑證簽發耗時(ms)、單次 presentation 驗證耗時(ms)、跑完一輪 demo/測試秒數。**必須實測填入**(見 §2)。
   - **架構/信任邊界一頁**:5 LE(yarn/fab/dye/brand/cb)+2 ECR(fab_cfo/brand_cso)+2 workload;誰簽什麼;四分頁六幕。
3. 允許小改 `Makefile` 加一個 `make bench`(或 README 記錄量測指令)產生 B-9 數字,若有助重現。

## 2. B-9 成本數字如何實測(不得杜撰)

- presign 張數:`ls data/vlei/*.presentation.json | wc -l`(應為 7)。
- 簽發耗時:對某 issue 路徑(如 /api/issue/upstream 或 aggregate)包 `performance.now()` 前後測,或寫一次性 bench 腳本跑 N 次取平均(ms)。
- 驗證耗時:對 verify-offline 或 /api/verify 單次 presentation 驗證測時(ms)。
- 一輪秒數:`time make test` 的實際秒數,或一次完整六幕 API 序列的秒數。
- 於 README 註明量測環境(機器/node 版本/日期)與方法,數字為實測區間或平均。

## 3. DoD(逐條)

1. deep-link:`?tab=…&case=…` 能深連到對應分頁/案件;vite build 過;parseDeepLink 有單元測試。
2. README 含全部 §1.2 列出的節,且:理由碼一覽與 shared/codes.ts 完全一致(無漏、無 CONSISTENCY_FAILED)、B-9 為實測數字(非佔位)、C-12 真/模擬分列正確、六幕劇本與 spec §7 一致、治理缺口誠實完整。
3. demo-reset SOP 在 README;`make demo-reset` 後 `make test` 全綠。
4. `make test` 全綠(含新 parseDeepLink 測試);守門 grep(`server web scripts policies CLAUDE.md data/seed.json`)0 行。
5. git status 乾淨(.vlei/、data/keys/、db/*.sqlite*、db/.tamper-backup.json 未被追蹤)。
6. 每幕可在 30 秒內經 deep-link + 少數點擊重現(A-2 清單所述畫面實際可達)。

## 4. 禁止事項

- B-9/係數/任何數值不得杜撰或寫死;成本數字必須實測並註明方法。
- 不加清單外重依賴(尤其為截圖裝 Playwright/瀏覽器——沒有就寫手動指引);不碰 vendor/;不建錢包/RPC/鏈上。
- README 不得宣稱 W3C VC 2.0 或 TE 認證;不得把「模擬」寫成「真的」(C-12 要誠實)。
- 理由碼一覽不得自行新增/改名 codes.ts 沒有的碼;不得列 CONSISTENCY_FAILED。
- 不動已驗過的 server 授權/撤銷邏輯(Phase 2.5/3a/3b);deep-link 只碰前端路由。
- H2/M2 六欄不得因前端改動而洩漏。
