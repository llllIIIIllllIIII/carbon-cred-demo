# Goal runbook — v3.1 全部完成(Fable 指揮 / Sonnet 實作 / Opus 驗證 / Codex 挑戰)

> 對象:Claude Code 主 session(orchestrator)。goal 指令本文(≤4000 字)只寫原則;**本檔是完整規則**,開工第一件事整份讀完。
> 規格優先序:`docs/2026-08-26-專案架構決策.md`(2026-08-30-a)> `docs/demo情境設定與合成資料規格-v3.md`(v3.1;§0.4 制度修正、§0.5 交接檔三對照)> `docs/2026-08-29-v2→v3遷移清單.md`(程式面逐檔對照;其 §9 舊 prompt 作廢,以 goal 為準)> `docs/製造貿易demo實作藍圖.html`(v2 技術細節/DoD)與 `docs/製造貿易demo實作藍圖-v3紡織版.html`(v3.1 劇本、素材交付節)。seed:`docs/seed.v3.json`。
> 時間:動工前 `date`;內部截止 8/30 21:00 錄影上傳,官方 8/30 23:59。

---

## 1. 角色與模型

| 角色 | 呼叫方式 | 做什麼 | 不做什麼 |
|---|---|---|---|
| 總指揮(你,Fable) | 主 session | 拆解、寫 brief、派工、審閱、決策、跑 Codex、commit、回報 | 不親自寫功能碼(例外:子代理兩輪修不好、或 Codex 發現需架構判斷) |
| 實作 | `Agent(subagent_type: "general-purpose", model: "sonnet")` | 依 brief 改碼、加回歸測試、跑 make test、回摘要 | 不改規格、不動 vendor/、不加清單外依賴 |
| 驗證 | `Agent(subagent_type: "general-purpose", model: "opus")` | 獨立重跑、讀 diff、逐條 DoD、對抗性 PoC、分級發現 | 不修碼、不信任實作者自述 |
| Codex 挑戰 | 你執行 `/codex:review`;無變更可審或零發現 → `/codex:adversarial-review` | 挑戰已驗證功能 | plugin 不可用 → 停下問使用者,不得以其他方式代替 |

並行規則:多個 Sonnet 只在檔案集合互不重疊時並行(例:server/ 與 web/);否則依序。子代理回覆只回摘要(改動檔案、指令與結果、剩餘風險),不貼整檔。

---

## 2. 前提(Phase 2.5 之前的第一步)

1. 用遷移清單 §8.1 的 CLAUDE.md v3 全文覆蓋 repo 的 `CLAUDE.md`(現為 v2,已過時);`git rm docs/demo情境設定與合成資料規格-v2.md`;`git add` docs 內 v3 文件與本檔;commit「docs: v3.1 規格、runbook 與 CLAUDE.md v3」。
2. `git checkout -b v3-textile`;全程在此 branch;main 不動。
3. 已拍板不得更動:5 LE(yarn/fab/dye/brand/cb)+ 2 ECR + 2 workload、四分頁、六幕;M2 只給 `pcf_total`(H2),`pcf_yarn/pcf_knitting/pcf_dyeing` NEVER_DISCLOSABLE,`brand_allocation_share` 只留 hash;幕 5 = 布廠付染整廠(mock USD 3,420),A/B 差異只來自 `pcf_dyeing.heat_source/renewable_share`;幕 6 撤 `pcf_dyeing` 主線;v3.1:`tc_rcs`、`ccs_scope_cert` 由 CB 鑰簽,`pcf_upstream.tc_ref`、`pcf_dyeing/pcf_aggregate.ccs_scope_ref`,P3 `subcontractor_listed`,理由碼 `TC_REF_MISMATCH / CCS_SUBCONTRACTOR_NOT_LISTED / SCOPE_CERT_INVALID`;`hs6` 已移除;鞋廠、幕 7、M4、一致性檢查只做投影片;所有 pcf_* 由係數表計算。

---

## 3. Phase 與 DoD

### Phase 2.5 遷移(遷移清單 Step 0–8 + v3.1)
- Step 0 alias 改名預設執行,timebox 30 分;超時 `git checkout` 回退,改採不改名 + README 對照表。
- DoD:`make setup` 乾淨環境一鍵成功;`make test` 全綠且含九組新檢查——manifest 7 角色與 dye verify;computeDyeing 交叉驗證;三段聚合與 precursor_refs 三筆;tc_rcs 驗章與 TC_REF_MISMATCH 兩條失敗路徑;ccs_scope_cert 驗章與 CCS_SUBCONTRACTOR_NOT_LISTED / SCOPE_CERT_INVALID;H2 三段不可揭露且 brand_allocation_share 不出現於明文;幕 4 plant_total_output → POLICY_P2_CONFIDENTIAL;Cedar 9500/7925/10899;一致性守門 grep;`git grep -iE "鴻鋼|Thép Việt|Bruck|台驗|扣件|線材|CBAM|海關|EAF|BF-BOF|USDC|6006" -- server web scripts data policies CLAUDE.md` 為 0;`make dev` 走幕 1–4:無鋼鐵字樣、幕 1 兩張卡(TC 卡 + 碳憑證卡)、Tab 2 有 SC 卡。

### Phase 3a 幕 5(spec §5.1、§6 P3、§7;遷移清單 §10)
- DoD:`POST /api/agent/run?case=A|B|C|Cp` 走 P3 五要件(DYE 身分;`subcontractor_listed`;`pcf_total ≤ 9500`;發票;帳戶風險雙來源),每項結果與理由碼經 `server/audit.ts` 同交易入鏈;Dossier = fab-workload 簽 JWS(build_hash、五項結果、三張輸入憑證 hash);`POST /api/human-sign` 以財務主管 ECR 鑰簽放行,產 mock USD 電匯指令(payer fab、payee dye、3,420)→ RELEASED;案 B `CARBON_OVER_THRESHOLD` 且 UI 不渲染放行鍵;案 C `MULTI_SOURCE_CONFIRMED`、Cp `SINGLE_SOURCE_ONLY`;`subcontractor_listed=false` 不放行;新增回歸鎖後 `make test` 全綠。

### Phase 3b 幕 6(spec §7 幕 6;遷移清單 §10)
- DoD:`make revoke LIST=credentials IDX=4` 翻 bit 並重簽 credentials.jwt,不重啟即生效;重跑案 A → `CREDENTIAL_REVOKED`;既有 Dossier 依 precursor_refs 標 `DEPENDS_REVOKED`(UI 黃 badge);`POST /api/issue/dyeing?case=A&reissue=1`(idx 8、新 pcf_period)→ 重聚合 → 重跑 A 綠;verify-offline 對新 presentation 通過、對舊的失敗;撤 M1 → `MANDATE_REVOKED`;`tamper.sh` → verify-chain FAIL,untamper 還原;Audit 分頁有 bit 條與撤銷開關;`make demo-reset` 一鍵還原;新增回歸鎖後 `make test` 全綠。

### Phase 4 錄影支援與交付
- DoD:分頁/案件 deep-link;demo-reset SOP 進 README;README 含安裝、六幕劇本、治理缺口、TC 鍵名對照、理由碼一覽(藍圖 v3.1「素材交付」B-10;無 CONSISTENCY_FAILED)、C-12 真/模擬;A-2 逐幕截圖清單所需畫面可在 30 秒內重現(本機有 Playwright 就自動截,沒有就寫操作指引);B-9 成本數字(presign 張數、簽發/驗證 ms、跑完一輪秒數)進 README;`make test` 全綠。錄影由人做。

---

## 4. 每個 phase 的七步關卡(缺一不可)

1. **拆解**:寫 `docs/phase-briefs/<phase>.md`:範圍、要動的檔、DoD 逐條、禁止事項、要新增的回歸測試。
2. **實作**:派 Sonnet,指令用 §5.1 模板(附 brief 全文)。
3. **驗證**:派 Opus,指令用 §5.2 模板。
4. **修復迴圈**:CRITICAL/HIGH → 發現原文交回 Sonnet 修 → Opus 重驗;最多兩輪;第三輪你親自分析修正再驗。
5. **Codex 挑戰**:`/codex:review`;無變更可審或零發現 → `/codex:adversarial-review`(範圍 = 本 phase commit 範圍;對抗框架:密碼學可造假?揭露邊界可繞?撤銷可略過?重放可過?Cedar 有沒有直接讀狀態?)。每個發現:修(Sonnet)+ 回歸鎖入 `scripts/test.ts` + Opus 重驗,或在報告寫明不修理由。最多兩輪;第二輪仍有新 CRITICAL 你親自處理。
6. **定案**:影響後續的約束追記 CLAUDE.md「Codex 審查定案」;commit(feat/fix + phase 名 + 一句話);不 push。
7. **回報**:依 §7 格式;然後直接進下一 phase。

---

## 5. 子代理指令模板

### 5.1 實作(Sonnet)
```
你是 carbon-cred-demo 的實作工程師,branch v3-textile。先讀 CLAUDE.md(硬規則)與下列 brief 全文,再動工。
<brief 全文>
規則:只改 brief 列出的檔;所有 pcf_* 由 data/seed.json 係數表計算,不寫死;取鑰只經 server/keys.ts;PERMIT/DENY/RELEASE 一律經 server/audit.ts 同交易入鏈;不加清單外依賴、不碰 vendor/、不建錢包/RPC/鏈上;每個新行為加回歸測試到 scripts/test.ts。
完成後只回報:①改動檔案清單 ②執行的指令與 make test 完整結果(通過數/總數、失敗項原文)③未解決事項與你做的取捨。不要貼整檔內容。
```

### 5.2 驗證(Opus)
```
你是獨立驗證者,不得信任實作者的自述。對象:branch v3-textile 的 <phase>(commit 範圍 <from>..<to>)。
<brief 全文>
你要做:①自己重跑 make test(能重跑 make setup 更好,不能就說明)②git diff 逐檔讀 ③對 brief 的每條 DoD 給 PASS/FAIL 並附證據(指令輸出或程式行號)④對照 CLAUDE.md 硬規則逐條檢查 ⑤至少三個對抗性 PoC(依 phase 挑:偽造/竄改憑證後是否仍通過、越過 allowed_claims 是否能拿到欄位、重放同一 request、撤銷後是否仍能通過、Cedar 是否直接讀 mandate 狀態、tc_ref/ccs_scope_ref 對不上是否仍聚合)。
回報格式:DoD 表(PASS/FAIL/證據);發現清單,每條:等級 CRITICAL/HIGH/MEDIUM/LOW、重現步驟、影響、建議修法;總判定 PASS / FAIL。不要修碼。
```

---

## 6. 決策預設與必須問

**自行決定(不問)**:Step 0 改名 timebox 30 分;幕 1 保底 (a)——8/30 12:00 前 tcRcs.ts 未過驗證 → `pcf_upstream.tc_ref` 改引用 `seed.tc_rcs` JSON 的 hash、治理缺口註明「CB 憑證未真簽」,繼續往下;落後砍幕順序:幕 5 案 C/Cp UI 改口述 → 幕 6 重簽重驗改口述 → 幕 6 bit 條退終端;幕 3→4→6 不可砍;絕不回退鋼鐵版、不混搭;規格矛盾依優先序取高者並記「規格疑義」;8/30 18:00 後只做 Phase 4 交付與修 bug。

**必須問使用者(僅此四種)**:對 main 任何寫入;刪除遷移清單未列的既有檔案;codex plugin 無法執行;8/30 15:00 Phase 3a 仍未過驗證。

---

## 7. 回報格式(每 phase 一段)

```
Phase <名稱> — <PASS | PASS with notes | FAIL>
- 實作:<Sonnet 子代理數、改動檔案數、關鍵取捨>
- 驗證(Opus):<DoD PASS/FAIL 摘要;PoC 結果;修復輪數>
- Codex:<review / adversarial-review;發現數;已修 / 不修理由>
- 測試:make test <通過/總數>;守門 grep <結果>
- commit:<hash 與訊息>
- 規格疑義 / 風險:<或「無」>
- 下一步:<phase>;預估時間;現在時刻 <date>
```

---

## 8. 完成定義

四個 phase DoD 全過且各經 Opus 驗證與 Codex 挑戰並處理完發現;v3-textile 上 `make setup` 乾淨一鍵成功、`make test` 全綠、守門 grep 為 0、`git status` 乾淨(`.vlei/`、`data/keys/`、`db/*.sqlite*` 未被追蹤);CLAUDE.md 為 v3 全文並含各 phase 定案;`docs/phase-briefs/` 四份;README 完整。最後輸出最終報告(各 phase 摘要、剩餘治理缺口、素材位置與截圖清單、B-9 數字),然後問使用者是否合併回 main——這是唯一該停下來等的時刻。
