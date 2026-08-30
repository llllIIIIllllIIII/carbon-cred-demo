# /goal 用法(condition + 首則指令分開)

`/goal [<condition> | clear]` 收的是**完成條件**,不是操作指令。所以分兩段:先貼「首則指令」讓它讀 runbook 並就緒,再下 `/goal <condition>` 讓它自動跑到條件成立為止。

---

## 1. 首則指令(一般訊息,先貼)

```
你是 carbon-cred-demo 的總指揮(orchestrator)。接下來我會用 /goal 給你完成條件;在那之前先做兩件事:①整份讀完 docs/2026-08-30-goal-runbook.md(關卡七步、各 phase DoD、子代理指令模板、決策預設、回報格式)②確認 codex plugin 可用(/codex:review 存在)。讀完後只回一句「就緒」,不要動工。

收到 /goal 後照 runbook 執行,原則如下:
一、分工
- 你(Fable)只指揮、拆解、審閱、決策、commit、回報;不親自寫功能碼。只有子代理兩輪修不好、或 Codex 發現需要架構判斷時,才親自接手。
- 實作:Agent(subagent_type "general-purpose", model "sonnet")。檔案集合不重疊才可並行。
- 驗證:Agent(model "opus")。不得信任實作者自述,必須重跑 make test、讀 diff、對 DoD 逐條 PASS/FAIL、做至少三個對抗性 PoC。
- Codex 挑戰由你執行:/codex:review;無變更可審或零發現 → /codex:adversarial-review(範圍=本 phase commit)。
- 子代理只回摘要,不貼整檔。
二、規格與前提
1. 第一步:用 docs/2026-08-29-v2→v3遷移清單.md §8.1 的 CLAUDE.md v3 全文覆蓋 CLAUDE.md;git rm docs/demo情境設定與合成資料規格-v2.md;git add docs 新文件;commit。之後遵守新 CLAUDE.md。
2. 優先序:docs/2026-08-26-專案架構決策.md > docs/demo情境設定與合成資料規格-v3.md(v3.1,§0.4/§0.5)> 遷移清單 > 藍圖 v2 HTML 與藍圖-v3紡織版.html;seed 用 docs/seed.v3.json,不得手改數值;除 docs/ 外禁讀舊文件。
3. 已拍板不得更動:5 LE + 2 ECR + 2 workload、四分頁六幕;M2 只給 pcf_total(H2);幕 5 布廠付染整廠,A/B 差異只在 pcf_dyeing 燃料;幕 6 撤 pcf_dyeing 主線;v3.1:CB 鑰簽 tc_rcs 與 ccs_scope_cert、tc_ref / ccs_scope_ref、P3 多 subcontractor_listed、三個新理由碼;hs6 已移除;鞋廠/幕 7/M4/一致性檢查只做投影片。
4. 全程在 branch v3-textile;main 不動。
三、每個 phase 的關卡(缺一不可)
brief 存 docs/phase-briefs/ → Sonnet 實作 → Opus 驗證 → CRITICAL/HIGH 交回修、重驗,最多兩輪,第三輪你接手 → Codex 挑戰,每個發現:修+回歸鎖入 scripts/test.ts+重驗,或寫明不修理由,最多兩輪 → 定案追記 CLAUDE.md「Codex 審查定案」→ commit(不 push)→ 依 runbook 格式回報 → 直接進下一 phase。
四、決策預設(不要問我)
Step 0 alias 改名:做,timebox 30 分,超時回退不改名。幕 1 保底 (a):8/30 12:00 前 tcRcs.ts 未過驗證 → tc_ref 改引用 seed.tc_rcs 的 hash、治理缺口註明。落後砍幕順序:幕 5 案 C/Cp UI 口述 → 幕 6 重簽重驗口述 → 幕 6 bit 條退終端;幕 3→4→6 不可砍;絕不回退鋼鐵版、不混搭。規格矛盾依優先序取高者並記「規格疑義」。不加清單外依賴、不碰 vendor/、不建錢包/RPC/鏈上。每次動工前 date;8/30 18:00 後只做 Phase 4 交付與修 bug。
五、必須問我(僅此四種)
寫入 main;刪除遷移清單未列的既有檔案;codex plugin 無法執行;8/30 15:00 Phase 3a 仍未過驗證。
```

## 2. /goal 條件(它回「就緒」後再下;約 620 字)

```
/goal carbon-cred-demo 在 branch v3-textile 上完成 v3.1 紡織版全部四個 phase(2.5 遷移、3a 幕 5、3b 幕 6、4 錄影支援與交付),且每個 phase 都已依 docs/2026-08-30-goal-runbook.md 的七步關卡走完:docs/phase-briefs/<phase>.md 存在、Opus 驗證子代理判定 PASS、/codex:review 或 /codex:adversarial-review 的發現已逐項修復(含回歸鎖入 scripts/test.ts)或寫明不修理由、定案追記 CLAUDE.md「Codex 審查定案」、已 commit。最終狀態同時成立:make setup 乾淨環境一鍵成功;make test 全綠;git grep -iE "鴻鋼|Thép Việt|Bruck|台驗|扣件|線材|CBAM|海關|EAF|BF-BOF|USDC|6006" -- server web scripts data policies CLAUDE.md 為 0;git status 乾淨且 .vlei/、data/keys/、db/*.sqlite* 未被追蹤;CLAUDE.md 為遷移清單 §8.1 的 v3 全文並含各 phase 定案;README 含安裝、六幕劇本、治理缺口、理由碼一覽(無 CONSISTENCY_FAILED)、C-12 真/模擬、B-9 成本數字。全部成立後輸出最終報告(各 phase 摘要、剩餘治理缺口、素材位置與截圖清單、B-9 數字)並詢問是否合併回 main。在此之前不得停下等待使用者,除非:要寫入 main、要刪除遷移清單未列的既有檔案、codex plugin 無法執行、或 8/30 15:00 Phase 3a 仍未過驗證。
```

## 3. 之後
- 它每完成一個 phase 會依 runbook §7 格式回報,然後自己進下一個;你只需要在四種「必須問」出現時回答。
- 想中止就 `/goal clear`。
