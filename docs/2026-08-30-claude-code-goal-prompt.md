# Claude Code goal prompt — 以 v3.1 完成全部實作(Fable 指揮 / Sonnet 實作 / Opus 驗證 / Codex 挑戰)

> 用法:在 `carbon-cred-demo` 資料夾開新的 Claude Code session(主模型 Fable),把下方整段貼為 goal 的指令;若 goal 功能另有「完成條件」欄位,填最後一節「完成定義」。目前時間以你貼上的時刻為準,截止 8/30 21:00(內部)/ 23:59(官方)。

```
你是本 repo 的總指揮(orchestrator)。你的目標:把 carbon-cred-demo 從目前的 v2 鋼鐵版(commit 51ae362,Phase 0–2 完成)完整推進到 v3.1 紡織版全部完成——Phase 2.5 遷移、Phase 3a 幕 5、Phase 3b 幕 6、Phase 4 錄影支援與交付素材——每個 phase 都必須通過同一套關卡流程才能進入下一個,直到「完成定義」全部成立。這是一個 goal:不要停下來等我,除非碰到下面「必須問我」的情況。

====================================================================
一、角色與模型分工(嚴格遵守)
====================================================================
- 你(主 session,Fable):只做指揮、拆解、審閱、決策、合併、回報。你不親自寫功能碼;只有在子代理連續兩輪修不好、或 Codex 的發現需要架構判斷時,你才接手直接思考與修改。
- 實作子代理:Agent(subagent_type: "general-purpose", model: "sonnet")。每個 phase 可拆成數個實作任務;檔案集合互不重疊時可並行,否則依序。
- 驗證子代理:Agent(subagent_type: "general-purpose", model: "opus")。驗證者不得信任實作者的自述,必須自己重跑 make test、讀 diff、對 DoD 與硬規則逐條查證,並嘗試用可重現的 PoC 打破功能。
- Codex 挑戰:由你(主 session)執行 codex plugin:先跑 /codex:review;若回報「無變更可審」或零發現,改跑 /codex:adversarial-review(指定審查範圍 = 本 phase 的 commit 範圍與對抗性框架:密碼學可造假?揭露邊界可繞?撤銷可略過?重放可過?)。若 codex plugin 不存在或無法執行,立刻停下來告訴我,不要用其他方式代替。
- 所有子代理的回覆只回摘要:改了哪些檔、跑了什麼、結果如何、剩什麼風險;不要把整份檔案貼回來。

====================================================================
二、前提與唯一規格來源
====================================================================
1. 第一件事:用 docs/2026-08-29-v2→v3遷移清單.md §8.1 的 CLAUDE.md v3 全文覆蓋 repo 根目錄的 CLAUDE.md(目前是 v2 版,已過時);git rm docs/demo情境設定與合成資料規格-v2.md;git add docs 內的 v3 文件;commit「docs: v3.1 規格與 CLAUDE.md」。之後每一步都遵守新 CLAUDE.md。
2. 規格優先序(衝突時):docs/2026-08-26-專案架構決策.md(2026-08-30-a)> docs/demo情境設定與合成資料規格-v3.md(v3.1,含 §0.4 制度修正與 §0.5 交接檔三對照)> docs/2026-08-29-v2→v3遷移清單.md(程式面逐檔對照;§9 為舊版 prompt,以本 goal 為準)> docs/製造貿易demo實作藍圖.html(v2 技術細節與 DoD)與 docs/製造貿易demo實作藍圖-v3紡織版.html(v3.1 六幕劇本、素材交付節)。seed 檔:docs/seed.v3.json(不得手改數值)。除 docs/ 外禁止讀取 workspace 其他同名或舊版文件。
3. 已拍板、不得更動:5 LE(yarn/fab/dye/brand/cb)+ 2 ECR + 2 workload、四分頁、六幕;M2 只給 pcf_total 一個排放數字(H2),pcf_yarn/pcf_knitting/pcf_dyeing NEVER_DISCLOSABLE,brand_allocation_share 只留 hash;幕 5 = 布廠付染整廠(mock USD 電匯 3,420),A/B 差異只來自 pcf_dyeing 的 heat_source/renewable_share;幕 6 撤 pcf_dyeing 為主線;v3.1:tc_rcs 與 ccs_scope_cert 由 CB 鑰簽,pcf_upstream 帶 tc_ref,pcf_dyeing/pcf_aggregate 帶 ccs_scope_ref,P3 多 subcontractor_listed,理由碼 TC_REF_MISMATCH / CCS_SUBCONTRACTOR_NOT_LISTED / SCOPE_CERT_INVALID;hs6 已移除;鞋廠、幕 7、稽核層 M4、一致性檢查只做投影片。所有 pcf_* 由 seed 係數表計算,不寫死。
4. 全程在 branch v3-textile 上工作;main 不動,直到完成定義成立後才合併。

====================================================================
三、Phase 清單與各自的 DoD
====================================================================
Phase 2.5 遷移(遷移清單 Step 0–8 + v3.1 項目)
  DoD:make setup 乾淨環境一鍵成功;make test 全綠且含九組新檢查(manifest 7 角色與 dye verify;computeDyeing 交叉驗證;三段聚合與 precursor_refs 三筆;tc_rcs 驗章與 TC_REF_MISMATCH 兩條失敗路徑;ccs_scope_cert 驗章與 CCS_SUBCONTRACTOR_NOT_LISTED / SCOPE_CERT_INVALID;H2 三段不可揭露且 brand_allocation_share 不出現於明文;幕 4 plant_total_output → POLICY_P2_CONFIDENTIAL;Cedar 9500/7925/10899;一致性守門 grep);git grep -iE "鴻鋼|Thép Việt|Bruck|台驗|扣件|線材|CBAM|海關|EAF|BF-BOF|USDC|6006" -- server web scripts data policies CLAUDE.md 為 0;make dev 走過幕 1–4,畫面文案無鋼鐵字樣、幕 1 為兩張卡(TC 卡 + 碳憑證卡)、Tab 2 有 SC 卡。
  Step 0(alias 改名)預設執行,timebox 30 分鐘;超時就回退改採「不改名 + README 對照表」。
Phase 3a 幕 5(spec v3.1 §5.1、§6 P3、§7 幕 5;遷移清單 §10)
  DoD:POST /api/agent/run?case=A|B|C|Cp 走 P3 五要件(DYE 身分、subcontractor_listed、pcf_total ≤ 9500、發票、帳戶風險雙來源),每個檢查結果與理由碼入 decisions + audit_chain 同交易;Dossier 為 fab-workload 簽的 JWS(build_hash、五項結果、三張輸入憑證 hash);POST /api/human-sign 以財務主管 ECR 鑰簽放行並產 mock USD 電匯指令(付款人 fab、收款人 dye、3,420)→ RELEASED;案 B 回 CARBON_OVER_THRESHOLD 且 UI 不渲染放行按鈕;案 C MULTI_SOURCE_CONFIRMED、案 Cp SINGLE_SOURCE_ONLY;subcontractor_listed=false 時不放行;make test 新增回歸鎖後全綠。
Phase 3b 幕 6(spec v3.1 §7 幕 6;遷移清單 §10)
  DoD:make revoke LIST=credentials IDX=4 翻 bit 並重簽 credentials.jwt,不重啟即生效;重跑案 A → CREDENTIAL_REVOKED;既有 Dossier 依 precursor_refs 標 DEPENDS_REVOKED(UI 黃 badge);POST /api/issue/dyeing?case=A&reissue=1(idx 8、新 pcf_period)→ 重聚合 → 重跑 A 綠、verify-offline 對新 presentation 通過、對舊的失敗;撤 M1 → MANDATE_REVOKED(輔線);tamper.sh → verify-chain FAIL,untamper 還原;Audit 分頁有 bit 條與撤銷開關;make demo-reset 一鍵還原;make test 新增回歸鎖後全綠。
Phase 4 錄影支援與交付
  DoD:分頁與案件 deep-link;demo-reset SOP 寫進 README;README 含安裝、六幕劇本、治理缺口、TC 鍵名對照、理由碼一覽(依藍圖 v3.1「素材交付」節 B-10,沒有 CONSISTENCY_FAILED)、「什麼是真的、什麼是模擬的」(C-12);以 Playwright(若本機可用)或手動指引產出 A-2 逐幕截圖清單所需畫面;B-9 成本側數字(presign 張數、簽發/驗證耗時 ms、跑完一輪秒數)寫進 README;make test 全綠。錄影本身由人做,你只負責讓每一幕可在 30 秒內重現。

====================================================================
四、每個 Phase 的固定關卡流程(七步,缺一不可)
====================================================================
步驟 1 拆解:你先寫一份 phase brief(範圍、要動的檔、DoD 逐條、禁止事項),存到 docs/phase-briefs/<phase>.md。
步驟 2 實作:派 Sonnet 實作子代理,指令必須包含:phase brief 全文、CLAUDE.md 硬規則、要新增的回歸測試、以及「完成後回報:改動檔案清單、make test 完整結果、未解決事項」。
步驟 3 驗證:派 Opus 驗證子代理,指令必須包含:phase brief、DoD 逐條、以及要求「自己重跑 make setup(乾淨環境可跳過但需說明)與 make test、讀 git diff、對每條 DoD 給出 PASS/FAIL 與證據、嘗試至少三個對抗性 PoC(依 phase:偽造憑證/繞過揭露邊界/重放/撤銷後仍通過/Cedar 直接讀狀態)、列出 CRITICAL/HIGH/MEDIUM/LOW 發現」。
步驟 4 修復迴圈:有 CRITICAL 或 HIGH → 把發現原文交回 Sonnet 修,修完再派 Opus 重驗;最多兩輪;第三輪仍不過,你親自接手分析並修正,再驗一次。
步驟 5 Codex 挑戰:你執行 /codex:review(無變更可審或零發現 → /codex:adversarial-review,範圍 = 本 phase commit 範圍)。逐項處理每個發現:需修 → 派 Sonnet 修 + 加回歸鎖入 scripts/test.ts + Opus 重驗;不修 → 在 phase 報告寫明理由。Codex 最多兩輪;若第二輪仍有新的 CRITICAL,你親自處理。
步驟 6 定案:把影響後續 phase 的約束追記到 CLAUDE.md「Codex 審查定案」節;commit(訊息:feat/fix + phase 名 + 一句話);不 push。
步驟 7 回報:用「回報格式」對我寫一段簡短報告,然後直接進下一個 phase,不要等我回覆。

====================================================================
五、決策預設(不要為這些停下來問我)
====================================================================
- Step 0 alias 改名:做;超時 30 分鐘就回退不做。
- 幕 1 保底 (a):8/30 12:00 前 tcRcs.ts 未通過驗證 → pcf_upstream.tc_ref 改為引用 seed.tc_rcs JSON 的 hash、治理缺口註明「CB 憑證未真簽」,繼續往下走,之後有空再補真簽。
- 進度落後的砍幕順序:幕 5 案 C/Cp UI 可口述 → 幕 6 重簽重驗改口述 → 幕 6 UI bit 條退成終端;絕不回退鋼鐵版,絕不混搭場景;幕 3→4→6 三幕是骨架不可砍。
- 遇到規格內部矛盾:依優先序取高者,並在 phase 報告記一條「規格疑義」,不要自行擴大範圍。
- 不新增依賴,除非遷移清單已列;不碰 vendor/;不建立錢包/RPC/鏈上;不宣稱 W3C VC 2.0。
- 每次動工前 `date` 看時間;8/30 18:00 後只准做 Phase 4 的交付與修 bug,不開新功能。

====================================================================
六、必須問我(只有這四種)
====================================================================
1. 要對 main 做任何寫入(合併、reset、force push)。
2. 要刪除 docs/ 或 data/vlei/ 以外的既有檔案而遷移清單沒有列。
3. codex plugin 無法執行。
4. 8/30 15:00 時 Phase 3a 仍未通過驗證(要我決定砍幕範圍)。
其他一律依「決策預設」自行判斷並在報告中說明。

====================================================================
七、回報格式(每個 phase 一段,貼在對話中)
====================================================================
Phase <名稱> — <PASS|PASS with notes|FAIL>
- 實作:<Sonnet 子代理數、改動檔案數、關鍵決定>
- 驗證(Opus):<DoD 逐條 PASS/FAIL 摘要;PoC 結果;發現與修復輪數>
- Codex:<review 或 adversarial-review;發現數;修了哪些、沒修的理由>
- 測試:make test <通過數/總數>;守門 grep 結果
- commit:<hash 與訊息>
- 規格疑義 / 風險:<若無寫「無」>
- 下一步:<phase 名>與預估時間;現在時刻 <date>

====================================================================
八、完成定義(全部成立才算 goal 完成)
====================================================================
- Phase 2.5、3a、3b、4 各自 DoD 全過,且每個 phase 都經過 Opus 驗證與 Codex 挑戰並處理完發現。
- branch v3-textile 上 make setup 乾淨環境一鍵成功、make test 全綠、守門 grep 為 0、git status 乾淨(.vlei/、data/keys/、db/*.sqlite* 未被追蹤)。
- CLAUDE.md 為 v3 全文並含各 phase 追記的 Codex 定案;docs/phase-briefs/ 有四份 brief;README 完整。
- 給我一份最終報告(全部 phase 摘要、剩餘治理缺口、給簡報端的素材位置與截圖清單、B-9 數字),然後問我是否合併回 main——這是你唯一該停下來等我的時刻。
```
