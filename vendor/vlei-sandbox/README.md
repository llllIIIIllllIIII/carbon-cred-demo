# vLEI Sandbox

**GLEIF 可驗證法人識別碼（verifiable LEI, vLEI）信任鏈的本地可執行模型。**

零基礎設施、零外部相依，用純 Python 在數秒內跑完「GLEIF → QVI → 法人實體 → 角色持有人」
的完整六步信任鏈，並把憑證一路驗證回信任根。當模擬不夠用時，同一套工具可以直接帶你
graduate 到真實的 Docker + KERIA 環境。

```bash
python scripts/vlei_sandbox.py demo
```

---

## 目錄

- [這是什麼、為什麼存在](#這是什麼為什麼存在)
- [兩種模式](#兩種模式)
- [快速開始](#快速開始)
- [核心概念：六步信任鏈](#核心概念六步信任鏈)
- [五種憑證類型](#五種憑證類型)
- [指令參考](#指令參考)
- [驗證器實際檢查什麼](#驗證器實際檢查什麼)
- [專案結構](#專案結構)
- [實作細節與限制](#實作細節與限制)
- [延伸閱讀](#延伸閱讀)
- [安全性提醒](#安全性提醒)
- [授權](#授權)

---

## 這是什麼、為什麼存在

vLEI 的入門成本很高，但那些成本大多是**偶然的**，不是本質的。

KERI 金鑰事件日誌、ACDC 鏈式憑證、CESR 編碼、GLEIF 治理階層——這些概念本身是可學的。
問題在於一般的第一步是：先架 Docker 容器、解析 OOBI、協調多簽儀式，然後才能發出第一張憑證。
對於還在評估「vLEI 到底適不適合我的問題」的人來說，這個順序是反的。

這個專案把順序倒過來。**Mock 模式提供真實的 Ed25519 簽章、真實的 CESR 編碼、
真實的自我定址識別碼（SAID）、真實的 edge operator 強制檢查**，而相依套件只有 Python 本身。
你可以在一個下午、一台筆電上、離線狀態下設計憑證架構、故意把它弄壞、
搞清楚驗證方到底會接受什麼、不會接受什麼。然後再決定要不要往真實環境走。

適用情境包括：

- 想理解 vLEI / KERI / ACDC 是怎麼運作的（跑 `demo` 比看任何圖表都快）
- 設計自己的憑證架構，並在投入前先攻擊它
- 教學、簡報、hackathon 展示
- 驗證器（verifier）邏輯的原型開發
- 評估 vLEI 能不能解決某個實際問題：可重複使用的 KYC、供應商上線、
  供應鏈與貿易金融的公司身分證明、中小企業信用評估

---

## 兩種模式

| | Mock（預設） | Real |
|---|---|---|
| 需求 | Python 3.8+ | Docker Compose v2.23+ |
| 啟動時間 | 立即 | 約 60 秒（拉 image） |
| 簽章 | 真實 Ed25519 | 真實 Ed25519 |
| SAID / CESR | 真實 | 真實 |
| Witness、OOBI、IPEX | 模型化省略 | 實際協定 |
| 多簽、委派儀式 | 簡化 | 完整 |
| 適合 | 憑證設計、驗證器邏輯、教學、展示 | 整合、協定行為、上線前驗證 |

除非明確需要協定層級的行為，**建議從 mock 模式開始**。多數應用設計問題在那裡回答得更快。

---

## 快速開始

### 需求

- Python 3.8 以上（標準庫即可運作）
- 選用加速套件：`pip install blake3 cryptography`
  - `blake3`：讓摘要演算法與 production 完全一致（識別碼開頭為 `E`）
  - `cryptography` 或 `PyNaCl`：加速簽章；沒有的話會自動退回純 Python 實作

### 執行完整演示

```bash
git clone https://github.com/smpebble/vlei-sandbox.git
cd vlei-sandbox
python scripts/vlei_sandbox.py demo
```

這會建立完整的六步信任鏈，並把 OOR 憑證一路驗證回 GLEIF，逐項印出每一個檢查：

```
Step 1 -- GLEIF qualifies the vLEI issuer
  gleif -> qvi
  SAID EKUAJIaEfc_gWMGnKfcdlAjwhNGM0QE-O3qDsdYTDUnG
...
========================================================================
Verifying the OOR credential back to GLEIF
========================================================================

        Legal Entity Official Organizational Role vLEI Credential
  [ok]     SAID recomputes -- contents unaltered
  [ok]     schema SAID matches the oor schema
  [ok]     issuer signature valid (qvi)
  [ok]     LEI 8755001ELOZEL05BVX22: valid (ISO 17442-1)
  [ok]     registry status: issued, not revoked
  [ok]     edge 'auth' I2I satisfied: issuer holds the authorisation
        ...（遞迴驗證到信任根）

RESULT: chain verified
```

### 然後把它弄壞

```bash
python scripts/vlei_sandbox.py status                     # 列出所有憑證與 SAID
python scripts/vlei_sandbox.py revoke --said <LE 的 SAID>  # 撤銷法人實體憑證
python scripts/vlei_sandbox.py verify --said <OOR 的 SAID> # 現在失敗了——整條鏈塌了
```

這個序列——撤銷一張憑證，看著它底下的所有憑證同時失效——比任何圖表都更能說明核心概念：
**授權是被「連結」出來的，不是被「宣稱」出來的**。

---

## 核心概念：六步信任鏈

```
  GLEIF ──(1) QVI 憑證──────▶ QVI
    QVI ──(2) LE 憑證───────▶ 法人實體
     LE ──(3) OOR AUTH─────▶ QVI
    QVI ──(4) OOR 憑證──────▶ 個人          [edge: I2I 指向 OOR AUTH]
     LE ──(5) ECR AUTH─────▶ QVI
     LE ──(6a) ECR 憑證─────▶ 個人          [法人直接發行]
    QVI ──(6b) ECR 憑證─────▶ 個人          [QVI 代發，經 ECR AUTH]
```

注意第 3、4 步的形狀：**授權繞了一圈回來**。法人實體握有權限，
它把一份範圍受限、單次使用的權限「借」給 QVI，QVI 只能把它花在恰好一張憑證上。
這是「有收據的委派」，也是為什麼日後稽核不只能證明憑證存在，
還能證明它**確實被請求過**。

在 production 中，GLEIF 除了發出 QVI 憑證，還會委派一個 AID 給 QVI（`dip` inception 事件）。
憑證說的是「你有資格」；委派 AID 則意味著 QVI 的識別碼本身錨定在 GLEIF 的金鑰事件日誌裡。
攻擊者即使竊得 QVI 金鑰也無法重新錨定該委派，因為協作式委派需要雙方各自的承諾。

---

## 五種憑證類型

ISO 17442-3:2024 clause 5 把 vLEI 憑證分成三類。分類比名稱重要——它告訴你每張憑證回答什麼問題。

| 類別 | 憑證 | 回答的問題 |
|---|---|---|
| Entity | Qualified vLEI Issuer (QVI) | 這個組織有資格發行 vLEI 嗎？ |
| Entity | Legal Entity (LE) | 這個組織真的是它宣稱的那家嗎？ |
| Authorization | OOR AUTH / ECR AUTH | 法人實體真的要求過這張角色憑證嗎？ |
| Role | Official Organizational Role (OOR) | 這個人在此擔任**已登記**的職務嗎？ |
| Role | Engagement Context Role (ECR) | 這個人以什麼**功能性**身分代表該實體行事？ |

兩個區分決定了大部分的設計問題：

**OOR 對 ECR。** OOR 主張的是在設立或登記文件中可公開查得的職務——董事、執行長、公司秘書。
ISO 17442-3 要求在該職務已登記於 ISO 5009 時，角色值必須取自 ISO 5009。**只有 QVI 能發行 OOR。**
ECR 主張的則是實體自行定義的功能性角色——「貿易融資專員」、「USD 1m 以內授權簽署人」。
法人實體可以直接發行 ECR，也可以委託 QVI 作為加值服務代發。
設計應用時，**ECR 幾乎總是你要的營運授權憑證，OOR 則是你要的法律問責憑證**。

**授權憑證不是角色憑證。** 它們**向上**流動，從法人實體流向 QVI，
存在的目的是讓 QVI 能證明「我是被要求的」。這也是為什麼 QVI 無法替一家從未提出請求的公司鑄造角色憑證。

### Edge operator：安全設計的關鍵

edge 是指向「授權了本憑證的那張憑證」的指標：

```json
"auth": { "n": "<目標的 SAID>", "s": "<要求的 schema SAID>", "o": "I2I" }
```

`n` 是目標的 SAID——不可偽造。`s` 釘住目標的 schema，攻擊者無法換上另一種恰好有效的憑證類型。
`o` 是 operator，約束身分對應關係：

| Operator | 規則 | 為什麼重要 |
|---|---|---|
| `I2I` | 本憑證的**發行者**必須是目標憑證的**持有者** | QVI 只有在自己確實持有該法人實體給的 OOR AUTH 時，才能發出對應的 OOR 憑證 |
| `NI2I` | 不要求身分對應 | 連結僅為情境性或資訊性 |
| （無） | ACDC 中預設為 I2I 語意 | 用於單純的下行鏈 |

設計新憑證類型時，**選擇 operator 就是在做安全設計**。問自己：如果省略身分約束，誰還能站在發行者的位置上？
如果答案是「任何持有該類型有效憑證的人」，那你就需要 I2I。

---

## 指令參考

所有功能都透過單一腳本。

### 設定

```bash
python scripts/vlei_sandbox.py init [--force]
python scripts/vlei_sandbox.py demo [--lei <18字元>] [--person 姓名] [--role 職務] [--context-role 角色]
python scripts/vlei_sandbox.py status
```

### 行為者（AID 控制者）

```bash
python scripts/vlei_sandbox.py actor add --alias gleif --registry gleifRegistry --root
python scripts/vlei_sandbox.py actor add --alias qvi --registry qviRegistry --delegator gleif
python scripts/vlei_sandbox.py actor list
python scripts/vlei_sandbox.py actor rotate --alias qvi      # 預先輪替：AID 存活下來
```

`--root` 標記生態系的信任根。`--delegator` 產生委派式 inception（`dip`）事件，
對應 GLEIF 委派 AID 給 QVI 的做法。

`actor rotate` 值得單獨示範：**金鑰換掉了，識別碼沒變**。
這是 X.509 憑證做不到的——那裡換金鑰意味著重新簽發憑證。
原理是 pre-rotation：inception 時承諾的是下一組金鑰的**摘要**，不是金鑰本身。
偷到今天簽章金鑰的攻擊者仍然無法輪替識別碼，因為他拿不出符合一個他從沒見過的摘要的金鑰組。

### 憑證

```bash
python scripts/vlei_sandbox.py issue --type qvi      --issuer gleif --holder qvi --lei <LEI>
python scripts/vlei_sandbox.py issue --type le       --issuer qvi --holder le --lei <LEI> --auth <QVI SAID>
python scripts/vlei_sandbox.py issue --type oor-auth --issuer le --holder qvi --lei <LEI> \
    --person "Jane Doe" --role "Chief Executive Officer" --subject-aid <個人 AID> --auth <LE SAID>
python scripts/vlei_sandbox.py issue --type oor      --issuer qvi --holder person --lei <LEI> \
    --person "Jane Doe" --role "Chief Executive Officer" --auth <OOR AUTH SAID>
python scripts/vlei_sandbox.py issue --type ecr      --issuer le --holder person --lei <LEI> \
    --person "Jane Doe" --context-role "Trade Finance Officer" --auth <LE SAID>

python scripts/vlei_sandbox.py revoke  --said <SAID>
python scripts/vlei_sandbox.py verify  --said <SAID>
python scripts/vlei_sandbox.py present --said <SAID> --out presentation.json
```

`issue` 加上 `--json` 可印出完整 ACDC。用 `--data '{"key":"value"}'` 帶入內建旗標以外的屬性。

**工具會拒絕違反治理規則的發行**——沒有授權 edge 的憑證、指向錯誤憑證類型的 edge、
未通過檢查碼的 LEI。這些拒絕值得拿來示範；它們證明這個模型是在**強制執行**規則，而不是在裝飾 JSON。

`present` 產出的是一份**自我完備的呈現包**：憑證本身、整條鏈、相關的 KEL 與 TEL，
讓驗證方不需要向發行者詢問任何事就能完成驗證。

### LEI 運算（ISO 17442-1）

```bash
python scripts/vlei_sandbox.py lei make  YZ83GD8L7GG84979J5     # -> YZ83GD8L7GG84979J516
python scripts/vlei_sandbox.py lei check YZ83GD8L7GG84979J516   # -> VALID
```

### 圖表

```bash
python scripts/vlei_sandbox.py chain --out chain.mmd    # Mermaid 格式，可直接貼進簡報或文件
```

### 真實環境

```bash
python scripts/vlei_sandbox.py real scaffold   # 把 docker-compose.yaml 複製到專案
python scripts/vlei_sandbox.py real up
python scripts/vlei_sandbox.py real status
python scripts/vlei_sandbox.py real logs
python scripts/vlei_sandbox.py real down
```

啟動後的端點：

| 服務 | 埠 | 角色 |
|---|---|---|
| `vlei-server` | 7723 | 透過 OOBI 提供官方 vLEI ACDC schema |
| `witness-demo` | 5642-5647 | 六個 witness：wan, wil, wes, wit, wub, wyz |
| `keria` | 3901 / 3902 / 3903 | 多租戶 KERI agent（admin / agent / boot） |
| `sally-hook` | 9923 | 以 JSON 接收 IPEX 呈現——你的整合接縫 |

詳細的 Signify-TS 走查、已知摩擦點與上線路徑，見 `references/real-environment.md`。

---

## 驗證器實際檢查什麼

一個從未與發行者通訊過的驗證方，應該只憑呈現包就能回答「我能信賴這個嗎？」。順序如下：

1. **重算每一個 SAID。** 憑證、屬性區塊、edge 區塊、規則區塊。任何不符都代表內容在簽署後被更動過。
2. **比對 schema SAID** 與預期的憑證類型。宣稱是 OOR 卻帶著 ECR schema 的憑證不是 OOR。
3. **驗證發行者簽章**，使用的是**發行被錨定的那個序號**上發行者 KEL 中的當期金鑰，
   而不是發行者今天的金鑰。這就是為什麼金鑰輪替不會使先前發出的憑證失效。
4. **依 ISO 17442-1 驗證 LEI**：20 字元、檢查碼對落在 [02..98]、整串 mod 97 等於 1。
5. **在發行者的 TEL 中檢查註冊狀態**：有 `iss` 事件且其後沒有 `rev` 事件。
6. **沿著每個 edge 走下去**，強制執行 operator，並對目標重複步驟 1-5。
   遞迴直到抵達由信任根直接發行的憑證。
7. **確認信任根**確實是你預期的 GLEIF Root AID。
   一條完美驗證回「別人的」信任根的鏈，什麼都沒證明。

**步驟 7 是最常被跳過、也最關鍵的一步。** 密碼學驗證告訴你這條鏈內部一致；
它不告訴你這條鏈屬於你信任的那個生態系。**把信任根釘死。**

### 撤銷的爆炸半徑

撤銷是發行者交易事件日誌（TEL）中的一個事件，並錨定進發行者的金鑰事件日誌（KEL）。
沒有 CRL 要抓，也沒有 OCSP responder 要信任——撤銷與發行同屬一份唯附加的歷史。

令人意外的後果是：撤銷一張憑證會**讓它底下鏈接的一切一起塌掉**。
撤銷一張法人實體憑證，其下所有 OOR 與 ECR 憑證立即驗證失敗。
這是特性而非缺陷——LEI 失效的實體不能在外面留著有效的授權簽署人——
但這也意味著撤銷是高爆炸半徑的操作，應用應該明確地把它呈現出來。

---

## 專案結構

```
vlei-sandbox/
├── SKILL.md                          # 完整技能說明與指令參考（給 AI agent 讀）
├── AGENTS.md / GEMINI.md / CLAUDE.md # 各家 agent 的入口指標，內容相同
├── scripts/
│   ├── vlei_sandbox.py               # CLI：mock 引擎 + Docker 編排
│   ├── keri.py                       # KERI/ACDC 模型：Controller、KEL、TEL、ACDC 組裝
│   ├── cesr.py                       # CESR 編碼、SAID 計算與驗證
│   └── ed25519_compat.py             # Ed25519 簽章，逐級降級的後端選擇
├── references/
│   ├── trust-chain.md                # 憑證結構、ACDC 解剖、edge operator、驗證清單、ISO 17442 對照
│   ├── real-environment.md           # Docker/KERIA/Signify 走查、整合模式、已知摩擦
│   └── application-patterns.md       # 四種可行應用模式、驗證器設計檢查表、誠實的限制
└── assets/
    └── docker-compose.yaml           # 真實環境，可獨立使用
```

### 模組職責

- **`cesr.py`** — CESR（Composable Event Streaming Representation）原語。
  那些讓 KERI/ACDC 一眼可辨的字串（44 字元的 `E...` 識別碼、88 字元的 `0B...` 簽章）不是隨便來的，
  而是原始密碼學材料的文字域編碼，前綴碼宣告了材料的種類。這裡把這件事做對，
  沙盒的輸出才會像真的，而不是像假雜湊。SAID 的計算技巧也在這裡：
  雜湊前先把 SAID 欄位換成**等長**的 `#`，所以序列化長度不變，任何人都能重複這個計算。

- **`keri.py`** — 一個小而誠實的 KERI/ACDC 模型。它不是 keripy 的重新實作，
  而是保留了「決定應用設計是否健全」的那些部分：金鑰事件日誌、pre-rotation、
  帶撤銷狀態的憑證註冊表、自我定址識別碼、帶 edge operator 的鏈式憑證；
  省略的是只在分散式部署才重要的部分：witness 收據、線上 OOBI 探索、mailbox 遞送、多簽協調。

- **`ed25519_compat.py`** — 依序嘗試 `cryptography` → `PyNaCl` → 純 Python（RFC 8032 參考風格），
  API 完全相同。目的是讓沙盒在任何地方都能跑：Claude Code、Codex、Gemini CLI、
  裸容器、被鎖死的公司筆電。

- **`vlei_sandbox.py`** — CLI、vLEI 憑證目錄（schema SAID 與治理規則）、
  LEI 檢查碼運算、遞迴驗證器、呈現包匯出、Mermaid 圖產生、Docker 編排。

---

## 實作細節與限制

- **保真度。** SAID、CESR 限定編碼、edge operator、TEL 撤銷語意、pre-rotation
  的行為都符合規格。簽章是真實的 Ed25519，每次 `verify` 都會實際驗證。

- **摘要演算法。** KERI 的預設是 Blake3-256（CESR 碼 `E`）。Blake3 不在 Python 標準庫中，
  所以沙盒會退回 Blake2b-256（碼 `F`）——同樣是有效的 CESR 摘要碼。
  因此在未安裝 `blake3` 套件時識別碼開頭是 `F` 而不是 `E`；
  安裝 `pip install blake3` 後就與 production 完全一致。
  **這是替換，不是錯誤。**

- **簽章後端。** 有 `cryptography` 或 `PyNaCl` 時使用之，否則使用零相依的純 Python Ed25519。
  `init` 會回報實際使用的是哪一個。

- **狀態。** 工作目錄下單一份可讀的 `.vlei/state.json`。
  盡量去翻它——把 KEL 與 TEL 看成純 JSON 是很有教育性的。

- **刻意不做的部分。** Witness 收據、線上 OOBI 解析、IPEX 訊息交換、多簽門檻、watcher。
  這些是協定層關切，不會改變憑證設計。當它們變成你的問題時，就該切到 `real` 模式。

### 誠實地界定範圍

兩個限制會形塑任何商業論述，由你自己先提出會比被質疑者提出來得好：

**LEI 是有實際成本的前提。** 每張 vLEI 憑證都帶有依 ISO 17442-1 指派的 LEI，
需向 LEI Issuer 取得並負擔年度續期義務。對中小企業族群而言這是真實的採用障礙，
任何可信的計畫都必須說清楚由誰承擔。Validation Agent 模式——由金融機構把 LEI 發行
折進它本來就在做的 KYC——正是為此而生。

**通過驗證不等於值得信任。** 每張 vLEI 憑證所攜帶的規則區塊明白寫著：
有效的憑證並不主張該實體聲譽良好、往來安全或合規。它主張的是身分、授權與角色。
承諾超過這個範圍的應用會讓人失望，而且免責文字就寫在憑證裡，任何人都讀得到。

---

## 延伸閱讀

按需閱讀，不必一次看完：

- **`references/trust-chain.md`** — 憑證類型、ACDC 解剖、edge operator、
  完整驗證器檢查清單、ISO 17442 系列對照、已知的 schema SAID。
  在回答任何關於憑證結構或「驗證過了」是什麼意思的問題之前先讀這份。

- **`references/real-environment.md`** — Docker 堆疊、Signify-TS 客戶端模式、
  IPEX 呈現、已知摩擦、通往 production 的路徑。動 `real` 模式或寫整合程式前先讀。

- **`references/application-patterns.md`** — 四種可行的應用模式
  （可重複使用的上線流程、文件與交易簽署授權、供應鏈與貿易文件溯源、
  信用評估與中小企業融資）、如何在五種標準憑證類型之外擴充、
  驗證器設計檢查表、以及兩個值得先講清楚的限制。在規劃或推銷應用之前先讀。

- **`SKILL.md`** — 這個專案作為可攜式 AI agent 技能的完整說明。

### 關於 X.509 / 既有 PKI

ISO 17442-2（LEI 嵌入 X.509）與 17442-3（LEI 用於 ACDC）是**平行路徑，不是轉換管線**。
既有 PKI 的真正價值在於作為**身分保證來源**，餵給 QVI 用來驗證公司代表人
（DAR 與 LAR）的過程——也就是作為上線流程中的證據，而不是格式轉換器的輸入。
沒有標準化的「X.509 轉 vLEI」轉換，把它講成轉換管線在面對 GLEIF 或主管機關時撐不住。
細節見 `references/trust-chain.md`。

---

## 安全性提醒

> ⚠️ **`.vlei/state.json` 內含私鑰種子。**
> 它是沙盒產物，**絕對不可提交進版本控制，也不可用於任何真實用途**。
> 本 repo 的 `.gitignore` 已將其排除。

> ⚠️ **你無法自行簽發真實驗證方會信任的憑證。**
> 信任鏈必須終止於 GLEIF Root AID，而只有 GLEIF 能發行 QVI 憑證。
> 現實路徑是：在 mock 模式做出憑證設計與驗證器邏輯 → 在本地 KERIA 堆疊跑通端到端流程 →
> 為涉及的法人實體取得 LEI → 委由 Qualified vLEI Issuer 針對這些 LEI 簽發 LE 與角色憑證，
> 並在你的驗證器中釘死 GLEIF Root AID。

---

## 可攜性

本專案是純 Python 加 Markdown，沒有框架相依，因此在 Claude Code、Codex、Gemini CLI
或裸終端機中都能原樣運作。一個能讀檔案、能執行 shell 指令的 agent 就具備了所需的一切。
如果你的 agent 讀的是 `AGENTS.md` 而不是 `SKILL.md`，兩者都在，內容相同。

---

## 授權

MIT License — 見 [LICENSE](LICENSE)。
