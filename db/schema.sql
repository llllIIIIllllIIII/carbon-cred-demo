-- carbon-cred-demo 資料庫結構(10 張表;架構決策 §2;Phase 3a 新增 dossiers)
-- 所有識別碼與數值皆為合成資料。

PRAGMA foreign_keys = ON;

-- 1) 參與方(自 data/vlei/manifest.json 灌入;不寫死 SAID)
CREATE TABLE IF NOT EXISTS parties (
  id            TEXT PRIMARY KEY,          -- 角色鍵:yarn / fab / brand / cb / fab_cfo / brand_cso
  kind          TEXT NOT NULL,             -- 'le' | 'ecr'
  alias         TEXT NOT NULL,             -- sandbox actor alias
  legal_name    TEXT NOT NULL,
  lei           TEXT NOT NULL,             -- 20 碼,ISO 17442-1(sandbox lei make 產生)
  aid           TEXT NOT NULL,             -- KERI AID(presign 產生,讀 manifest)
  public_key    TEXT NOT NULL,             -- CESR qb64 verkey(公開材料)
  credential_said TEXT NOT NULL,           -- 對應 vLEI 憑證 SAID(讀 manifest)
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 2) 應用層憑證(SD-JWT VC:pcf_upstream / pcf_aggregate / invoice / rba_dcc)
CREATE TABLE IF NOT EXISTS credentials (
  id            TEXT PRIMARY KEY,
  type          TEXT NOT NULL,             -- 'pcf_upstream' | 'pcf_aggregate' | 'invoice' | 'rba_dcc'
  case_id       TEXT,                      -- 'A' | 'B' | 'C' | 'Cp'(對應 seed 案件)
  issuer_party  TEXT NOT NULL REFERENCES parties(id),
  holder_party  TEXT REFERENCES parties(id),
  sd_jwt        TEXT,                      -- compact SD-JWT(幕 1/2 簽發後回填)
  payload_json  TEXT,                      -- 簽發時之 claims 快照(公開材料)
  status_idx    INTEGER,                   -- Token Status List 之 idx
  status_uri    TEXT,                      -- Token Status List 之 uri(status.status_list = {idx, uri})
  issued_at     TEXT NOT NULL,
  valid_from    TEXT NOT NULL,
  valid_until   TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 3) 委任狀(M1 / M2)
CREATE TABLE IF NOT EXISTS mandates (
  id            TEXT PRIMARY KEY,          -- 'M1' | 'M2'
  jti           TEXT NOT NULL UNIQUE,      -- mandate 唯一 ID(防偽引用)
  issuer_party  TEXT NOT NULL REFERENCES parties(id),
  aud           TEXT NOT NULL,             -- 受眾(fab-gateway)
  purpose       TEXT,
  agent_id      TEXT,
  delegate_kid  TEXT NOT NULL,             -- 綁定之 workload 公鑰 kid
  allowed_claims TEXT NOT NULL,            -- JSON array
  max_granularity TEXT NOT NULL,
  query_cap     INTEGER,
  queries_used  INTEGER NOT NULL DEFAULT 0,
  policy_version TEXT NOT NULL,
  mandate_nonce TEXT NOT NULL,
  extra_json    TEXT,                      -- scope_tools / thresholds 等其餘欄位
  token         TEXT,                      -- 簽章後之 mandate JWT(Phase 2 回填)
  status_idx    INTEGER NOT NULL,
  status_uri    TEXT NOT NULL,
  valid_from    TEXT NOT NULL,
  valid_until   TEXT NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 4) 出示紀錄(重放防護:同 mandate 之 request_nonce 不得重複)
CREATE TABLE IF NOT EXISTS presentations (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  mandate_id    TEXT NOT NULL REFERENCES mandates(id),
  request_nonce TEXT NOT NULL,
  requested_claims TEXT,                   -- JSON array
  presentation  TEXT,                      -- 回傳之 SD-JWT presentation
  decision_id   INTEGER,
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (mandate_id, request_nonce)
);

-- 5) 政策(Cedar 原文;前端顯示同一份)
CREATE TABLE IF NOT EXISTS policies (
  id            TEXT PRIMARY KEY,          -- 'P1' | 'P2' | 'P3'
  version       TEXT NOT NULL,             -- pol-2026-08-v2
  name          TEXT NOT NULL,
  cedar_text    TEXT NOT NULL,
  active        INTEGER NOT NULL DEFAULT 1
);

-- 6) 決策(每筆 PERMIT/DENY/RELEASE/REPLAY_DETECTED;與 audit_chain 同一交易寫入)
CREATE TABLE IF NOT EXISTS decisions (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  action        TEXT NOT NULL,             -- DiscloseClaim / EmitReleaseCredential / ...
  effect        TEXT NOT NULL,             -- PERMIT / DENY / RELEASE / REPLAY_DETECTED
  reason_code   TEXT NOT NULL,             -- shared/codes.ts 常數
  policy_id    TEXT,
  case_id       TEXT,
  mandate_id    TEXT,
  context_json  TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 7) 收款帳戶風險訊號(識別碼為合成字串)
CREATE TABLE IF NOT EXISTS risk_signals (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  account_ref   TEXT NOT NULL,             -- 合成帳戶識別碼
  case_id       TEXT NOT NULL,             -- 'A' | 'B' | 'C' | 'Cp'
  provider      TEXT NOT NULL,             -- provider_a / provider_b
  score         INTEGER NOT NULL,
  labels        TEXT NOT NULL,             -- JSON array
  observed_at   TEXT NOT NULL
);

-- 8) 稽核鏈(hash chain + 簽章收據;server/audit.ts 唯一寫入入口)
CREATE TABLE IF NOT EXISTS audit_chain (
  seq           INTEGER PRIMARY KEY AUTOINCREMENT,
  prev_hash     TEXT NOT NULL,
  entry_hash    TEXT NOT NULL,             -- sha256(prev_hash ‖ payload_hash ‖ ts)
  sig           TEXT NOT NULL,             -- workload 鑰 Ed25519 簽章(base64url)
  event_type    TEXT NOT NULL,
  payload_json  TEXT NOT NULL,
  created_at    TEXT NOT NULL
);

-- 9) 狀態清單(Token Status List;正式檔為 data/status/*.jwt)
CREATE TABLE IF NOT EXISTS status_lists (
  name          TEXT PRIMARY KEY,          -- 'mandates' | 'credentials'
  uri           TEXT NOT NULL,             -- 引用方 status.status_list.uri
  bits          INTEGER NOT NULL DEFAULT 1,
  size          INTEGER NOT NULL,
  file          TEXT NOT NULL,             -- data/status/<name>.jwt
  updated_at    TEXT NOT NULL
);

-- 10) Dossier(幕 5 門檻與付款閘道;Phase 3a 新增)
-- P3 五要件全過後由 fab-workload 鑰簽之 JWS(payload 含 build_hash/version/五項結果/
-- 三張輸入憑證 hash/case/mandate_jti);財務主管 ECR 鑰簽 release 後狀態轉 RELEASED、
-- 回填 release_jws 與 mock USD 電匯指令(payment_instruction_json)。
-- (mandate_id, request_nonce) UNIQUE 為 POST /api/agent/run 之防重放最終防線,語意同
-- presentations 表對 (mandate_id, request_nonce) 之 UNIQUE 用法。
-- mandate_id 刻意不設 REFERENCES mandates(id)(比照 decisions.mandate_id 之既有慣例):
-- 既有測項會 DELETE FROM mandates WHERE id='M1' 後重簽以驗證併發 insert-if-absent,
-- dossiers 為歷史留痕表,不應因 mandate 列重建而被 FK 卡住。
CREATE TABLE IF NOT EXISTS dossiers (
  id                        TEXT PRIMARY KEY,
  case_id                   TEXT NOT NULL,             -- 'A' | 'B' | 'C' | 'Cp'
  mandate_id                TEXT NOT NULL,             -- 'M1'(對應 mandates.id,無 FK,理由見上)
  mandate_jti               TEXT NOT NULL,
  request_nonce             TEXT NOT NULL,
  jws                       TEXT NOT NULL,             -- fab-workload 簽之 compact JWS
  status                    TEXT NOT NULL,             -- 'PENDING_HUMAN' | 'RELEASED' | 'DEPENDS_REVOKED'
  decision_id               INTEGER,                   -- 對應 P3 PERMIT 之 decisions.id
  release_jws               TEXT,                      -- 財務主管 ECR 鑰簽之 release JWS(human-sign 後回填)
  payment_instruction_json  TEXT,                      -- mock USD 電匯指令(human-sign 後回填;無錢包/RPC/鏈上)
  created_at                TEXT NOT NULL DEFAULT (datetime('now')),
  released_at               TEXT,
  UNIQUE (mandate_id, request_nonce)
);
