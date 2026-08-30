/**
 * credentials 表存取小工具——幕 1(pcf_upstream)/幕 2(pcf_aggregate)共用同一張表 schema
 * (db/schema.sql 第 2 張表),避免各 route 各自重複同一段 SQL。
 *
 * Codex 審查 P1-1 修法(Phase 3b):每次落庫(insertCredentialIfAbsent/upsertCredential)
 * 一併寫入 credential_history(append-only,以 sha256(sd_jwt) 為主鍵)——reissue 會覆蓋
 * credentials 表同 id 那一列,但 Dossier JWS 凍結的 credential_hashes 指向「建卡當下那一版」,
 * 若不留歷史,重驗撤銷狀態時會被迫改看「現況」列而誤判(見 server/routes/agent.ts
 * checkDossierInputsCurrent 之說明)。
 */
import crypto from 'node:crypto';
import type Database from 'better-sqlite3';

function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/** 供 insertCredentialIfAbsent/upsertCredential 內部呼叫;同一 hash 已存在則忽略(同內容只留一份)。 */
function recordCredentialHistory(db: Database.Database, id: string, type: string, sdJwt: string): void {
  db.prepare('INSERT OR IGNORE INTO credential_history (hash, id, type, sd_jwt) VALUES (?, ?, ?, ?)').run(
    sha256Hex(sdJwt),
    id,
    type,
    sdJwt,
  );
}

/** 供撤銷重驗端(checkDossierInputsCurrent)以 Dossier 凍結之 hash 查回「那一版」sd_jwt。 */
export function getCredentialHistoryByHash(db: Database.Database, hash: string): { sd_jwt: string } | undefined {
  return db.prepare('SELECT sd_jwt FROM credential_history WHERE hash = ?').get(hash) as { sd_jwt: string } | undefined;
}

export interface CredentialRecord {
  id: string;
  type: string;
  caseId: string | null;
  issuerParty: string;
  holderParty: string | null;
  sdJwt: string;
  payload: unknown;
  statusIdx: number;
  statusUri: string;
  issuedAt: string;
  validFrom: string;
  validUntil: string;
}

export interface CredentialRow {
  id: string;
  type: string;
  case_id: string | null;
  issuer_party: string;
  holder_party: string | null;
  sd_jwt: string;
  payload_json: string;
  status_idx: number;
  status_uri: string;
  issued_at: string;
  valid_from: string;
  valid_until: string;
}

/**
 * 寫入/更新一筆憑證(id 衝突則覆蓋簽發相關欄位;case_id/issuer_party/holder_party 不因重簽而變動)。
 * P2-6(Codex 審查第二輪):credentials 寫入與 credential_history 寫入包在同一 immediate
 * transaction 內——原本兩個各自獨立的陳述式,若 commit credentials 後、寫 history 前行程中止
 * (crash/例外),會留下「有 credential 但缺 history」的列;且正常簽發之冪等路徑常在下次呼叫
 * 直接回傳既有 credential(不再呼叫本函式補寫 history),使該筆憑證往後建立的 Dossier 永遠
 * 解不回歷史版本、被誤判 DEPENDS_REVOKED。immediate 交易確保兩寫入要嘛都成功、要嘛都不寫。
 */
export function upsertCredential(db: Database.Database, rec: CredentialRecord): void {
  const tx = db.transaction(() => {
    db.prepare(
      `INSERT INTO credentials
         (id, type, case_id, issuer_party, holder_party, sd_jwt, payload_json, status_idx, status_uri, issued_at, valid_from, valid_until)
       VALUES
         (@id, @type, @case_id, @issuer_party, @holder_party, @sd_jwt, @payload_json, @status_idx, @status_uri, @issued_at, @valid_from, @valid_until)
       ON CONFLICT(id) DO UPDATE SET
         sd_jwt = excluded.sd_jwt,
         payload_json = excluded.payload_json,
         status_idx = excluded.status_idx,
         status_uri = excluded.status_uri,
         issued_at = excluded.issued_at,
         valid_from = excluded.valid_from,
         valid_until = excluded.valid_until`,
    ).run({
      id: rec.id,
      type: rec.type,
      case_id: rec.caseId,
      issuer_party: rec.issuerParty,
      holder_party: rec.holderParty,
      sd_jwt: rec.sdJwt,
      payload_json: JSON.stringify(rec.payload),
      status_idx: rec.statusIdx,
      status_uri: rec.statusUri,
      issued_at: rec.issuedAt,
      valid_from: rec.validFrom,
      valid_until: rec.validUntil,
    });
    recordCredentialHistory(db, rec.id, rec.type, rec.sdJwt);
  });
  tx.immediate();
}

/** 讀一筆憑證(找不到回傳 undefined)——幕 2 用來判斷該案上游憑證是否已簽發過。 */
export function getCredential(db: Database.Database, id: string): CredentialRow | undefined {
  return db.prepare('SELECT * FROM credentials WHERE id = ?').get(id) as CredentialRow | undefined;
}

export interface InsertIfAbsentResult {
  row: CredentialRow;
  /** true = 本次插入被忽略(另一併發請求先落庫);呼叫端應棄用自己剛簽出的 token,改採 row。 */
  reused: boolean;
}

/**
 * 原子 get-or-create(Codex 審查發現 1 之修法)——「讀→await 簽章→無條件 upsert」在併發下會讓兩個
 * 請求各自簽出內容相同、位元組不同的 SD-JWT(隨機 disclosure 鹽),最後 upsert 覆蓋導致下游已引用
 * 其 hash 的憑證(如 pcf_aggregate.precursor_ref)對不上「現在」DB 裡的版本。
 * 改用 INSERT OR IGNORE(id 為 PRIMARY KEY,衝突即忽略,不覆寫)——插入後一律重讀 DB,回傳落庫勝者;
 * 呼叫端若輸掉競態(reused=true),須丟棄自己剛簽的 token,改用 row 內的落庫版本作為回應/後續引用依據。
 */
export function insertCredentialIfAbsent(db: Database.Database, rec: CredentialRecord): InsertIfAbsentResult {
  // P2-6(Codex 審查第二輪):credential 插入 + history 記錄包在同一 immediate transaction
  // 內(理由同 upsertCredential 之說明)。
  const tx = db.transaction((): InsertIfAbsentResult => {
    const info = db
      .prepare(
        `INSERT OR IGNORE INTO credentials
           (id, type, case_id, issuer_party, holder_party, sd_jwt, payload_json, status_idx, status_uri, issued_at, valid_from, valid_until)
         VALUES
           (@id, @type, @case_id, @issuer_party, @holder_party, @sd_jwt, @payload_json, @status_idx, @status_uri, @issued_at, @valid_from, @valid_until)`,
      )
      .run({
        id: rec.id,
        type: rec.type,
        case_id: rec.caseId,
        issuer_party: rec.issuerParty,
        holder_party: rec.holderParty,
        sd_jwt: rec.sdJwt,
        payload_json: JSON.stringify(rec.payload),
        status_idx: rec.statusIdx,
        status_uri: rec.statusUri,
        issued_at: rec.issuedAt,
        valid_from: rec.validFrom,
        valid_until: rec.validUntil,
      });
    const row = getCredential(db, rec.id);
    if (!row) throw new Error(`原子插入後讀不到該筆憑證(id=${rec.id})——不應發生`);
    // 一律以「落庫勝者」之內容記歷史(自己輸掉競態時,history 早已由勝者那次呼叫寫入;
    // INSERT OR IGNORE 依 hash 去重,重複呼叫安全)。
    recordCredentialHistory(db, row.id, row.type, row.sd_jwt);
    return { row, reused: info.changes === 0 };
  });
  return tx.immediate();
}
