/**
 * credentials 表存取小工具——幕 1(pcf_upstream)/幕 2(pcf_aggregate)共用同一張表 schema
 * (db/schema.sql 第 2 張表),避免各 route 各自重複同一段 SQL。
 */
import type Database from 'better-sqlite3';

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

/** 寫入/更新一筆憑證(id 衝突則覆蓋簽發相關欄位;case_id/issuer_party/holder_party 不因重簽而變動)。 */
export function upsertCredential(db: Database.Database, rec: CredentialRecord): void {
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
  return { row, reused: info.changes === 0 };
}
