/**
 * mandates 表存取小工具——仿 server/creds/store.ts 之原子 get-or-create 模式
 * (insertCredentialIfAbsent),避免 M1/M2 併發簽發各自落庫不同 token(同一併發競態
 * 類型,見 store.ts 註解之 Codex 審查發現 1)。
 */
import type Database from 'better-sqlite3';
import type { MandateId } from '../../shared/types';

export interface MandateRecord {
  id: MandateId;
  jti: string;
  issuerParty: string;
  aud: string;
  purpose?: string;
  agentId?: string;
  delegateKid: string;
  allowedClaims: string[];
  maxGranularity: string;
  queryCap?: number;
  policyVersion: string;
  mandateNonce: string;
  extra?: Record<string, unknown>;
  token: string;
  statusIdx: number;
  statusUri: string;
  validFrom: string;
  validUntil: string;
}

export interface MandateRow {
  id: string;
  jti: string;
  issuer_party: string;
  aud: string;
  purpose: string | null;
  agent_id: string | null;
  delegate_kid: string;
  allowed_claims: string;
  max_granularity: string;
  query_cap: number | null;
  queries_used: number;
  policy_version: string;
  mandate_nonce: string;
  extra_json: string | null;
  token: string | null;
  status_idx: number;
  status_uri: string;
  valid_from: string;
  valid_until: string;
  created_at: string;
}

export function getMandate(db: Database.Database, id: string): MandateRow | undefined {
  return db.prepare('SELECT * FROM mandates WHERE id = ?').get(id) as MandateRow | undefined;
}

/** 幕 3 disclose:request_jws payload.mandate_id 實為 mandate.jti(非 db 之 id),須以此查表。 */
export function getMandateByJti(db: Database.Database, jti: string): MandateRow | undefined {
  return db.prepare('SELECT * FROM mandates WHERE jti = ?').get(jti) as MandateRow | undefined;
}

export interface InsertMandateIfAbsentResult {
  row: MandateRow;
  /** true = 本次插入被忽略(另一併發請求先落庫);呼叫端應棄用自己剛簽的 token,改採 row。 */
  reused: boolean;
}

/** 原子 get-or-create(比照 store.ts insertCredentialIfAbsent);id('M1'/'M2')為 mandates 表 PRIMARY KEY。 */
export function insertMandateIfAbsent(db: Database.Database, rec: MandateRecord): InsertMandateIfAbsentResult {
  const info = db
    .prepare(
      `INSERT OR IGNORE INTO mandates
         (id, jti, issuer_party, aud, purpose, agent_id, delegate_kid, allowed_claims, max_granularity,
          query_cap, queries_used, policy_version, mandate_nonce, extra_json, token, status_idx, status_uri,
          valid_from, valid_until)
       VALUES
         (@id, @jti, @issuer_party, @aud, @purpose, @agent_id, @delegate_kid, @allowed_claims, @max_granularity,
          @query_cap, 0, @policy_version, @mandate_nonce, @extra_json, @token, @status_idx, @status_uri,
          @valid_from, @valid_until)`,
    )
    .run({
      id: rec.id,
      jti: rec.jti,
      issuer_party: rec.issuerParty,
      aud: rec.aud,
      purpose: rec.purpose ?? null,
      agent_id: rec.agentId ?? null,
      delegate_kid: rec.delegateKid,
      allowed_claims: JSON.stringify(rec.allowedClaims),
      max_granularity: rec.maxGranularity,
      query_cap: rec.queryCap ?? null,
      policy_version: rec.policyVersion,
      mandate_nonce: rec.mandateNonce,
      extra_json: rec.extra ? JSON.stringify(rec.extra) : null,
      token: rec.token,
      status_idx: rec.statusIdx,
      status_uri: rec.statusUri,
      valid_from: rec.validFrom,
      valid_until: rec.validUntil,
    });
  const row = getMandate(db, rec.id);
  if (!row) throw new Error(`原子插入後讀不到該筆 mandate(id=${rec.id})——不應發生`);
  return { row, reused: info.changes === 0 };
}

/** query_cap 扣次(呼叫端須包在與 presentations 寫入/audit 相同的 better-sqlite3 transaction 內)。 */
export function incrementMandateQueriesUsed(db: Database.Database, id: string): void {
  db.prepare('UPDATE mandates SET queries_used = queries_used + 1 WHERE id = ?').run(id);
}
