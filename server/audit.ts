/**
 * 稽核唯一入口(信任邊界原則 3):所有 PERMIT/DENY/RELEASE/REPLAY_DETECTED
 * 一律經 recordDecision(),decisions 與 audit_chain 在同一筆 better-sqlite3
 * transaction 寫入;DENY 與重放也入鏈。
 *
 * entry_hash = sha256(prev_hash ‖ payload_hash ‖ ts)(hex),
 * 其中 payload_hash = sha256(event_type ‖ '\n' ‖ payload_json)——
 * event_type 一併納入雜湊,防止改寫事件語意而鏈驗證仍過(Codex 審查定案);
 * sig = fab-workload 鑰對 entry_hash 之 Ed25519 簽章(base64url)。
 */
import crypto from 'node:crypto';
import type Database from 'better-sqlite3';
import { loadWorkloadKey } from './keys';
import type { DecisionEffect } from '../shared/types';
import type { ReasonCode } from '../shared/codes';

const GENESIS = '0'.repeat(64);

/** 附加一筆稽核鏈紀錄(呼叫端負責包在 transaction 內)。回傳 seq。 */
export function appendAudit(db: Database.Database, eventType: string, payload: unknown): number {
  const prev = db.prepare('SELECT entry_hash FROM audit_chain ORDER BY seq DESC LIMIT 1').get() as
    | { entry_hash: string }
    | undefined;
  const prevHash = prev?.entry_hash ?? GENESIS;
  const ts = new Date().toISOString();
  const payloadJson = JSON.stringify(payload ?? {});
  const payloadHash = crypto.createHash('sha256').update(`${eventType}\n${payloadJson}`).digest('hex');
  const entryHash = crypto.createHash('sha256').update(prevHash + payloadHash + ts).digest('hex');
  const key = loadWorkloadKey('fab-workload');
  const sig = crypto.sign(null, Buffer.from(entryHash), key.privateKey).toString('base64url');
  const r = db
    .prepare(
      'INSERT INTO audit_chain (prev_hash, entry_hash, sig, event_type, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)',
    )
    .run(prevHash, entryHash, sig, eventType, payloadJson, ts);
  return Number(r.lastInsertRowid);
}

export interface DecisionInput {
  action: string;
  effect: DecisionEffect;
  reason_code: ReasonCode;
  policy_id?: string;
  case_id?: string;
  mandate_id?: string;
  context?: unknown;
}

/** decisions + audit_chain 同一交易(全案唯一決策寫入口)。回傳 decision id 與 audit seq。 */
export function recordDecision(db: Database.Database, d: DecisionInput): { decisionId: number; auditSeq: number } {
  const tx = db.transaction(() => {
    const r = db
      .prepare(
        'INSERT INTO decisions (action, effect, reason_code, policy_id, case_id, mandate_id, context_json) VALUES (?, ?, ?, ?, ?, ?, ?)',
      )
      .run(d.action, d.effect, d.reason_code, d.policy_id ?? null, d.case_id ?? null, d.mandate_id ?? null, JSON.stringify(d.context ?? {}));
    const decisionId = Number(r.lastInsertRowid);
    const auditSeq = appendAudit(db, `decision:${d.effect}`, { decisionId, ...d });
    return { decisionId, auditSeq };
  });
  return tx();
}
