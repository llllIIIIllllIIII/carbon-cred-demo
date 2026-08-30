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

/**
 * 附加一筆稽核鏈紀錄。回傳 seq。
 * P1-4(Codex 審查第二輪):SELECT prev_hash + INSERT 本體包在同一 immediate transaction 內,
 * 序列化所有寫入者——原本兩者各自獨立陳述式,若兩個呼叫端(如 reissue supersede 之裸
 * appendAudit、scripts/revoke.ts CLI、POST /api/audit/revoke)併發呼叫,可能都 SELECT 到
 * 同一個「尾列」、各自算出 entry_hash 後插入兩筆互為兄弟的列(prev_hash 相同)——
 * verify-chain.ts 只會接受其中一筆銜接得上,判另一筆為斷鏈竄改。immediate 模式在 BEGIN
 * 當下就取得寫入鎖,確保 SELECT 讀到的必是「目前唯一、已提交」的尾列。可安全巢狀於
 * recordDecision 的外層交易內(better-sqlite3 以 SAVEPOINT 實作巢狀交易,已實測巢狀
 * .immediate() 呼叫不拋錯)。
 */
export function appendAudit(db: Database.Database, eventType: string, payload: unknown): number {
  const tx = db.transaction((): number => {
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
  });
  return tx.immediate();
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
  // P1-4(Codex 審查第二輪):outer transaction 亦改 immediate,與 appendAudit 內層一致,
  // 使 decisions+audit_chain 這一整組寫入從 BEGIN 起就序列化,不再依賴「deferred 交易於
  // 第一個寫入陳述式才升級鎖」的時序(該時序在高併發下仍可能讓 SELECT 讀到陳舊 tip)。
  return tx.immediate();
}
