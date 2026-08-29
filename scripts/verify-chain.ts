/**
 * scripts/verify-chain.ts — 幕 4 DoD:「deny 事件能被 verify-chain.ts 驗到」
 * (證明「連拒絕都留痕」;架構決策/藍圖 幕4 ④)。
 *
 * 逐列重算 CLAUDE.md Codex 審查定案之雜湊公式:
 *   payload_hash = sha256(event_type ‖ '\n' ‖ payload_json)
 *   entry_hash   = sha256(prev_hash ‖ payload_hash ‖ ts)
 * 並驗 sig(fab-workload 鑰之 Ed25519 簽章,對 entry_hash)。斷鏈/竄改/簽章不符
 * → 非零退出 + AUDIT_CHAIN_TAMPERED。
 *
 * 用法:npx tsx scripts/verify-chain.ts [--db <sqlite 檔路徑,預設 db/demo.sqlite>]
 */
import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import { DB_PATH } from '../server/db';
import { loadWorkloadKey } from '../server/keys';
import { CODES } from '../shared/codes';

const GENESIS = '0'.repeat(64);

interface AuditRow {
  seq: number;
  prev_hash: string;
  entry_hash: string;
  sig: string;
  event_type: string;
  payload_json: string;
  created_at: string;
}

function parseDbPath(argv: string[]): string {
  const i = argv.indexOf('--db');
  return i !== -1 && argv[i + 1] ? argv[i + 1] : DB_PATH;
}

function main() {
  const dbPath = parseDbPath(process.argv.slice(2));
  console.log(`== verify-chain(db=${dbPath})==`);

  const db = new Database(dbPath, { readonly: true, fileMustExist: true });
  const rows = db.prepare('SELECT seq, prev_hash, entry_hash, sig, event_type, payload_json, created_at FROM audit_chain ORDER BY seq ASC').all() as AuditRow[];
  db.close();

  const publicKey = loadWorkloadKey('fab-workload').publicKey;
  let prevHash = GENESIS;
  let tampered = false;
  let denyLikeCount = 0;

  console.log(`共 ${rows.length} 筆稽核紀錄`);
  for (const row of rows) {
    const payloadHash = crypto.createHash('sha256').update(`${row.event_type}\n${row.payload_json}`).digest('hex');
    const expectedEntryHash = crypto.createHash('sha256').update(prevHash + payloadHash + row.created_at).digest('hex');
    const prevLinkOk = row.prev_hash === prevHash;
    const hashOk = row.entry_hash === expectedEntryHash;
    let sigOk = false;
    try {
      sigOk = crypto.verify(null, Buffer.from(row.entry_hash), publicKey, Buffer.from(row.sig, 'base64url'));
    } catch {
      sigOk = false;
    }
    const ok = prevLinkOk && hashOk && sigOk;
    if (!ok) tampered = true;
    if (/DENY|REPLAY_DETECTED/.test(row.event_type)) denyLikeCount++;
    console.log(`  ${ok ? '✓' : '✗'} #${row.seq} ${row.event_type}${ok ? '' : ` (prevLink=${prevLinkOk} hash=${hashOk} sig=${sigOk})`}`);
    prevHash = row.entry_hash;
  }

  console.log(`拒絕/重放類事件(DENY/REPLAY_DETECTED)在鏈上共 ${denyLikeCount} 筆(幕 4 DoD:連拒絕都留痕)`);

  if (tampered) {
    console.log(`== 結果:鏈驗證失敗 — ${CODES.AUDIT_CHAIN_TAMPERED} ==`);
    process.exit(1);
  }
  console.log('== 結果:鏈完整,全數驗證通過 ==');
  process.exit(0);
}

main();
