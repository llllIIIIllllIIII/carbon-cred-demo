/**
 * make untamper — 還原 make tamper 建立的 row-level 備份(db/.tamper-backup.json)——把
 * audit_chain 該筆之 payload_json 復原為竄改前的原始值,再移除備份側車檔。
 * 見 scripts/tamper.ts 檔頭註解:改用 row-level 備份(而非整份 db 檔複製)之原因。
 */
import fs from 'node:fs';
import path from 'node:path';
import { openDb } from '../server/db';
import { TAMPER_BACKUP_PATH } from './tamperBackup';

interface TamperBackup {
  seq: number;
  payload_json: string;
}

function main(): void {
  if (!fs.existsSync(TAMPER_BACKUP_PATH)) {
    throw new Error(`找不到備份檔 ${path.relative(process.cwd(), TAMPER_BACKUP_PATH)}——請先跑 make tamper N=<n>`);
  }
  const backup = JSON.parse(fs.readFileSync(TAMPER_BACKUP_PATH, 'utf-8')) as TamperBackup;
  if (typeof backup.seq !== 'number' || typeof backup.payload_json !== 'string') {
    throw new Error(`備份檔內容異常(缺 seq/payload_json):${path.relative(process.cwd(), TAMPER_BACKUP_PATH)}`);
  }

  const db = openDb();
  try {
    const info = db.prepare('UPDATE audit_chain SET payload_json = ? WHERE seq = ?').run(backup.payload_json, backup.seq);
    if (info.changes === 0) {
      throw new Error(`還原失敗:audit_chain 找不到 seq=${backup.seq}(備份檔未移除,可手動確認後重試)`);
    }
  } finally {
    db.close();
  }

  fs.rmSync(TAMPER_BACKUP_PATH);
  console.log(`已還原 audit_chain 第 ${backup.seq} 筆之原始 payload_json(移除備份 ${path.relative(process.cwd(), TAMPER_BACKUP_PATH)})`);
}

try {
  main();
} catch (e) {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
}
