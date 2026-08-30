import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DB_PATH = path.join(ROOT, 'db', 'demo.sqlite');
const SCHEMA_PATH = path.join(ROOT, 'db', 'schema.sql');

/**
 * vLEI 公開狀態目錄(H3 修法):sandbox verify 需要一份 workspace 才能查驗信任鏈,
 * 但 `.vlei/` 內含各方私鑰種子,Brand 端不得讀(CLAUDE.md:25)。改由 server/keys.ts
 * (全案唯一可讀 state.json 之模組)匯出「去除 seed/next_seed 的公開子集」到本目錄,
 * Brand 端驗證只對這份公開材料執行 sandbox verify——路徑常數放這裡供雙方共用,
 * 避免 keys.ts ↔ manifest.ts 迴圈相依。實體檔案:<此目錄>/.vlei/state.json
 * (`.vlei` 子目錄名由 vendor/vlei-sandbox 之 WORKSPACE 常數決定,vendor 唯讀不得改)。
 */
export const VLEI_PUBLIC_STATE_DIR = path.join(ROOT, 'data', 'vlei', 'public-state');

/**
 * P1-2(Codex 審查第二輪):既有(pre-3b,或未經 make demo-reset 之舊)DB 開啟時,
 * credential_history 表可能是空的,但 credentials 表已有既存憑證列——agent/run 沿用
 * 既有列(冪等路徑,不重簽、不呼叫寫史 helper)簽發之 Dossier,其 credential_hashes 會在
 * credential_history 查無版本,human-sign/GET /api/dossiers 因此誤判 DEPENDS_REVOKED。
 * 每次 openDb() 皆對現況 credentials 表逐列 backfill(INSERT OR IGNORE,依 hash 去重)——
 * 對全新庫(credentials 表本就空)或已補齊之庫皆為零筆/低成本 no-op,不影響正常 make setup。
 */
function backfillCredentialHistory(db: Database.Database): void {
  const rows = db.prepare('SELECT id, type, sd_jwt FROM credentials WHERE sd_jwt IS NOT NULL').all() as {
    id: string;
    type: string;
    sd_jwt: string;
  }[];
  if (rows.length === 0) return;
  const insert = db.prepare('INSERT OR IGNORE INTO credential_history (hash, id, type, sd_jwt) VALUES (?, ?, ?, ?)');
  const tx = db.transaction((items: typeof rows) => {
    for (const r of items) {
      insert.run(crypto.createHash('sha256').update(r.sd_jwt).digest('hex'), r.id, r.type, r.sd_jwt);
    }
  });
  tx(rows);
}

/** 開啟(必要時建立)資料庫並套用 schema。 */
export function openDb(dbPath: string = DB_PATH): Database.Database {
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.exec(fs.readFileSync(SCHEMA_PATH, 'utf-8'));
  backfillCredentialHistory(db);
  return db;
}

/** 只讀開啟;資料庫不存在時回傳 null(供 Phase 0 殼路由容錯)。 */
export function openDbIfExists(dbPath: string = DB_PATH): Database.Database | null {
  if (!fs.existsSync(dbPath)) return null;
  return openDb(dbPath);
}
