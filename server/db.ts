import fs from 'node:fs';
import path from 'node:path';
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

/** 開啟(必要時建立)資料庫並套用 schema。 */
export function openDb(dbPath: string = DB_PATH): Database.Database {
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.exec(fs.readFileSync(SCHEMA_PATH, 'utf-8'));
  return db;
}

/** 只讀開啟;資料庫不存在時回傳 null(供 Phase 0 殼路由容錯)。 */
export function openDbIfExists(dbPath: string = DB_PATH): Database.Database | null {
  if (!fs.existsSync(dbPath)) return null;
  return openDb(dbPath);
}
