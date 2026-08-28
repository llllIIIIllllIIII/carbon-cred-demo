import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const DB_PATH = path.join(ROOT, 'db', 'demo.sqlite');
const SCHEMA_PATH = path.join(ROOT, 'db', 'schema.sql');

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
