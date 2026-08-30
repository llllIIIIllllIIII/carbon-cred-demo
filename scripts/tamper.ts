/**
 * make tamper N=<seq> — 幕 6 稽核鏈竄改示範(brief phase-3b §1.6):對 audit_chain 第 N 筆
 * (seq=N)之 payload_json 做一行 sqlite UPDATE(entry_hash/sig 不動)——使該筆之 payload_hash
 * 與既存 entry_hash 對不上,`make verify-chain` 應自該筆起回報 FAIL。竄改內容維持合法 JSON
 * (僅改一個既有欄位值),不觸碰任何鑰或簽章邏輯。用 `make untamper` 還原。
 *
 * 備份設計(row-level,非整檔複製):只備份「第 N 筆原始 payload_json」到一個小型 JSON
 * 側車檔(db/.tamper-backup.json),而非複製整份 db/demo.sqlite。原因(實測發現):
 * 這支 CLI 與長駐的 `make dev`/`make test` 行程共用同一份 WAL 模式 sqlite 檔,若對整份
 * db 檔做「checkpoint + fs.copyFileSync 整檔複製」再由 make untamper 事後整檔覆寫回去,
 * 在同一個長時間執行的 node 行程(如 scripts/test.ts 一次跑數百項檢查)反覆呼叫兩輪
 * tamper/untamper 後,曾實測觸發 `SQLITE_IOERR_SHORT_READ`(其他行程置換底層檔案內容,
 * 與長駐行程既有的 WAL/共享記憶體狀態不同步)。改成只 UPDATE/還原「這一列」,透過與
 * server/db.ts 相同的 openDb() 走正常 WAL 讀寫路徑,不做任何整檔層級的檔案置換,
 * 可穩定重跑多輪且行為完全等價(tamper 可逆、verify-chain 前後對照皆正確)。
 *
 * P2-7(Codex 審查)兩項修法(於 row-level 備份下同樣適用):
 *   1. 備份檔已存在時拒絕執行——原（整檔複製版)實作無條件覆寫既有備份,使第二次 make tamper
 *      悄悄把第一次 tamper 前的原始內容沖掉,之後 make untamper 再也還原不回最初狀態。
 *   2. 備份前先確認目標列存在——原實作對無效 seq 仍先建立/覆寫備份,才在讀不到列時報錯。
 *      改為:先查目標列存在,確認通過才寫備份檔,無效 seq 直接報錯、不建立任何備份。
 *
 * P2-8(Codex 審查第二輪):備份檔改以獨占 'wx' flag 建立(單一原子系統呼叫),取代「先
 * fs.existsSync 檢查、再 fs.writeFileSync」兩步式——原兩步式中間有 TOCTOU 空隙:兩個併發
 * `make tamper`(鎖定不同列)皆可能通過 existsSync 檢查,其一之 writeFileSync 覆寫另一之
 * 備份,之後 make untamper 只還原得回其中一筆。'wx' 檔案不存在才成功建立,已存在必定拋
 * EEXIST,不會有「兩者都通過檢查」的中間態。
 */
import fs from 'node:fs';
import path from 'node:path';
import { DB_PATH, openDb } from '../server/db';
import { TAMPER_BACKUP_PATH } from './tamperBackup';

interface TamperBackup {
  seq: number;
  payload_json: string;
}

function parseN(argv: string[]): number {
  let v: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--n' || argv[i] === '-n') v = argv[++i];
  }
  v = v ?? process.env.N;
  const n = v != null ? Number(v) : NaN;
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error('請指定合法的稽核鏈序號,例如:make tamper N=42(或 npx tsx scripts/tamper.ts --n 42)');
  }
  return n;
}

/** 竄改一段 JSON 文字(維持合法 JSON,保證與原字串不同):改動第一個非空字串欄位,
 * 找不到則改動第一個數字欄位,皆無則加一個標記欄位。非 JSON 內容則直接附加字元作退路。 */
function tamperJsonText(text: string): string {
  try {
    const obj = JSON.parse(text) as Record<string, unknown>;
    for (const k of Object.keys(obj)) {
      const v = obj[k];
      if (typeof v === 'string' && v.length > 0) {
        obj[k] = `${v}·TAMPERED`;
        return JSON.stringify(obj);
      }
    }
    for (const k of Object.keys(obj)) {
      if (typeof obj[k] === 'number') {
        obj[k] = (obj[k] as number) + 1;
        return JSON.stringify(obj);
      }
    }
    return JSON.stringify({ ...obj, __tampered: true });
  } catch {
    return `${text} `;
  }
}

function main(): void {
  const n = parseN(process.argv.slice(2));
  if (!fs.existsSync(DB_PATH)) {
    throw new Error(`db 不存在:${DB_PATH}(先跑 make setup)`);
  }

  const db = openDb();
  try {
    // P2-7 修法:先確認目標列存在,才寫備份——無效 seq 直接報錯,備份/db 皆不變動。
    const targetRow = db.prepare('SELECT seq, payload_json FROM audit_chain WHERE seq = ?').get(n) as
      | { seq: number; payload_json: string }
      | undefined;
    if (!targetRow) {
      throw new Error(`audit_chain 找不到 seq=${n}——可先跑 make verify-chain 查看目前共幾筆(備份未建立,db 未變動)`);
    }

    // P2-8 修法:備份以獨占 'wx' 建立——已存在必定拋 EEXIST,無 TOCTOU 空隙可被併發覆寫。
    const backup: TamperBackup = { seq: targetRow.seq, payload_json: targetRow.payload_json };
    try {
      fs.writeFileSync(TAMPER_BACKUP_PATH, JSON.stringify(backup), { flag: 'wx' });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'EEXIST') {
        throw new Error(
          `備份檔已存在:${path.relative(process.cwd(), TAMPER_BACKUP_PATH)}——拒絕覆寫(可能是前一次/併發之 make tamper 尚未 make untamper)。` +
            `請先 make untamper 還原,或確認無誤後手動移除該備份再重試。`,
        );
      }
      throw e;
    }
    console.log(`已備份第 ${n} 筆原始 payload_json → ${path.relative(process.cwd(), TAMPER_BACKUP_PATH)}`);

    const tampered = tamperJsonText(targetRow.payload_json);
    db.prepare('UPDATE audit_chain SET payload_json = ? WHERE seq = ?').run(tampered, n);
  } finally {
    db.close();
  }
  console.log(`已竄改 audit_chain 第 ${n} 筆之 payload_json(entry_hash/sig 不動;make verify-chain 應自該筆起 FAIL)`);
}

try {
  main();
} catch (e) {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
}
