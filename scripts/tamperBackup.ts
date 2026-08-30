/**
 * 幕 6 tamper/untamper 共用之備份路徑常數——獨立成小檔,避免 scripts/untamper.ts 若改為
 * `import { TAMPER_BACKUP_PATH } from './tamper'` 會連帶執行 scripts/tamper.ts 模組頂層的
 * `main()` 呼叫(該呼叫在無 --n 參數時會拋錯並 process.exit(1),使 untamper 尚未執行就中止)。
 *
 * row-level 備份(見 scripts/tamper.ts 檔頭註解):此檔為小型 JSON 側車檔(僅存
 * { seq, payload_json }),不是整份 db 的複本。
 */
import path from 'node:path';
import { ROOT } from '../server/db';

export const TAMPER_BACKUP_PATH = path.join(ROOT, 'db', '.tamper-backup.json');
