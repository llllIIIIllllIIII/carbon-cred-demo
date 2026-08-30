/**
 * make revoke LIST=credentials|mandates IDX=<n> — 幕 6(稽核與撤銷)操作端 CLI:
 *   翻轉 data/status/<LIST>.jwt 指定 idx 為撤銷(1),以 FAB LE 鑰重簽整份 Token Status List
 *   Token(server/statuslist.ts revokeStatusIndex,經 server/keys.ts 取鑰),寫回同一份
 *   compact signed JWT 檔——不需重啟 `make dev` 即生效(消費端每次現讀該檔,無快取)。
 * idx 固定表見 data/seed.json 之 status_list_idx。裸 JSON bit array 不得出現於正式流程:
 * 輸入輸出皆為 compact 已簽章 JWT。
 *
 * 用法:npx tsx scripts/revoke.ts --list credentials|mandates --idx <n>
 *      make revoke LIST=credentials IDX=4
 *
 * P1-5(Codex 審查):撤銷本身須留痕——CLI 改了權威清單卻不入鏈,等於「撤銷」這個動作不在
 * 防竄改稽核鏈上,違反「撤銷留痕」之鐵律。成功後經 server/audit.ts 之 appendAudit()(唯一
 * 稽核鏈寫入入口)記一筆 admin:revoke 事件(actor=cli),verify-chain.ts 可驗到。
 */
import { openDb } from '../server/db';
import { appendAudit } from '../server/audit';
import { revokeStatusIndex, STATUS_LIST_NAMES, STATUS_LIST_SIZE, type StatusListName } from '../server/statuslist';

interface RevokeArgs {
  list: string;
  idx: number;
}

function parseArgs(argv: string[]): RevokeArgs {
  let list: string | undefined;
  let idxStr: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--list') list = argv[++i];
    else if (argv[i] === '--idx') idxStr = argv[++i];
  }
  list = list ?? process.env.LIST;
  idxStr = idxStr ?? process.env.IDX;
  return { list: list ?? '', idx: idxStr != null ? Number(idxStr) : NaN };
}

async function main(): Promise<void> {
  const { list, idx } = parseArgs(process.argv.slice(2));
  if (!STATUS_LIST_NAMES.includes(list as StatusListName)) {
    throw new Error(`--list 必須是 ${STATUS_LIST_NAMES.join('|')}(收到:"${list}");用法:make revoke LIST=credentials|mandates IDX=<n>`);
  }
  if (!Number.isInteger(idx) || idx < 0 || idx >= STATUS_LIST_SIZE) {
    throw new Error(`--idx 必須是 0~${STATUS_LIST_SIZE - 1} 的整數(收到:"${Number.isNaN(idx) ? '' : idx}")`);
  }
  await revokeStatusIndex(list as StatusListName, idx);

  const db = openDb();
  try {
    appendAudit(db, 'admin:revoke', { list, idx, actor: 'cli' });
  } finally {
    db.close();
  }

  console.log(`已撤銷 ${list} idx=${idx}(以 FAB LE 鑰重簽 data/status/${list}.jwt;不重啟即生效;已入稽核鏈)`);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
