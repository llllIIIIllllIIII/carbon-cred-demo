/**
 * scripts/verify-offline.ts — 幕 3 DoD:「斷網狀態驗證仍成功」的離線示範腳本
 * (architecture:110)。零網路呼叫(不開 HTTP server、不連閘道 API);只讀
 * token、manifest 公鑰、data/vlei/、data/status/ 本機檔案,與 POST /api/verify
 * 共用同一驗證核心(server/creds/verifyPresentation.ts),避免雙寫。
 *
 * 用法:
 *   npx tsx scripts/verify-offline.ts --presentation <file> --mandate <file>
 *   或不帶參數,從 stdin 讀一段 JSON:{ "presentation": "...", "mandate_jwt": "..." }
 *
 * 輸出逐項 ✓/✗ 報告;全數通過 exit 0,任一失敗 exit 1。
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { readManifest } from '../server/manifest';
import { verifyPresentation } from '../server/creds/verifyPresentation';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function parseArgs(argv: string[]): { presentation?: string; mandate?: string; receipt?: string } {
  const out: { presentation?: string; mandate?: string; receipt?: string } = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--presentation') out.presentation = argv[++i];
    else if (argv[i] === '--mandate') out.mandate = argv[++i];
    else if (argv[i] === '--receipt') out.receipt = argv[++i];
  }
  return out;
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

async function loadInput(): Promise<{ presentation: string; mandate_jwt: string; receipt?: string }> {
  const args = parseArgs(process.argv.slice(2));
  if (args.presentation && args.mandate) {
    return {
      presentation: fs.readFileSync(path.resolve(ROOT, args.presentation), 'utf-8').trim(),
      mandate_jwt: fs.readFileSync(path.resolve(ROOT, args.mandate), 'utf-8').trim(),
      // F4:閘道 receipt(key-binding);離線驗證同樣須驗此 receipt 才算通過。
      receipt: args.receipt ? fs.readFileSync(path.resolve(ROOT, args.receipt), 'utf-8').trim() : undefined,
    };
  }
  const stdin = await readStdin();
  const parsed = JSON.parse(stdin) as { presentation?: string; mandate_jwt?: string; receipt?: string };
  if (!parsed.presentation || !parsed.mandate_jwt) {
    throw new Error('stdin JSON 須含 presentation 與 mandate_jwt 兩個欄位');
  }
  return { presentation: parsed.presentation, mandate_jwt: parsed.mandate_jwt, receipt: parsed.receipt };
}

async function main() {
  console.log('== verify-offline(幕 3 DoD:斷網狀態驗證)==');

  const manifest = readManifest();
  if (!manifest) {
    console.error('manifest.json 不存在——先跑 make setup(scripts/presign-vlei.sh)。');
    process.exit(1);
  }

  let input: { presentation: string; mandate_jwt: string; receipt?: string };
  try {
    input = await loadInput();
  } catch (e) {
    console.error(`輸入讀取失敗:${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
    return;
  }

  const result = await verifyPresentation({
    presentationSdJwt: input.presentation,
    mandateJwt: input.mandate_jwt,
    manifest,
    receipt: input.receipt,
  });

  for (const check of result.checks) {
    const mark = check.ok ? '✓' : '✗';
    const suffix = check.ok ? '' : ` — ${check.reasonCode ?? ''}${check.detail ? `:${check.detail}` : ''}`;
    console.log(`  ${mark} ${check.name}${suffix}`);
  }
  console.log(result.ok ? '== 結果:全數通過(OFFLINE)==' : '== 結果:驗證失敗 ==');
  process.exit(result.ok ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
