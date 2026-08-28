/**
 * make test — Phase 0 驗收(全綠才算過):
 *  1) /api/healthz 200
 *  2) GET /status/mandates:Content-Type application/statuslist+jwt;
 *     先驗 compact JWS 簽章(manifest 公鑰),再解碼 payload.status_list(bits==1、lst 可 zlib 解壓)
 *  3) manifest.json 存在且 6 角色齊(四家法人 + 兩張 ECR)
 *  4) sandbox verify 對兩張 ECR SAID 成功
 *  5) key loader 以 Thép Việt LE 鑰簽測試 payload、以 manifest 公鑰驗證
 *  6) git check-ignore:.vlei/、data/keys/、db/*.sqlite
 *  7) 一致性守門(docs/ 與程式目錄)
 */
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { jwtVerify, decodeProtectedHeader } from 'jose';
import { buildServer } from '../server/index';
import { ROOT } from '../server/db';
import { loadSandboxKey, publicKeyFromQb64 } from '../server/keys';
import { STATUS_MEDIA_TYPE, STATUS_LIST_SIZE } from '../server/statuslist';
import type { Manifest } from '../shared/types';

let passed = 0;
let failed = 0;
function check(name: string, ok: boolean, detail = '') {
  if (ok) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

// ---------- 一致性守門 ----------
const NEG = /(不|禁|移除|非|棄|僅|保底|fallback|mock|合成|out of (core )?scope)/i;
const EXT = new Set(['.md', '.html', '.ts', '.tsx', '.sql', '.cedar', '.sh']);

function* walk(dir: string): Generator<string> {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (EXT.has(path.extname(e.name))) yield p;
  }
}

function consistencyScan(): string[] {
  const dirs = ['docs', 'server', 'shared', 'scripts', 'web/src', 'policies'];
  const self = path.join(ROOT, 'scripts', 'test.ts');
  const violations: string[] = [];
  // 文字規則(同一行有否定/範圍標記者豁免——docs 內以「不得出現…」引用禁詞屬合法)
  const textRules: Array<[string, RegExp]> = [
    ['5 個角色', /(5 ?個角色|五個角色)/],
    ['三家法人 / 3 LE', /(三家法人|(^|[^0-9A-Za-z])3 ?LE([^0-9A-Za-z]|$))/],
    ['五案 / 五組 seed', /(五案|五組)/],
    ['human.key', /human[._]key/i],
    ['status_list_ref', /status_list_ref/],
    ['encodedList', /encodedList/],
    ['單一 workload.key 命名', /(?<!hunggang-)(?<!bruck-)workload\.key/],
    ['錢包/RPC/testnet 建立指示', /(testnet|RPC 連線|建立錢包)/i],
  ];
  // 裸 bit array 僅得與 fallback/保底 同現
  const nakedRule: [string, RegExp, RegExp] = ['裸 bit array 未標示 fallback', /(裸[^\n]{0,8}bit|裸 ?JSON)/i, /(fallback|保底|明確標示)/];
  // 程式檔硬規則(無豁免):不得出現任何鏈上連線/錢包建立技術指標
  const codeHard: [string, RegExp] = ['程式含鏈上/testnet 技術指標', /(testnet|sepolia|goerli|JsonRpcProvider|createWallet|new +Wallet\(|infura|mnemonic)/];

  for (const d of dirs) {
    const full = path.join(ROOT, d);
    if (!fs.existsSync(full)) continue;
    for (const file of walk(full)) {
      if (path.resolve(file) === path.resolve(self)) continue; // 本檔以字面值持有禁詞
      const rel = path.relative(ROOT, file);
      const isDoc = /\.(md|html)$/.test(file);
      const lines = fs.readFileSync(file, 'utf-8').split('\n');
      lines.forEach((line, i) => {
        for (const [rule, re] of textRules) {
          if (re.test(line) && !NEG.test(line)) violations.push(`${rel}:${i + 1} [${rule}] ${line.trim().slice(0, 80)}`);
        }
        const [nRule, nRe, nAllow] = nakedRule;
        if (nRe.test(line) && !nAllow.test(line)) violations.push(`${rel}:${i + 1} [${nRule}] ${line.trim().slice(0, 80)}`);
        if (!isDoc) {
          const [cRule, cRe] = codeHard;
          if (cRe.test(line)) violations.push(`${rel}:${i + 1} [${cRule}] ${line.trim().slice(0, 80)}`);
        }
      });
    }
  }
  return violations;
}

async function main() {
  console.log('== Phase 0 驗收(make test)==');

  // 3) manifest
  const manifestPath = path.join(ROOT, 'data', 'vlei', 'manifest.json');
  const ROLES = ['thepviet', 'hunggang', 'bruck', 'taiwanverify', 'hunggang_cfo', 'bruck_cso'];
  let manifest: Manifest | null = null;
  if (fs.existsSync(manifestPath)) manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
  check(
    'manifest.json 存在且 6 角色齊(四家法人 + 兩張 ECR)',
    !!manifest && ROLES.every((r) => manifest![r]?.aid && manifest![r]?.public_key && manifest![r]?.credential_said && manifest![r]?.lei?.length === 20),
    manifest ? `roles=${Object.keys(manifest).join(',')}` : 'manifest 不存在',
  );
  if (!manifest) process.exit(finish());

  // 1) healthz + 2) status list(經同一個 fastify 實例 inject)
  const app = buildServer();
  const h = await app.inject({ method: 'GET', url: '/api/healthz' });
  check('/api/healthz 回 200', h.statusCode === 200 && h.json().ok === true, `status=${h.statusCode}`);

  const s = await app.inject({ method: 'GET', url: '/status/mandates' });
  check(
    'GET /status/mandates Content-Type 為 application/statuslist+jwt',
    s.statusCode === 200 && String(s.headers['content-type']).startsWith(STATUS_MEDIA_TYPE),
    `status=${s.statusCode} ct=${s.headers['content-type']}`,
  );
  const token = s.body;
  const header = decodeProtectedHeader(token);
  check('Status List Token header.typ == "statuslist+jwt"', header.typ === 'statuslist+jwt', `typ=${header.typ}`);

  // 驗證方順序:先驗 compact JWS 簽章(鴻鋼 LE 公鑰,取自 manifest),再解碼 payload
  let payload: Record<string, any> | null = null;
  try {
    payload = (await jwtVerify(token, publicKeyFromQb64(manifest.hunggang.public_key))).payload as Record<string, any>;
  } catch {
    /* 驗簽失敗 → payload 維持 null */
  }
  check('Status List compact JWS 簽章驗證成功(先驗簽再解碼)', !!payload);
  check('payload.status_list.bits == 1', payload?.status_list?.bits === 1);
  let inflated: Buffer | null = null;
  try {
    inflated = zlib.inflateSync(Buffer.from(String(payload?.status_list?.lst ?? ''), 'base64url'));
  } catch {
    /* 解壓失敗 → inflated 維持 null */
  }
  check('lst 可 zlib 解壓為位元陣列', !!inflated && inflated.length === STATUS_LIST_SIZE / 8, `bytes=${inflated?.length}`);
  await app.close();

  // 4) sandbox verify × 2 ECR
  const py = path.join(ROOT, '.venv', 'bin', 'python');
  const sb = path.join(ROOT, 'vendor', 'vlei-sandbox', 'scripts', 'vlei_sandbox.py');
  for (const role of ['hunggang_cfo', 'bruck_cso'] as const) {
    const said = manifest[role].credential_said;
    const r = spawnSync(py, [sb, '--dir', ROOT, 'verify', '--said', said], { encoding: 'utf-8' });
    check(`sandbox verify ${role} ECR(${said.slice(0, 12)}…)`, r.status === 0 && r.stdout.includes('chain verified'));
  }

  // 5) key loader 簽驗章
  try {
    const k = loadSandboxKey('thepviet');
    const payloadBuf = Buffer.from('carbon-cred-demo · phase0 · key-loader self test');
    const sig = crypto.sign(null, payloadBuf, k.privateKey);
    const ok = crypto.verify(null, payloadBuf, publicKeyFromQb64(manifest.thepviet.public_key), sig);
    check('key loader:Thép Việt LE 鑰簽章 → manifest 公鑰驗證成功', ok);
  } catch (e) {
    check('key loader:Thép Việt LE 鑰簽章 → manifest 公鑰驗證成功', false, String(e));
  }

  // 6) git check-ignore
  for (const p of ['.vlei', 'data/keys', 'db/demo.sqlite']) {
    const r = spawnSync('git', ['check-ignore', '-q', p], { cwd: ROOT });
    check(`git check-ignore ${p}`, r.status === 0);
  }

  // 7) cedar-wasm 實際解析三條政策(P1 .contains、P3 整數 kgCO2e/t——Codex 審查修正的回歸鎖)
  try {
    const cedar = await import('@cedar-policy/cedar-wasm/nodejs');
    for (const pid of ['p1', 'p2', 'p3']) {
      const text = fs.readFileSync(path.join(ROOT, 'policies', `${pid}.cedar`), 'utf-8');
      const r = cedar.checkParsePolicySet({ staticPolicies: text }) as { type: string };
      check(`cedar-wasm 解析 policies/${pid}.cedar`, r.type === 'success', JSON.stringify(r).slice(0, 120));
    }
  } catch (e) {
    check('cedar-wasm 解析 policies/*.cedar', false, String(e));
  }

  // 8) 私鑰檔權限(.vlei 為 700、state.json 為 600;presign umask 077)
  try {
    const dirMode = fs.statSync(path.join(ROOT, '.vlei')).mode & 0o777;
    const fileMode = fs.statSync(path.join(ROOT, '.vlei', 'state.json')).mode & 0o777;
    check('.vlei 權限收緊(dir 700 / state.json 600)', dirMode === 0o700 && fileMode === 0o600, `dir=${dirMode.toString(8)} file=${fileMode.toString(8)}`);
  } catch (e) {
    check('.vlei 權限收緊(dir 700 / state.json 600)', false, String(e));
  }

  // 9) 一致性守門
  const violations = consistencyScan();
  check('一致性守門(docs/ 與程式目錄)', violations.length === 0);
  for (const v of violations.slice(0, 20)) console.log(`      ${v}`);

  process.exit(finish());
}

function finish(): number {
  console.log(`== 結果:${passed} 通過 / ${failed} 失敗 ==`);
  return failed === 0 ? 0 : 1;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
