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
 *  8) 幕 1(簽發 pcf_upstream,架構決策 §4):issue 回傳可解析 SD-JWT、verify() 以 manifest
 *     公鑰驗過、竄改 payload 1 byte 同一驗證路徑失敗、欄位三分法(公開層明文/SD 揭露/機密
 *     只留 commitment hash)、status.status_list.idx/uri、issued_at 回填約三個月前
 */
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { jwtVerify, decodeProtectedHeader } from 'jose';
import { splitSdJwt, decodeJwt } from '@sd-jwt/core';
import { buildServer } from '../server/index';
import { ROOT, openDb } from '../server/db';
import { loadSandboxKey, publicKeyFromQb64 } from '../server/keys';
import { STATUS_MEDIA_TYPE, STATUS_LIST_SIZE, statusListUri } from '../server/statuslist';
import { verifyCompactSdJwt } from '../server/creds/verifier';
import { insertCredentialIfAbsent } from '../server/creds/store';
import { CODES } from '../shared/codes';
import {
  PCF_UPSTREAM_PUBLIC_FIELDS,
  PCF_UPSTREAM_CUSTOMS_SD_FIELDS,
  PCF_UPSTREAM_CUSTOMER_SD_FIELDS,
  PCF_UPSTREAM_CONFIDENTIAL_FIELDS,
  type Manifest,
} from '../shared/types';

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

  // 8) 幕 1:簽發 pcf_upstream(POST /api/issue/upstream)+ verify()/竄改示範 + 欄位三分法
  {
    const seed = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8'));
    const app1 = buildServer();
    try {
      // (a) issue 回傳可解析 SD-JWT
      const issueRes = await app1.inject({ method: 'POST', url: '/api/issue/upstream', payload: { case_id: 'A' } });
      check('POST /api/issue/upstream 回 200', issueRes.statusCode === 200, `status=${issueRes.statusCode} body=${issueRes.body.slice(0, 200)}`);
      const issued = issueRes.json() as {
        sd_jwt: string;
        claims: Record<string, unknown>;
        issued_at: string;
        valid_from: string;
        valid_until: string;
      };

      let jwtPart = '';
      let disclosureCount = -1;
      let rawPayload: Record<string, unknown> = {};
      try {
        const split = splitSdJwt(issued.sd_jwt);
        jwtPart = split.jwt;
        disclosureCount = split.disclosures.length;
        rawPayload = decodeJwt(jwtPart).payload as Record<string, unknown>;
      } catch {
        /* 解析失敗留給下方 check 回報 */
      }
      check(
        '簽發回傳之 compact SD-JWT 可解析(header.payload.signature~d1~d2…)',
        jwtPart.split('.').length === 3 && disclosureCount === PCF_UPSTREAM_CUSTOMS_SD_FIELDS.length + PCF_UPSTREAM_CUSTOMER_SD_FIELDS.length,
        `disclosures=${disclosureCount}`,
      );

      // (a2) M2 修正:重複呼叫本路由(同案)必須冪等——回既有憑證(reused:true)、sd_jwt 不變,
      // 不得重簽(重簽會用新的隨機 disclosure 鹽產生不同 sd_jwt,若該案已被拿去簽 pcf_aggregate,
      // 會讓 pcf_aggregate.precursor_ref.hash 對不上「現在」DB 裡的上游 sd_jwt,信任鏈靜默斷裂)。
      const issueAgainRes = await app1.inject({ method: 'POST', url: '/api/issue/upstream', payload: { case_id: 'A' } });
      const issuedAgain = issueAgainRes.json() as { sd_jwt: string; reused?: boolean };
      check(
        'M2:重複呼叫 POST /api/issue/upstream(同案 A)冪等——reused:true 且 sd_jwt 不變(不重簽)',
        issueAgainRes.statusCode === 200 && issuedAgain.reused === true && issuedAgain.sd_jwt === issued.sd_jwt,
        `reused=${issuedAgain.reused} sameSdJwt=${issuedAgain.sd_jwt === issued.sd_jwt}`,
      );

      // (b) verify() 以 manifest 公鑰驗過
      const verifyRes = await app1.inject({ method: 'POST', url: '/api/creds/verify', payload: { sd_jwt: issued.sd_jwt } });
      const verifyBody = verifyRes.json() as { valid: boolean; error?: string; payload?: Record<string, unknown> };
      check('verify() 以 manifest 公鑰驗證通過', verifyRes.statusCode === 200 && verifyBody.valid === true, JSON.stringify(verifyBody).slice(0, 200));
      check(
        'verify() 回傳之 payload 含已揭露之海關/客戶層欄位',
        verifyBody.payload?.specific_direct_embedded_emissions === seed.cases.A.direct && verifyBody.payload?.production_route === 'EAF',
      );

      // H1 負向測項:以他方(鴻鋼)公鑰驗本方(Thép Việt)的 pcf_upstream 必須失敗(信任邊界原則
      // 「一方一鑰」;繞過 kid 自動解析,強制傳入錯誤的公鑰解析函式)。
      const wrongPartyResult = await verifyCompactSdJwt(issued.sd_jwt, () => publicKeyFromQb64(manifest!.hunggang.public_key));
      check(
        'H1:以鴻鋼公鑰驗 Thép Việt 的 pcf_upstream 必須失敗(一方一鑰)',
        wrongPartyResult.ok === false && wrongPartyResult.reasonCode === CODES.CREDENTIAL_SIG_INVALID,
        JSON.stringify({ ok: wrongPartyResult.ok, reasonCode: wrongPartyResult.reasonCode, error: wrongPartyResult.error }),
      );

      // (c) 竄改 payload 1 byte → 同一驗證路徑失敗(先驗證成功、竄改後失敗,對照上面 (b) 的成功結果)
      const tamperRes = await app1.inject({ method: 'POST', url: '/api/creds/tamper-demo', payload: { sd_jwt: issued.sd_jwt } });
      const tampered = (tamperRes.json() as { sd_jwt: string }).sd_jwt;
      check('竄改後 token 與原始 token 不同(僅改 1 個位元組,保持 UTF-8/JSON 合法)', typeof tampered === 'string' && tampered !== issued.sd_jwt);
      const verifyTamperedRes = await app1.inject({ method: 'POST', url: '/api/creds/verify', payload: { sd_jwt: tampered } });
      const verifyTamperedBody = verifyTamperedRes.json() as { valid: boolean; reason_code?: string; error?: string };
      check('竄改 payload 1 byte 後,同一 /api/creds/verify 驗證失敗(DoD,藍圖:133)', verifyTamperedBody.valid === false);
      // H1 修正驗證:失敗原因必須是簽章層(CREDENTIAL_SIG_INVALID),不是解析層(舊 bug:竄改必翻中點
      // base64url 字元恆落在 customer_list_hash 的 `_` 上,解出不合法 UTF-8,驗證器先報「Invalid JWT
      // as input」,走不到驗簽,demo 現場最沒說服力的答案——見 server/creds/tamper.ts 註解)。
      check(
        'H1:竄改後驗證失敗的理由碼是簽章層 CREDENTIAL_SIG_INVALID(不是解析層 CREDENTIAL_PARSE_ERROR)',
        verifyTamperedBody.reason_code === CODES.CREDENTIAL_SIG_INVALID,
        `reason_code=${verifyTamperedBody.reason_code} error=${verifyTamperedBody.error}`,
      );
      check(
        'H1:竄改後錯誤訊息為簽章層錯誤(非解析層的「Invalid JWT as input」)',
        typeof verifyTamperedBody.error === 'string' && !/Invalid JWT as input/i.test(verifyTamperedBody.error) && /signature/i.test(verifyTamperedBody.error),
        `error=${verifyTamperedBody.error}`,
      );

      // (d) 欄位三分法:公開層明文在原始 JWT payload、SD 欄以 disclosure 存在(不在原始 payload)、
      //     機密欄位名稱/原始值不出現在憑證任何層,commitment/emission_factor_table_hash 則以明文存在
      const publicFieldsPresent = PCF_UPSTREAM_PUBLIC_FIELDS.every((k) => k in rawPayload);
      check('公開層欄位(cn_code/quantity_t/country_of_origin/四個 commitment hash)明文存在於原始 JWT payload', publicFieldsPresent, JSON.stringify(Object.keys(rawPayload)));

      const sdFields = [...PCF_UPSTREAM_CUSTOMS_SD_FIELDS, ...PCF_UPSTREAM_CUSTOMER_SD_FIELDS];
      const sdFieldsHiddenFromRawPayload = sdFields.every((k) => !(k in rawPayload));
      check('海關層 + 客戶層欄位不以明文存在於原始 JWT payload(只在 disclosure 內)', sdFieldsHiddenFromRawPayload);
      const sdFieldsDisclosed = sdFields.every((k) => k in (issued.claims ?? {}));
      check('海關層 + 客戶層欄位以 disclosure 形式存在(issue 回應之 claims 含全部揭露)', sdFieldsDisclosed);

      const confidentialValues = [
        seed.pcf_defaults.confidential.machine_energy,
        seed.pcf_defaults.confidential.ppa_contract,
        seed.pcf_defaults.confidential.recipe,
        seed.pcf_defaults.confidential.customer_list,
      ];
      const noConfidentialLeak =
        PCF_UPSTREAM_CONFIDENTIAL_FIELDS.every((name) => !issued.sd_jwt.includes(name)) && confidentialValues.every((v) => !issued.sd_jwt.includes(v));
      check('機密欄位名稱與原始值(machine_energy/ppa_contract/recipe/customer_list/capacity_utilization)不出現於憑證任何層', noConfidentialLeak);

      const hashFields = ['machine_energy_hash', 'ppa_contract_hash', 'recipe_hash', 'customer_list_hash', 'emission_factor_table_hash'];
      const hashesPresent = hashFields.every((k) => typeof rawPayload[k] === 'string' && /^[0-9a-f]{64}$/.test(rawPayload[k] as string));
      check('commitment hash 與 emission_factor_table_hash(含 capacity_utilization)以一般 claim 存在,皆為 SHA-256 hex', hashesPresent);

      // (e) status.status_list.idx/uri
      const status = rawPayload.status as { status_list?: { idx?: number; uri?: string } } | undefined;
      check(
        'status.status_list.idx/uri 存在且 uri 指向本機 /status/credentials',
        status?.status_list?.idx === 0 && status?.status_list?.uri === statusListUri('credentials'),
        JSON.stringify(status),
      );

      // (f) issued_at/效期為固定 seed 值(規格v2:273「issued_at 回填約三個月前」之意圖已由 seed 固定
      //     值承載)——Codex 審查發現 3:改斷言固定事實,不再用 Date.now() 換算天數,避免驗收測試
      //     隨真實時間推移而翻紅。
      check(
        `issued_at(${issued.issued_at})與 data/seed.json pcf_defaults.issued_at 一致`,
        issued.issued_at === seed.pcf_defaults.issued_at,
        `got=${issued.issued_at} expected=${seed.pcf_defaults.issued_at}`,
      );
      check(
        `效期涵蓋 2026-Q3(valid_from ${issued.valid_from} ≤ 2026-07-01 且 valid_until ${issued.valid_until} ≥ 2026-09-30)`,
        Date.parse(`${issued.valid_from}T00:00:00Z`) <= Date.parse('2026-07-01T00:00:00Z') &&
          Date.parse(`${issued.valid_until}T00:00:00Z`) >= Date.parse('2026-09-30T00:00:00Z'),
        `valid_from=${issued.valid_from} valid_until=${issued.valid_until}`,
      );
    } finally {
      await app1.close();
    }
  }

  // 9) 幕 2:聚合(POST /api/aggregate;架構決策 §4)——聚合值必須由程式計算(不得寫死),
  //    上游憑證消費前必先驗章,pcf_aggregate 不含上游任何明細欄位。
  {
    const seed = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8'));
    const agg = seed.aggregate_defaults;
    const app2 = buildServer();
    try {
      type AggResult = {
        sd_jwt: string;
        claims: Record<string, unknown>;
        breakdown: {
          precursor_contribution_tco2e_per_t: number;
          self_direct_tco2e_per_t: number;
          self_indirect_tco2e_per_t: number;
          carbon_total_tco2e_per_t: number;
        };
        precursor_ref: { id: string; hash: string };
        issued_at: string;
        valid_from: string;
        valid_until: string;
      };
      const byCase: Record<'A' | 'B', { agg: AggResult; upstreamSdJwt: string; upstreamIssuedAt: string }> = {} as any;

      for (const c of ['A', 'B'] as const) {
        // 先確保該案上游憑證存在(幕 1 邏輯),取得其 sd_jwt/issued_at 供後續比對
        const upstreamRes = await app2.inject({ method: 'POST', url: '/api/issue/upstream', payload: { case_id: c } });
        const upstreamBody = upstreamRes.json() as { sd_jwt: string; issued_at: string };

        const aggRes = await app2.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: c } });
        check(`POST /api/aggregate(案 ${c})回 200`, aggRes.statusCode === 200, `status=${aggRes.statusCode} body=${aggRes.body.slice(0, 200)}`);
        byCase[c] = { agg: aggRes.json() as AggResult, upstreamSdJwt: upstreamBody.sd_jwt, upstreamIssuedAt: upstreamBody.issued_at };
      }

      const A = byCase.A.agg;
      const B = byCase.B.agg;

      // (a) 回傳可解析之 compact SD-JWT
      let jwtPartA = '';
      try {
        jwtPartA = splitSdJwt(A.sd_jwt).jwt;
      } catch {
        /* 解析失敗留給下方 check 回報 */
      }
      check('pcf_aggregate(案 A)sd_jwt 可解析(header.payload.signature)', jwtPartA.split('.').length === 3);

      // (b) pcf_aggregate 以鴻鋼 manifest 公鑰驗章通過(同一 /api/creds/verify 路徑,依 kid 解出鴻鋼公鑰)
      const verifyA = await app2.inject({ method: 'POST', url: '/api/creds/verify', payload: { sd_jwt: A.sd_jwt } });
      const verifyABody = verifyA.json() as { valid: boolean; payload?: Record<string, unknown> };
      check('pcf_aggregate(案 A)以鴻鋼 manifest 公鑰驗章通過', verifyABody.valid === true, JSON.stringify(verifyABody).slice(0, 200));
      const verifyB = await app2.inject({ method: 'POST', url: '/api/creds/verify', payload: { sd_jwt: B.sd_jwt } });
      check('pcf_aggregate(案 B)以鴻鋼 manifest 公鑰驗章通過', (verifyB.json() as { valid: boolean }).valid === true);

      // (c) 聚合值正確(規格v2 §4.3:自身製程 + 前驅物內含排放 × 投入係數;此處為獨立算式,不呼叫production computeAggregateBreakdown)
      const expectedA = agg.precursor_input_ratio_t_per_t * (seed.cases.A.direct + seed.cases.A.indirect) + agg.self_direct + agg.self_indirect;
      const expectedB = agg.precursor_input_ratio_t_per_t * (seed.cases.B.direct + seed.cases.B.indirect) + agg.self_direct + agg.self_indirect;
      const close = (a: number, b: number) => Math.abs(a - b) < 1e-6;
      check(
        `案 A 聚合值 = 1.05×1.05+0.08+0.33 ≈ ${expectedA.toFixed(4)}(§4.3 精確語意)`,
        close(A.breakdown.carbon_total_tco2e_per_t, expectedA),
        `got=${A.breakdown.carbon_total_tco2e_per_t}`,
      );
      check(
        `案 B 聚合值 = 1.05×2.10+0.08+0.33 ≈ ${expectedB.toFixed(4)}(§4.3 對應公式值)`,
        close(B.breakdown.carbon_total_tco2e_per_t, expectedB),
        `got=${B.breakdown.carbon_total_tco2e_per_t}`,
      );

      // (d) precursor_ref 的 id 與 hash 對得上該案上游憑證
      const sha256Hex = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
      check('案 A precursor_ref.id 對得上 pcf_upstream-A', A.precursor_ref.id === 'pcf_upstream-A');
      check('案 A precursor_ref.hash == sha256(上游 sd_jwt)', A.precursor_ref.hash === sha256Hex(byCase.A.upstreamSdJwt));
      check('案 B precursor_ref.id 對得上 pcf_upstream-B', B.precursor_ref.id === 'pcf_upstream-B');
      check('案 B precursor_ref.hash == sha256(上游 sd_jwt)', B.precursor_ref.hash === sha256Hex(byCase.B.upstreamSdJwt));

      // (e) 上游明細欄位名不出現於 pcf_aggregate 任何層(compact token 字面值 + 已揭露 claims 皆檢查)
      const upstreamOnlyFieldNames = [
        'specific_direct_embedded_emissions',
        'production_route',
        'specific_indirect_embedded_emissions',
        'electricity_mix_ref',
        'installation_unlocode',
        'primary_data_share',
      ];
      const noLeak = (r: AggResult) => upstreamOnlyFieldNames.every((k) => !r.sd_jwt.includes(k) && !(k in (r.claims ?? {})));
      check('pcf_aggregate(案 A)不含任何上游明細欄位名稱', noLeak(A));
      check('pcf_aggregate(案 B)不含任何上游明細欄位名稱', noLeak(B));

      // (f) status.status_list.idx/uri 正確,且與 pcf_upstream 之 idx(0/1)不衝突
      const statusOf = (r: AggResult) => (r.claims.status as { status_list?: { idx?: number; uri?: string } } | undefined)?.status_list;
      check(
        '案 A pcf_aggregate status.status_list.idx=2、uri 指向 /status/credentials',
        statusOf(A)?.idx === 2 && statusOf(A)?.uri === statusListUri('credentials'),
        JSON.stringify(statusOf(A)),
      );
      check('案 B pcf_aggregate status.status_list.idx=3(與案 A、pcf_upstream 之 0/1 皆不衝突)', statusOf(B)?.idx === 3, JSON.stringify(statusOf(B)));

      // (g) 案 A 與案 B 聚合回傳值不同(支撐「換 seed 圖跟著變」的 DoD,藍圖:159)
      check(
        '案 A 與案 B 聚合回傳值不同(換 seed 圖跟著變)',
        A.breakdown.carbon_total_tco2e_per_t !== B.breakdown.carbon_total_tco2e_per_t,
        `A=${A.breakdown.carbon_total_tco2e_per_t} B=${B.breakdown.carbon_total_tco2e_per_t}`,
      );

      // L3 修正:合約碳排門檻改由後端(data/seed.json transaction.contract_carbon_max)提供,
      // 前端疊層熱點圖不再寫死 2.0——回應必須帶這個欄位且值與 seed 一致。
      check(
        'L3:pcf_aggregate 回應含 contract_carbon_max,值與 data/seed.json 一致',
        (A as unknown as { contract_carbon_max?: number }).contract_carbon_max === seed.transaction.contract_carbon_max,
        `got=${(A as unknown as { contract_carbon_max?: number }).contract_carbon_max} expected=${seed.transaction.contract_carbon_max}`,
      );

      // (h) issued_at/效期為固定 seed 值,且晚於上游憑證 issued_at(信任鏈時序合理,規格v2:273「issued_at
      //     回填約三個月前」之意圖已由 seed 固定值承載)——Codex 審查發現 3:改斷言固定事實,不再用
      //     Date.now() 換算天數,避免驗收測試隨真實時間推移而翻紅。
      check(
        `pcf_aggregate issued_at(${A.issued_at})與 data/seed.json aggregate_defaults.issued_at 一致`,
        A.issued_at === agg.issued_at,
        `got=${A.issued_at} expected=${agg.issued_at}`,
      );
      check(
        `pcf_aggregate issued_at(${A.issued_at})晚於上游 pcf_upstream issued_at(${byCase.A.upstreamIssuedAt})`,
        Date.parse(`${A.issued_at}T00:00:00Z`) > Date.parse(`${byCase.A.upstreamIssuedAt}T00:00:00Z`),
      );
      check(
        `pcf_aggregate 效期涵蓋 2026-Q3(valid_from ${A.valid_from} ≤ 2026-07-01 且 valid_until ${A.valid_until} ≥ 2026-09-30)`,
        Date.parse(`${A.valid_from}T00:00:00Z`) <= Date.parse('2026-07-01T00:00:00Z') &&
          Date.parse(`${A.valid_until}T00:00:00Z`) >= Date.parse('2026-09-30T00:00:00Z'),
        `valid_from=${A.valid_from} valid_until=${A.valid_until}`,
      );
    } finally {
      await app2.close();
    }
  }

  // 10) Codex 審查回歸鎖(2026-08-29 定案):發現 1(併發競態)+ 發現 2(case_id 顯式驗證)
  {
    const app3 = buildServer();
    try {
      // (a0) 發現 1(併發競態)——直接鎖定 server/creds/store.ts 的原子 get-or-create 語意:
      //      HTTP 層以 Promise.all 併發打 app.inject() 在本測試環境下無法可靠重現交錯執行(fastify
      //      inject() + 全同步 better-sqlite3 使兩個請求實質序列化,經 5+ 次重跑驗證皆未觀察到交錯,
      //      即使暫時退回舊版「無條件 upsert」語意也不會讓下方 (a)/(b) 的 HTTP 併發測項翻紅——因此
      //      不能只靠 HTTP 層測項自證修法有效)。改為直接呼叫 insertCredentialIfAbsent 模擬「兩個
      //      已各自簽完、只等寫入」的並行呼叫(真實併發時哪個先簽完無法保證,但無論順序為何,原子
      //      語意都必須滿足):先到者必須落庫(reused=false);後到者必須被忽略,且回傳值改採先到者
      //      版本(reused=true,不得覆寫、不得回傳自己剛簽的 token)。此區塊經 mutation testing 驗證
      //      (退回舊版無條件 upsert 語意會使其翻紅,詳見交付報告)。
      const primDb = openDb();
      primDb.prepare('DELETE FROM credentials WHERE id = ?').run('pcf_upstream-A');
      const raceBaseRec = {
        id: 'pcf_upstream-A',
        type: 'pcf_upstream',
        caseId: 'A',
        issuerParty: 'thepviet',
        holderParty: 'hunggang',
        payload: { note: 'race-primitive-self-test' },
        statusIdx: 0,
        statusUri: statusListUri('credentials'),
        issuedAt: '2026-05-29',
        validFrom: '2026-05-29',
        validUntil: '2026-12-31',
      };
      const raceFirst = insertCredentialIfAbsent(primDb, { ...raceBaseRec, sdJwt: 'race-token-first' });
      const raceSecond = insertCredentialIfAbsent(primDb, { ...raceBaseRec, sdJwt: 'race-token-second' });
      check(
        '發現 1(併發競態,store.ts 原子語意):先到者插入成功(reused=false)',
        raceFirst.reused === false && raceFirst.row.sd_jwt === 'race-token-first',
        `reused=${raceFirst.reused} sd_jwt=${raceFirst.row.sd_jwt}`,
      );
      check(
        '發現 1(併發競態,store.ts 原子語意):後到者輸掉競態(reused=true),回傳值改採先到者版本(不是自己剛簽的 token)',
        raceSecond.reused === true && raceSecond.row.sd_jwt === 'race-token-first',
        `reused=${raceSecond.reused} row.sd_jwt=${raceSecond.row.sd_jwt}`,
      );
      const primRows = primDb.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').all('pcf_upstream-A') as { sd_jwt: string }[];
      check(
        '發現 1(併發競態,store.ts 原子語意):credentials 表該案只有一列,且內容為先到者版本(未被後到者覆寫)',
        primRows.length === 1 && primRows[0].sd_jwt === 'race-token-first',
        `rows=${primRows.length} sd_jwt=${primRows[0]?.sd_jwt}`,
      );
      primDb.close();

      // (a) 發現 1(併發競態,server/routes/issue.ts 呼叫路徑):先清空案 A 上游列(不依賴前面測項
      //     殘留),再併發打兩個 /api/issue/upstream(同案 A)。若各自讀到「未入庫」而各自簽出不同
      //     token(SD-JWT 含隨機 disclosure 鹽),兩份回應的 sd_jwt 會不同——用兩個呼叫者「各自看到
      //     的回應」互相比對(不只是跟 DB 比),不受哪一方先簽/後寫的執行順序影響,才能可靠抓到回歸。
      const raceDb = openDb();
      raceDb.prepare('DELETE FROM credentials WHERE id = ?').run('pcf_upstream-A');
      raceDb.close();

      const [raceIssue1, raceIssue2] = await Promise.all([
        app3.inject({ method: 'POST', url: '/api/issue/upstream', payload: { case_id: 'A' } }),
        app3.inject({ method: 'POST', url: '/api/issue/upstream', payload: { case_id: 'A' } }),
      ]);
      const issueBody1 = raceIssue1.json() as { sd_jwt: string; reused?: boolean };
      const issueBody2 = raceIssue2.json() as { sd_jwt: string; reused?: boolean };
      check(
        '發現 1(併發競態):併發兩個 POST /api/issue/upstream(案 A)皆回 200',
        raceIssue1.statusCode === 200 && raceIssue2.statusCode === 200,
        `status1=${raceIssue1.statusCode} status2=${raceIssue2.statusCode}`,
      );
      check(
        '發現 1(併發競態):兩個呼叫者收到的 sd_jwt 相同(輸掉競態者改採落庫勝者,不各自保留自己剛簽的 token)',
        issueBody1.sd_jwt === issueBody2.sd_jwt,
        `sd_jwt1=${issueBody1.sd_jwt?.slice(0, 24)}… sd_jwt2=${issueBody2.sd_jwt?.slice(0, 24)}…`,
      );
      check(
        '發現 1(併發競態):兩個呼叫者之一 reused=true(輸掉競態等同冪等重用,而非各自真簽一份)',
        issueBody1.reused !== issueBody2.reused && (issueBody1.reused === true || issueBody2.reused === true),
        `reused1=${issueBody1.reused} reused2=${issueBody2.reused}`,
      );

      const raceDbCheck = openDb();
      const upstreamRowsA = raceDbCheck.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').all('pcf_upstream-A') as { sd_jwt: string }[];
      raceDbCheck.close();
      check(
        '發現 1(併發競態):credentials 表 pcf_upstream-A 該案只有一列',
        upstreamRowsA.length === 1,
        `rows=${upstreamRowsA.length}`,
      );

      // (b) 發現 1(併發競態,server/creds/pcfAggregate.ts ensureUpstreamCredential 呼叫路徑):
      //     清空案 B 上游/聚合列,併發打兩個 /api/aggregate(同案 B)。同理,用兩份聚合回應的
      //     precursor_ref.hash 互相比對(不只是跟 DB 比)——同一案只能有一個合法上游,兩份聚合
      //     若引用不同雜湊,代表兩個呼叫者各自簽了一份不同的上游 token,信任鏈已經分岔。
      const raceDb2 = openDb();
      raceDb2.prepare('DELETE FROM credentials WHERE id IN (?, ?)').run('pcf_upstream-B', 'pcf_aggregate-B');
      raceDb2.close();

      const [raceAgg1, raceAgg2] = await Promise.all([
        app3.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'B' } }),
        app3.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'B' } }),
      ]);
      const aggBody1 = raceAgg1.json() as { precursor_ref?: { hash?: string } };
      const aggBody2 = raceAgg2.json() as { precursor_ref?: { hash?: string } };
      check(
        '發現 1(併發競態):併發兩個 POST /api/aggregate(案 B)皆回 200',
        raceAgg1.statusCode === 200 && raceAgg2.statusCode === 200,
        `status1=${raceAgg1.statusCode} status2=${raceAgg2.statusCode}`,
      );
      check(
        '發現 1(併發競態):兩份聚合回應的 precursor_ref.hash 相同(同一案只有一個合法上游,不得分岔)',
        !!aggBody1.precursor_ref?.hash && aggBody1.precursor_ref?.hash === aggBody2.precursor_ref?.hash,
        `hash1=${aggBody1.precursor_ref?.hash?.slice(0, 12)} hash2=${aggBody2.precursor_ref?.hash?.slice(0, 12)}`,
      );

      const raceDbCheck2 = openDb();
      const upstreamRowsB = raceDbCheck2.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').all('pcf_upstream-B') as { sd_jwt: string }[];
      raceDbCheck2.close();
      const sha256HexRace = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
      check(
        '發現 1(併發競態):credentials 表 pcf_upstream-B 該案只有一列,且聚合 precursor_ref.hash === sha256(落庫上游 sd_jwt)',
        upstreamRowsB.length === 1 && aggBody1.precursor_ref?.hash === sha256HexRace(upstreamRowsB[0]?.sd_jwt ?? ''),
        `rows=${upstreamRowsB.length} dbHash=${upstreamRowsB[0] ? sha256HexRace(upstreamRowsB[0].sd_jwt).slice(0, 12) : 'N/A'} aggHash=${aggBody1.precursor_ref?.hash?.slice(0, 12)}`,
      );

      // (b) 發現 2(case_id 顯式驗證):缺值與打錯字一律 400 + INVALID_CASE_ID,不得靜默塌成 'A' 真簽憑證。
      const negCases: Array<{ url: string; payload: Record<string, unknown> }> = [
        { url: '/api/issue/upstream', payload: {} },
        { url: '/api/issue/upstream', payload: { case_id: 'X' } },
        { url: '/api/aggregate', payload: {} },
        { url: '/api/aggregate', payload: { case_id: 'X' } },
      ];
      for (const { url, payload } of negCases) {
        const res = await app3.inject({ method: 'POST', url, payload });
        const body = res.json() as { reason_code?: string };
        check(
          `發現 2(case_id 驗證):POST ${url} payload=${JSON.stringify(payload)} 回 400 + INVALID_CASE_ID`,
          res.statusCode === 400 && body.reason_code === CODES.INVALID_CASE_ID,
          `status=${res.statusCode} body=${res.body}`,
        );
      }
    } finally {
      await app3.close();
    }
  }

  // 11) 一致性守門
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
