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
import { SignJWT, jwtVerify, decodeProtectedHeader, decodeJwt as decodeJoseJwt } from 'jose';
import { splitSdJwt, decodeJwt, type DisclosureFrame } from '@sd-jwt/core';
import type { SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc';
import { buildServer } from '../server/index';
import { ROOT, openDb, VLEI_PUBLIC_STATE_DIR } from '../server/db';
import { loadSandboxKey, loadWorkloadKey, publicKeyFromQb64 } from '../server/keys';
import { STATUS_MEDIA_TYPE, STATUS_LIST_SIZE, statusListUri } from '../server/statuslist';
import { verifyCompactSdJwt } from '../server/creds/verifier';
import { insertCredentialIfAbsent } from '../server/creds/store';
import { tamperPayloadByte } from '../server/creds/tamper';
import { issuePcfAggregate, PCF_AGGREGATE_VCT } from '../server/creds/pcfAggregate';
import { buildIssuerInstance } from '../server/creds/issuer';
import { presentSelectedDisclosures, presentRawDisclosures, NeverDisclosableClaimError } from '../server/creds/presenter';
import { verifyPresentation, verifyVleiChainSandbox } from '../server/creds/verifyPresentation';
import { processDiscloseRequest } from '../server/creds/discloseGateway';
import { resolvePublicKeyFromManifest } from '../server/manifest';
import { readStatusListToken, checkStatusBit, buildAndWriteStatusList, STATUS_TTL_SECONDS } from '../server/statuslist';
import { M2_ALLOWED_CLAIMS, NEVER_DISCLOSABLE_CLAIMS, isSelectableDisclosure } from '../server/policy/claims';
import { PUBLIC_VLEI_STATE_FILE } from '../server/keys';
import { CODES } from '../shared/codes';
import {
  PCF_UPSTREAM_PUBLIC_FIELDS,
  PCF_UPSTREAM_CUSTOMS_SD_FIELDS,
  PCF_UPSTREAM_CUSTOMER_SD_FIELDS,
  PCF_UPSTREAM_CONFIDENTIAL_FIELDS,
  type Manifest,
} from '../shared/types';

const TSX_BIN = path.join(ROOT, 'node_modules', '.bin', 'tsx');

/**
 * 幕 3/4 測試小工具:以 workload 鑰簽 disclose request_jws(architecture:136;impl-spec §2)。
 * iatSec 可覆寫(M1 新鮮度窗測項用「相對於現在的過期時間」,不寫死日期,不會在未來某天翻紅)。
 */
async function signDiscloseRequest(
  key: ReturnType<typeof loadWorkloadKey>,
  mandateJti: string,
  caseId: 'A' | 'B',
  requestedClaims: string[],
  nonce: string,
  iatSec: number = Math.floor(Date.now() / 1000),
): Promise<string> {
  return new SignJWT({
    mandate_id: mandateJti,
    case_id: caseId,
    requested_claims: requestedClaims,
    request_nonce: nonce,
    iat: iatSec,
  })
    .setProtectedHeader({ alg: 'EdDSA', kid: key.kid })
    .sign(key.privateKey);
}

function randomNonce(): string {
  return crypto.randomBytes(12).toString('base64url');
}

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
    ['單一 workload.key 命名', /(?<!fab-)(?<!brand-)workload\.key/],
    ['錢包/RPC/testnet 建立指示', /(testnet|RPC 連線|建立錢包)/i],
  ];
  // 裸 bit array 僅得與 fallback/保底 同現,或以禁用語(v3:不得出現/無退路)引用
  const nakedRule: [string, RegExp, RegExp] = ['裸 bit array 未標示 fallback', /(裸[^\n]{0,8}bit|裸 ?JSON)/i, /(fallback|保底|明確標示|不得出現|退路)/];
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
  const ROLES = ['yarn', 'fab', 'brand', 'cb', 'fab_cfo', 'brand_cso'];
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
    payload = (await jwtVerify(token, publicKeyFromQb64(manifest.fab.public_key))).payload as Record<string, any>;
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
  for (const role of ['fab_cfo', 'brand_cso'] as const) {
    const said = manifest[role].credential_said;
    const r = spawnSync(py, [sb, '--dir', ROOT, 'verify', '--said', said], { encoding: 'utf-8' });
    check(`sandbox verify ${role} ECR(${said.slice(0, 12)}…)`, r.status === 0 && r.stdout.includes('chain verified'));
  }

  // 5) key loader 簽驗章
  try {
    const k = loadSandboxKey('yarn');
    const payloadBuf = Buffer.from('carbon-cred-demo · phase0 · key-loader self test');
    const sig = crypto.sign(null, payloadBuf, k.privateKey);
    const ok = crypto.verify(null, payloadBuf, publicKeyFromQb64(manifest.yarn.public_key), sig);
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
      const wrongPartyResult = await verifyCompactSdJwt(issued.sd_jwt, () => publicKeyFromQb64(manifest!.fab.public_key));
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
      // F1(Codex adversarial review):/api/aggregate 已不再回完整可再揭露 sd_jwt / 整包 claims。
      // 回應形狀改為「鴻鋼自有閘道頁」內部檢視;完整 SD-JWT 屬鴻鋼自持,改由 credentials 表(鴻鋼自有 DB)讀取,
      // 密碼學驗章強度不變(同一 /api/creds/verify 路徑),只是憑證來源改為鴻鋼內部而非跨組織 HTTP 回應。
      type AggResult = {
        id: string;
        breakdown: {
          precursor_contribution_tco2e_per_t: number;
          self_direct_tco2e_per_t: number;
          self_indirect_tco2e_per_t: number;
          carbon_total_tco2e_per_t: number;
        };
        cn_code: string;
        carbon_price_paid_origin: string;
        precursor_ref: { id: string; hash: string };
        status: { idx: number; uri: string };
        issued_at: string;
        valid_from: string;
        valid_until: string;
      };
      const byCase: Record<'A' | 'B', { agg: AggResult; rawResponse: Record<string, unknown>; sdJwt: string; upstreamSdJwt: string; upstreamIssuedAt: string }> =
        {} as any;

      for (const c of ['A', 'B'] as const) {
        // 先確保該案上游憑證存在(幕 1 邏輯),取得其 sd_jwt/issued_at 供後續比對
        const upstreamRes = await app2.inject({ method: 'POST', url: '/api/issue/upstream', payload: { case_id: c } });
        const upstreamBody = upstreamRes.json() as { sd_jwt: string; issued_at: string };

        const aggRes = await app2.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: c } });
        check(`POST /api/aggregate(案 ${c})回 200`, aggRes.statusCode === 200, `status=${aggRes.statusCode} body=${aggRes.body.slice(0, 200)}`);
        // 完整 pcf_aggregate SD-JWT 為鴻鋼自持——自 credentials 表(鴻鋼自有 DB)讀,不從 HTTP 回應取。
        const aggDb = openDb();
        const aggDbRow = aggDb.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').get(`pcf_aggregate-${c}`) as { sd_jwt: string } | undefined;
        aggDb.close();
        byCase[c] = {
          agg: aggRes.json() as AggResult,
          rawResponse: aggRes.json() as Record<string, unknown>,
          sdJwt: aggDbRow?.sd_jwt ?? '',
          upstreamSdJwt: upstreamBody.sd_jwt,
          upstreamIssuedAt: upstreamBody.issued_at,
        };
      }

      const A = byCase.A.agg;
      const B = byCase.B.agg;

      // F1 鎖:/api/aggregate 回應不含完整可再揭露 SD-JWT,也不含三個 NEVER_DISCLOSABLE 分項的可攜揭露。
      for (const c of ['A', 'B'] as const) {
        const resp = byCase[c].rawResponse;
        const respJson = JSON.stringify(resp);
        check(
          `F1:POST /api/aggregate(案 ${c})回應不含完整可再揭露 SD-JWT(無 sd_jwt/claims 欄,外部無法藉此持有並自行 present)`,
          !('sd_jwt' in resp) && !('claims' in resp),
          `keys=${Object.keys(resp).join(',')}`,
        );
        check(
          `F1:POST /api/aggregate(案 ${c})回應不含三個 NEVER_DISCLOSABLE 分項名稱作為可攜揭露(precursor/self_direct/self_indirect 僅存在於 breakdown 疊層圖真值)`,
          NEVER_DISCLOSABLE_CLAIMS.every((f) => !(f in resp)),
          `keys=${Object.keys(resp).join(',')}`,
        );
        // 內部檢視 breakdown 仍在(鴻鋼自有閘道頁 StackChart 真值來源)——F1 收斂的是跨組織可攜 token,不砍自有檢視。
        check(`F1 對照組:案 ${c} 回應仍含 breakdown(鴻鋼自有閘道頁疊層圖真值不受影響)`, typeof resp.breakdown === 'object' && resp.breakdown != null, respJson.slice(0, 120));
      }

      // (a) 鴻鋼自持之完整 pcf_aggregate SD-JWT(自 credentials 表讀)可解析
      let jwtPartA = '';
      try {
        jwtPartA = splitSdJwt(byCase.A.sdJwt).jwt;
      } catch {
        /* 解析失敗留給下方 check 回報 */
      }
      check('pcf_aggregate(案 A)sd_jwt 可解析(header.payload.signature)', jwtPartA.split('.').length === 3);

      // (b) pcf_aggregate 以鴻鋼 manifest 公鑰驗章通過(同一 /api/creds/verify 路徑,依 kid 解出鴻鋼公鑰)
      const verifyA = await app2.inject({ method: 'POST', url: '/api/creds/verify', payload: { sd_jwt: byCase.A.sdJwt } });
      const verifyABody = verifyA.json() as { valid: boolean; payload?: Record<string, unknown> };
      check('pcf_aggregate(案 A)以鴻鋼 manifest 公鑰驗章通過', verifyABody.valid === true, JSON.stringify(verifyABody).slice(0, 200));
      const verifyB = await app2.inject({ method: 'POST', url: '/api/creds/verify', payload: { sd_jwt: byCase.B.sdJwt } });
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
      // 鴻鋼自持之完整 SD-JWT(credentials 表)不得含任何上游明細欄位名稱(compact token 字面值檢查)。
      const noLeak = (c: 'A' | 'B') => upstreamOnlyFieldNames.every((k) => !byCase[c].sdJwt.includes(k));
      check('pcf_aggregate(案 A)不含任何上游明細欄位名稱', noLeak('A'));
      check('pcf_aggregate(案 B)不含任何上游明細欄位名稱', noLeak('B'));

      // (f) status.status_list.idx/uri 正確,且與 pcf_upstream 之 idx(0/1)不衝突(F1 後改讀回應之 status 欄)
      check(
        '案 A pcf_aggregate status.status_list.idx=2、uri 指向 /status/credentials',
        A.status?.idx === 2 && A.status?.uri === statusListUri('credentials'),
        JSON.stringify(A.status),
      );
      check('案 B pcf_aggregate status.status_list.idx=3(與案 A、pcf_upstream 之 0/1 皆不衝突)', B.status?.idx === 3, JSON.stringify(B.status));

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
        issuerParty: 'yarn',
        holderParty: 'fab',
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

  // 12) 幕 3 mandate 簽發(POST /api/mandates;架構決策 §4)——M2 為主線,M1 為背景亦須可簽。
  let m2Summary!: { jti: string; allowed_claims: string[]; valid_until: string; delegate_kid: string; status: { idx: number; uri: string } };
  let m2MandateJwt!: string;
  {
    const app12 = buildServer();
    try {
      const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'vlei', 'manifest.json'), 'utf-8')) as Manifest;
      const brandWorkload = loadWorkloadKey('brand-workload');

      const m2Res = await app12.inject({ method: 'POST', url: '/api/mandates', payload: { mandate: 'M2' } });
      check('POST /api/mandates(M2)回 200', m2Res.statusCode === 200, `status=${m2Res.statusCode} body=${m2Res.body.slice(0, 200)}`);
      const m2Body = m2Res.json() as { mandate_jwt: string; reused: boolean; summary: typeof m2Summary };
      m2Summary = m2Body.summary;
      m2MandateJwt = m2Body.mandate_jwt;

      check('M2 delegate_kid == brand-workload 公鑰 kid', m2Summary.delegate_kid === brandWorkload.kid, `got=${m2Summary.delegate_kid}`);
      check('M2 mandates Token Status List idx == 1', m2Summary.status.idx === 1, `got=${m2Summary.status.idx}`);
      check(
        'M2 簽發者 kid 為 Brand 永續長 ECR AID',
        decodeProtectedHeader(m2MandateJwt).kid === manifest.brand_cso.aid,
        `kid=${decodeProtectedHeader(m2MandateJwt).kid} expected=${manifest.brand_cso.aid}`,
      );
      check(
        '遺留(b)鎖:M2 allowed_claims 不含 precursor_contribution_tco2e_per_t',
        !m2Summary.allowed_claims.includes('precursor_contribution_tco2e_per_t'),
        JSON.stringify(m2Summary.allowed_claims),
      );
      check(
        `M2 allowed_claims 恰為 pcf_aggregate 可揭露欄位扣除永不揭露分項之集合(${M2_ALLOWED_CLAIMS.length} 欄)`,
        m2Summary.allowed_claims.length === M2_ALLOWED_CLAIMS.length && M2_ALLOWED_CLAIMS.every((c) => m2Summary.allowed_claims.includes(c)),
        JSON.stringify(m2Summary.allowed_claims),
      );
      // H2 靜態鎖:三個聚合分項一律不得出現在 M2.allowed_claims(任兩項相加減即可還原第三項與上游合計)。
      check(
        'H2 靜態鎖:M2 allowed_claims 不含任何聚合分項(precursor_contribution / self_direct / self_indirect)',
        NEVER_DISCLOSABLE_CLAIMS.every((c) => !m2Summary.allowed_claims.includes(c)),
        JSON.stringify(m2Summary.allowed_claims),
      );
      // L2 鎖:mandate 效期不得寫死到近期日期——距今至少 90 天,否則 demo 會在某天全面 MANDATE_EXPIRED。
      const m2Exp = (decodeJoseJwt(m2MandateJwt) as { exp?: number }).exp ?? 0;
      check(
        'L2:M2 mandate exp 距今 ≥ 90 天(效期不寫死近期日期,demo 不會某天全面 MANDATE_EXPIRED)',
        m2Exp - Math.floor(Date.now() / 1000) >= 90 * 24 * 60 * 60,
        `exp=${new Date(m2Exp * 1000).toISOString().slice(0, 10)} valid_until=${m2Summary.valid_until}`,
      );

      // 冪等:重複呼叫回同一 token。
      const m2AgainRes = await app12.inject({ method: 'POST', url: '/api/mandates', payload: { mandate: 'M2' } });
      const m2Again = m2AgainRes.json() as { mandate_jwt: string; reused: boolean };
      check(
        'M2 冪等:重複呼叫 reused=true 且 token 不變',
        m2AgainRes.statusCode === 200 && m2Again.reused === true && m2Again.mandate_jwt === m2MandateJwt,
        `reused=${m2Again.reused}`,
      );

      // 併發:兩個 POST /api/mandates(M1)只落一列、回同一 token(與上面 M2 冪等測項互不干擾)。
      // 先清空 M1(若前一輪 make test 未 demo-reset 就重跑,M1 早已存在會讓兩邊都是 reused=true,
      // 測項本身要驗的是「兩個同時到達的請求誰先落庫」,而非「M1 是否已存在」)。
      const cleanM1Db = openDb();
      cleanM1Db.prepare('DELETE FROM mandates WHERE id = ?').run('M1');
      cleanM1Db.close();
      const [m1Res1, m1Res2] = await Promise.all([
        app12.inject({ method: 'POST', url: '/api/mandates', payload: { mandate: 'M1' } }),
        app12.inject({ method: 'POST', url: '/api/mandates', payload: { mandate: 'M1' } }),
      ]);
      type MandateApiBody = { mandate_jwt: string; reused: boolean; summary: { delegate_kid: string; status: { idx: number } } };
      const m1Body1 = m1Res1.json() as MandateApiBody;
      const m1Body2 = m1Res2.json() as MandateApiBody;
      check(
        '併發兩個 POST /api/mandates(M1)皆回 200 且拿到同一 token',
        m1Res1.statusCode === 200 && m1Res2.statusCode === 200 && m1Body1.mandate_jwt === m1Body2.mandate_jwt,
        `status1=${m1Res1.statusCode} status2=${m1Res2.statusCode}`,
      );
      check(
        '併發兩個 POST /api/mandates(M1)之一 reused=true',
        m1Body1.reused !== m1Body2.reused && (m1Body1.reused === true || m1Body2.reused === true),
        `reused1=${m1Body1.reused} reused2=${m1Body2.reused}`,
      );
      check(
        'M1 delegate_kid == fab-workload 公鑰 kid、mandates Token Status List idx == 0',
        m1Body1.summary.delegate_kid === loadWorkloadKey('fab-workload').kid && m1Body1.summary.status.idx === 0,
        JSON.stringify(m1Body1.summary),
      );
      const mandateDb = openDb();
      const m1Rows = mandateDb.prepare('SELECT id FROM mandates WHERE id = ?').all('M1') as { id: string }[];
      mandateDb.close();
      check('mandates 表 M1 該案只有一列', m1Rows.length === 1, `rows=${m1Rows.length}`);
    } finally {
      await app12.close();
    }
  }

  // 13) 幕 3 disclose PERMIT(POST /api/disclose)——六欄 presentation 只含 allowed disclosures。
  let permitRequestJws!: string;
  let permitPresentation!: string;
  let permitReceipt!: string;
  {
    const app13 = buildServer();
    try {
      const brandWorkload = loadWorkloadKey('brand-workload');
      const permitNonce = randomNonce();
      permitRequestJws = await signDiscloseRequest(brandWorkload, m2Summary.jti, 'A', m2Summary.allowed_claims, permitNonce);

      const mandateDbBefore = openDb();
      const queriesUsedBefore = (mandateDbBefore.prepare('SELECT queries_used FROM mandates WHERE id = ?').get('M2') as { queries_used: number })
        .queries_used;
      mandateDbBefore.close();
      const auditBeforeRes = await app13.inject({ method: 'GET', url: '/api/audit?after=0' });
      const auditCountBefore = (auditBeforeRes.json() as unknown[]).length;

      const discloseRes = await app13.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: permitRequestJws } });
      check(
        'POST /api/disclose(M2,案 A,allowed_claims 全量)回 200 PERMIT',
        discloseRes.statusCode === 200,
        `status=${discloseRes.statusCode} body=${discloseRes.body.slice(0, 300)}`,
      );
      const discloseBody = discloseRes.json() as { decision: string; policy_id: string; presentation: string; receipt: string; mandate_id: string; case_id: string };
      check(
        '回應 decision=PERMIT、policy_id=P1',
        discloseBody.decision === 'PERMIT' && discloseBody.policy_id === 'P1',
        JSON.stringify(discloseBody).slice(0, 200),
      );
      permitPresentation = discloseBody.presentation;
      permitReceipt = discloseBody.receipt;
      // F4:PERMIT 回應必附閘道簽章 receipt(供 Brand 端 key-binding 驗證)。
      check('F4:PERMIT 回應含閘道簽章 receipt(非空字串)', typeof permitReceipt === 'string' && permitReceipt.length > 0, `receipt=${String(permitReceipt).slice(0, 24)}…`);

      // 逐欄核對「在/不在」:presentation 只含 M2.allowed_claims 六欄(以 verifyCompactSdJwt 解出已揭露 payload)。
      const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'vlei', 'manifest.json'), 'utf-8')) as Manifest;
      const presVerify = await verifyCompactSdJwt(permitPresentation, resolvePublicKeyFromManifest(manifest));
      check('presentation 可用鴻鋼公鑰驗章通過', presVerify.ok === true, JSON.stringify({ ok: presVerify.ok, error: presVerify.error }));
      const presPayload = (presVerify.payload ?? {}) as Record<string, unknown>;
      const allInAllowed = m2Summary.allowed_claims.every((claim) => claim in presPayload);
      check(`presentation 含全部允許欄位(${m2Summary.allowed_claims.length} 欄逐一核對「在」)`, allInAllowed, JSON.stringify(Object.keys(presPayload)));
      check(
        '遺留(b)鎖:presentation 不含 precursor_contribution_tco2e_per_t(逐欄核對「不在」)',
        !('precursor_contribution_tco2e_per_t' in presPayload),
        JSON.stringify(Object.keys(presPayload)),
      );

      const auditAfterRes = await app13.inject({ method: 'GET', url: '/api/audit?after=0' });
      const auditCountAfter = (auditAfterRes.json() as unknown[]).length;
      check('audit 鏈多一筆(PERMIT 入鏈)', auditCountAfter === auditCountBefore + 1, `before=${auditCountBefore} after=${auditCountAfter}`);

      const mandateDbAfter = openDb();
      const queriesUsedAfter = (mandateDbAfter.prepare('SELECT queries_used FROM mandates WHERE id = ?').get('M2') as { queries_used: number })
        .queries_used;
      mandateDbAfter.close();
      check('query_cap 扣一次(mandates.queries_used +1)', queriesUsedAfter === queriesUsedBefore + 1, `before=${queriesUsedBefore} after=${queriesUsedAfter}`);
    } finally {
      await app13.close();
    }
  }

  // 14) 幕 4 越界攔截 DENY(加碼索取 machine_energy)——Cedar P2 forbid,零欄位外洩。
  {
    const app14 = buildServer();
    try {
      const brandWorkload = loadWorkloadKey('brand-workload');
      const overRequestClaims = [...m2Summary.allowed_claims, 'machine_energy'];
      const requestJws = await signDiscloseRequest(brandWorkload, m2Summary.jti, 'A', overRequestClaims, randomNonce());

      const auditBeforeRes = await app14.inject({ method: 'GET', url: '/api/audit?after=0' });
      const auditCountBefore = (auditBeforeRes.json() as unknown[]).length;

      const res = await app14.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: requestJws } });
      check('幕 4:加碼索取 machine_energy → 403', res.statusCode === 403, `status=${res.statusCode} body=${res.body}`);
      const body = res.json() as Record<string, unknown>;
      check(
        '理由碼 POLICY_P2_CONFIDENTIAL、policy_id=P2',
        body.reason_code === CODES.POLICY_P2_CONFIDENTIAL && body.policy_id === 'P2',
        JSON.stringify(body),
      );
      check(
        '零欄位外洩:回應無 presentation 欄位,亦不含任何 pcf_aggregate 欄位值',
        !('presentation' in body) && !('carbon_total_tco2e_per_t' in body),
        JSON.stringify(body),
      );

      const auditAfterRes = await app14.inject({ method: 'GET', url: '/api/audit?after=0' });
      const auditCountAfter = (auditAfterRes.json() as unknown[]).length;
      check('audit 鏈多一筆(DENY 入鏈)', auditCountAfter === auditCountBefore + 1, `before=${auditCountBefore} after=${auditCountAfter}`);
    } finally {
      await app14.close();
    }
  }

  // 15) 重放:同 (mandate_id, request_nonce) 二次 → 409 REPLAY_DETECTED;audit 入鏈。
  {
    const app15 = buildServer();
    try {
      const auditBeforeRes = await app15.inject({ method: 'GET', url: '/api/audit?after=0' });
      const auditCountBefore = (auditBeforeRes.json() as unknown[]).length;

      const res = await app15.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: permitRequestJws } });
      check('重放同一 request_jws(與幕 3 PERMIT 同 nonce)→ 409', res.statusCode === 409, `status=${res.statusCode} body=${res.body}`);
      const body = res.json() as Record<string, unknown>;
      check('理由碼 REPLAY_DETECTED', body.reason_code === CODES.REPLAY_DETECTED, JSON.stringify(body));

      const auditAfterRes = await app15.inject({ method: 'GET', url: '/api/audit?after=0' });
      const auditCountAfter = (auditAfterRes.json() as unknown[]).length;
      check('audit 鏈多一筆(REPLAY_DETECTED 入鏈)', auditCountAfter === auditCountBefore + 1, `before=${auditCountBefore} after=${auditCountAfter}`);
    } finally {
      await app15.close();
    }
  }

  // 16) mandate 負路徑:壞簽章 → MANDATE_SIG_INVALID;非 delegate 鑰簽 request → DELEGATE_KEY_MISMATCH。
  {
    const app16 = buildServer();
    try {
      const brandWorkload = loadWorkloadKey('brand-workload');
      const fabWorkload = loadWorkloadKey('fab-workload');

      // (a) 壞簽章:直接竄改 DB 內 M2 mandate 的 token(模擬 mandates 表遭竄改),測完立即復原。
      const tamperDb = openDb();
      const originalToken = (tamperDb.prepare('SELECT token FROM mandates WHERE id = ?').get('M2') as { token: string }).token;
      const tamperedToken = tamperPayloadByte(originalToken);
      tamperDb.prepare('UPDATE mandates SET token = ? WHERE id = ?').run(tamperedToken, 'M2');
      tamperDb.close();

      const badSigRequestJws = await signDiscloseRequest(brandWorkload, m2Summary.jti, 'A', m2Summary.allowed_claims, randomNonce());
      const badSigRes = await app16.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: badSigRequestJws } });
      check(
        'mandate 遭竄改(壞簽章)→ 403 MANDATE_SIG_INVALID',
        badSigRes.statusCode === 403 && (badSigRes.json() as { reason_code?: string }).reason_code === CODES.MANDATE_SIG_INVALID,
        `status=${badSigRes.statusCode} body=${badSigRes.body}`,
      );

      const restoreDb = openDb();
      restoreDb.prepare('UPDATE mandates SET token = ? WHERE id = ?').run(originalToken, 'M2');
      restoreDb.close();

      // (b) 非 delegate 鑰簽 request → DELEGATE_KEY_MISMATCH(以 fab-workload 鑰簽,冒充 brand-workload)。
      const wrongDelegateJws = await signDiscloseRequest(fabWorkload, m2Summary.jti, 'A', m2Summary.allowed_claims, randomNonce());
      const wrongDelegateRes = await app16.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: wrongDelegateJws } });
      check(
        '非 delegate 鑰簽 request(fab-workload 冒簽)→ 403 DELEGATE_KEY_MISMATCH',
        wrongDelegateRes.statusCode === 403 && (wrongDelegateRes.json() as { reason_code?: string }).reason_code === CODES.DELEGATE_KEY_MISMATCH,
        `status=${wrongDelegateRes.statusCode} body=${wrongDelegateRes.body}`,
      );

      // 復原後確認 M2 仍可正常運作(避免復原邏輯本身有誤,靜默留下壞資料)。
      const sanityJws = await signDiscloseRequest(brandWorkload, m2Summary.jti, 'A', m2Summary.allowed_claims, randomNonce());
      const sanityRes = await app16.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: sanityJws } });
      check(
        '復原 mandate token 後,正常簽章的 disclose request 仍可 PERMIT(確認復原成功、未留壞資料)',
        sanityRes.statusCode === 200,
        `status=${sanityRes.statusCode} body=${sanityRes.body.slice(0, 200)}`,
      );
    } finally {
      await app16.close();
    }
  }

  // 17) Brand 端驗證(server/creds/verifyPresentation.ts,幕 3 DoD)。
  {
    const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'vlei', 'manifest.json'), 'utf-8')) as Manifest;

    // (a) 合法 presentation + 閘道 receipt 全綠(F4:缺 receipt 會在 key-binding 檢查失敗)。
    const goodResult = await verifyPresentation({ presentationSdJwt: permitPresentation, mandateJwt: m2MandateJwt, manifest, receipt: permitReceipt });
    check('Brand 端驗證:合法 presentation 全部檢查項通過', goodResult.ok && goodResult.checks.every((c) => c.ok), JSON.stringify(goodResult.checks));

    // (b) 竄改(tamper)presentation → 簽章驗證失敗(重用既有竄改工具,經 /api/creds/tamper-demo)。
    const app17 = buildServer();
    let tamperedPresentation = '';
    try {
      const tamperRes = await app17.inject({ method: 'POST', url: '/api/creds/tamper-demo', payload: { sd_jwt: permitPresentation } });
      tamperedPresentation = (tamperRes.json() as { sd_jwt: string }).sd_jwt;
    } finally {
      await app17.close();
    }
    const tamperedResult = await verifyPresentation({ presentationSdJwt: tamperedPresentation, mandateJwt: m2MandateJwt, manifest });
    check(
      'Brand 端驗證:竄改後 presentation 於 SD-JWT 簽章檢查項失敗',
      tamperedResult.ok === false && tamperedResult.checks[0]?.ok === false,
      JSON.stringify(tamperedResult.checks.slice(0, 1)),
    );

    // (c) allowed_claims 外多挑一個 disclosure → CLAIM_NOT_IN_MANDATE(幕 3 DoD:雙向約束)。
    const aggDb = openDb();
    const aggRow = aggDb.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').get('pcf_aggregate-A') as { sd_jwt: string } | undefined;
    aggDb.close();
    if (!aggRow) {
      check('雙向約束測項前置:credentials 表存在 pcf_aggregate-A', false, '找不到 pcf_aggregate-A(前面幕 2 測項應已簽發)');
    } else {
      const overBroadFrame: Record<string, boolean> = {};
      for (const claim of m2Summary.allowed_claims) if (isSelectableDisclosure(claim)) overBroadFrame[claim] = true;
      overBroadFrame.precursor_contribution_tco2e_per_t = true; // 故意多挑一個不在 allowed_claims 內的 disclosure
      // 以低階入口 presentRawDisclosures 構造(繞過 L4 的 presenter deny-list),模擬「閘道被繞過/
      // 惡意 presenter」——正是要證明即使前面兩道防線失效,Brand 端雙向約束仍會攔下。
      const overBroadPresentation = await presentRawDisclosures(aggRow.sd_jwt, overBroadFrame as never);
      const overBroadResult = await verifyPresentation({ presentationSdJwt: overBroadPresentation, mandateJwt: m2MandateJwt, manifest });
      const boundaryCheck = overBroadResult.checks.find((c) => c.name.includes('雙向約束'));
      check(
        '幕 3 DoD(雙向約束):allowed_claims 外多挑一個 disclosure → CLAIM_NOT_IN_MANDATE',
        overBroadResult.ok === false && boundaryCheck?.ok === false && boundaryCheck?.reasonCode === CODES.CLAIM_NOT_IN_MANDATE,
        JSON.stringify(boundaryCheck),
      );
    }

    // (d) 遺留(a)鎖:錯誤角色簽發(vct 宣稱 pcf_aggregate,實際由 Thép Việt LE 鑰簽發,非鴻鋼)→ 拒絕。
    const yarnKey = loadSandboxKey('yarn');
    const nowSec = Math.floor(Date.now() / 1000);
    const forgedPayload = {
      vct: PCF_AGGREGATE_VCT,
      iss: yarnKey.kid,
      iat: nowSec,
      nbf: nowSec,
      exp: nowSec + 3600,
      status: { status_list: { idx: 2, uri: statusListUri('credentials') } },
      cn_code: '7318.15',
      precursor_ref: { id: 'pcf_upstream-A', hash: '0'.repeat(64) },
      carbon_total_tco2e_per_t: 1.5125,
    };
    const forgedFrame = { carbon_total_tco2e_per_t: true } as unknown as DisclosureFrame<SdJwtVcPayload>;
    const forgedInstance = buildIssuerInstance(yarnKey);
    const forgedSdJwt = await forgedInstance.issue(forgedPayload as unknown as SdJwtVcPayload, forgedFrame, { header: { kid: yarnKey.kid } });
    const forgedResult = await verifyPresentation({ presentationSdJwt: forgedSdJwt, mandateJwt: m2MandateJwt, manifest });
    const vctCheck = forgedResult.checks.find((c) => c.name.includes('vct'));
    check(
      '遺留(a)鎖:pcf_aggregate 由 Thép Việt LE 鑰(非鴻鋼)簽發 → vct↔簽發者 AID 綁定檢查失敗(VCT_ISSUER_UNAUTHORIZED)',
      forgedResult.ok === false && vctCheck?.ok === false && vctCheck?.reasonCode === CODES.VCT_ISSUER_UNAUTHORIZED,
      JSON.stringify(vctCheck),
    );
  }

  // 18) scripts/verify-offline.ts:實際 spawn 執行(不起 server)→ 幕 3 DoD「斷網狀態驗證仍成功」。
  {
    const presFile = path.join(ROOT, 'data', '.tmp-verify-offline-presentation.txt');
    const mandateFile = path.join(ROOT, 'data', '.tmp-verify-offline-mandate.txt');
    const receiptFile = path.join(ROOT, 'data', '.tmp-verify-offline-receipt.txt');
    fs.writeFileSync(presFile, permitPresentation);
    fs.writeFileSync(mandateFile, m2MandateJwt);
    fs.writeFileSync(receiptFile, permitReceipt); // F4:離線驗證同樣需要閘道 receipt
    try {
      const r = spawnSync(
        TSX_BIN,
        [
          'scripts/verify-offline.ts',
          '--presentation',
          path.relative(ROOT, presFile),
          '--mandate',
          path.relative(ROOT, mandateFile),
          '--receipt',
          path.relative(ROOT, receiptFile),
        ],
        { cwd: ROOT, encoding: 'utf-8' },
      );
      check(
        'scripts/verify-offline.ts 實際 spawn 執行成功(exit 0,不起 server、零網路呼叫)',
        r.status === 0 && r.stdout.includes('全數通過'),
        `status=${r.status} stdout=${r.stdout.slice(-300)} stderr=${r.stderr.slice(0, 300)}`,
      );
    } finally {
      fs.rmSync(presFile, { force: true });
      fs.rmSync(mandateFile, { force: true });
      fs.rmSync(receiptFile, { force: true });
    }
  }

  // 19) scripts/verify-chain.ts:正常鏈通過;手動竄改一列 payload 後非零退出;
  //     DENY/REPLAY_DETECTED 事件在鏈上驗得過(幕 4 DoD:連拒絕都留痕)。
  {
    const okRun = spawnSync(TSX_BIN, ['scripts/verify-chain.ts'], { cwd: ROOT, encoding: 'utf-8' });
    check('scripts/verify-chain.ts 正常鏈驗證通過(exit 0)', okRun.status === 0, `status=${okRun.status} stdout=${okRun.stdout.slice(-300)}`);
    check(
      '幕 4 DoD:DENY/REPLAY_DETECTED 事件在鏈上驗得過(連拒絕都留痕)',
      /拒絕\/重放類事件.*共 [1-9]\d* 筆/.test(okRun.stdout),
      okRun.stdout.slice(-300),
    );

    const tamperedDbPath = path.join(ROOT, 'db', '.tmp-verify-chain-tampered.sqlite');
    for (const suffix of ['', '-wal', '-shm']) {
      if (fs.existsSync(tamperedDbPath + suffix)) fs.rmSync(tamperedDbPath + suffix);
    }
    fs.copyFileSync(path.join(ROOT, 'db', 'demo.sqlite'), tamperedDbPath);
    try {
      const tamperConn = openDb(tamperedDbPath);
      tamperConn.prepare('UPDATE audit_chain SET payload_json = ? WHERE seq = 1').run(JSON.stringify({ tampered: true }));
      tamperConn.close();

      const tamperedRun = spawnSync(TSX_BIN, ['scripts/verify-chain.ts', '--db', tamperedDbPath], { cwd: ROOT, encoding: 'utf-8' });
      check(
        '手動竄改一列 payload 後 scripts/verify-chain.ts 非零退出 + AUDIT_CHAIN_TAMPERED',
        tamperedRun.status !== 0 && tamperedRun.stdout.includes(CODES.AUDIT_CHAIN_TAMPERED),
        `status=${tamperedRun.status} stdout=${tamperedRun.stdout.slice(-300)}`,
      );
    } finally {
      for (const suffix of ['', '-wal', '-shm']) {
        if (fs.existsSync(tamperedDbPath + suffix)) fs.rmSync(tamperedDbPath + suffix);
      }
    }
  }

  // 20) 遺留(c)(d)鎖:直接併發呼叫 issuePcfAggregate(函式層,非 HTTP)→ credentials 表該案一列,
  //     兩邊拿到同一 token(HTTP 層 Promise.all 測項無法可靠重現交錯執行,見既有 (a0) 區塊註解)。
  {
    const raceDb = openDb();
    raceDb.prepare('DELETE FROM credentials WHERE id IN (?, ?)').run('pcf_upstream-A', 'pcf_aggregate-A');
    raceDb.close();

    const dbForCall1 = openDb();
    const dbForCall2 = openDb();
    let issuance1: Awaited<ReturnType<typeof issuePcfAggregate>>;
    let issuance2: Awaited<ReturnType<typeof issuePcfAggregate>>;
    try {
      [issuance1, issuance2] = await Promise.all([issuePcfAggregate(dbForCall1, 'A'), issuePcfAggregate(dbForCall2, 'A')]);
    } finally {
      dbForCall1.close();
      dbForCall2.close();
    }
    check(
      '遺留(c)(d):併發直接呼叫 issuePcfAggregate(函式層,非 HTTP)兩邊拿到同一 sd_jwt(落庫勝者)',
      issuance1.sdJwt === issuance2.sdJwt && issuance1.sdJwt.length > 0,
      `sd_jwt1=${issuance1.sdJwt.slice(0, 24)}… sd_jwt2=${issuance2.sdJwt.slice(0, 24)}…`,
    );

    const checkDb = openDb();
    const rows = checkDb.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').all('pcf_aggregate-A') as { sd_jwt: string }[];
    checkDb.close();
    check(
      '遺留(c)(d):credentials 表 pcf_aggregate-A 該案只有一列,且與函式回傳之落庫勝者一致',
      rows.length === 1 && rows[0].sd_jwt === issuance1.sdJwt,
      `rows=${rows.length}`,
    );
  }

  // 21) Phase 2 前端 demo 輔助 route(server/routes/demo.ts、server/routes/policies.ts;
  //     phase2-frontend-spec.md「workload 簽章取得(定案)」+ Tab2 §2 政策原文小補充)。
  {
    const app21 = buildServer();
    try {
      // (a) GET /api/policies:唯讀回傳 policies/p1.cedar、p2.cedar 原文,與檔案內容逐字相同。
      const policiesRes = await app21.inject({ method: 'GET', url: '/api/policies' });
      const policiesBody = policiesRes.json() as { p1?: string; p2?: string };
      const p1Text = fs.readFileSync(path.join(ROOT, 'policies', 'p1.cedar'), 'utf-8');
      const p2Text = fs.readFileSync(path.join(ROOT, 'policies', 'p2.cedar'), 'utf-8');
      check(
        'GET /api/policies 回 200 且 p1/p2 內容與 policies/*.cedar 逐字相同',
        policiesRes.statusCode === 200 && policiesBody.p1 === p1Text && policiesBody.p2 === p2Text,
        `status=${policiesRes.statusCode}`,
      );

      // (b) POST /api/demo/sign-disclose-request:缺欄位/打錯字 → 400(不得靜默塌成合法值)。
      const badBodies: Array<Record<string, unknown>> = [
        {},
        { mandate_id: m2Summary.jti, case_id: 'X', requested_claims: ['cn_code'] },
        { mandate_id: m2Summary.jti, case_id: 'A', requested_claims: [] },
      ];
      for (const payload of badBodies) {
        const r = await app21.inject({ method: 'POST', url: '/api/demo/sign-disclose-request', payload });
        check(`demo 輔助路由缺欄位/打錯字(${JSON.stringify(payload)})→ 400`, r.statusCode === 400, `status=${r.statusCode} body=${r.body}`);
      }

      // (c) 合法呼叫 → 200,request_jws header.kid == brand-workload kid,payload 欄位與請求一致。
      const brandWorkload = loadWorkloadKey('brand-workload');
      const demoReqClaims = m2Summary.allowed_claims;
      const signRes = await app21.inject({
        method: 'POST',
        url: '/api/demo/sign-disclose-request',
        payload: { mandate_id: m2Summary.jti, case_id: 'A', requested_claims: demoReqClaims },
      });
      check(
        'POST /api/demo/sign-disclose-request 回 200',
        signRes.statusCode === 200,
        `status=${signRes.statusCode} body=${signRes.body.slice(0, 200)}`,
      );
      const signBody = signRes.json() as { request_jws: string; request_nonce: string };
      check(
        'request_jws header.kid == brand-workload 公鑰 kid',
        decodeProtectedHeader(signBody.request_jws).kid === brandWorkload.kid,
        `kid=${decodeProtectedHeader(signBody.request_jws).kid}`,
      );
      const signedPayload = (decodeJwt(signBody.request_jws) as unknown as { payload: Record<string, unknown> }).payload;
      check(
        'request_jws payload 欄位與請求一致(mandate_id/case_id/requested_claims/request_nonce)',
        signedPayload.mandate_id === m2Summary.jti &&
          signedPayload.case_id === 'A' &&
          JSON.stringify(signedPayload.requested_claims) === JSON.stringify(demoReqClaims) &&
          signedPayload.request_nonce === signBody.request_nonce,
        JSON.stringify(signedPayload),
      );

      // (d) demo 輔助路由簽出的 request_jws 送進 /api/disclose 仍走完整驗證管線 → PERMIT(未繞過任何驗證)。
      const discloseViaDemoRes = await app21.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: signBody.request_jws } });
      check(
        'demo 輔助路由簽出的 request_jws 送進 /api/disclose 仍走完整驗證管線,回 200 PERMIT(未繞過任何驗證)',
        discloseViaDemoRes.statusCode === 200 && (discloseViaDemoRes.json() as { decision?: string }).decision === 'PERMIT',
        `status=${discloseViaDemoRes.statusCode} body=${discloseViaDemoRes.body.slice(0, 200)}`,
      );
    } finally {
      await app21.close();
    }
  }

  // 23) Phase 2 總驗收缺陷修復回歸鎖(C1 / H1 / H2 / M1 / M2 / L3 / L4 / H3)。
  //     每一項都對應一個曾以 PoC 重現的真缺陷,退回舊寫法必翻紅。
  {
    const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'vlei', 'manifest.json'), 'utf-8')) as Manifest;
    const seedData = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8'));
    const brandWorkload = loadWorkloadKey('brand-workload');
    const app23 = buildServer();

    try {
      // ---------- C1:vct ↔ 簽發者 AID 綁定必須以「實際驗章鑰」為準 ----------
      // (a) 不誠實偽造:攻擊者用 Thép Việt LE 鑰**實際簽章**(header.kid = Thép Việt AID),
      //     payload.iss 卻填鴻鋼 LE AID。舊版綁定檢查只比對 payload.iss、取鑰卻走 header.kid,
      //     兩者從不互相校驗 → 偽造的 carbon_total 會被判 valid=true(PoC 已證實)。
      const attackerKey = loadSandboxKey('yarn');
      const c1Now = Math.floor(Date.now() / 1000);
      const forgedClaims = {
        vct: PCF_AGGREGATE_VCT,
        iss: manifest.fab.aid, // 宣稱鴻鋼簽的
        iat: c1Now,
        nbf: c1Now,
        exp: c1Now + 3600,
        status: { status_list: { idx: 2, uri: statusListUri('credentials') } },
        cn_code: '7318.15',
        precursor_ref: { id: 'pcf_upstream-A', hash: '0'.repeat(64) },
        carbon_total_tco2e_per_t: 0.0001, // 偽造的超低碳排
        carbon_price_paid_origin: '(偽造)',
      };
      const forgedFrame23 = {
        _sd: ['carbon_total_tco2e_per_t', 'carbon_price_paid_origin'],
      } as unknown as DisclosureFrame<SdJwtVcPayload>;
      const dishonestSdJwt = await buildIssuerInstance(attackerKey).issue(forgedClaims as unknown as SdJwtVcPayload, forgedFrame23, {
        header: { kid: attackerKey.kid }, // 誠實標示自己的鑰(簽章驗得過),只在 payload 說謊
      });
      const dishonestResult = await verifyPresentation({ presentationSdJwt: dishonestSdJwt, mandateJwt: m2MandateJwt, manifest });
      const dishonestSigCheck = dishonestResult.checks[0];
      const dishonestVctCheck = dishonestResult.checks.find((c) => c.name.includes('vct'));
      check(
        'C1:header.kid(實際簽章者 Thép Việt)≠ payload.iss(宣稱鴻鋼)之偽造 pcf_aggregate → VCT_ISSUER_UNAUTHORIZED',
        dishonestResult.ok === false && dishonestVctCheck?.ok === false && dishonestVctCheck?.reasonCode === CODES.VCT_ISSUER_UNAUTHORIZED,
        JSON.stringify(dishonestVctCheck),
      );
      check(
        'C1:該偽造憑證的簽章檢查本身是通過的(證明擋下它的是綁定檢查,不是簽章驗證)',
        dishonestSigCheck?.ok === true,
        JSON.stringify(dishonestSigCheck),
      );
      check(
        'C1:偽造的 carbon_total(0.0001)不會被判定為有效資料(整體 valid=false)',
        dishonestResult.ok === false,
        JSON.stringify(dishonestResult.checks.map((c) => [c.name, c.ok])),
      );

      // (b) kid 冒充:header.kid 填鴻鋼 AID、實際仍用 Thép Việt 鑰簽 → 第 1 項簽章驗證即失敗
      //     (取鑰依 kid,解出鴻鋼公鑰,驗不過攻擊者的簽章)。
      const kidSpoofSdJwt = await buildIssuerInstance(attackerKey).issue(forgedClaims as unknown as SdJwtVcPayload, forgedFrame23, {
        header: { kid: manifest.fab.aid },
      });
      const kidSpoofResult = await verifyPresentation({ presentationSdJwt: kidSpoofSdJwt, mandateJwt: m2MandateJwt, manifest });
      check(
        'C1:header.kid 冒充鴻鋼、實際用 Thép Việt 鑰簽 → 簽章檢查失敗(CREDENTIAL_SIG_INVALID)',
        kidSpoofResult.ok === false && kidSpoofResult.checks[0]?.ok === false && kidSpoofResult.checks[0]?.reasonCode === CODES.CREDENTIAL_SIG_INVALID,
        JSON.stringify(kidSpoofResult.checks[0]),
      );

      // ---------- H2:最小揭露不得有算術洩漏 ----------
      const presVerify23 = await verifyCompactSdJwt(permitPresentation, resolvePublicKeyFromManifest(manifest));
      const presPayload23 = (presVerify23.payload ?? {}) as Record<string, unknown>;
      const emissionFieldNames = ['carbon_total_tco2e_per_t', ...NEVER_DISCLOSABLE_CLAIMS];
      const disclosedEmissionFields = emissionFieldNames.filter((f) => f in presPayload23);
      check(
        'H2:PERMIT presentation 內的排放數字欄位至多 1 個(只有聚合值,無法兩兩相減)',
        disclosedEmissionFields.length <= 1,
        JSON.stringify(disclosedEmissionFields),
      );
      check(
        'H2:PERMIT presentation 不含任何聚合分項(precursor_contribution / self_direct / self_indirect)',
        NEVER_DISCLOSABLE_CLAIMS.every((f) => !(f in presPayload23)),
        JSON.stringify(Object.keys(presPayload23)),
      );

      // 還原攻擊:對 presentation 內**所有**數值(含巢狀)做任意 ± 組合,都不得等於
      // precursor_contribution(1.05×1.05=1.1025)或上游合計(0.42+0.63=1.05)。
      const collectNumbers = (v: unknown, out: number[] = []): number[] => {
        if (typeof v === 'number' && Number.isFinite(v)) out.push(v);
        else if (Array.isArray(v)) v.forEach((x) => collectNumbers(x, out));
        else if (v && typeof v === 'object') Object.values(v as Record<string, unknown>).forEach((x) => collectNumbers(x, out));
        return out;
      };
      const disclosedNumbers = collectNumbers(presPayload23);
      const upstreamTotal = seedData.cases.A.direct + seedData.cases.A.indirect;
      const precursorContribution = seedData.aggregate_defaults.precursor_input_ratio_t_per_t * upstreamTotal;
      const reconstructionTargets = [precursorContribution, upstreamTotal];
      let reconstructed: string | null = null;
      const combos = 3 ** disclosedNumbers.length;
      for (let mask = 1; mask < combos && !reconstructed; mask++) {
        let sum = 0;
        let used = 0;
        let m = mask;
        const terms: string[] = [];
        for (const n of disclosedNumbers) {
          const sign = m % 3; // 0=不用 1=加 2=減
          m = Math.floor(m / 3);
          if (sign === 1) {
            sum += n;
            used++;
            terms.push(`+${n}`);
          } else if (sign === 2) {
            sum -= n;
            used++;
            terms.push(`-${n}`);
          }
        }
        if (used === 0) continue;
        for (const target of reconstructionTargets) {
          if (Math.abs(sum - target) < 1e-9) reconstructed = `${terms.join('')} = ${target}`;
        }
      }
      check(
        `H2 還原攻擊:揭露數值(${disclosedNumbers.length} 個)的任意 ± 組合都無法還原 precursor_contribution(${precursorContribution})或上游合計(${upstreamTotal})`,
        reconstructed === null,
        `命中組合:${reconstructed}`,
      );

      // ---------- M2:mandate 必須由預期 ECR 角色簽發 ----------
      const mandatePayloadOriginal = decodeJoseJwt(m2MandateJwt) as Record<string, unknown>;
      const cfoKey = loadSandboxKey('fab_cfo');
      // (a) 換角色簽(鴻鋼財務主管 ECR 冒簽 M2):kid/iss 都誠實寫自己 → 必須因「非預期角色」被拒。
      const wrongRoleMandate = await new SignJWT({ ...mandatePayloadOriginal, iss: cfoKey.kid })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'mandate+jwt', kid: cfoKey.kid })
        .sign(cfoKey.privateKey);
      // (b) kid 冒充 Brand 永續長、實際用鴻鋼財務主管鑰簽 → 簽章驗證失敗。
      const kidSpoofMandate = await new SignJWT({ ...mandatePayloadOriginal })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'mandate+jwt', kid: manifest.brand_cso.aid })
        .sign(cfoKey.privateKey);

      const mandateDb23 = openDb();
      const originalM2Token = (mandateDb23.prepare('SELECT token FROM mandates WHERE id = ?').get('M2') as { token: string }).token;
      mandateDb23.close();
      for (const [label, badToken] of [
        ['非預期角色(鴻鋼財務主管 ECR)簽發 M2', wrongRoleMandate],
        ['kid 冒充 Brand 永續長、實際用他方鑰簽', kidSpoofMandate],
      ] as const) {
        const swapDb = openDb();
        swapDb.prepare('UPDATE mandates SET token = ? WHERE id = ?').run(badToken, 'M2');
        swapDb.close();
        const jws = await signDiscloseRequest(brandWorkload, m2Summary.jti, 'A', m2Summary.allowed_claims, randomNonce());
        const res = await app23.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: jws } });
        check(
          `M2:${label} → 403 MANDATE_SIG_INVALID(mandate iss 綁定預期 ECR 角色)`,
          res.statusCode === 403 && (res.json() as { reason_code?: string }).reason_code === CODES.MANDATE_SIG_INVALID,
          `status=${res.statusCode} body=${res.body}`,
        );
        const restoreDb = openDb();
        restoreDb.prepare('UPDATE mandates SET token = ? WHERE id = ?').run(originalM2Token, 'M2');
        restoreDb.close();
      }
      // Brand 端(verifyPresentation 第 5 項)同樣不接受非預期角色簽發的 M2。
      const wrongRoleVerify = await verifyPresentation({ presentationSdJwt: permitPresentation, mandateJwt: wrongRoleMandate, manifest, receipt: permitReceipt });
      const mandateCheck23 = wrongRoleVerify.checks.find((c) => c.name.includes('M2 mandate 完整性'));
      check(
        'M2:Brand 端驗證亦拒絕非預期角色簽發的 M2 mandate(MANDATE_SIG_INVALID)',
        wrongRoleVerify.ok === false && mandateCheck23?.ok === false && mandateCheck23?.reasonCode === CODES.MANDATE_SIG_INVALID,
        JSON.stringify(mandateCheck23),
      );

      // ---------- M1:request_jws 新鮮度窗 ----------
      const nowSec23 = Math.floor(Date.now() / 1000);
      const staleNonce = randomNonce();
      const staleJws = await signDiscloseRequest(brandWorkload, m2Summary.jti, 'A', m2Summary.allowed_claims, staleNonce, nowSec23 - 3600);
      const staleRes = await app23.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: staleJws } });
      check(
        'M1:iat 過舊(1 小時前)的 request_jws → 400 DISCLOSE_REQUEST_INVALID(被拒的請求無法長期保存待條件變好再用)',
        staleRes.statusCode === 400 && (staleRes.json() as { reason_code?: string }).reason_code === CODES.DISCLOSE_REQUEST_INVALID,
        `status=${staleRes.statusCode} body=${staleRes.body}`,
      );
      const staleRetryRes = await app23.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: staleJws } });
      check(
        'M1:同一份過期 request_jws 稍後再重放仍是 400(新鮮度窗不因狀態改變而放行)',
        staleRetryRes.statusCode === 400,
        `status=${staleRetryRes.statusCode}`,
      );
      const futureJws = await signDiscloseRequest(brandWorkload, m2Summary.jti, 'A', m2Summary.allowed_claims, randomNonce(), nowSec23 + 3600);
      const futureRes = await app23.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: futureJws } });
      check(
        'M1:iat 超前(1 小時後)的未來票 request_jws → 400 DISCLOSE_REQUEST_INVALID',
        futureRes.statusCode === 400 && (futureRes.json() as { reason_code?: string }).reason_code === CODES.DISCLOSE_REQUEST_INVALID,
        `status=${futureRes.statusCode} body=${futureRes.body}`,
      );
      const freshJws = await signDiscloseRequest(brandWorkload, m2Summary.jti, 'A', m2Summary.allowed_claims, randomNonce());
      const freshRes = await app23.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: freshJws } });
      check(
        'M1 對照組:新鮮的 request_jws 仍 PERMIT(新鮮度窗沒有把正常路徑一起擋死)',
        freshRes.statusCode === 200,
        `status=${freshRes.statusCode} body=${freshRes.body.slice(0, 160)}`,
      );

      // ---------- L3:Status List Token 必須驗 typ ----------
      const realStatusToken = readStatusListToken('credentials');
      const fabKey23 = loadSandboxKey('fab');
      const statusIssuerPubKey = publicKeyFromQb64(manifest.fab.public_key);
      const realStatusPayload = decodeJoseJwt(realStatusToken ?? '') as Record<string, unknown>;
      const typSpoofToken = await new SignJWT(realStatusPayload)
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: fabKey23.kid }) // 同一把鑰、內容合法,只是 typ 不對
        .sign(fabKey23.privateKey);
      const typSpoofResult = await checkStatusBit(typSpoofToken, 2, statusIssuerPubKey, statusListUri('credentials'));
      check(
        'L3:typ 非 "statuslist+jwt" 的 JWT(同鑰簽、內容相同)→ checkStatusBit 拒絕',
        typSpoofResult.ok === false && /typ/.test(typSpoofResult.error ?? ''),
        JSON.stringify(typSpoofResult),
      );
      const realStatusResult = await checkStatusBit(realStatusToken ?? '', 2, statusIssuerPubKey, statusListUri('credentials'));
      check('L3 對照組:正式 Status List Token(typ 正確)仍通過', realStatusResult.ok === true && realStatusResult.revoked === false, JSON.stringify(realStatusResult));

      // ---------- L4:presenter 端硬 deny-list(縱深防禦)----------
      const aggDb23 = openDb();
      const aggSdJwt23 = (aggDb23.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').get('pcf_aggregate-A') as { sd_jwt: string }).sd_jwt;
      aggDb23.close();
      for (const denied of NEVER_DISCLOSABLE_CLAIMS) {
        let caught: unknown = null;
        try {
          await presentSelectedDisclosures(aggSdJwt23, { [denied]: true } as never);
        } catch (e) {
          caught = e;
        }
        check(
          `L4:presenter 挑到 ${denied} → 硬拒(NeverDisclosableClaimError,不看 mandate 寫什麼)`,
          caught instanceof NeverDisclosableClaimError,
          String(caught),
        );
      }
      const allowedOnlyPresentation = await presentSelectedDisclosures(aggSdJwt23, { carbon_total_tco2e_per_t: true } as never);
      check('L4 對照組:只挑允許欄位仍可正常出示', typeof allowedOnlyPresentation === 'string' && allowedOnlyPresentation.length > 0);

      // ---------- H3:Brand 端 vLEI 鏈查驗只讀 data/vlei/(不再讀 .vlei/ 私鑰種子)----------
      check('H3:vLEI 公開狀態檔存在於 data/vlei/(由 server/keys.ts 於 seed 時匯出)', fs.existsSync(PUBLIC_VLEI_STATE_FILE), PUBLIC_VLEI_STATE_FILE);
      const publicStateText = fs.existsSync(PUBLIC_VLEI_STATE_FILE) ? fs.readFileSync(PUBLIC_VLEI_STATE_FILE, 'utf-8') : '';
      const publicStateJson = publicStateText ? (JSON.parse(publicStateText) as { actors: Record<string, Record<string, unknown>> }) : { actors: {} };
      check(
        'H3:公開狀態不含任何 actor 私鑰種子(無 seed/next_seed 欄位,且無 CESR "A" 碼 44 字元種子字串)',
        Object.values(publicStateJson.actors).every((a) => !('seed' in a) && !('next_seed' in a)) && !/"A[A-Za-z0-9_-]{43}"/.test(publicStateText),
        `actors=${Object.keys(publicStateJson.actors).length}`,
      );
      const publicStateVerify = spawnSync(py, [sb, '--dir', VLEI_PUBLIC_STATE_DIR, 'verify', '--said', manifest.fab.credential_said], {
        encoding: 'utf-8',
      });
      check(
        'H3:sandbox verify 對「只含公開材料」的狀態目錄執行成功(查驗強度不變:SAID 重算 + 簽章 + TEL 撤銷)',
        publicStateVerify.status === 0 && publicStateVerify.stdout.includes('chain verified'),
        `status=${publicStateVerify.status} stderr=${publicStateVerify.stderr.slice(0, 200)}`,
      );
      const verifyPresentationSource = fs.readFileSync(path.join(ROOT, 'server', 'creds', 'verifyPresentation.ts'), 'utf-8');
      check(
        'H3:verifyPresentation 以 VLEI_PUBLIC_STATE_DIR 執行 sandbox verify(不再 --dir 指向 repo 根)',
        verifyPresentationSource.includes("'--dir', VLEI_PUBLIC_STATE_DIR") && !/'--dir',\s*ROOT/.test(verifyPresentationSource),
      );
      const brandAgentSource = fs.readFileSync(path.join(ROOT, 'web', 'src', 'tabs', 'BrandAgent.tsx'), 'utf-8');
      check(
        'H3:BrandAgent 文案「只讀 token、manifest 公鑰、data/vlei/、data/status/」現在為真(讀取範圍與程式一致)',
        brandAgentSource.includes('只讀 token、manifest 公鑰、data/vlei/、data/status/') && verifyPresentationSource.includes('VLEI_PUBLIC_STATE_DIR'),
      );

      // ---------- H1:query_cap 併發不得超額(函式層,非只 HTTP Promise.all)----------
      // 設定剩餘額度 2,併發 6 筆各自合法、nonce 互異的 disclose;舊寫法(交易外讀舊快照)
      // 實測會放行 5 筆、queries_used 衝到 13。
      const capSetupDb = openDb();
      const capRow = capSetupDb.prepare('SELECT query_cap, queries_used FROM mandates WHERE id = ?').get('M2') as {
        query_cap: number;
        queries_used: number;
      };
      const queryCap = capRow.query_cap;
      const remaining = 2;
      const concurrency = 6;
      capSetupDb.prepare('UPDATE mandates SET queries_used = ? WHERE id = ?').run(queryCap - remaining, 'M2');
      capSetupDb.close();

      const capJwsList: string[] = [];
      for (let i = 0; i < concurrency; i++) {
        capJwsList.push(await signDiscloseRequest(brandWorkload, m2Summary.jti, 'A', m2Summary.allowed_claims, randomNonce()));
      }
      const capDbs = capJwsList.map(() => openDb());
      const capResults = await Promise.all(capJwsList.map((jws, i) => processDiscloseRequest(capDbs[i], jws)));
      capDbs.forEach((d) => d.close());
      const capPermits = capResults.filter((r) => r.kind === 'success').length;
      const capDenials = capResults.filter((r) => r.kind === 'error' && r.reasonCode === CODES.QUERY_CAP_EXCEEDED).length;
      const capAfterDb = openDb();
      const queriesUsedAfterRace = (capAfterDb.prepare('SELECT queries_used FROM mandates WHERE id = ?').get('M2') as { queries_used: number })
        .queries_used;
      const presentationsAfterRace = (
        capAfterDb.prepare('SELECT COUNT(*) c FROM presentations WHERE mandate_id = ?').get('M2') as { c: number }
      ).c;
      capAfterDb.close();
      check(
        `H1:剩餘額度 ${remaining}、併發 ${concurrency} 筆合法 disclose → PERMIT 數 ≤ ${remaining}`,
        capPermits <= remaining,
        `permits=${capPermits} denials(QUERY_CAP_EXCEEDED)=${capDenials}`,
      );
      check(
        `H1:queries_used 收斂到 ≤ query_cap(${queryCap})`,
        queriesUsedAfterRace <= queryCap,
        `queries_used=${queriesUsedAfterRace} cap=${queryCap}`,
      );
      check(
        'H1:超額請求以 QUERY_CAP_EXCEEDED 被擋(交易內回滾,不是靜默放行)',
        capDenials >= concurrency - remaining,
        `denials=${capDenials} permits=${capPermits}`,
      );
      check('H1 對照組:額度未用罄前仍至少放行 1 筆(不是把整條路鎖死)', capPermits >= 1, `permits=${capPermits}`);
      check(
        'H1:PERMIT 筆數與 presentations 落庫筆數一致(扣次、出示紀錄、audit 同一筆交易)',
        presentationsAfterRace >= capPermits,
        `permits=${capPermits} presentations=${presentationsAfterRace}`,
      );
      // 還原額度,避免影響後續(本區塊之後只剩一致性守門,仍照樣復原)。
      const capRestoreDb = openDb();
      capRestoreDb.prepare('UPDATE mandates SET queries_used = ? WHERE id = ?').run(capRow.queries_used, 'M2');
      capRestoreDb.close();
    } finally {
      await app23.close();
    }
  }

  // 24) Codex adversarial review(Phase 2 No-ship)8 條 finding 回歸鎖(F1 已在幕 2 區塊,
  //     此處為 F2–F8)。每一項退回舊寫法必翻紅(對應 PoC 已實打舊洞/新擋)。
  {
    const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'vlei', 'manifest.json'), 'utf-8')) as Manifest;
    const brandWorkload = loadWorkloadKey('brand-workload');
    const fabKey = loadSandboxKey('fab');
    const brandCso = loadSandboxKey('brand_cso');
    const statusIssuerPubKey = publicKeyFromQb64(manifest.fab.public_key);
    const m2Payload = decodeJoseJwt(m2MandateJwt) as Record<string, unknown>;
    const app24 = buildServer();

    // 本區塊多次 disclose 會扣 M2 query_cap;前面各幕已把 cap 用得差不多,這裡先歸零 queries_used
    // 讓 F3/F4 的 disclose 有額度(不影響 H1 cap 測項——那在 section 23 已獨立驗過並復原)。
    const capResetDb = openDb();
    capResetDb.prepare('UPDATE mandates SET queries_used = 0 WHERE id = ?').run('M2');
    capResetDb.close();

    try {
      // ---------- F2:未認證 demo 簽章 oracle → production 不註冊 ----------
      const prevNodeEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      const prodApp = buildServer();
      try {
        const r = await prodApp.inject({
          method: 'POST',
          url: '/api/demo/sign-disclose-request',
          payload: { mandate_id: m2Summary.jti, case_id: 'A', requested_claims: ['cn_code'] },
        });
        check('F2:production(NODE_ENV=production)下 demo 簽章 oracle route 不註冊(404)', r.statusCode === 404, `status=${r.statusCode}`);
      } finally {
        await prodApp.close();
        if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
        else process.env.NODE_ENV = prevNodeEnv;
      }
      const demoModeApp = buildServer();
      try {
        const r = await demoModeApp.inject({ method: 'POST', url: '/api/demo/sign-disclose-request', payload: {} });
        check('F2 對照組:demo 模式(預設)下該 route 仍註冊(缺欄位回 400,非 404)', r.statusCode === 400, `status=${r.statusCode}`);
      } finally {
        await demoModeApp.close();
      }

      // ---------- F6:status-list 跨清單替換 + 陳舊 ----------
      const credToken = readStatusListToken('credentials') ?? '';
      const crossListResult = await checkStatusBit(credToken, 1, statusIssuerPubKey, statusListUri('mandates'));
      check(
        'F6:拿 credentials token 當 mandates 查(sub 不符)→ 拒(跨清單替換防線)',
        crossListResult.ok === false && /sub/.test(crossListResult.error ?? ''),
        JSON.stringify(crossListResult),
      );
      const farFutureMs = Date.now() + (STATUS_TTL_SECONDS + 3600) * 1000;
      const staleResult = await checkStatusBit(credToken, 2, statusIssuerPubKey, statusListUri('credentials'), { now: farFutureMs });
      check(
        'F6:同一 token 時間前移超過 ttl+skew 後 → 判定陳舊被拒(exp 仍在 180 天內也不接受快取)',
        staleResult.ok === false && /陳舊|ttl/.test(staleResult.error ?? ''),
        JSON.stringify(staleResult),
      );
      const freshResult = await checkStatusBit(credToken, 2, statusIssuerPubKey, statusListUri('credentials'), { now: Date.now() });
      check('F6 對照組:同一 token 以現在時間查 → 通過(新鮮、未撤銷)', freshResult.ok === true && freshResult.revoked === false, JSON.stringify(freshResult));

      // ---------- F7:同步 vLEI 驗證加 timeout(不阻塞 event loop)----------
      const t0 = Date.now();
      const timeoutResult = verifyVleiChainSandbox(manifest.fab.credential_said, { timeoutMs: 1 });
      const elapsed = Date.now() - t0;
      check(
        'F7:vLEI 查驗以極短 timeout(1ms)→ 回明確失敗而非無限阻塞(且很快返回)',
        timeoutResult.ok === false && elapsed < 8000,
        `ok=${timeoutResult.ok} elapsed=${elapsed}ms detail=${timeoutResult.detail}`,
      );
      const normalVleiResult = verifyVleiChainSandbox(manifest.fab.credential_said);
      check('F7 對照組:正常 timeout 下 vLEI 查驗仍通過(查驗強度不變)', normalVleiResult.ok === true, JSON.stringify(normalVleiResult));

      // ---------- F8:雙向約束改為 disclosure-derived(schema 演進不 fail-open)----------
      const f8Now = Math.floor(Date.now() / 1000);
      const extraPayload = {
        vct: PCF_AGGREGATE_VCT,
        iss: fabKey.kid,
        iat: f8Now,
        nbf: f8Now,
        exp: f8Now + 3600,
        status: { status_list: { idx: 2, uri: statusListUri('credentials') } },
        cn_code: '7318.15',
        precursor_ref: { id: 'pcf_upstream-A', hash: '0'.repeat(64) },
        carbon_total_tco2e_per_t: 1.5125,
        carbon_price_paid_origin: '台灣碳費',
        // 授權簽發者(鴻鋼)新增並揭露的一個 mandate 未列 claim——舊版硬編 PCF_AGGREGATE_SD_FIELDS 不含它 → fail-open。
        unexpected_extra_claim: 'schema-evolution-injected',
      };
      const extraFrame = {
        _sd: ['carbon_total_tco2e_per_t', 'carbon_price_paid_origin', 'unexpected_extra_claim'],
      } as unknown as DisclosureFrame<SdJwtVcPayload>;
      const extraSdJwt = await buildIssuerInstance(fabKey).issue(extraPayload as unknown as SdJwtVcPayload, extraFrame, { header: { kid: fabKey.kid } });
      const f8Result = await verifyPresentation({ presentationSdJwt: extraSdJwt, mandateJwt: m2MandateJwt, manifest, receipt: permitReceipt });
      const f8Boundary = f8Result.checks.find((c) => c.name.includes('雙向約束'));
      check(
        'F8:授權簽發者揭露一個 mandate 未列的新 claim(unexpected_extra_claim)→ CLAIM_NOT_IN_MANDATE(不 fail-open)',
        f8Result.ok === false && f8Boundary?.ok === false && f8Boundary?.reasonCode === CODES.CLAIM_NOT_IN_MANDATE,
        JSON.stringify(f8Boundary),
      );

      // ---------- F4:presentation 綁定閘道 receipt(重放/配對他 mandate 被抓)----------
      // 第二次 disclose 取另一組 presentation/receipt(用來證明 P1↔R2 / P2↔R1 交叉配對會被 hash 綁定擋下)。
      const secondJws = await signDiscloseRequest(brandWorkload, m2Summary.jti, 'A', m2Summary.allowed_claims, randomNonce());
      const secondRes = await app24.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: secondJws } });
      const secondBody = secondRes.json() as { presentation: string; receipt: string };
      // (a) 缺 receipt → RECEIPT_INVALID。
      const noReceipt = await verifyPresentation({ presentationSdJwt: permitPresentation, mandateJwt: m2MandateJwt, manifest });
      const noReceiptCheck = noReceipt.checks.find((c) => c.name.includes('receipt'));
      check(
        'F4:缺閘道 receipt 的裸 presentation → RECEIPT_INVALID(無 key-binding 不予採信)',
        noReceipt.ok === false && noReceiptCheck?.ok === false && noReceiptCheck?.reasonCode === CODES.RECEIPT_INVALID,
        JSON.stringify(noReceiptCheck),
      );
      // (b) 竄改 receipt(改 1 字元)→ 簽章壞 → RECEIPT_INVALID。
      const tamperedReceipt = permitReceipt.slice(0, -2) + (permitReceipt.slice(-2) === 'AA' ? 'BB' : 'AA');
      const badReceipt = await verifyPresentation({ presentationSdJwt: permitPresentation, mandateJwt: m2MandateJwt, manifest, receipt: tamperedReceipt });
      const badReceiptCheck = badReceipt.checks.find((c) => c.name.includes('receipt'));
      check(
        'F4:竄改 receipt(簽章壞)→ RECEIPT_INVALID',
        badReceipt.ok === false && badReceiptCheck?.ok === false && badReceiptCheck?.reasonCode === CODES.RECEIPT_INVALID,
        JSON.stringify(badReceiptCheck),
      );
      // (c) 交叉配對:P1 + R2 / P2 + R1 → presentation_hash 綁定不符 → RECEIPT_INVALID。
      const crossPR = await verifyPresentation({ presentationSdJwt: permitPresentation, mandateJwt: m2MandateJwt, manifest, receipt: secondBody.receipt });
      const crossPRCheck = crossPR.checks.find((c) => c.name.includes('receipt'));
      check(
        'F4:擷取的 presentation 配另一次請求的 receipt(P1+R2)→ presentation_hash 不符 → RECEIPT_INVALID',
        crossPR.ok === false && crossPRCheck?.ok === false && crossPRCheck?.reasonCode === CODES.RECEIPT_INVALID,
        JSON.stringify(crossPRCheck),
      );
      // (d) 配對另一張相容 mandate(Brand-CSO 簽、jti 不同)→ mandate_jti 綁定不符 → RECEIPT_INVALID。
      const swappedMandate = await new SignJWT({ ...m2Payload, jti: crypto.randomUUID() })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'mandate+jwt', kid: brandCso.kid })
        .sign(brandCso.privateKey);
      const swapResult = await verifyPresentation({ presentationSdJwt: permitPresentation, mandateJwt: swappedMandate, manifest, receipt: permitReceipt });
      const swapReceiptCheck = swapResult.checks.find((c) => c.name.includes('receipt'));
      check(
        'F4:captured presentation+receipt 配對另一張相容 mandate(jti 不同)→ mandate_jti 綁定不符 → RECEIPT_INVALID',
        swapResult.ok === false && swapReceiptCheck?.ok === false && swapReceiptCheck?.reasonCode === CODES.RECEIPT_INVALID,
        JSON.stringify(swapReceiptCheck),
      );
      // (e) 對照組:P2 + R2 正確配對 → 全綠。
      const properPair = await verifyPresentation({ presentationSdJwt: secondBody.presentation, mandateJwt: m2MandateJwt, manifest, receipt: secondBody.receipt });
      check('F4 對照組:正確配對(P2+R2)→ 全數通過', properPair.ok === true, JSON.stringify(properPair.checks.map((c) => [c.name, c.ok])));

      // ---------- F5:離線驗證完整驗 mandate(typ/aud/撤銷位元)----------
      // (a) typ 非 mandate+jwt → MANDATE_SIG_INVALID(check 5)。
      const typBadMandate = await new SignJWT({ ...m2Payload })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: brandCso.kid })
        .sign(brandCso.privateKey);
      const typBadResult = await verifyPresentation({ presentationSdJwt: permitPresentation, mandateJwt: typBadMandate, manifest, receipt: permitReceipt });
      const typBadCheck = typBadResult.checks.find((c) => c.name.includes('M2 mandate 完整性'));
      check(
        'F5:mandate typ 非 "mandate+jwt"(同鑰簽、內容相同)→ MANDATE_SIG_INVALID',
        typBadResult.ok === false && typBadCheck?.ok === false && typBadCheck?.reasonCode === CODES.MANDATE_SIG_INVALID,
        JSON.stringify(typBadCheck),
      );
      // (b) aud 非本閘道 → MANDATE_SIG_INVALID(check 5)。
      const audBadMandate = await new SignJWT({ ...m2Payload, aud: 'evil-audience' })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'mandate+jwt', kid: brandCso.kid })
        .sign(brandCso.privateKey);
      const audBadResult = await verifyPresentation({ presentationSdJwt: permitPresentation, mandateJwt: audBadMandate, manifest, receipt: permitReceipt });
      const audBadCheck = audBadResult.checks.find((c) => c.name.includes('M2 mandate 完整性'));
      check(
        'F5:mandate aud 非本閘道(evil-audience)→ MANDATE_SIG_INVALID',
        audBadResult.ok === false && audBadCheck?.ok === false && audBadCheck?.reasonCode === CODES.MANDATE_SIG_INVALID,
        JSON.stringify(audBadCheck),
      );
      // (c) 撤銷 M2 mandate 位元後離線驗證 → MANDATE_REVOKED(check 6)。測完立即還原。
      const revokedMandates = new Array<number>(STATUS_LIST_SIZE).fill(0);
      revokedMandates[1] = 1; // M2 位於 mandates 清單 idx=1
      await buildAndWriteStatusList('mandates', revokedMandates);
      try {
        const revokedResult = await verifyPresentation({ presentationSdJwt: permitPresentation, mandateJwt: m2MandateJwt, manifest, receipt: permitReceipt });
        const mStatusCheck = revokedResult.checks.find((c) => c.name.includes('mandate 撤銷狀態'));
        check(
          'F5:撤銷 M2 mandate 位元後離線驗證該 presentation → MANDATE_REVOKED',
          revokedResult.ok === false && mStatusCheck?.ok === false && mStatusCheck?.reasonCode === CODES.MANDATE_REVOKED,
          JSON.stringify(mStatusCheck),
        );
      } finally {
        await buildAndWriteStatusList('mandates'); // 還原全 0
      }

      // ---------- F3:閘道對已撤銷/過期 aggregate 停止揭露(不扣 cap、不寫 presentation)----------
      // (a) 撤銷 credentials idx=2(案 A pcf_aggregate)後 disclose → CREDENTIAL_REVOKED、cap 未扣、無 presentation。
      const f3Before = openDb();
      const qBefore = (f3Before.prepare('SELECT queries_used FROM mandates WHERE id = ?').get('M2') as { queries_used: number }).queries_used;
      const presBefore = (f3Before.prepare('SELECT COUNT(*) c FROM presentations WHERE mandate_id = ?').get('M2') as { c: number }).c;
      f3Before.close();
      const revokedCreds = new Array<number>(STATUS_LIST_SIZE).fill(0);
      revokedCreds[2] = 1;
      await buildAndWriteStatusList('credentials', revokedCreds);
      try {
        const jws = await signDiscloseRequest(brandWorkload, m2Summary.jti, 'A', m2Summary.allowed_claims, randomNonce());
        const res = await app24.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: jws } });
        check(
          'F3:credentials 撤銷位元設起後 disclose(案 A)→ 403 CREDENTIAL_REVOKED',
          res.statusCode === 403 && (res.json() as { reason_code?: string }).reason_code === CODES.CREDENTIAL_REVOKED,
          `status=${res.statusCode} body=${res.body}`,
        );
        const f3After = openDb();
        const qAfter = (f3After.prepare('SELECT queries_used FROM mandates WHERE id = ?').get('M2') as { queries_used: number }).queries_used;
        const presAfter = (f3After.prepare('SELECT COUNT(*) c FROM presentations WHERE mandate_id = ?').get('M2') as { c: number }).c;
        f3After.close();
        check('F3:被撤 aggregate 的 disclose 不扣 query_cap(queries_used 不變)', qAfter === qBefore, `before=${qBefore} after=${qAfter}`);
        check('F3:被撤 aggregate 的 disclose 不寫 presentation(presentations 筆數不變)', presAfter === presBefore, `before=${presBefore} after=${presAfter}`);
      } finally {
        await buildAndWriteStatusList('credentials'); // 還原全 0
      }
      // (b) 過期 aggregate(exp 在過去)→ CREDENTIAL_EXPIRED。以過期版本暫換 DB pcf_aggregate-A,測完還原。
      const past = Math.floor(Date.parse('2020-01-01T00:00:00Z') / 1000);
      const expiredPayload = {
        vct: PCF_AGGREGATE_VCT,
        iss: fabKey.kid,
        iat: past,
        nbf: past,
        exp: past + 3600,
        status: { status_list: { idx: 2, uri: statusListUri('credentials') } },
        cn_code: '7318.15',
        precursor_ref: { id: 'pcf_upstream-A', hash: '0'.repeat(64) },
        carbon_total_tco2e_per_t: 1.5125,
        carbon_price_paid_origin: '台灣碳費',
      };
      const expiredFrame = {
        _sd: ['carbon_total_tco2e_per_t', 'carbon_price_paid_origin'],
      } as unknown as DisclosureFrame<SdJwtVcPayload>;
      const expiredSdJwt = await buildIssuerInstance(fabKey).issue(expiredPayload as unknown as SdJwtVcPayload, expiredFrame, { header: { kid: fabKey.kid } });
      const swapAggDb = openDb();
      const origAgg = (swapAggDb.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').get('pcf_aggregate-A') as { sd_jwt: string }).sd_jwt;
      swapAggDb.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(expiredSdJwt, 'pcf_aggregate-A');
      swapAggDb.close();
      try {
        const jws = await signDiscloseRequest(brandWorkload, m2Summary.jti, 'A', m2Summary.allowed_claims, randomNonce());
        const res = await app24.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: jws } });
        check(
          'F3:被揭露 aggregate 已過期(exp 在過去)→ 403 CREDENTIAL_EXPIRED',
          res.statusCode === 403 && (res.json() as { reason_code?: string }).reason_code === CODES.CREDENTIAL_EXPIRED,
          `status=${res.statusCode} body=${res.body}`,
        );
      } finally {
        const restoreAggDb = openDb();
        restoreAggDb.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(origAgg, 'pcf_aggregate-A');
        restoreAggDb.close();
      }
      // (c) 對照組:未撤銷、未過期 → 正常 PERMIT(F3 沒有把正常路徑一起擋死)。
      const okJws = await signDiscloseRequest(brandWorkload, m2Summary.jti, 'A', m2Summary.allowed_claims, randomNonce());
      const okRes = await app24.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: okJws } });
      check('F3 對照組:未撤銷、未過期的 aggregate → 正常 PERMIT', okRes.statusCode === 200, `status=${okRes.statusCode} body=${okRes.body.slice(0, 160)}`);
    } finally {
      await app24.close();
    }
  }

  // 22) 一致性守門
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
