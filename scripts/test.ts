/**
 * make test — Phase 0 驗收(全綠才算過):
 *  1) /api/healthz 200
 *  2) GET /status/mandates:Content-Type application/statuslist+jwt;
 *     先驗 compact JWS 簽章(manifest 公鑰),再解碼 payload.status_list(bits==1、lst 可 zlib 解壓)
 *  3) manifest.json 存在且 6 角色齊(四家法人 + 兩張 ECR)
 *  4) sandbox verify 對兩張 ECR SAID 成功
 *  5) key loader 以 YARN LE 鑰簽測試 payload、以 manifest 公鑰驗證
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
import { StatusList, createHeaderAndPayload, JWT_STATUS_LIST_TYPE } from '@owf/token-status-list';
import { splitSdJwt, decodeJwt, type DisclosureFrame } from '@sd-jwt/core';
import type { SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc';
import { buildServer } from '../server/index';
import { ROOT, openDb, VLEI_PUBLIC_STATE_DIR } from '../server/db';
import { loadSandboxKey, loadWorkloadKey, publicKeyFromQb64, type SandboxRole } from '../server/keys';
import { STATUS_MEDIA_TYPE, STATUS_LIST_SIZE, statusListUri } from '../server/statuslist';
import { verifyCompactSdJwt } from '../server/creds/verifier';
import { insertCredentialIfAbsent } from '../server/creds/store';
import { tamperPayloadByte } from '../server/creds/tamper';
import { issuePcfAggregate, computeAggregateBreakdown, PCF_AGGREGATE_VCT } from '../server/creds/pcfAggregate';
import { computeDyeing } from '../server/creds/pcfDyeing';
import { issueTcRcs } from '../server/creds/tcRcs';
import { verifyScopeCert, isSubcontractorListed } from '../server/creds/ccsScopeCert';
import { buildIssuerInstance } from '../server/creds/issuer';
import { presentSelectedDisclosures, presentRawDisclosures, NeverDisclosableClaimError } from '../server/creds/presenter';
import { verifyPresentation, verifyVleiChainSandbox } from '../server/creds/verifyPresentation';
import { processDiscloseRequest } from '../server/creds/discloseGateway';
import { resolvePublicKeyFromManifest } from '../server/manifest';
import { readStatusListToken, checkStatusBit, buildAndWriteStatusList, statusListFile, STATUS_TTL_SECONDS } from '../server/statuslist';
import { M2_ALLOWED_CLAIMS, NEVER_DISCLOSABLE_CLAIMS, isSelectableDisclosure } from '../server/policy/claims';
import { authorizeEmitReleaseCredential } from '../server/policy/cedar';
import { PUBLIC_VLEI_STATE_FILE } from '../server/keys';
import { CODES } from '../shared/codes';
import {
  PCF_UPSTREAM_PUBLIC_FIELDS,
  PCF_UPSTREAM_BRAND_SD_FIELDS,
  PCF_UPSTREAM_AUDIT_SD_FIELDS,
  PCF_UPSTREAM_CONFIDENTIAL_FIELDS,
  TC_RCS_BRAND_SD_FIELDS,
  type AssociatedSubcontractor,
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

/**
 * v3.1 3a 測試小工具:偽造一份內容取自 seed.tc_rcs、但可覆寫 seller_lei/buyer_lei 的 tc_rcs,
 * 預設由**真正的** CB sandbox LE 鑰簽章(簽章本身合法,只是欄位內容經覆寫)——用來隔離測試
 * 聚合前核對 ②③(seller_lei/buyer_lei 綁定),不涉及竄改簽章本身。
 * Opus 獨立驗證 HIGH #1 回歸鎖:signerRole 可覆寫為 'cb' 以外的角色(如 'fab'/'yarn'),
 * 用真正的該角色 LE 鑰簽出一份「TC 欄位填得完全正確、但簽發者不是 CB」的 tc_rcs——
 * 驗證消費端釘住簽發者角色(而非只驗簽章通過)。
 */
async function forgeTcRcs(overrides: { seller_lei?: string; buyer_lei?: string; signerRole?: SandboxRole } = {}): Promise<string> {
  const seedForForge = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8'));
  const d = seedForForge.tc_rcs;
  const manifestForForge = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'vlei', 'manifest.json'), 'utf-8')) as Manifest;
  const key = loadSandboxKey(overrides.signerRole ?? 'cb');
  const nowSec = Math.floor(Date.now() / 1000);
  const payload = {
    vct: 'https://carbon-cred-demo.local/vct/tc_rcs',
    iss: key.kid,
    iat: nowSec,
    nbf: nowSec,
    exp: nowSec + 3600 * 24 * 30,
    status: { status_list: { idx: 9, uri: statusListUri('credentials') } },
    tcNo: d.tcNo,
    tcStandard: d.tcStandard,
    tcProductStandardLabelGrade: d.tcProductStandardLabelGrade,
    tcProductCategoryCode: d.tcProductCategoryCode,
    tcProductDetailCode: d.tcProductDetailCode,
    tcCertifiedRawMaterialCountryOrArea: d.tcCertifiedRawMaterialCountryOrArea,
    sellerTeId: d.sellerTeId,
    buyerTeId: d.buyerTeId,
    seller_lei: overrides.seller_lei ?? manifestForForge.yarn.lei,
    buyer_lei: overrides.buyer_lei ?? manifestForForge.fab.lei,
    volume_reconciled: d.volume_reconciled,
    tcShipmentInvoiceReferences_hash: crypto.createHash('sha256').update(JSON.stringify(d.confidential.tcShipmentInvoiceReferences)).digest('hex'),
    tcProductRawMaterialCode: d.tcProductRawMaterialCode,
    tcProductRawMaterialPercentage: d.tcProductRawMaterialPercentage,
    tcProductCertifiedWeight: d.tcProductCertifiedWeight,
    tcShipmentDate: d.tcShipmentDate,
    tcShipmentNo: d.tcShipmentNo,
    inputTcNo: d.inputTcNo,
    tcProductLastProcessorName: d.tcProductLastProcessorName,
    tcProductLastProcessorCountry: d.tcProductLastProcessorCountry,
  };
  const frame = { _sd: [...TC_RCS_BRAND_SD_FIELDS] } as unknown as DisclosureFrame<SdJwtVcPayload>;
  return buildIssuerInstance(key).issue(payload as unknown as SdJwtVcPayload, frame, { header: { kid: key.kid } });
}

/**
 * v3.1 3b 測試小工具:偽造一份內容取自 seed.ccs_scope_cert、但可覆寫 associated_subcontractors
 * 的 ccs_scope_cert,預設由**真正的** CB sandbox LE 鑰簽章——用來隔離測試聚合前核對 ⑥(分包商清單)。
 * Opus 獨立驗證 HIGH #1 回歸鎖:signerRole 可覆寫為 'cb' 以外角色,驗證 verifyScopeCert 釘住 cb。
 */
async function forgeCcsScopeCert(overrides: { associated_subcontractors?: AssociatedSubcontractor[]; signerRole?: SandboxRole } = {}): Promise<string> {
  const seedForForge = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8'));
  const d = seedForForge.ccs_scope_cert;
  const manifestForForge = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'vlei', 'manifest.json'), 'utf-8')) as Manifest;
  const key = loadSandboxKey(overrides.signerRole ?? 'cb');
  const nowSec = Math.floor(Date.now() / 1000);
  const defaultSubs: AssociatedSubcontractor[] = d.associated_subcontractors.map((s: { party: string; name: string; process: string; audited: boolean }) => ({
    lei: manifestForForge[s.party].lei,
    name: s.name,
    process: s.process,
    audited: s.audited,
  }));
  const payload = {
    vct: 'https://carbon-cred-demo.local/vct/ccs_scope_cert',
    iss: key.kid,
    iat: nowSec,
    nbf: nowSec,
    exp: nowSec + 3600 * 24 * 30,
    status: { status_list: { idx: 10, uri: statusListUri('credentials') } },
    sc_no: d.sc_no,
    holder_lei: manifestForForge.fab.lei,
    holder_name: manifestForForge.fab.legal_name,
    standards: d.standards,
    processes: d.processes,
    associated_subcontractors: overrides.associated_subcontractors ?? defaultSubs,
    cb_lei: manifestForForge.cb.lei,
    cb_name: manifestForForge.cb.legal_name,
    valid_from: d.valid_from,
    valid_until: d.valid_until,
  };
  const frame = { _sd: [] } as unknown as DisclosureFrame<SdJwtVcPayload>;
  return buildIssuerInstance(key).issue(payload as unknown as SdJwtVcPayload, frame, { header: { kid: key.kid } });
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
// v3.1:加入「照舊」——docs/ 內文件(如遷移清單、phase brief)常以「原有守門 human.key/…/testnet
// 照舊」之句式引用整份禁詞清單本身(屬合法之規格說明,非違規),與既有「不得出現…」句式同一用意。
const NEG = /(不|禁|移除|非|棄|僅|保底|照舊|fallback|mock|合成|out of (core )?scope)/i;
const EXT = new Set(['.md', '.html', '.ts', '.tsx', '.sql', '.cedar', '.sh']);

function* walk(dir: string): Generator<string> {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name.startsWith('.')) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(p);
    else if (EXT.has(path.extname(e.name))) yield p;
  }
}

// v3 檢查 7:鋼鐵版殘留禁詞(server/web/scripts/data/policies/CLAUDE.md;docs 為歷史文件不掃)。
// 禁詞以字元拼接構造——若直接寫字面值,本檔自己就會被驗收用的外部 git grep 命中。
const STEEL_TERMS = [
  '鴻' + '鋼',
  'Thép' + ' ' + 'Việt',
  'Br' + 'uck',
  '台' + '驗',
  '扣' + '件',
  '線' + '材',
  'CB' + 'AM',
  '海' + '關',
  'EA' + 'F',
  'BF-' + 'BOF',
  'USD' + 'C',
  '60' + '06', // v3.1:HS 稅則碼殘留(移除 hs6/downstream_hs6 後不得再出現任何稅則碼字面值;字元拼接理由同檔頭註記)
];
const STEEL_RE = new RegExp(`(${STEEL_TERMS.join('|')}|0x[0-9a-fA-F]{4})`);

function consistencyScan(): string[] {
  const dirs = ['docs', 'server', 'shared', 'scripts', 'web/src', 'policies'];
  const self = path.join(ROOT, 'scripts', 'test.ts');
  const violations: string[] = [];

  // 鋼鐵殘留掃描(程式與資料面;無任何豁免)
  const steelFiles: string[] = [path.join(ROOT, 'CLAUDE.md'), path.join(ROOT, 'data', 'seed.json')];
  for (const d of ['server', 'shared', 'scripts', 'web/src', 'policies']) {
    const full = path.join(ROOT, d);
    if (fs.existsSync(full)) steelFiles.push(...walk(full));
  }
  for (const file of steelFiles) {
    if (path.resolve(file) === path.resolve(self)) continue;
    if (!fs.existsSync(file)) continue;
    const rel = path.relative(ROOT, file);
    fs.readFileSync(file, 'utf-8')
      .split('\n')
      .forEach((line, i) => {
        if (STEEL_RE.test(line)) violations.push(`${rel}:${i + 1} [鋼鐵版殘留禁詞] ${line.trim().slice(0, 80)}`);
      });
  }
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

  // 3) manifest(v3:7 角色 = 5 LE + 2 ECR)
  const manifestPath = path.join(ROOT, 'data', 'vlei', 'manifest.json');
  const LE_ROLES = ['yarn', 'fab', 'dye', 'brand', 'cb'];
  const ECR_ROLES = ['fab_cfo', 'brand_cso'];
  const ROLES = [...LE_ROLES, ...ECR_ROLES];
  let manifest: Manifest | null = null;
  if (fs.existsSync(manifestPath)) manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
  check(
    'manifest.json 存在且 7 角色齊(5 LE + 2 ECR)',
    !!manifest && ROLES.every((r) => manifest![r]?.aid && manifest![r]?.public_key && manifest![r]?.credential_said && manifest![r]?.lei?.length === 20),
    manifest ? `roles=${Object.keys(manifest).join(',')}` : 'manifest 不存在',
  );
  check(
    'manifest kind 正確(5 × le + 2 × ecr)',
    !!manifest && LE_ROLES.every((r) => manifest![r]?.kind === 'le') && ECR_ROLES.every((r) => manifest![r]?.kind === 'ecr'),
    manifest ? JSON.stringify(Object.fromEntries(ROLES.map((r) => [r, manifest![r]?.kind]))) : 'manifest 不存在',
  );
  check(
    'dye 的 presentation 檔存在(data/vlei/dye.presentation.json)',
    !!manifest && fs.existsSync(path.join(ROOT, manifest.dye?.presentation_file ?? 'data/vlei/dye.presentation.json')),
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

  // 驗證方順序:先驗 compact JWS 簽章(FAB LE 公鑰,取自 manifest),再解碼 payload
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

  // 4) sandbox verify × 2 ECR + dye LE(v3 新增角色的信任鏈)
  const py = path.join(ROOT, '.venv', 'bin', 'python');
  const sb = path.join(ROOT, 'vendor', 'vlei-sandbox', 'scripts', 'vlei_sandbox.py');
  for (const role of ['fab_cfo', 'brand_cso', 'dye'] as const) {
    const said = manifest[role].credential_said;
    const r = spawnSync(py, [sb, '--dir', ROOT, 'verify', '--said', said], { encoding: 'utf-8' });
    check(`sandbox verify ${role}(${said.slice(0, 12)}…)`, r.status === 0 && r.stdout.includes('chain verified'));
  }

  // 5) key loader 簽驗章
  try {
    const k = loadSandboxKey('yarn');
    const payloadBuf = Buffer.from('carbon-cred-demo · phase0 · key-loader self test');
    const sig = crypto.sign(null, payloadBuf, k.privateKey);
    const ok = crypto.verify(null, payloadBuf, publicKeyFromQb64(manifest.yarn.public_key), sig);
    check('key loader:YARN LE 鑰簽章 → manifest 公鑰驗證成功', ok);
  } catch (e) {
    check('key loader:YARN LE 鑰簽章 → manifest 公鑰驗證成功', false, String(e));
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
      // (a0) v3.1 3a(正向):tc_rcs(CB 簽,卡 1)——POST /api/issue/tc 冪等載入(seed 時已簽發),
      // 以 CB 公鑰驗章通過、volume_reconciled === true(CCS-102 E2.1.8 數量勾稽結果宣告)。
      const tcRes = await app1.inject({ method: 'POST', url: '/api/issue/tc' });
      check('POST /api/issue/tc 回 200', tcRes.statusCode === 200, `status=${tcRes.statusCode} body=${tcRes.body.slice(0, 200)}`);
      const tcIssued = tcRes.json() as { sd_jwt: string; claims: Record<string, unknown>; reused?: boolean };
      check('v3.1:POST /api/issue/tc 冪等(seed 時已由 CB 簽發過)——reused:true', tcIssued.reused === true, JSON.stringify(tcIssued.reused));
      const tcVerifyRes = await app1.inject({ method: 'POST', url: '/api/creds/verify', payload: { sd_jwt: tcIssued.sd_jwt } });
      const tcVerifyBody = tcVerifyRes.json() as { valid: boolean; payload?: Record<string, unknown> };
      check('v3.1:tc_rcs 以 CB 公鑰驗章通過(manifest 動態解出,經 /api/creds/verify)', tcVerifyBody.valid === true, JSON.stringify(tcVerifyBody).slice(0, 160));
      check(
        'v3.1:tc_rcs.volume_reconciled === true(且與 seed.tc_rcs 一致)',
        tcVerifyBody.payload?.volume_reconciled === true && tcVerifyBody.payload?.volume_reconciled === seed.tc_rcs.volume_reconciled,
        JSON.stringify(tcVerifyBody.payload?.volume_reconciled),
      );
      const manifestForTc = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'vlei', 'manifest.json'), 'utf-8')) as Manifest;
      check(
        'v3.1:tc_rcs.seller_lei/buyer_lei 自 manifest 取(不寫死),對得上紗廠/布廠 LEI',
        tcVerifyBody.payload?.seller_lei === manifestForTc.yarn.lei && tcVerifyBody.payload?.buyer_lei === manifestForTc.fab.lei,
        JSON.stringify({ seller_lei: tcVerifyBody.payload?.seller_lei, buyer_lei: tcVerifyBody.payload?.buyer_lei }),
      );

      // (a0b) v3.1:ccs_scope_cert(CB 簽)——POST /api/issue/scope-cert 冪等載入(seed 時已簽發),
      // 以 CB 公鑰驗章通過;associated_subcontractors 之 lei 自 manifest 取,對得上染整廠 LEI。
      const scRes = await app1.inject({ method: 'POST', url: '/api/issue/scope-cert' });
      check('POST /api/issue/scope-cert 回 200', scRes.statusCode === 200, `status=${scRes.statusCode} body=${scRes.body.slice(0, 200)}`);
      const scIssued = scRes.json() as { sd_jwt: string; claims: Record<string, unknown>; reused?: boolean };
      check(
        'v3.1:POST /api/issue/scope-cert 冪等(seed 時已由 CB 簽發過)——reused:true',
        scIssued.reused === true,
        JSON.stringify(scIssued.reused),
      );
      const scVerifyRes = await app1.inject({ method: 'POST', url: '/api/creds/verify', payload: { sd_jwt: scIssued.sd_jwt } });
      const scVerifyBody = scVerifyRes.json() as { valid: boolean; payload?: Record<string, unknown> };
      check('v3.1:ccs_scope_cert 以 CB 公鑰驗章通過(經 /api/creds/verify)', scVerifyBody.valid === true, JSON.stringify(scVerifyBody).slice(0, 160));
      const scSubs = (scVerifyBody.payload?.associated_subcontractors ?? []) as Array<{ lei?: string; process?: string }>;
      check(
        'v3.1:ccs_scope_cert.associated_subcontractors[].lei 自 manifest 取(不寫死),對得上染整廠 LEI',
        scSubs.some((s) => s.lei === manifestForTc.dye.lei),
        JSON.stringify(scSubs),
      );

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
        jwtPart.split('.').length === 3 && disclosureCount === PCF_UPSTREAM_BRAND_SD_FIELDS.length + PCF_UPSTREAM_AUDIT_SD_FIELDS.length,
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
        'verify() 回傳之 payload 含已揭露之品牌/稽核層欄位(pcf_direct 與 pcf_period 對得上 seed)',
        verifyBody.payload?.pcf_direct === seed.upstream_defaults.pcf_direct && verifyBody.payload?.pcf_period === seed.upstream_defaults.pcf_period,
      );

      // v3.1:公開層 tc_ref 綁定 tc_rcs——id/hash 對得上入庫 tc_rcs 之 sd_jwt。
      const tcRcsCheckDb = openDb();
      const tcRcsCheckRow = tcRcsCheckDb.prepare('SELECT sd_jwt, payload_json FROM credentials WHERE id = ?').get('tc_rcs') as
        | { sd_jwt: string; payload_json: string }
        | undefined;
      tcRcsCheckDb.close();
      const tcRcsCheckPayload = tcRcsCheckRow ? (JSON.parse(tcRcsCheckRow.payload_json) as { tcNo: string }) : undefined;
      const tcRefClaim = (issued.claims as { tc_ref?: { id?: string; tcNo?: string; issuer_lei?: string; hash?: string } }).tc_ref;
      check(
        'v3.1:pcf_upstream.tc_ref 綁定入庫 tc_rcs(id="tc_rcs"、tcNo 對得上、hash == sha256(tc_rcs sd_jwt))',
        !!tcRcsCheckRow &&
          tcRefClaim?.id === 'tc_rcs' &&
          tcRefClaim?.tcNo === tcRcsCheckPayload?.tcNo &&
          tcRefClaim?.hash === crypto.createHash('sha256').update(tcRcsCheckRow.sd_jwt).digest('hex'),
        JSON.stringify(tcRefClaim),
      );

      // H1 負向測項:以他方(FAB)公鑰驗本方(YARN)的 pcf_upstream 必須失敗(信任邊界原則
      // 「一方一鑰」;繞過 kid 自動解析,強制傳入錯誤的公鑰解析函式)。
      const wrongPartyResult = await verifyCompactSdJwt(issued.sd_jwt, () => publicKeyFromQb64(manifest!.fab.public_key));
      check(
        'H1:以FAB公鑰驗 YARN 的 pcf_upstream 必須失敗(一方一鑰)',
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
      check('公開層欄位(tc_ref、product_code/country_of_origin + 四個 commitment hash)明文存在於原始 JWT payload', publicFieldsPresent, JSON.stringify(Object.keys(rawPayload)));

      const sdFields = [...PCF_UPSTREAM_BRAND_SD_FIELDS, ...PCF_UPSTREAM_AUDIT_SD_FIELDS];
      const sdFieldsHiddenFromRawPayload = sdFields.every((k) => !(k in rawPayload));
      check('品牌層 + 稽核層欄位不以明文存在於原始 JWT payload(只在 disclosure 內)', sdFieldsHiddenFromRawPayload);
      const sdFieldsDisclosed = sdFields.every((k) => k in (issued.claims ?? {}));
      check('品牌層 + 稽核層欄位以 disclosure 形式存在(issue 回應之 claims 含全部揭露)', sdFieldsDisclosed);

      const confidentialValues = [
        seed.upstream_defaults.confidential.unit_price,
        seed.upstream_defaults.confidential.energy_invoice,
        seed.upstream_defaults.confidential.recycler_name,
      ];
      const noConfidentialLeak =
        PCF_UPSTREAM_CONFIDENTIAL_FIELDS.every((name) => !(name in rawPayload) && !(name in (issued.claims ?? {}))) &&
        confidentialValues.every((v) => !issued.sd_jwt.includes(v));
      check('機密欄位名稱與原始值(unit_price/energy_invoice/recycler_name)不出現於憑證任何層', noConfidentialLeak);

      const hashFields = ['unit_price_hash', 'energy_invoice_hash', 'recycler_name_hash', 'emission_factor_table_hash'];
      const hashesPresent = hashFields.every((k) => typeof rawPayload[k] === 'string' && /^[0-9a-f]{64}$/.test(rawPayload[k] as string));
      check('commitment hash 與 emission_factor_table_hash 以一般 claim 存在,皆為 SHA-256 hex', hashesPresent);

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
        `issued_at(${issued.issued_at})與 data/seed.json upstream_defaults.issued_at 一致`,
        issued.issued_at === seed.upstream_defaults.issued_at,
        `got=${issued.issued_at} expected=${seed.upstream_defaults.issued_at}`,
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
      // 回應形狀改為「FAB自有閘道頁」內部檢視;完整 SD-JWT 屬FAB自持,改由 credentials 表(FAB自有 DB)讀取,
      // 密碼學驗章強度不變(同一 /api/creds/verify 路徑),只是憑證來源改為FAB內部而非跨組織 HTTP 回應。
      type AggResult = {
        id: string;
        breakdown: {
          pcf_yarn: number;
          pcf_knitting: number;
          pcf_dyeing: number;
          pcf_total: number;
        };
        product: string;
        origin: string;
        ccs_scope_ref: { sc_no: string; hash: string };
        quantity_kg: number;
        precursor_refs: Array<{ id: string; hash: string }>;
        status: { idx: number; uri: string };
        issued_at: string;
        valid_from: string;
        valid_until: string;
      };
      const byCase: Record<
        'A' | 'B',
        {
          agg: AggResult;
          rawResponse: Record<string, unknown>;
          sdJwt: string;
          tcRcsSdJwt: string;
          upstreamSdJwt: string;
          dyeingSdJwt: string;
          upstreamIssuedAt: string;
        }
      > = {} as any;

      for (const c of ['A', 'B'] as const) {
        // 先確保該案外部輸入憑證存在(幕 1/前置邏輯;v3.1 tc_rcs 於 seed 時已由 CB 簽發),取得
        // 其 sd_jwt/issued_at 供後續比對。
        const tcRes = await app2.inject({ method: 'POST', url: '/api/issue/tc' });
        const tcBody = tcRes.json() as { sd_jwt: string };
        const upstreamRes = await app2.inject({ method: 'POST', url: '/api/issue/upstream', payload: { case_id: c } });
        const upstreamBody = upstreamRes.json() as { sd_jwt: string; issued_at: string };
        const dyeingRes = await app2.inject({ method: 'POST', url: `/api/issue/dyeing?case=${c}` });
        check(`POST /api/issue/dyeing?case=${c} 回 200`, dyeingRes.statusCode === 200, `status=${dyeingRes.statusCode} body=${dyeingRes.body.slice(0, 200)}`);
        const dyeingBody = dyeingRes.json() as { sd_jwt: string; claims: Record<string, unknown> };

        const aggRes = await app2.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: c } });
        check(`POST /api/aggregate(案 ${c})回 200`, aggRes.statusCode === 200, `status=${aggRes.statusCode} body=${aggRes.body.slice(0, 200)}`);
        // 完整 pcf_aggregate SD-JWT 為 FAB 自持——自 credentials 表(FAB 自有 DB)讀,不從 HTTP 回應取。
        const aggDb = openDb();
        const aggDbRow = aggDb.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').get(`pcf_aggregate-${c}`) as { sd_jwt: string } | undefined;
        aggDb.close();
        byCase[c] = {
          agg: aggRes.json() as AggResult,
          rawResponse: aggRes.json() as Record<string, unknown>,
          sdJwt: aggDbRow?.sd_jwt ?? '',
          tcRcsSdJwt: tcBody.sd_jwt,
          upstreamSdJwt: upstreamBody.sd_jwt,
          dyeingSdJwt: dyeingBody.sd_jwt,
          upstreamIssuedAt: upstreamBody.issued_at,
        };
      }

      // v3 檢查 2:pcf_dyeing A/B 由 computeDyeing 與獨立算式交叉驗證 = seed expected_pcf_dyeing;
      // A/B 差異只來自 heat_source / renewable_share(dyeing_defaults 共用)。
      const ef = seed.emission_factor_table;
      const dd = seed.dyeing_defaults;
      for (const c of ['A', 'B'] as const) {
        const cs = seed.cases[c];
        const viaFn = computeDyeing(dd, ef, cs.heat_source, cs.renewable_share);
        // 獨立算式(不經 computeDyeing;round4 亦獨立實作)
        const r4 = (n: number) => Math.round(n * 10000) / 10000;
        const fuel = cs.heat_source === 'coal' ? ef.coal_kg_per_mj : ef.natural_gas_kg_per_mj;
        const indepDirect = r4((dd.heat_mj_per_kg / ef.boiler_efficiency[cs.heat_source]) * fuel);
        const indepIndirect = r4(dd.electricity_kwh_per_kg * ef.grid_tw_kg_per_kwh * (1 - cs.renewable_share));
        const indepTotal = r4(indepDirect + indepIndirect);
        check(
          `v3:pcf_dyeing(案 ${c})computeDyeing 與獨立算式交叉驗證一致且 = expected_pcf_dyeing(${cs.expected_pcf_dyeing})`,
          viaFn.total === indepTotal && viaFn.total === cs.expected_pcf_dyeing,
          `fn=${viaFn.total} indep=${indepTotal} expected=${cs.expected_pcf_dyeing}`,
        );
        // 憑證內的 pcf_total 亦必須等於計算值(不寫死)
        const dyeVerify = await app2.inject({ method: 'POST', url: '/api/creds/verify', payload: { sd_jwt: byCase[c].dyeingSdJwt } });
        const dyePayload = (dyeVerify.json() as { valid: boolean; payload?: Record<string, unknown> }).payload ?? {};
        check(
          `v3:pcf_dyeing(案 ${c})憑證驗章通過且 pcf_total/heat_source 對得上計算值與 seed`,
          (dyeVerify.json() as { valid: boolean }).valid === true && dyePayload.pcf_total === cs.expected_pcf_dyeing && dyePayload.heat_source === cs.heat_source,
          `pcf_total=${dyePayload.pcf_total} heat_source=${dyePayload.heat_source}`,
        );
      }
      check(
        'v3:A/B 染整差異只來自 heat_source/renewable_share(dyeing_defaults 共用一組)',
        seed.cases.A.heat_source !== seed.cases.B.heat_source && seed.cases.A.renewable_share !== seed.cases.B.renewable_share,
        JSON.stringify({ A: seed.cases.A.heat_source, B: seed.cases.B.heat_source }),
      );

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
        // 內部檢視 breakdown 仍在(FAB自有閘道頁 StackChart 真值來源)——F1 收斂的是跨組織可攜 token,不砍自有檢視。
        check(`F1 對照組:案 ${c} 回應仍含 breakdown(FAB自有閘道頁疊層圖真值不受影響)`, typeof resp.breakdown === 'object' && resp.breakdown != null, respJson.slice(0, 120));
      }

      // (a) FAB自持之完整 pcf_aggregate SD-JWT(自 credentials 表讀)可解析
      let jwtPartA = '';
      try {
        jwtPartA = splitSdJwt(byCase.A.sdJwt).jwt;
      } catch {
        /* 解析失敗留給下方 check 回報 */
      }
      check('pcf_aggregate(案 A)sd_jwt 可解析(header.payload.signature)', jwtPartA.split('.').length === 3);

      // (b) pcf_aggregate 以FAB manifest 公鑰驗章通過(同一 /api/creds/verify 路徑,依 kid 解出FAB公鑰)
      const verifyA = await app2.inject({ method: 'POST', url: '/api/creds/verify', payload: { sd_jwt: byCase.A.sdJwt } });
      const verifyABody = verifyA.json() as { valid: boolean; payload?: Record<string, unknown> };
      check('pcf_aggregate(案 A)以FAB manifest 公鑰驗章通過', verifyABody.valid === true, JSON.stringify(verifyABody).slice(0, 200));
      const verifyB = await app2.inject({ method: 'POST', url: '/api/creds/verify', payload: { sd_jwt: byCase.B.sdJwt } });
      check('pcf_aggregate(案 B)以FAB manifest 公鑰驗章通過', (verifyB.json() as { valid: boolean }).valid === true);

      // (c) 三段聚合值正確(spec v3 §4.4;此處為獨立算式 + computeAggregateBreakdown 交叉驗證,
      //     兩者皆與 seed 的 expected_pcf_total 比對——v3 檢查 3)
      const r4agg = (n: number) => Math.round(n * 10000) / 10000;
      const yarnTotalIndep = r4agg(seed.upstream_defaults.pcf_direct + r4agg(seed.upstream_defaults.electricity_kwh_per_kg * ef.grid_vn_kg_per_kwh));
      const close = (a: number, b: number) => Math.abs(a - b) < 1e-6;
      for (const c of ['A', 'B'] as const) {
        const cs = seed.cases[c];
        const viaFn = computeAggregateBreakdown(yarnTotalIndep, cs.expected_pcf_dyeing, {
          yarnLossFactor: agg.yarn_loss_factor,
          knittingKwhPerKg: agg.knitting_electricity_kwh_per_kg,
          gridTw: ef.grid_tw_kg_per_kwh,
        });
        const indepTotal = r4agg(r4agg(yarnTotalIndep * agg.yarn_loss_factor) + r4agg(agg.knitting_electricity_kwh_per_kg * ef.grid_tw_kg_per_kwh) + cs.expected_pcf_dyeing);
        const got = byCase[c].agg.breakdown.pcf_total;
        check(
          `v3:案 ${c} 三段聚合(紗×損耗 + 織布用電 + 染整)= expected_pcf_total(${cs.expected_pcf_total})——API/computeAggregateBreakdown/獨立算式三方一致`,
          close(got, cs.expected_pcf_total) && close(viaFn.total, cs.expected_pcf_total) && close(indepTotal, cs.expected_pcf_total),
          `api=${got} fn=${viaFn.total} indep=${indepTotal}`,
        );
        check(
          `v3:案 ${c} 分項一致(pcf_yarn=${agg.expected_pcf_yarn} / pcf_knitting=${agg.expected_pcf_knitting} / pcf_dyeing=${cs.expected_pcf_dyeing})`,
          close(byCase[c].agg.breakdown.pcf_yarn, agg.expected_pcf_yarn) &&
            close(byCase[c].agg.breakdown.pcf_knitting, agg.expected_pcf_knitting) &&
            close(byCase[c].agg.breakdown.pcf_dyeing, cs.expected_pcf_dyeing),
          JSON.stringify(byCase[c].agg.breakdown),
        );
      }

      // (d) v3.1:precursor_refs 恰三筆(tc_rcs、pcf_upstream、pcf_dyeing),id/hash 對得上該案入庫 sd_jwt。
      const sha256Hex = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
      for (const c of ['A', 'B'] as const) {
        const refs = byCase[c].agg.precursor_refs;
        check(`v3.1:案 ${c} precursor_refs 恰三筆(tc_rcs + 紗 + 染整)`, Array.isArray(refs) && refs.length === 3, JSON.stringify(refs));
        const tcRef = refs?.find((r) => r.id === 'tc_rcs');
        const yarnRef = refs?.find((r) => r.id === `pcf_upstream-${c}`);
        const dyeRef = refs?.find((r) => r.id === `pcf_dyeing-${c}`);
        check(`v3.1:案 ${c} precursor_refs 之 TC 參照 hash == sha256(tc_rcs sd_jwt)`, tcRef?.hash === sha256Hex(byCase[c].tcRcsSdJwt), JSON.stringify(tcRef));
        check(`案 ${c} precursor_refs 之紗參照 hash == sha256(上游 sd_jwt)`, yarnRef?.hash === sha256Hex(byCase[c].upstreamSdJwt), JSON.stringify(yarnRef));
        check(`案 ${c} precursor_refs 之染整參照 hash == sha256(染整 sd_jwt)`, dyeRef?.hash === sha256Hex(byCase[c].dyeingSdJwt), JSON.stringify(dyeRef));
      }

      // (e) 上游/染整明細欄位名不出現於 pcf_aggregate 任何層(以 DB 內完整 claims payload 檢查 key)
      const inputOnlyFieldNames = [
        'tcShipmentDate',
        'tcShipmentNo',
        'inputTcNo',
        'sellerTeId',
        'buyerTeId',
        'tcProductLastProcessorName',
        'heat_mj_per_kg',
        'heat_source',
        'renewable_share',
        'boiler_efficiency',
      ];
      const aggClaimsDb = openDb();
      const noLeak = (c: 'A' | 'B') => {
        const row = aggClaimsDb.prepare('SELECT payload_json FROM credentials WHERE id = ?').get(`pcf_aggregate-${c}`) as
          | { payload_json: string }
          | undefined;
        const keys = Object.keys(JSON.parse(row?.payload_json ?? '{}'));
        return inputOnlyFieldNames.every((k) => !keys.includes(k));
      };
      check('pcf_aggregate(案 A)不含任何上游/染整明細欄位名稱', noLeak('A'));
      check('pcf_aggregate(案 B)不含任何上游/染整明細欄位名稱', noLeak('B'));
      aggClaimsDb.close();

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
        A.breakdown.pcf_total !== B.breakdown.pcf_total,
        `A=${A.breakdown.pcf_total} B=${B.breakdown.pcf_total}`,
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

  // 9a) v3.1 檢查 3a:tc_rcs 聚合前核對——tc_ref.hash 對不上入庫 tc_rcs、tc_rcs.buyer_lei 改別家,
  //     兩條失敗路徑皆回 TC_REF_MISMATCH(測後還原)。
  {
    const app3a = buildServer();
    try {
      const manifest3a = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'vlei', 'manifest.json'), 'utf-8')) as Manifest;
      const db3aInit = openDb();
      const origTcRcsRow = db3aInit.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').get('tc_rcs') as { sd_jwt: string };
      db3aInit.close();

      // (路徑一)tc_rcs 內容換版(重簽一份聲明內容相同、但隨機 disclosure 鹽使位元組/hash 不同的
      // tc_rcs)——pcf_upstream-A 既有 tc_ref.hash 仍綁定舊版,兩者不再一致(對應「竄改入庫 tc_rcs」
      // 之效果:pcf_upstream 引用的 tc_rcs 內容已非現況)。
      const freshTcRcsSdJwt = await issueTcRcs();
      const swapDb1 = openDb();
      swapDb1.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(freshTcRcsSdJwt.sdJwt, 'tc_rcs');
      swapDb1.close();
      try {
        // Opus 獨立驗證 MEDIUM #2 回歸鎖:TC_REF_MISMATCH 之前完全未入鏈(PoC:502 後 audit_chain
        // 列數不變)——now 觸發後 audit_chain 必須多一筆 DENY,且 verify-chain.ts 仍驗得過。
        const auditBefore = (await app3a.inject({ method: 'GET', url: '/api/audit?after=0' })).json() as unknown[];
        const res = await app3a.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
        check(
          'v3.1 3a(路徑一):tc_rcs 換版後 pcf_upstream.tc_ref.hash 對不上入庫現況 → 502 TC_REF_MISMATCH',
          res.statusCode === 502 && (res.json() as { reason_code?: string }).reason_code === CODES.TC_REF_MISMATCH,
          `status=${res.statusCode} body=${res.body.slice(0, 200)}`,
        );
        const auditAfter = (await app3a.inject({ method: 'GET', url: '/api/audit?after=0' })).json() as unknown[];
        check(
          'MEDIUM #2:TC_REF_MISMATCH 觸發後 audit_chain 多一筆(recordDecision effect=DENY 入鏈)',
          auditAfter.length === auditBefore.length + 1,
          `before=${auditBefore.length} after=${auditAfter.length}`,
        );
      } finally {
        const restoreDb1 = openDb();
        restoreDb1.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(origTcRcsRow.sd_jwt, 'tc_rcs');
        restoreDb1.close();
      }
      const okRes1 = await app3a.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
      check('v3.1 3a 對照組(路徑一還原後):聚合恢復 200', okRes1.statusCode === 200, `status=${okRes1.statusCode}`);

      // (路徑二)tc_rcs.buyer_lei 改別家(借用染整廠 LEI,肯定不等於布廠 LEI)——重簽 pcf_upstream-A
      // 綁定此偽造版本(tc_ref.hash 對得上),隔離出 buyer_lei 核對失效這條路徑。
      const badBuyerTcRcsSdJwt = await forgeTcRcs({ buyer_lei: manifest3a.dye.lei });
      const swapDb2 = openDb();
      swapDb2.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(badBuyerTcRcsSdJwt, 'tc_rcs');
      swapDb2.prepare('DELETE FROM credentials WHERE id = ?').run('pcf_upstream-A');
      swapDb2.close();
      try {
        const reissueRes = await app3a.inject({ method: 'POST', url: '/api/issue/upstream', payload: { case_id: 'A' } });
        check('v3.1 3a(路徑二)前置:pcf_upstream-A 重簽綁定偽造 tc_rcs 成功', reissueRes.statusCode === 200, `status=${reissueRes.statusCode}`);
        const res2 = await app3a.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
        check(
          'v3.1 3a(路徑二):tc_rcs.buyer_lei 改別家(非布廠 LEI)→ 502 TC_REF_MISMATCH',
          res2.statusCode === 502 && (res2.json() as { reason_code?: string }).reason_code === CODES.TC_REF_MISMATCH,
          `status=${res2.statusCode} body=${res2.body.slice(0, 200)}`,
        );
      } finally {
        const restoreDb2 = openDb();
        restoreDb2.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(origTcRcsRow.sd_jwt, 'tc_rcs');
        restoreDb2.prepare('DELETE FROM credentials WHERE id = ?').run('pcf_upstream-A');
        restoreDb2.close();
        const finalReissue = await app3a.inject({ method: 'POST', url: '/api/issue/upstream', payload: { case_id: 'A' } });
        check('v3.1 3a 還原:pcf_upstream-A 重簽回綁定原版 tc_rcs', finalReissue.statusCode === 200, `status=${finalReissue.statusCode}`);
      }
      const okRes2 = await app3a.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
      check('v3.1 3a 對照組(路徑二還原後):聚合恢復 200', okRes2.statusCode === 200, `status=${okRes2.statusCode}`);
    } finally {
      await app3a.close();
    }
  }

  // 9b) v3.1 檢查 3b:ccs_scope_cert 聚合前核對——associated_subcontractors 清空重灌 →
  //     CCS_SUBCONTRACTOR_NOT_LISTED;sc_no 同但已重簽替換(hash 不符)→ SCOPE_CERT_INVALID(P1-c);
  //     Token Status List 撤 idx=10 → SCOPE_CERT_INVALID(測後還原)。
  {
    const app3b = buildServer();
    try {
      const manifest3b = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'vlei', 'manifest.json'), 'utf-8')) as Manifest;
      const db3bInit = openDb();
      const origScopeCertRow = db3bInit.prepare('SELECT sd_jwt, payload_json FROM credentials WHERE id = ?').get('ccs_scope_cert') as {
        sd_jwt: string;
        payload_json: string;
      };
      const dyeRowInit = db3bInit.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').get('pcf_dyeing-A') as { sd_jwt: string };
      db3bInit.close();
      const origScopeCertPayload = JSON.parse(origScopeCertRow.payload_json) as {
        sc_no: string;
        associated_subcontractors: AssociatedSubcontractor[];
      };

      // (a) 正向:ccs_scope_cert 以 CB 公鑰驗章通過;DYE 在分包商清單內;pcf_dyeing.ccs_scope_ref.sc_no 一致。
      const scopeVerify = await verifyScopeCert(origScopeCertRow.sd_jwt);
      check(
        'v3.1 3b:ccs_scope_cert 以 CB 公鑰驗章通過(verifyScopeCert;含效期 + Token Status List)',
        scopeVerify.ok === true,
        JSON.stringify({ ok: scopeVerify.ok, error: scopeVerify.error }),
      );
      check(
        'v3.1 3b:染整廠(DYE)LEI ∈ ccs_scope_cert.associated_subcontractors(isSubcontractorListed)',
        !!scopeVerify.payload && isSubcontractorListed(scopeVerify.payload, manifest3b.dye.lei, 'dyeing_finishing'),
      );
      const dyeVerify3b = await verifyCompactSdJwt(dyeRowInit.sd_jwt, resolvePublicKeyFromManifest(manifest3b));
      const dyePayload3b = dyeVerify3b.payload as { ccs_scope_ref?: { sc_no?: string } } | undefined;
      check(
        'v3.1 3b:pcf_dyeing.ccs_scope_ref.sc_no 與入庫 ccs_scope_cert.sc_no 一致',
        dyeVerify3b.ok === true && dyePayload3b?.ccs_scope_ref?.sc_no === origScopeCertPayload.sc_no,
        JSON.stringify(dyePayload3b?.ccs_scope_ref),
      );

      // (b) associated_subcontractors 清空重灌(sc_no 不變,單獨隔離分包商清單失效這條路徑)——
      //     Codex 審查 P1-c 修法後,ccs_scope_ref 除比 sc_no 亦比 hash,forgeCcsScopeCert 隨機鹽會
      //     使 hash 改變;故連帶重簽 pcf_dyeing-A 綁定此偽造版本(hash 對得上),才能單獨隔離出
      //     「分包商清單失效」這條路徑,而非提前命中 hash 不符(SCOPE_CERT_INVALID,見 (d))。
      const emptySubsSdJwt = await forgeCcsScopeCert({ associated_subcontractors: [] });
      const swapDb3 = openDb();
      swapDb3.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(emptySubsSdJwt, 'ccs_scope_cert');
      swapDb3.prepare('DELETE FROM credentials WHERE id = ?').run('pcf_dyeing-A');
      swapDb3.close();
      try {
        const rebindRes = await app3b.inject({ method: 'POST', url: '/api/issue/dyeing?case=A' });
        check('v3.1 3b(b)前置:pcf_dyeing-A 重簽綁定偽造(分包商清空)ccs_scope_cert 成功', rebindRes.statusCode === 200, `status=${rebindRes.statusCode}`);
        const auditBeforeB = (await app3b.inject({ method: 'GET', url: '/api/audit?after=0' })).json() as unknown[];
        const res = await app3b.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
        check(
          'v3.1 3b:ccs_scope_cert.associated_subcontractors 清空重灌 → 502 CCS_SUBCONTRACTOR_NOT_LISTED',
          res.statusCode === 502 && (res.json() as { reason_code?: string }).reason_code === CODES.CCS_SUBCONTRACTOR_NOT_LISTED,
          `status=${res.statusCode} body=${res.body.slice(0, 200)}`,
        );
        const auditAfterB = (await app3b.inject({ method: 'GET', url: '/api/audit?after=0' })).json() as unknown[];
        check(
          'MEDIUM #2:CCS_SUBCONTRACTOR_NOT_LISTED 觸發後 audit_chain 多一筆(DENY 入鏈)',
          auditAfterB.length === auditBeforeB.length + 1,
          `before=${auditBeforeB.length} after=${auditAfterB.length}`,
        );
      } finally {
        const restoreDb3 = openDb();
        restoreDb3.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(origScopeCertRow.sd_jwt, 'ccs_scope_cert');
        restoreDb3.prepare('DELETE FROM credentials WHERE id = ?').run('pcf_dyeing-A');
        restoreDb3.close();
        const finalRebind = await app3b.inject({ method: 'POST', url: '/api/issue/dyeing?case=A' });
        check('v3.1 3b 還原:pcf_dyeing-A 重簽回綁定原版 ccs_scope_cert', finalRebind.statusCode === 200, `status=${finalRebind.statusCode}`);
      }
      const okRes3 = await app3b.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
      check('v3.1 3b 對照組(分包商清單還原後):聚合恢復 200', okRes3.statusCode === 200, `status=${okRes3.statusCode}`);

      // (b2) Codex 審查 P1-c 回歸鎖:sc_no 相同、但 ccs_scope_cert 已重簽/替換(hash 不同,
      //     pcf_dyeing-A 仍指向舊 token)→ 502 SCOPE_CERT_INVALID(不是 CCS_SUBCONTRACTOR_NOT_LISTED)。
      const freshScopeCertSdJwt = await forgeCcsScopeCert();
      const swapDb3d = openDb();
      swapDb3d.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(freshScopeCertSdJwt, 'ccs_scope_cert');
      swapDb3d.close();
      try {
        const res = await app3b.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
        check(
          'P1-c:ccs_scope_cert 以相同 sc_no 重簽替換(hash 不同,pcf_dyeing-A 仍指向舊 token)→ 502 SCOPE_CERT_INVALID',
          res.statusCode === 502 && (res.json() as { reason_code?: string }).reason_code === CODES.SCOPE_CERT_INVALID,
          `status=${res.statusCode} body=${res.body.slice(0, 200)}`,
        );
      } finally {
        const restoreDb3d = openDb();
        restoreDb3d.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(origScopeCertRow.sd_jwt, 'ccs_scope_cert');
        restoreDb3d.close();
      }
      const okRes3d = await app3b.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
      check('P1-c 對照組(ccs_scope_cert 還原後):聚合恢復 200', okRes3d.statusCode === 200, `status=${okRes3d.statusCode}`);

      // (c) 撤 idx=10(ccs_scope_cert)→ SCOPE_CERT_INVALID(測後還原 bit)。
      const revokedList = new Array<number>(STATUS_LIST_SIZE).fill(0);
      revokedList[10] = 1;
      await buildAndWriteStatusList('credentials', revokedList);
      try {
        const auditBeforeC = (await app3b.inject({ method: 'GET', url: '/api/audit?after=0' })).json() as unknown[];
        const res = await app3b.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
        check(
          'v3.1 3b:Token Status List 撤銷 idx=10(ccs_scope_cert)→ 502 SCOPE_CERT_INVALID',
          res.statusCode === 502 && (res.json() as { reason_code?: string }).reason_code === CODES.SCOPE_CERT_INVALID,
          `status=${res.statusCode} body=${res.body.slice(0, 200)}`,
        );
        const auditAfterC = (await app3b.inject({ method: 'GET', url: '/api/audit?after=0' })).json() as unknown[];
        check(
          'MEDIUM #2:SCOPE_CERT_INVALID 觸發後 audit_chain 多一筆(DENY 入鏈)',
          auditAfterC.length === auditBeforeC.length + 1,
          `before=${auditBeforeC.length} after=${auditAfterC.length}`,
        );
      } finally {
        await buildAndWriteStatusList('credentials'); // 還原全 0
      }
      const okRes4 = await app3b.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
      check('v3.1 3b 對照組(Status List 還原後):聚合恢復 200', okRes4.statusCode === 200, `status=${okRes4.statusCode}`);
    } finally {
      await app3b.close();
    }
  }

  // 9c) Opus 獨立驗證修法回歸鎖(2026-08-30):
  //   HIGH #1 — 消費端(pcfAggregate.ts verifyInput / ccsScopeCert.ts verifyScopeCert)此前只驗
  //     簽章通過、未釘住簽發者角色——manifest 內任一角色的鑰簽的 tc_rcs/ccs_scope_cert 皆判為合法,
  //     PoC 證實 FAB/YARN 可自簽 tc_rcs、FAB 可自簽 ccs_scope_cert 並讓聚合成功。
  //   MEDIUM #3 — 聚合消費前撤銷檢查不對稱:此前只查 ccs_scope_cert(idx 10),未查 tc_rcs(idx 9)、
  //     pcf_upstream(idx 0/1)、pcf_dyeing(idx 4/5),被撤的輸入仍能撐起新聚合。
  //   LOW #5 — pcf_upstream 簽發前未驗證 tc_rcs 即採信其 tcNo/issuer_lei(與 HIGH #1 連動,見 (b))。
  {
    const app9c = buildServer();
    try {
      const db9cInit = openDb();
      const origTcRcsRow9c = db9cInit.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').get('tc_rcs') as { sd_jwt: string };
      const origScopeCertRow9c = db9cInit.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').get('ccs_scope_cert') as { sd_jwt: string };
      db9cInit.close();

      // ---------- HIGH #1(a):FAB 自簽 tc_rcs(seller_lei/buyer_lei 等欄位填對,簽章本身合法)——
      //     消費端(聚合)必須釘住簽發者角色 = cb,不是「manifest 內任一角色簽的都算」。
      const fabSignedTcRcs = await forgeTcRcs({ signerRole: 'fab' });
      const swapDb9c1 = openDb();
      swapDb9c1.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(fabSignedTcRcs, 'tc_rcs');
      swapDb9c1.close();
      try {
        const res = await app9c.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
        check(
          'HIGH #1:FAB 自簽 tc_rcs(欄位填對、簽章合法)→ 502 VCT_ISSUER_UNAUTHORIZED(消費端釘住簽發者角色 cb)',
          res.statusCode === 502 && (res.json() as { reason_code?: string }).reason_code === CODES.VCT_ISSUER_UNAUTHORIZED,
          `status=${res.statusCode} body=${res.body.slice(0, 200)}`,
        );
      } finally {
        const restoreDb9c1 = openDb();
        restoreDb9c1.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(origTcRcsRow9c.sd_jwt, 'tc_rcs');
        restoreDb9c1.close();
      }
      const okRes9c1 = await app9c.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
      check('HIGH #1 對照組(tc_rcs 還原後):聚合恢復 200', okRes9c1.statusCode === 200, `status=${okRes9c1.statusCode}`);

      // ---------- HIGH #1(b)+ LOW #5:入庫 tc_rcs 為 FAB 自簽時,直接對 POST /api/issue/upstream
      //     (issuePcfUpstream 本身,非聚合層)發起簽發——紗廠不得引用非 CB 簽發之 TC;tc_ref 之
      //     tcNo/issuer_lei 不得盲信未驗證的入庫紀錄(LOW #5)。
      const swapDb9c2 = openDb();
      swapDb9c2.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(fabSignedTcRcs, 'tc_rcs');
      swapDb9c2.prepare('DELETE FROM credentials WHERE id = ?').run('pcf_upstream-A');
      swapDb9c2.close();
      try {
        const res = await app9c.inject({ method: 'POST', url: '/api/issue/upstream', payload: { case_id: 'A' } });
        check(
          'HIGH #1 + LOW #5:入庫 tc_rcs 為 FAB 自簽時,POST /api/issue/upstream 拒簽(400 TC_REF_MISMATCH),不得靜默採信',
          res.statusCode === 400 && (res.json() as { reason_code?: string }).reason_code === CODES.TC_REF_MISMATCH,
          `status=${res.statusCode} body=${res.body.slice(0, 200)}`,
        );
      } finally {
        const restoreDb9c2 = openDb();
        restoreDb9c2.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(origTcRcsRow9c.sd_jwt, 'tc_rcs');
        restoreDb9c2.prepare('DELETE FROM credentials WHERE id = ?').run('pcf_upstream-A');
        restoreDb9c2.close();
        const finalReissue = await app9c.inject({ method: 'POST', url: '/api/issue/upstream', payload: { case_id: 'A' } });
        check('HIGH #1 還原:tc_rcs 還原後 pcf_upstream-A 重簽成功', finalReissue.statusCode === 200, `status=${finalReissue.statusCode}`);
      }

      // ---------- HIGH #1(c):FAB 自簽 ccs_scope_cert(sc_no/associated_subcontractors 皆填對)——
      //     verifyScopeCert 必須釘住簽發者角色 = cb;PoC 原本回 ok:true。
      const fabSignedScopeCert = await forgeCcsScopeCert({ signerRole: 'fab' });
      const directVerify = await verifyScopeCert(fabSignedScopeCert);
      check(
        'HIGH #1:FAB 自簽 ccs_scope_cert(欄位填對、簽章合法)→ verifyScopeCert 回 ok:false + SCOPE_CERT_INVALID',
        directVerify.ok === false && directVerify.reasonCode === CODES.SCOPE_CERT_INVALID,
        JSON.stringify({ ok: directVerify.ok, reasonCode: directVerify.reasonCode, error: directVerify.error }),
      );
      const swapDb9c3 = openDb();
      swapDb9c3.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(fabSignedScopeCert, 'ccs_scope_cert');
      swapDb9c3.close();
      try {
        const res = await app9c.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
        check(
          'HIGH #1:FAB 自簽 ccs_scope_cert → 聚合亦拒(502 SCOPE_CERT_INVALID)',
          res.statusCode === 502 && (res.json() as { reason_code?: string }).reason_code === CODES.SCOPE_CERT_INVALID,
          `status=${res.statusCode} body=${res.body.slice(0, 200)}`,
        );
      } finally {
        const restoreDb9c3 = openDb();
        restoreDb9c3.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(origScopeCertRow9c.sd_jwt, 'ccs_scope_cert');
        restoreDb9c3.close();
      }
      const okRes9c3 = await app9c.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
      check('HIGH #1 對照組(ccs_scope_cert 還原後):聚合恢復 200', okRes9c3.statusCode === 200, `status=${okRes9c3.statusCode}`);

      // ---------- MEDIUM #3:聚合消費前對四張輸入一律查 credentials Status List 撤銷位——此前只查
      //     ccs_scope_cert(idx 10);此處鎖 tc_rcs(idx 9)與 pcf_upstream-A(idx 0)兩個此前未查的缺口。
      const revokeTcRcsList = new Array<number>(STATUS_LIST_SIZE).fill(0);
      revokeTcRcsList[9] = 1;
      await buildAndWriteStatusList('credentials', revokeTcRcsList);
      try {
        const auditBefore9c = (await app9c.inject({ method: 'GET', url: '/api/audit?after=0' })).json() as unknown[];
        const res = await app9c.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
        check(
          'MEDIUM #3:撤銷 tc_rcs(idx=9)後聚合 → 502 CREDENTIAL_REVOKED(此前 aggregate 仍回 200 的缺口)',
          res.statusCode === 502 && (res.json() as { reason_code?: string }).reason_code === CODES.CREDENTIAL_REVOKED,
          `status=${res.statusCode} body=${res.body.slice(0, 200)}`,
        );
        const auditAfter9c = (await app9c.inject({ method: 'GET', url: '/api/audit?after=0' })).json() as unknown[];
        check(
          'MEDIUM #2+#3:CREDENTIAL_REVOKED(聚合路徑)觸發後 audit_chain 亦多一筆(DENY 入鏈)',
          auditAfter9c.length === auditBefore9c.length + 1,
          `before=${auditBefore9c.length} after=${auditAfter9c.length}`,
        );
      } finally {
        await buildAndWriteStatusList('credentials'); // 還原全 0
      }
      const okRes9c4 = await app9c.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
      check('MEDIUM #3 對照組(tc_rcs Status List 還原後):聚合恢復 200', okRes9c4.statusCode === 200, `status=${okRes9c4.statusCode}`);

      const revokeUpstreamList = new Array<number>(STATUS_LIST_SIZE).fill(0);
      revokeUpstreamList[0] = 1; // pcf_upstream-A 之 idx
      await buildAndWriteStatusList('credentials', revokeUpstreamList);
      try {
        const res = await app9c.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
        check(
          'MEDIUM #3:撤銷 pcf_upstream-A(idx=0)後聚合 → 502 CREDENTIAL_REVOKED',
          res.statusCode === 502 && (res.json() as { reason_code?: string }).reason_code === CODES.CREDENTIAL_REVOKED,
          `status=${res.statusCode} body=${res.body.slice(0, 200)}`,
        );
      } finally {
        await buildAndWriteStatusList('credentials'); // 還原全 0
      }
      const okRes9c5 = await app9c.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
      check('MEDIUM #3 對照組(pcf_upstream Status List 還原後):聚合恢復 200', okRes9c5.statusCode === 200, `status=${okRes9c5.statusCode}`);
    } finally {
      await app9c.close();
    }
  }

  // 9d) LOW #4:CredCard.tsx tc_ref 美化分支必須可達——Row 需把 fieldKey 轉交 formatValue,
  //     否則 formatValue 內 key==='tc_ref' 分支永不觸發、tc_ref 以原始 JSON.stringify 渲染。
  //     無 DOM 測試框架(不加清單外依賴),以原始碼靜態檢查鎖住修法。
  {
    const credCardSource = fs.readFileSync(path.join(ROOT, 'web', 'src', 'components', 'CredCard.tsx'), 'utf-8');
    check(
      'LOW #4:Row 呼叫 formatValue(fieldKey, value)(不是寫死空字串),tc_ref 美化分支可達',
      /formatValue\(fieldKey,\s*value\)/.test(credCardSource) && !/formatValue\(''\s*,\s*value\)/.test(credCardSource),
      'CredCard.tsx 原始碼未含預期呼叫',
    );
    check(
      'LOW #4:Row 呼叫端(publicFields/brandFields map)皆傳入 fieldKey={k}',
      (credCardSource.match(/<Row key=\{k\} fieldKey=\{k\}/g) ?? []).length >= 2,
      'CredCard.tsx 呼叫端未傳入 fieldKey',
    );
  }

  // 9e) Codex review 修法回歸鎖(2026-08-30;4 條真實漏洞,全在本輪新增的信任鏈程式)+
  //     Opus 獨立驗證回合二 A/B 修法(P1-b 首版改用純讀 readStatusListToken 補了 fail-open,卻
  //     引入 staleness 副作用:on-disk 清單 iat 固定在 setup 當下,閒置超過 ttl+skew(360s)後會
  //     讓合法未撤銷輸入假性失敗;B:verifyScopeCert 仍用 fail-open 的 readFreshStatusListToken,
  //     幕 5 P3 若拿它當獨立撤銷閘門會重現 fail-open)——最終修法見 server/creds/statusGuard.ts
  //     之 safeReadOrRefreshStatusListToken(既有清單可解碼且驗章通過才刷新續用,缺/壞才 fail-closed),
  //     pcfAggregate.ts 之 verifyInput 與 ccsScopeCert.ts 之 verifyScopeCert 皆已改用同一函式:
  //   P1-a — verifyScopeCert 型別混淆(CB 同時簽 tc_rcs 與 ccs_scope_cert,unchecked cast 讓
  //     一張合法 tc_rcs 被誤判為有效 SC);P1-b — 撤銷清單不可用時 fail-open;P1-c — scope-ref
  //     只比 sc_no 沒比 hash(已併入 9b 區塊,見上方 (b2));P2 — ensureInputs 內 TcRefMissingError
  //     未被 catch 涵蓋,落到未入鏈的 500 而非承諾的 502 DENY。
  {
    const app9e = buildServer();
    try {
      // ---------- P1-a:把 tc_rcs 的 sd_jwt 傳進 verifyScopeCert(CB 同時簽兩種憑證,kid/效期/
      //     status 皆對)→ 必須因型別不符(vct/iss)判定 ok:false,不得誤判為有效 SC。
      const db9eInit = openDb();
      const tcRcsRowForP1a = db9eInit.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').get('tc_rcs') as { sd_jwt: string };
      db9eInit.close();
      const p1aResult = await verifyScopeCert(tcRcsRowForP1a.sd_jwt);
      check(
        'P1-a:把 tc_rcs 的 sd_jwt 傳進 verifyScopeCert(型別混淆)→ ok:false + SCOPE_CERT_INVALID(kid/效期/status 皆對也不得誤判)',
        p1aResult.ok === false && p1aResult.reasonCode === CODES.SCOPE_CERT_INVALID,
        JSON.stringify({ ok: p1aResult.ok, reasonCode: p1aResult.reasonCode, error: p1aResult.error }),
      );
      // 對照組:真正的 ccs_scope_cert 仍正常通過(不誤傷正常路徑)。
      const db9eInit2 = openDb();
      const realScopeCertRowP1a = db9eInit2.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').get('ccs_scope_cert') as { sd_jwt: string };
      db9eInit2.close();
      const p1aOkResult = await verifyScopeCert(realScopeCertRowP1a.sd_jwt);
      check('P1-a 對照組:真正的 ccs_scope_cert 仍 ok:true(型別檢查未誤傷正常路徑)', p1aOkResult.ok === true, JSON.stringify(p1aOkResult.error));

      // ---------- P1-b(fail-closed):credentials.jwt 缺失或損毀時,消費前撤銷檢查必須拒絕
      //     (CREDENTIAL_REVOKED),不得因清單「不可用」就靜默視為全部有效並放行聚合。
      const credentialsStatusFile = statusListFile('credentials');
      const originalStatusFileContent = fs.readFileSync(credentialsStatusFile, 'utf-8');
      fs.rmSync(credentialsStatusFile);
      try {
        const res = await app9e.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
        check(
          'P1-b(fail-closed):credentials.jwt 缺失時聚合被拒(不是全過)→ 502 CREDENTIAL_REVOKED',
          res.statusCode === 502 && (res.json() as { reason_code?: string }).reason_code === CODES.CREDENTIAL_REVOKED,
          `status=${res.statusCode} body=${res.body.slice(0, 200)}`,
        );
      } finally {
        fs.writeFileSync(credentialsStatusFile, originalStatusFileContent);
      }
      const okResP1bMissing = await app9e.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
      check('P1-b 對照組(credentials.jwt 還原後):聚合恢復 200', okResP1bMissing.statusCode === 200, `status=${okResP1bMissing.statusCode}`);

      fs.writeFileSync(credentialsStatusFile, 'not-a-valid-status-list-jwt');
      try {
        const res = await app9e.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
        check(
          'P1-b(fail-closed):credentials.jwt 損毀(非合法 JWT)時聚合被拒 → 502 CREDENTIAL_REVOKED',
          res.statusCode === 502 && (res.json() as { reason_code?: string }).reason_code === CODES.CREDENTIAL_REVOKED,
          `status=${res.statusCode} body=${res.body.slice(0, 200)}`,
        );
      } finally {
        fs.writeFileSync(credentialsStatusFile, originalStatusFileContent);
      }
      const okResP1bCorrupt = await app9e.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
      check('P1-b 對照組(credentials.jwt 損毀後還原):聚合恢復 200', okResP1bCorrupt.statusCode === 200, `status=${okResP1bCorrupt.statusCode}`);

      // ---------- A(Opus 獨立驗證回合二):on-disk credentials.jwt 陳舊(iat 遠超 ttl+skew=360s)
      //     但**合法且未撤銷**(簽章正確、typ 正確、bits 全 0)→ 必須被安全刷新(換新 iat、保留
      //     bits),不得誤判為撤銷。若退回「readStatusListToken 純讀、不刷新」的寫法,此測項會因
      //     checkStatusBit 判定陳舊而翻紅(502 CREDENTIAL_REVOKED),證明 safeReadOrRefreshStatusListToken
      //     的「陳舊但可解碼 → 刷新續用」路徑確實有效。
      const staleFabKey = loadSandboxKey('fab');
      const staleIatSec = Math.floor(Date.now() / 1000) - 1000; // 1000s ago,遠超 ttl(300)+skew(60)=360s
      const staleList = new StatusList(new Array<number>(STATUS_LIST_SIZE).fill(0), 1);
      const { header: staleHeader, payload: stalePayload } = createHeaderAndPayload(
        staleList,
        { sub: statusListUri('credentials'), iat: staleIatSec, exp: staleIatSec + 60 * 60 * 24 * 180, ttl: STATUS_TTL_SECONDS },
        { alg: 'EdDSA', typ: JWT_STATUS_LIST_TYPE },
      );
      const staleToken = await new SignJWT(stalePayload as Record<string, unknown>)
        .setProtectedHeader({ ...staleHeader, kid: staleFabKey.kid })
        .sign(staleFabKey.privateKey);
      fs.writeFileSync(credentialsStatusFile, staleToken);
      try {
        const res = await app9e.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
        check(
          'A:credentials.jwt 陳舊但合法未撤銷(簽章/typ/bits 皆正確,只是 iat 太老)→ 安全刷新後聚合仍 200(不誤判為撤銷)',
          res.statusCode === 200,
          `status=${res.statusCode} body=${res.body.slice(0, 200)}`,
        );
        // 刷新後檔案應已換新 iat(不再陳舊)——證明「刷新」確實發生,而非巧合通過。
        const refreshedContent = fs.readFileSync(credentialsStatusFile, 'utf-8');
        const refreshedIat = (decodeJoseJwt(refreshedContent) as { iat?: number }).iat ?? 0;
        check(
          'A:刷新後 on-disk credentials.jwt 之 iat 已更新為新鮮值(非原陳舊 iat)',
          refreshedIat > staleIatSec + 900,
          `staleIat=${staleIatSec} refreshedIat=${refreshedIat}`,
        );
      } finally {
        fs.writeFileSync(credentialsStatusFile, originalStatusFileContent);
      }
      const okResStale = await app9e.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
      check('A 對照組(還原為原始新鮮清單後):聚合恢復 200', okResStale.statusCode === 200, `status=${okResStale.statusCode}`);

      // ---------- B(Opus 獨立驗證回合二):verifyScopeCert 本身(幕 5 P3 context.subcontractor_listed
      //     判定函式)在 credentials.jwt 缺失時,必須獨立 fail-closed——不能只靠聚合路徑「先跑
      //     verifyInput('tc_rcs') fail-closed」來遮蔽,因為 Phase 3a 可能單獨呼叫 verifyScopeCert。
      const db9eInit4 = openDb();
      const scopeCertRowForB = db9eInit4.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').get('ccs_scope_cert') as { sd_jwt: string };
      db9eInit4.close();
      fs.rmSync(credentialsStatusFile);
      try {
        const directResult = await verifyScopeCert(scopeCertRowForB.sd_jwt);
        check(
          'B:credentials.jwt 缺失時直接呼叫 verifyScopeCert(合法 SC)→ ok:false + SCOPE_CERT_INVALID(不靠 tc_rcs 遮蔽)',
          directResult.ok === false && directResult.reasonCode === CODES.SCOPE_CERT_INVALID,
          JSON.stringify({ ok: directResult.ok, reasonCode: directResult.reasonCode, error: directResult.error }),
        );
      } finally {
        fs.writeFileSync(credentialsStatusFile, originalStatusFileContent);
      }
      const okResB = await verifyScopeCert(scopeCertRowForB.sd_jwt);
      check('B 對照組(credentials.jwt 還原後):verifyScopeCert 恢復 ok:true', okResB.ok === true, JSON.stringify(okResB.error));

      // ---------- P2:pcf_upstream 不存在(強制 ensureInputs 重簽)+ 入庫 tc_rcs 驗證失敗(FAB 自簽)
      //     → issuePcfUpstream 拋 TcRefMissingError,此前未被路由 catch 涵蓋而落到未入鏈的 500。
      const db9eInit3 = openDb();
      const origTcRcsRowP2 = db9eInit3.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').get('tc_rcs') as { sd_jwt: string };
      db9eInit3.close();
      const fabSignedTcRcsForP2 = await forgeTcRcs({ signerRole: 'fab' });
      const swapDbP2 = openDb();
      swapDbP2.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(fabSignedTcRcsForP2, 'tc_rcs');
      swapDbP2.prepare('DELETE FROM credentials WHERE id = ?').run('pcf_upstream-A');
      swapDbP2.close();
      try {
        const auditBeforeP2 = (await app9e.inject({ method: 'GET', url: '/api/audit?after=0' })).json() as unknown[];
        const res = await app9e.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
        check(
          'P2:pcf_upstream 不存在且入庫 tc_rcs 驗證失敗(FAB 自簽)→ ensureInputs 拋 TcRefMissingError → 502 TC_REF_MISMATCH(不是未入鏈的 500)',
          res.statusCode === 502 && (res.json() as { reason_code?: string }).reason_code === CODES.TC_REF_MISMATCH,
          `status=${res.statusCode} body=${res.body.slice(0, 200)}`,
        );
        const auditAfterP2 = (await app9e.inject({ method: 'GET', url: '/api/audit?after=0' })).json() as unknown[];
        check(
          'P2:此路徑觸發後 audit_chain 多一筆(DENY 入鏈;此前完全未入鏈)',
          auditAfterP2.length === auditBeforeP2.length + 1,
          `before=${auditBeforeP2.length} after=${auditAfterP2.length}`,
        );
      } finally {
        const restoreDbP2 = openDb();
        restoreDbP2.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(origTcRcsRowP2.sd_jwt, 'tc_rcs');
        restoreDbP2.prepare('DELETE FROM credentials WHERE id = ?').run('pcf_upstream-A');
        restoreDbP2.close();
        const finalReissueP2 = await app9e.inject({ method: 'POST', url: '/api/issue/upstream', payload: { case_id: 'A' } });
        check('P2 還原:tc_rcs 還原後 pcf_upstream-A 重簽成功', finalReissueP2.statusCode === 200, `status=${finalReissueP2.statusCode}`);
      }
      const okResP2 = await app9e.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
      check('P2 對照組(還原後):聚合恢復 200', okResP2.statusCode === 200, `status=${okResP2.statusCode}`);
    } finally {
      await app9e.close();
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

      // (b) 發現 1(併發競態,server/creds/pcfAggregate.ts ensureInputs 呼叫路徑):
      //     清空案 B 兩張輸入/聚合列,併發打兩個 /api/aggregate(同案 B)。同理,用兩份聚合回應的
      //     precursor_refs hash 互相比對(不只是跟 DB 比)——同一案只能有一組合法輸入,兩份聚合
      //     若引用不同雜湊,代表兩個呼叫者各自簽了不同的輸入 token,信任鏈已經分岔。
      const raceDb2 = openDb();
      raceDb2.prepare('DELETE FROM credentials WHERE id IN (?, ?, ?)').run('pcf_upstream-B', 'pcf_dyeing-B', 'pcf_aggregate-B');
      raceDb2.close();

      const [raceAgg1, raceAgg2] = await Promise.all([
        app3.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'B' } }),
        app3.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'B' } }),
      ]);
      type RaceAggBody = { precursor_refs?: Array<{ id: string; hash: string }> };
      const aggBody1 = raceAgg1.json() as RaceAggBody;
      const aggBody2 = raceAgg2.json() as RaceAggBody;
      const refHash = (b: RaceAggBody, id: string) => b.precursor_refs?.find((r) => r.id === id)?.hash;
      check(
        '發現 1(併發競態):併發兩個 POST /api/aggregate(案 B)皆回 200',
        raceAgg1.statusCode === 200 && raceAgg2.statusCode === 200,
        `status1=${raceAgg1.statusCode} status2=${raceAgg2.statusCode}`,
      );
      check(
        '發現 1(併發競態):兩份聚合回應的 precursor_refs hash 逐筆相同(同一案只有一組合法輸入,不得分岔)',
        !!refHash(aggBody1, 'pcf_upstream-B') &&
          refHash(aggBody1, 'pcf_upstream-B') === refHash(aggBody2, 'pcf_upstream-B') &&
          !!refHash(aggBody1, 'pcf_dyeing-B') &&
          refHash(aggBody1, 'pcf_dyeing-B') === refHash(aggBody2, 'pcf_dyeing-B'),
        `up1=${refHash(aggBody1, 'pcf_upstream-B')?.slice(0, 12)} up2=${refHash(aggBody2, 'pcf_upstream-B')?.slice(0, 12)}`,
      );

      const raceDbCheck2 = openDb();
      const upstreamRowsB = raceDbCheck2.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').all('pcf_upstream-B') as { sd_jwt: string }[];
      const dyeingRowsB = raceDbCheck2.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').all('pcf_dyeing-B') as { sd_jwt: string }[];
      raceDbCheck2.close();
      const sha256HexRace = (s: string) => crypto.createHash('sha256').update(s).digest('hex');
      check(
        '發現 1(併發競態):credentials 表兩張輸入各只有一列,且聚合 precursor_refs hash === sha256(落庫輸入 sd_jwt)',
        upstreamRowsB.length === 1 &&
          dyeingRowsB.length === 1 &&
          refHash(aggBody1, 'pcf_upstream-B') === sha256HexRace(upstreamRowsB[0]?.sd_jwt ?? '') &&
          refHash(aggBody1, 'pcf_dyeing-B') === sha256HexRace(dyeingRowsB[0]?.sd_jwt ?? ''),
        `upRows=${upstreamRowsB.length} dyeRows=${dyeingRowsB.length}`,
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
        '遺留(b)鎖:M2 allowed_claims 不含 pcf_yarn',
        !m2Summary.allowed_claims.includes('pcf_yarn'),
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
      check('presentation 可用FAB公鑰驗章通過', presVerify.ok === true, JSON.stringify({ ok: presVerify.ok, error: presVerify.error }));
      const presPayload = (presVerify.payload ?? {}) as Record<string, unknown>;
      const allInAllowed = m2Summary.allowed_claims.every((claim) => claim in presPayload);
      check(`presentation 含全部允許欄位(${m2Summary.allowed_claims.length} 欄逐一核對「在」)`, allInAllowed, JSON.stringify(Object.keys(presPayload)));
      check(
        '遺留(b)鎖:presentation 不含 pcf_yarn(逐欄核對「不在」)',
        !('pcf_yarn' in presPayload),
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

  // 14) 幕 4 越界攔截 DENY(加碼索取 plant_total_output 全廠產量)——Cedar P2 forbid,零欄位外洩。
  {
    const app14 = buildServer();
    try {
      const brandWorkload = loadWorkloadKey('brand-workload');
      const overRequestClaims = [...m2Summary.allowed_claims, 'plant_total_output'];
      const requestJws = await signDiscloseRequest(brandWorkload, m2Summary.jti, 'A', overRequestClaims, randomNonce());

      const auditBeforeRes = await app14.inject({ method: 'GET', url: '/api/audit?after=0' });
      const auditCountBefore = (auditBeforeRes.json() as unknown[]).length;

      const res = await app14.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: requestJws } });
      check('幕 4:加碼索取 plant_total_output → 403', res.statusCode === 403, `status=${res.statusCode} body=${res.body}`);
      const body = res.json() as Record<string, unknown>;
      check(
        '理由碼 POLICY_P2_CONFIDENTIAL、policy_id=P2',
        body.reason_code === CODES.POLICY_P2_CONFIDENTIAL && body.policy_id === 'P2',
        JSON.stringify(body),
      );
      check(
        '零欄位外洩:回應無 presentation 欄位,亦不含任何 pcf_aggregate 欄位值',
        !('presentation' in body) && !('pcf_total' in body),
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
      overBroadFrame.pcf_yarn = true; // 故意多挑一個不在 allowed_claims 內的 disclosure
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

    // (d) 遺留(a)鎖:錯誤角色簽發(vct 宣稱 pcf_aggregate,實際由 YARN LE 鑰簽發,非FAB)→ 拒絕。
    const yarnKey = loadSandboxKey('yarn');
    const nowSec = Math.floor(Date.now() / 1000);
    const forgedPayload = {
      vct: PCF_AGGREGATE_VCT,
      iss: yarnKey.kid,
      iat: nowSec,
      nbf: nowSec,
      exp: nowSec + 3600,
      status: { status_list: { idx: 2, uri: statusListUri('credentials') } },
      precursor_refs: [
        { id: 'pcf_upstream-A', hash: '0'.repeat(64) },
        { id: 'pcf_dyeing-A', hash: '1'.repeat(64) },
      ],
      pcf_total: 1.5125,
    };
    const forgedFrame = { pcf_total: true } as unknown as DisclosureFrame<SdJwtVcPayload>;
    const forgedInstance = buildIssuerInstance(yarnKey);
    const forgedSdJwt = await forgedInstance.issue(forgedPayload as unknown as SdJwtVcPayload, forgedFrame, { header: { kid: yarnKey.kid } });
    const forgedResult = await verifyPresentation({ presentationSdJwt: forgedSdJwt, mandateJwt: m2MandateJwt, manifest });
    const vctCheck = forgedResult.checks.find((c) => c.name.includes('vct'));
    check(
      '遺留(a)鎖:pcf_aggregate 由 YARN LE 鑰(非FAB)簽發 → vct↔簽發者 AID 綁定檢查失敗(VCT_ISSUER_UNAUTHORIZED)',
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
      // (a) 不誠實偽造:攻擊者用 YARN LE 鑰**實際簽章**(header.kid = YARN AID),
      //     payload.iss 卻填FAB LE AID。舊版綁定檢查只比對 payload.iss、取鑰卻走 header.kid,
      //     兩者從不互相校驗 → 偽造的 carbon_total 會被判 valid=true(PoC 已證實)。
      const attackerKey = loadSandboxKey('yarn');
      const c1Now = Math.floor(Date.now() / 1000);
      const forgedClaims = {
        vct: PCF_AGGREGATE_VCT,
        iss: manifest.fab.aid, // 宣稱FAB簽的
        iat: c1Now,
        nbf: c1Now,
        exp: c1Now + 3600,
        status: { status_list: { idx: 2, uri: statusListUri('credentials') } },
        precursor_refs: [
        { id: 'pcf_upstream-A', hash: '0'.repeat(64) },
        { id: 'pcf_dyeing-A', hash: '1'.repeat(64) },
      ],
        pcf_total: 0.0001, // 偽造的超低碳排
        pcf_period: '2026-05',
      };
      const forgedFrame23 = {
        _sd: ['pcf_total', 'pcf_period'],
      } as unknown as DisclosureFrame<SdJwtVcPayload>;
      const dishonestSdJwt = await buildIssuerInstance(attackerKey).issue(forgedClaims as unknown as SdJwtVcPayload, forgedFrame23, {
        header: { kid: attackerKey.kid }, // 誠實標示自己的鑰(簽章驗得過),只在 payload 說謊
      });
      const dishonestResult = await verifyPresentation({ presentationSdJwt: dishonestSdJwt, mandateJwt: m2MandateJwt, manifest });
      const dishonestSigCheck = dishonestResult.checks[0];
      const dishonestVctCheck = dishonestResult.checks.find((c) => c.name.includes('vct'));
      check(
        'C1:header.kid(實際簽章者 YARN)≠ payload.iss(宣稱FAB)之偽造 pcf_aggregate → VCT_ISSUER_UNAUTHORIZED',
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

      // (b) kid 冒充:header.kid 填FAB AID、實際仍用 YARN 鑰簽 → 第 1 項簽章驗證即失敗
      //     (取鑰依 kid,解出FAB公鑰,驗不過攻擊者的簽章)。
      const kidSpoofSdJwt = await buildIssuerInstance(attackerKey).issue(forgedClaims as unknown as SdJwtVcPayload, forgedFrame23, {
        header: { kid: manifest.fab.aid },
      });
      const kidSpoofResult = await verifyPresentation({ presentationSdJwt: kidSpoofSdJwt, mandateJwt: m2MandateJwt, manifest });
      check(
        'C1:header.kid 冒充FAB、實際用 YARN 鑰簽 → 簽章檢查失敗(CREDENTIAL_SIG_INVALID)',
        kidSpoofResult.ok === false && kidSpoofResult.checks[0]?.ok === false && kidSpoofResult.checks[0]?.reasonCode === CODES.CREDENTIAL_SIG_INVALID,
        JSON.stringify(kidSpoofResult.checks[0]),
      );

      // ---------- H2:最小揭露不得有算術洩漏 ----------
      const presVerify23 = await verifyCompactSdJwt(permitPresentation, resolvePublicKeyFromManifest(manifest));
      const presPayload23 = (presVerify23.payload ?? {}) as Record<string, unknown>;
      const emissionFieldNames = ['pcf_total', ...NEVER_DISCLOSABLE_CLAIMS];
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
      // v3 還原目標:三段分項(pcf_yarn / pcf_knitting / pcf_dyeing)——presentation 內任意 ± 組合
      // 都不得等於任一分項(等於即代表布廠自家織布強度或外包段可被反推)。
      const h2r4 = (n: number) => Math.round(n * 10000) / 10000;
      const h2YarnTotal = h2r4(
        seedData.upstream_defaults.pcf_direct + h2r4(seedData.upstream_defaults.electricity_kwh_per_kg * seedData.emission_factor_table.grid_vn_kg_per_kwh),
      );
      const reconstructionTargets = [
        h2r4(h2YarnTotal * seedData.aggregate_defaults.yarn_loss_factor),
        h2r4(seedData.aggregate_defaults.knitting_electricity_kwh_per_kg * seedData.emission_factor_table.grid_tw_kg_per_kwh),
        seedData.cases.A.expected_pcf_dyeing,
      ];
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
        `H2 還原攻擊:揭露數值(${disclosedNumbers.length} 個)的任意 ± 組合都無法還原任一分項(${reconstructionTargets.join(' / ')})`,
        reconstructed === null,
        `命中組合:${reconstructed}`,
      );

      // v3 檢查 4(補):對三個 NEVER_DISCLOSABLE 分項各發 disclose 請求 → CLAIM_NOT_IN_MANDATE(政策層);
      // presenter 層硬拒已由 L4 區塊覆蓋;brand_allocation_share 明文不得出現於 presentation(僅 *_hash)。
      for (const denied of NEVER_DISCLOSABLE_CLAIMS) {
        const deniedJws = await signDiscloseRequest(brandWorkload, m2Summary.jti, 'A', [...m2Summary.allowed_claims, denied], randomNonce());
        const deniedRes = await app23.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws: deniedJws } });
        check(
          `v3 H2:disclose 索取分項 ${denied} → 403 CLAIM_NOT_IN_MANDATE`,
          deniedRes.statusCode === 403 && (deniedRes.json() as { reason_code?: string }).reason_code === CODES.CLAIM_NOT_IN_MANDATE,
          `status=${deniedRes.statusCode} body=${deniedRes.body.slice(0, 160)}`,
        );
      }
      check(
        'v3 H2:brand_allocation_share 不出現於 presentation 明文(僅 brand_allocation_share_hash commitment)',
        !('brand_allocation_share' in presPayload23) && typeof presPayload23.brand_allocation_share_hash === 'string',
        JSON.stringify(Object.keys(presPayload23)),
      );

      // ---------- M2:mandate 必須由預期 ECR 角色簽發 ----------
      const mandatePayloadOriginal = decodeJoseJwt(m2MandateJwt) as Record<string, unknown>;
      const cfoKey = loadSandboxKey('fab_cfo');
      // (a) 換角色簽(FAB財務主管 ECR 冒簽 M2):kid/iss 都誠實寫自己 → 必須因「非預期角色」被拒。
      const wrongRoleMandate = await new SignJWT({ ...mandatePayloadOriginal, iss: cfoKey.kid })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'mandate+jwt', kid: cfoKey.kid })
        .sign(cfoKey.privateKey);
      // (b) kid 冒充 Brand 永續長、實際用FAB財務主管鑰簽 → 簽章驗證失敗。
      const kidSpoofMandate = await new SignJWT({ ...mandatePayloadOriginal })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'mandate+jwt', kid: manifest.brand_cso.aid })
        .sign(cfoKey.privateKey);

      const mandateDb23 = openDb();
      const originalM2Token = (mandateDb23.prepare('SELECT token FROM mandates WHERE id = ?').get('M2') as { token: string }).token;
      mandateDb23.close();
      for (const [label, badToken] of [
        ['非預期角色(FAB財務主管 ECR)簽發 M2', wrongRoleMandate],
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
      const allowedOnlyPresentation = await presentSelectedDisclosures(aggSdJwt23, { pcf_total: true } as never);
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
        precursor_refs: [
        { id: 'pcf_upstream-A', hash: '0'.repeat(64) },
        { id: 'pcf_dyeing-A', hash: '1'.repeat(64) },
      ],
        pcf_total: 1.5125,
        pcf_period: '2026-05',
        // 授權簽發者(FAB)新增並揭露的一個 mandate 未列 claim——舊版硬編 PCF_AGGREGATE_SD_FIELDS 不含它 → fail-open。
        unexpected_extra_claim: 'schema-evolution-injected',
      };
      const extraFrame = {
        _sd: ['pcf_total', 'pcf_period', 'unexpected_extra_claim'],
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
        precursor_refs: [
        { id: 'pcf_upstream-A', hash: '0'.repeat(64) },
        { id: 'pcf_dyeing-A', hash: '1'.repeat(64) },
      ],
        pcf_total: 1.5125,
        pcf_period: '2026-05',
      };
      const expiredFrame = {
        _sd: ['pcf_total', 'pcf_period'],
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

  // 25) v3 檢查 6:Cedar 整數單位(kgCO₂e/kg × 1000 → gCO₂e/kg;Codex 審查定案)——
  //     mandate 資料欄位維持 9.5,政策比較一律整數 g;A 7925 ≤ 9500 過、B 10899 不過。
  //     v3.1(§3 檢查 8):以 authorizeEmitReleaseCredential 實際呼叫 cedar-wasm 驗
  //     context.subcontractor_listed=false 時 P3 不放行(Phase 3 接上真實 P3 pipeline 時共用同一函式)。
  {
    const seedV3 = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8'));
    const toG = (kg: number) => Math.round(kg * 1000);
    check(
      'v3 Cedar 單位:seed contract_carbon_max_g == 9500 且 == round(contract_carbon_max × 1000)',
      seedV3.transaction.contract_carbon_max_g === 9500 && toG(seedV3.transaction.contract_carbon_max) === 9500,
      `g=${seedV3.transaction.contract_carbon_max_g} kg=${seedV3.transaction.contract_carbon_max}`,
    );
    const aG = toG(seedV3.cases.A.expected_pcf_total);
    const bG = toG(seedV3.cases.B.expected_pcf_total);
    check('v3 Cedar 單位:案 A carbon_total_g == 7925 且 ≤ 9500(過門檻)', aG === 7925 && aG <= 9500, `aG=${aG}`);
    check('v3 Cedar 單位:案 B carbon_total_g == 10899 且 > 9500(不過門檻)', bG === 10899 && bG > 9500, `bG=${bG}`);
    const p3Text = fs.readFileSync(path.join(ROOT, 'policies', 'p3.cedar'), 'utf-8');
    check(
      'v3 Cedar 單位:p3.cedar 以 carbon_total_g <= principal.mandate.carbon_max_g 比較(整數 g,不用浮點 kg)',
      p3Text.includes('context.carbon_total_g <= principal.mandate.carbon_max_g') && !p3Text.includes('carbon_max_kg'),
    );
    check('v3.1:p3.cedar 含 context.subcontractor_listed 布林(後端算好,Cedar 不得直接讀 SC 狀態)', p3Text.includes('context.subcontractor_listed'));

    // v3.1(§3 檢查 8):authorizeEmitReleaseCredential 實際跑 cedar-wasm——五要件全過(含
    // subcontractor_listed=true)才 PERMIT;subcontractor_listed=false 時單獨翻盤為 DENY。
    const baseP3Context = {
      mandate_status_ok: true,
      identity_ok: true,
      subcontractor_listed: true,
      carbon_total_g: aG, // 案 A 7925 ≤ 9500
      invoice_ok: true,
      wallet_risk: 12,
      risk_sources_confirming: 1,
      amount: 3420,
    };
    const permitResult = authorizeEmitReleaseCredential({ carbonMaxG: 9500, maxAmount: 50000, context: baseP3Context });
    check(
      'v3.1 Cedar P3:五要件全過(含 subcontractor_listed=true)→ PERMIT',
      permitResult.allow === true && permitResult.matchedPolicies.includes('P3'),
      JSON.stringify(permitResult),
    );
    const subNotListedResult = authorizeEmitReleaseCredential({
      carbonMaxG: 9500,
      maxAmount: 50000,
      context: { ...baseP3Context, subcontractor_listed: false },
    });
    check(
      'v3.1 Cedar P3:context.subcontractor_listed=false → 其餘要件皆過仍 DENY(後端算好之布林,Cedar 不直接讀 SC 狀態)',
      subNotListedResult.allow === false,
      JSON.stringify(subNotListedResult),
    );
    const carbonOverResult = authorizeEmitReleaseCredential({
      carbonMaxG: 9500,
      maxAmount: 50000,
      context: { ...baseP3Context, carbon_total_g: bG }, // 案 B 10899 > 9500
    });
    check(
      'v3.1 Cedar P3 對照組:carbon_total_g(案 B 10899)> carbon_max_g(9500)→ DENY',
      carbonOverResult.allow === false,
      JSON.stringify(carbonOverResult),
    );
  }

  // 26) v3 檢查 3(補):外部輸入憑證消費前驗章失敗路徑 → CREDENTIAL_SIG_INVALID(不得跳過驗章)。
  {
    const app26 = buildServer();
    try {
      for (const inputId of ['tc_rcs', 'pcf_upstream-A', 'pcf_dyeing-A'] as const) {
        const vDb = openDb();
        const orig = (vDb.prepare('SELECT sd_jwt FROM credentials WHERE id = ?').get(inputId) as { sd_jwt: string }).sd_jwt;
        vDb.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(tamperPayloadByte(orig), inputId);
        vDb.close();
        try {
          const res = await app26.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
          check(
            `v3:${inputId} 遭竄改後聚合 → 502 CREDENTIAL_SIG_INVALID(消費前驗章擋下,不得跳過)`,
            res.statusCode === 502 && (res.json() as { reason_code?: string }).reason_code === CODES.CREDENTIAL_SIG_INVALID,
            `status=${res.statusCode} body=${res.body.slice(0, 160)}`,
          );
        } finally {
          const rDb = openDb();
          rDb.prepare('UPDATE credentials SET sd_jwt = ? WHERE id = ?').run(orig, inputId);
          rDb.close();
        }
      }
      // 對照組:還原後聚合恢復 200。
      const okRes = await app26.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
      check('v3 對照組:輸入憑證還原後聚合恢復 200', okRes.statusCode === 200, `status=${okRes.statusCode}`);
    } finally {
      await app26.close();
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
