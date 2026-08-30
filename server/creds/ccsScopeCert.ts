/**
 * ccs_scope_cert — 認證機構(CB)簽發之布廠 Scope Certificate SD-JWT VC(seed 時簽;
 * 幕 2 聚合前核對、幕 5 P3 分包商核對;架構決策 §4:POST /api/issue/scope-cert)。
 * spec v3.1 §4.5(CCS-101 C5.2.1/C5.4、CCS-102 D3.4):demo 只建模「布廠持有 SC、
 * 染整廠列為 associated subcontractor」這一種允許型態。全部公開層(非 SD;不做選擇性揭露)。
 * holder_lei/cb_lei/associated_subcontractors[].lei 於簽發時自 manifest 取,不寫死。
 * A/B 兩案共用同一張(id 固定為 ccs_scope_cert;idx 依 seed.status_list_idx.credentials.ccs_scope_cert)。
 */
import fs from 'node:fs';
import path from 'node:path';
import type Database from 'better-sqlite3';
import type { DisclosureFrame } from '@sd-jwt/core';
import type { SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc';
import { ROOT } from '../db';
import { loadSandboxKey } from '../keys';
import { buildIssuerInstance } from './issuer';
import { verifyCompactSdJwt } from './verifier';
import { checkStatusBit, statusListUri } from '../statuslist';
import { safeReadOrRefreshStatusListToken } from './statusGuard';
import { readManifest, resolvePublicKeyFromManifest } from '../manifest';
import { getCredential, insertCredentialIfAbsent, type CredentialRow } from './store';
import { CODES, type ReasonCode } from '../../shared/codes';
import type { AssociatedSubcontractor, CcsScopeCertPayload } from '../../shared/types';

export const CCS_SCOPE_CERT_VCT = 'https://carbon-cred-demo.local/vct/ccs_scope_cert';

/** id 固定(A/B 兩案共用同一張 SC)。 */
export const CCS_SCOPE_CERT_ID = 'ccs_scope_cert';

/** 效期新鮮度之有界時鐘偏移(秒)——與既有 discloseGateway.ts 的憑證效期檢查慣例一致。 */
const SCOPE_CERT_CLOCK_SKEW_SEC = 60;

interface CcsScopeCertSeedData {
  sc_no: string;
  standards: string[];
  processes: Array<{ code: string; name: string; site: string }>;
  associated_subcontractors: Array<{ party: string; name: string; process: string; audited: boolean }>;
  issued_at: string;
  valid_from: string;
  valid_until: string;
}

interface SeedData {
  ccs_scope_cert: CcsScopeCertSeedData;
  status_list_idx: { credentials: Record<string, number> };
}

function readSeed(): SeedData {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8'));
}

export interface CcsScopeCertIssuance {
  id: string;
  caseId: null;
  sdJwt: string;
  payload: CcsScopeCertPayload;
  issuedAt: string;
  validFrom: string;
  validUntil: string;
  issuerParty: 'cb';
  holderParty: 'fab';
  statusIdx: number;
  statusUri: string;
}

/** 簽出 ccs_scope_cert(CB sandbox LE AID 鑰;holder_lei/cb_lei/分包商 lei 自 manifest 取)。純函式,不落庫。 */
export async function issueCcsScopeCert(): Promise<CcsScopeCertIssuance> {
  const seed = readSeed();
  const d = seed.ccs_scope_cert;
  const key = loadSandboxKey('cb');
  const manifest = readManifest();
  if (!manifest?.fab?.lei || !manifest?.cb?.lei) {
    throw new Error('manifest 缺 fab/cb 角色(先跑 make setup)——ccs_scope_cert 的 holder_lei/cb_lei 需要兩者 LEI');
  }

  const associatedSubcontractors: AssociatedSubcontractor[] = d.associated_subcontractors.map((s) => {
    const role = manifest[s.party];
    if (!role?.lei) throw new Error(`manifest 缺 ${s.party} 角色(先跑 make setup)——ccs_scope_cert 分包商 lei 需要之`);
    return { lei: role.lei, name: s.name, process: s.process, audited: s.audited };
  });

  const statusIdx = seed.status_list_idx.credentials[CCS_SCOPE_CERT_ID];
  if (typeof statusIdx !== 'number') throw new Error(`seed.status_list_idx.credentials 缺 ${CCS_SCOPE_CERT_ID}`);
  const statusUri = statusListUri('credentials');

  const issuedAtSec = Math.floor(new Date(`${d.issued_at}T00:00:00Z`).getTime() / 1000);
  const validFromSec = Math.floor(new Date(`${d.valid_from}T00:00:00Z`).getTime() / 1000);
  const validUntilSec = Math.floor(new Date(`${d.valid_until}T00:00:00Z`).getTime() / 1000);

  const payload: CcsScopeCertPayload = {
    vct: CCS_SCOPE_CERT_VCT,
    iss: key.kid,
    iat: issuedAtSec,
    nbf: validFromSec,
    exp: validUntilSec,
    status: { status_list: { idx: statusIdx, uri: statusUri } },
    sc_no: d.sc_no,
    holder_lei: manifest.fab.lei,
    holder_name: manifest.fab.legal_name,
    standards: d.standards,
    processes: d.processes,
    associated_subcontractors: associatedSubcontractors,
    cb_lei: manifest.cb.lei,
    cb_name: manifest.cb.legal_name,
    valid_from: d.valid_from,
    valid_until: d.valid_until,
  };

  // 全部公開層(非 SD)——_sd 空陣列,無選擇性揭露(spec v3.1 §4.5)。
  const disclosureFrame = { _sd: [] } as unknown as DisclosureFrame<SdJwtVcPayload>;

  const instance = buildIssuerInstance(key);
  const sdJwt = await instance.issue(payload as unknown as SdJwtVcPayload, disclosureFrame, { header: { kid: key.kid } });

  return {
    id: CCS_SCOPE_CERT_ID,
    caseId: null,
    sdJwt,
    payload,
    issuedAt: d.issued_at,
    validFrom: d.valid_from,
    validUntil: d.valid_until,
    issuerParty: 'cb',
    holderParty: 'fab',
    statusIdx,
    statusUri,
  };
}

/**
 * 冪等取得(必要時先簽發並入庫)ccs_scope_cert——與 tcRcs.ts 的 ensureTcRcs() 相同模式。
 * 供 scripts/seed.ts(灌案件前)、server/routes/issue.ts(POST /api/issue/scope-cert)、
 * server/creds/pcfAggregate.ts ensureInputs() 共用同一入口。
 */
export async function ensureCcsScopeCert(db: Database.Database): Promise<{ row: CredentialRow; reused: boolean }> {
  const existing = getCredential(db, CCS_SCOPE_CERT_ID);
  if (existing) return { row: existing, reused: true };

  const issuance = await issueCcsScopeCert();
  return insertCredentialIfAbsent(db, {
    id: issuance.id,
    type: 'ccs_scope_cert',
    caseId: issuance.caseId,
    issuerParty: issuance.issuerParty,
    holderParty: issuance.holderParty,
    sdJwt: issuance.sdJwt,
    payload: issuance.payload,
    statusIdx: issuance.statusIdx,
    statusUri: issuance.statusUri,
    issuedAt: issuance.issuedAt,
    validFrom: issuance.validFrom,
    validUntil: issuance.validUntil,
  });
}

export interface VerifyScopeCertResult {
  ok: boolean;
  payload?: CcsScopeCertPayload;
  reasonCode?: ReasonCode;
  error?: string;
}

/**
 * 驗 ccs_scope_cert:簽章(manifest 公鑰)+ **釘住簽發者角色 cb**(HIGH #1:僅驗簽章通過不夠,
 * manifest 內任一角色的鑰都能簽出「驗章通過」的 token——PoC 證實 FAB 可自簽 ccs_scope_cert 並讓
 * verifyScopeCert 回 ok:true;實際驗章鑰 header.kid 必須等於 manifest.cb.aid,不符即
 * SCOPE_CERT_INVALID)+ **型別綁定**(Codex 審查 P1-a:CB 同時簽 tc_rcs 與 ccs_scope_cert,一張合法
 * tc_rcs 傳進來時 kid/效期/status 皆對、只靠 unchecked cast 會被誤判為有效 SC——payload.vct 必須等於
 * CCS_SCOPE_CERT_VCT 且 payload.iss 必須等於實際驗章鑰 kid,不符即 SCOPE_CERT_INVALID)+ 效期
 * (nbf/exp,有界 skew)+ Token Status List(先驗 compact JWS 簽章再解碼查 idx)——任一不過即
 * CODES.SCOPE_CERT_INVALID(v3.1 聚合前核對 ⑤;幕 5 P3 context.subcontractor_listed 判定亦呼叫本函式)。
 */
export async function verifyScopeCert(sdJwt: string, opts: { now?: number } = {}): Promise<VerifyScopeCertResult> {
  const manifest = readManifest();
  if (!manifest) return { ok: false, reasonCode: CODES.SCOPE_CERT_INVALID, error: 'manifest 尚未產生(先跑 make setup)' };

  const verifyResult = await verifyCompactSdJwt(sdJwt, resolvePublicKeyFromManifest(manifest));
  if (!verifyResult.ok || !verifyResult.payload) {
    return { ok: false, reasonCode: CODES.SCOPE_CERT_INVALID, error: verifyResult.error ?? 'ccs_scope_cert 簽章驗證失敗' };
  }
  if (verifyResult.kid !== manifest.cb.aid) {
    return {
      ok: false,
      reasonCode: CODES.SCOPE_CERT_INVALID,
      error: `ccs_scope_cert 簽發者(kid=${verifyResult.kid ?? '(無)'})不是唯一被授權角色 cb(AID=${manifest.cb.aid})`,
    };
  }
  const untypedPayload = verifyResult.payload as unknown as { vct?: string; iss?: string };
  if (untypedPayload.vct !== CCS_SCOPE_CERT_VCT || untypedPayload.iss !== verifyResult.kid) {
    return {
      ok: false,
      reasonCode: CODES.SCOPE_CERT_INVALID,
      error: `型別不符:vct=${untypedPayload.vct ?? '(無)'}(期望 ${CCS_SCOPE_CERT_VCT})或 iss≠實際驗章鑰——不是 ccs_scope_cert(例如 CB 亦簽發之 tc_rcs 被誤傳入)`,
    };
  }
  const payload = verifyResult.payload as unknown as CcsScopeCertPayload;

  const nowMs = opts.now ?? Date.now();
  const nowSec = Math.floor(nowMs / 1000);
  if (typeof payload.nbf === 'number' && nowSec + SCOPE_CERT_CLOCK_SKEW_SEC < payload.nbf) {
    return { ok: false, reasonCode: CODES.SCOPE_CERT_INVALID, error: 'ccs_scope_cert 尚未生效(nbf)' };
  }
  if (typeof payload.exp === 'number' && nowSec - SCOPE_CERT_CLOCK_SKEW_SEC > payload.exp) {
    return { ok: false, reasonCode: CODES.SCOPE_CERT_INVALID, error: 'ccs_scope_cert 已過期(exp)' };
  }

  // Opus 獨立驗證 B:此函式是幕 5 P3 context.subcontractor_listed 的判定函式,一旦 Phase 3a 讓它
  // 當獨立撤銷閘門,原本呼叫 readFreshStatusListToken 的 fail-open(清單檔缺失/損毀時靜默重建
  // 全 0 清單)就會被利用(已撤 SC 蒙混)。改用 ./statusGuard.ts 之
  // safeReadOrRefreshStatusListToken——語意與 pcfAggregate.ts 之 verifyInput 一致:既有清單能
  // 成功解碼且驗章通過才刷新續用(消除 staleness,不誤判合法未撤銷為撤銷);缺檔/損毀一律
  // fail-closed 回 null。
  const statusEntry = (payload as unknown as { status?: { status_list?: { idx?: number; uri?: string } } }).status?.status_list;
  // Status List Token 由 FAB LE 鑰簽署(閘道為 data/status/ 兩份清單的發布方)。
  const issuerKey = resolvePublicKeyFromManifest(manifest)(manifest.fab.aid);
  const credentialsToken = issuerKey ? await safeReadOrRefreshStatusListToken('credentials', issuerKey, nowMs) : null;
  if (statusEntry?.idx == null || statusEntry.uri !== statusListUri('credentials') || !issuerKey || !credentialsToken) {
    return { ok: false, reasonCode: CODES.SCOPE_CERT_INVALID, error: 'ccs_scope_cert status 參照或 credentials 清單缺失/損毀(fail-closed)' };
  }
  const bit = await checkStatusBit(credentialsToken, statusEntry.idx, issuerKey, statusListUri('credentials'), { now: nowMs });
  if (!bit.ok || bit.revoked) {
    return { ok: false, reasonCode: CODES.SCOPE_CERT_INVALID, error: bit.error ?? `ccs_scope_cert idx=${statusEntry.idx} 已撤銷` };
  }

  return { ok: true, payload };
}

/**
 * 染整廠是否列於布廠 SC 之 associated_subcontractors(以 LEI + 製程判定;v3.1 聚合前核對 ⑥、
 * 幕 5 P3 context.subcontractor_listed)。純函式,不驗章/效期/撤銷——呼叫端應先經 verifyScopeCert。
 */
export function isSubcontractorListed(payload: CcsScopeCertPayload, dyeLei: string, process: string): boolean {
  return payload.associated_subcontractors.some((s) => s.lei === dyeLei && s.process === process);
}
