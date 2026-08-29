/**
 * Brand 端驗證核心(幕 3 DoD)——POST /api/verify 與 scripts/verify-offline.ts 共用同一函式,
 * 避免雙寫(impl-spec §3)。
 *
 * 鐵則(CLAUDE.md:25):只讀 token、manifest 公鑰、data/vlei/、data/status/;不得呼叫閘道 API、
 * 不得讀他方 DB 資料——本檔不 import server/db.ts 的 openDb()/openDbIfExists(),不碰
 * db/demo.sqlite。
 *
 * H3 修正(Phase 2 總驗收):vLEI 鏈查驗仍以 sandbox verify(child_process)執行真實查驗,
 * 但 --dir 改指 data/vlei/public-state/(server/keys.ts 匯出之公開子集,不含任何私鑰種子),
 * 不再指向 repo 根而讀到 `.vlei/state.json`。先前雖然驗證本身只消費公開材料(沒用到 seed),
 * 讀取範圍仍逾越 CLAUDE.md:25、也與前端「只讀 token/manifest/data/vlei/data/status」的文案
 * 不符;現在該文案為真。查驗強度不變(SAID 重算 + 簽章 + TEL 撤銷 + 邊 I2I 全部照跑)。
 *
 * 檢查項(impl-spec §3,每項獨立布林 + 失敗理由碼):
 *   1. SD-JWT 簽章 + 揭露完整性(verifyCompactSdJwt)。
 *   2. vct ↔ 簽發者 AID 綁定(遺留 a + C1):pcf_aggregate 只認鴻鋼 LE AID、pcf_upstream 只認
 *      Thép Việt LE AID——AID 動態自 manifest 取,不硬編;**以實際驗章鑰(header.kid)為準**,
 *      並要求 payload.iss 與實際簽章者一致;不符 → VCT_ISSUER_UNAUTHORIZED。
 *   3. vLEI 鏈(sandbox verify child_process;查的是**實際簽章者**對應的角色 SAID)。
 *   4. Status List(credentials 清單;先驗 JWS 簽章再解碼查 idx)。
 *   5. 雙向約束(幕 3 DoD):presentation 揭露的 claims ⊆ M2 mandate_jwt.allowed_claims,
 *      違者 → CLAIM_NOT_IN_MANDATE。
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { jwtVerify, decodeProtectedHeader } from 'jose';
import { ROOT, VLEI_PUBLIC_STATE_DIR } from '../db';
import { verifyCompactSdJwt } from './verifier';
import { resolvePublicKeyFromManifest } from '../manifest';
import { checkStatusBit, readStatusListToken, statusListUri } from '../statuslist';
import { PCF_AGGREGATE_VCT } from './pcfAggregate';
import { PCF_UPSTREAM_VCT } from './tcCarbonUpstream';
import { GATEWAY_AUD, RECEIPT_TYP, RECEIPT_AUDIENCE } from './mandate';
import { CODES, type ReasonCode } from '../../shared/codes';
import type { Manifest, MandatePayload } from '../../shared/types';

/** vct → 唯一被授權簽發該 vct 的角色(manifest 鍵)——遺留(a)之綁定表,動態查 AID,不硬編字面值。 */
const VCT_ISSUER_ROLE: Record<string, string> = {
  [PCF_AGGREGATE_VCT]: 'fab',
  [PCF_UPSTREAM_VCT]: 'yarn',
};

/** M2 mandate 之唯一合法簽發角色(Brand 永續長 ECR;M2 修正:mandate iss 必須綁預期角色)。 */
const M2_ISSUER_ROLE = 'brand_cso';

/**
 * F8(Codex adversarial review):協定保留 claim——非應用層 claim,不與 mandate.allowed_claims 比對。
 * 雙向約束改為「從實際提交的 disclosures 推導 claim 名,逐一比對 allowed_claims」,只排除這些保留名;
 * 舊版只看硬編的 PCF_AGGREGATE_SD_FIELDS,授權簽發者若新增並揭露一個新 claim 就會 fail-open。
 */
const RESERVED_CLAIM_NAMES = new Set(['vct', 'iss', 'iat', 'nbf', 'exp', 'status', 'sub', 'aud', 'jti', '_sd', '_sd_alg', 'cnf']);

/** F4:閘道 receipt 新鮮度窗與有界時鐘偏移(秒)。 */
const RECEIPT_MAX_AGE_SEC = 3600;
const RECEIPT_CLOCK_SKEW_SEC = 60;

/** F7:vLEI 鏈查驗子行程逾時上限(毫秒)——逾時即終止子行程、回明確失敗,不無限阻塞 event loop。 */
export const VLEI_VERIFY_TIMEOUT_MS = 10_000;

/** manifest 反查:AID → 角色鍵(C1:由**實際驗章鑰**決定角色,而非由 payload 宣稱值決定)。 */
function roleOfAid(manifest: Manifest, aid: string): string | undefined {
  return Object.entries(manifest).find(([, r]) => r.aid === aid)?.[0];
}

export interface VerifyCheck {
  name: string;
  ok: boolean;
  reasonCode?: ReasonCode;
  detail?: string;
}

export interface VerifyPresentationResult {
  ok: boolean;
  checks: VerifyCheck[];
  payload?: Record<string, unknown>;
}

export interface VerifyPresentationInput {
  presentationSdJwt: string;
  mandateJwt: string;
  manifest: Manifest;
  /** F4:閘道對本次 PERMIT 簽出之 receipt(隨 presentation 回傳);缺此則 key-binding 檢查失敗。 */
  receipt?: string;
  /** 新鮮度/撤銷查驗之時間基準(epoch 毫秒);預設 Date.now()。測試以此注入固定時間,不寫死日期。 */
  now?: number;
}

/**
 * vLEI 鏈查驗(真實 sandbox verify:SAID 重算 + 簽章 + LEI 檢核碼 + TEL 撤銷狀態 + 邊 I2I)。
 * H3:--dir 指向公開狀態目錄(不含私鑰種子);該目錄由 scripts/seed.ts(make setup /
 * make demo-reset)經 server/keys.ts 產生,缺檔時明確回報,不靜默當成「鏈壞掉」。
 */
export function verifyVleiChainSandbox(credentialSaid: string, opts: { timeoutMs?: number } = {}): { ok: boolean; detail?: string } {
  const publicState = path.join(VLEI_PUBLIC_STATE_DIR, '.vlei', 'state.json');
  if (!fs.existsSync(publicState)) {
    return { ok: false, detail: `vLEI 公開狀態不存在(${path.relative(ROOT, publicState)})——先跑 make demo-reset(scripts/seed.ts)` };
  }
  const py = path.join(ROOT, '.venv', 'bin', 'python');
  const sb = path.join(ROOT, 'vendor', 'vlei-sandbox', 'scripts', 'vlei_sandbox.py');
  const timeoutMs = opts.timeoutMs ?? VLEI_VERIFY_TIMEOUT_MS;
  // F7:spawnSync 帶嚴格 timeout + SIGKILL + 有界 maxBuffer——掛住的 child 會被終止,不會卡死所有 route。
  const r = spawnSync(py, [sb, '--dir', VLEI_PUBLIC_STATE_DIR, 'verify', '--said', credentialSaid], {
    encoding: 'utf-8',
    timeout: timeoutMs,
    killSignal: 'SIGKILL',
    maxBuffer: 1024 * 1024,
  });
  if (r.error) {
    const timedOut = (r.error as NodeJS.ErrnoException).code === 'ETIMEDOUT' || r.signal === 'SIGKILL' || r.signal === 'SIGTERM';
    return { ok: false, detail: timedOut ? `vLEI 查驗逾時(>${timeoutMs}ms),已終止子行程` : `vLEI 子行程啟動失敗:${r.error.message}`.slice(0, 300) };
  }
  const ok = r.status === 0 && (r.stdout ?? '').includes('chain verified');
  return { ok, detail: ok ? undefined : (r.stderr || r.stdout || `exit=${r.status}`).slice(0, 300) };
}

/**
 * 驗 M2 mandate_jwt 簽章(供第 5 項雙向約束比對 allowed_claims;僅供本地比對用,不重跑完整閘道管線)。
 * M2 修正(C1 同源):簽章鑰必須是 Brand 永續長 ECR AID(manifest 動態取),且 payload.iss 必須
 * 等於該 AID——header.kid 取鑰卻不校驗 iss,等於讓任何 manifest 內的鑰都能簽出「M2 委任狀」。
 */
async function verifyMandateForComparison(
  mandateJwt: string,
  manifest: Manifest,
): Promise<{ ok: boolean; payload?: MandatePayload; error?: string }> {
  const expectedIssuerAid = manifest[M2_ISSUER_ROLE]?.aid;
  if (!expectedIssuerAid) return { ok: false, error: `manifest 缺少 ${M2_ISSUER_ROLE} 角色,無法確認 M2 mandate 簽發者` };
  try {
    const header = decodeProtectedHeader(mandateJwt);
    // F5:typ 必須為 "mandate+jwt"(不驗 typ 等於接受任何 Brand-CSO 鑰簽出的 JWT 冒充委任狀)。
    if (header.typ !== 'mandate+jwt') {
      return { ok: false, error: `M2 mandate header.typ 不是 "mandate+jwt"(typ=${header.typ ?? '(無)'})` };
    }
    if (header.kid !== expectedIssuerAid) {
      return { ok: false, error: `M2 mandate 簽章鑰(kid=${header.kid ?? '(無)'})非 Brand 永續長 ECR AID(${expectedIssuerAid})` };
    }
    const key = resolvePublicKeyFromManifest(manifest)(expectedIssuerAid);
    if (!key) return { ok: false, error: `找不到 mandate 簽發者公鑰(kid=${expectedIssuerAid})` };
    // F5:issuer(payload.iss=實際驗章鑰對應 AID)+ audience(必須是本閘道)一併驗;jose 亦自動驗 exp/nbf。
    const { payload } = await jwtVerify(mandateJwt, key, { issuer: expectedIssuerAid, audience: GATEWAY_AUD });
    const mp = payload as unknown as MandatePayload;
    // F5:必要 M2 claims 與語意(缺 allowed_claims/delegate_kid/jti 或 allowed_claims 非陣列 → 拒)。
    if (!Array.isArray(mp.allowed_claims) || typeof mp.delegate_kid !== 'string' || typeof mp.jti !== 'string' || !mp.jti) {
      return { ok: false, error: 'M2 mandate 缺必要 claims(allowed_claims 陣列 / delegate_kid / jti)' };
    }
    return { ok: true, payload: mp };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/**
 * F4:驗證閘道 receipt(present() 為無 key-binding 的裸 bearer,單靠 presentation 無法防重放/配對他 mandate)。
 * 綁定:receipt 簽章(鴻鋼閘道 LE 鑰)+ typ/iss/aud + presentation_hash == sha256(本 presentation)
 * + mandate_jti == 本次驗證所用 mandate 之 jti + request_nonce 存在 + iat 新鮮度。任一不符 → 拒。
 */
async function verifyGatewayReceipt(
  receipt: string | undefined,
  ctx: { presentationSdJwt: string; mandateJti: string; manifest: Manifest; nowMs: number },
): Promise<{ ok: boolean; error?: string }> {
  if (!receipt) return { ok: false, error: '缺少閘道 receipt(無 key-binding 的裸 presentation 不予採信;重放/擷取無法憑此通過)' };
  const gatewayAid = ctx.manifest.fab?.aid;
  if (!gatewayAid) return { ok: false, error: 'manifest 缺 fab 閘道角色' };
  const key = resolvePublicKeyFromManifest(ctx.manifest)(gatewayAid);
  if (!key) return { ok: false, error: '找不到閘道公鑰' };
  let payload: Record<string, unknown>;
  try {
    const header = decodeProtectedHeader(receipt);
    if (header.typ !== RECEIPT_TYP) return { ok: false, error: `receipt typ 不符(${header.typ ?? '(無)'})` };
    if (header.kid !== gatewayAid) return { ok: false, error: `receipt kid(${header.kid ?? '(無)'})非閘道 AID` };
    const v = await jwtVerify(receipt, key, { issuer: gatewayAid, audience: RECEIPT_AUDIENCE });
    payload = v.payload as Record<string, unknown>;
  } catch (e) {
    return { ok: false, error: `receipt 簽章/宣告驗證失敗:${e instanceof Error ? e.message : String(e)}` };
  }
  const expectedHash = crypto.createHash('sha256').update(ctx.presentationSdJwt).digest('hex');
  if (payload.presentation_hash !== expectedHash) {
    return { ok: false, error: 'receipt.presentation_hash 與此 presentation 不符(presentation 與 receipt 不成對——擷取/替換)' };
  }
  if (payload.mandate_jti !== ctx.mandateJti) {
    return { ok: false, error: `receipt.mandate_jti(${String(payload.mandate_jti)})≠ 本次驗證 mandate 之 jti(${ctx.mandateJti})——配對他 mandate 重放` };
  }
  if (typeof payload.request_nonce !== 'string' || !payload.request_nonce) return { ok: false, error: 'receipt 缺 request_nonce' };
  const nowSec = Math.floor(ctx.nowMs / 1000);
  const iat = typeof payload.iat === 'number' ? payload.iat : undefined;
  if (iat == null) return { ok: false, error: 'receipt 缺 iat' };
  if (iat - nowSec > RECEIPT_CLOCK_SKEW_SEC) return { ok: false, error: 'receipt iat 在未來' };
  if (nowSec - iat > RECEIPT_MAX_AGE_SEC) return { ok: false, error: `receipt 已逾新鮮度窗(iat 距今 ${nowSec - iat}s)` };
  return { ok: true };
}

/** Brand 端驗證主流程——依序執行 5 項檢查,任一失敗即回傳(已完成之檢查全數附在 checks 內)。 */
export async function verifyPresentation(input: VerifyPresentationInput): Promise<VerifyPresentationResult> {
  const checks: VerifyCheck[] = [];
  const nowMs = input.now ?? Date.now();

  // 1) SD-JWT 簽章 + 揭露完整性。
  const sigResult = await verifyCompactSdJwt(input.presentationSdJwt, resolvePublicKeyFromManifest(input.manifest));
  checks.push({
    name: 'SD-JWT 簽章與揭露完整性',
    ok: sigResult.ok,
    reasonCode: sigResult.reasonCode,
    detail: sigResult.error,
  });
  if (!sigResult.ok || !sigResult.payload) return { ok: false, checks };
  const payload = sigResult.payload as unknown as Record<string, unknown>;

  // 2) vct ↔ 簽發者 AID 綁定(遺留 a + C1)。
  //    C1:綁定的對象是「實際驗過章的鑰」(sigResult.kid),不是 payload 宣稱的 iss。
  //    舊版只比對 payload.iss,而取鑰走 header.kid,兩者從不互相校驗——攻擊者用自己的鑰簽章、
  //    把 iss 填成鴻鋼 AID 即可通過全部檢查(PoC 已證實可偽造 carbon_total)。此處三個條件同時要求:
  //      (i) 實際簽章者 = 該 vct 唯一被授權的角色 AID;(ii) payload.iss = 實際簽章者(不得脫鉤)。
  const vct = typeof payload.vct === 'string' ? payload.vct : undefined;
  const expectedRole = vct ? VCT_ISSUER_ROLE[vct] : undefined;
  const expectedAid = expectedRole ? input.manifest[expectedRole]?.aid : undefined;
  const signerAid = sigResult.kid; // 實際解出公鑰、且驗章通過的那把鑰
  const claimedIss = typeof payload.iss === 'string' ? payload.iss : undefined;
  const signerRole = signerAid ? roleOfAid(input.manifest, signerAid) : undefined;
  const vctOk = !!expectedRole && !!expectedAid && !!signerAid && signerAid === expectedAid && claimedIss === signerAid;
  checks.push({
    name: 'vct↔簽發者 AID 綁定(以實際驗章鑰為準)',
    ok: vctOk,
    reasonCode: vctOk ? undefined : CODES.VCT_ISSUER_UNAUTHORIZED,
    detail: vctOk
      ? undefined
      : `vct=${vct ?? '(無)'} 實際簽章者=${signerAid ?? '(無)'}(角色=${signerRole ?? '未登錄'}) ` +
        `宣稱 iss=${claimedIss ?? '(無)'} 預期角色=${expectedRole ?? '未知 vct'} 預期AID=${expectedAid ?? '(無)'}`,
  });
  if (!vctOk) return { ok: false, checks, payload };

  // 3) vLEI 鏈(sandbox verify)——查的是**實際簽章者**對應角色的憑證 SAID(C1:不得用 payload 宣稱值,
  //    否則等於拿被冒充方的憑證去驗攻擊者的簽章)。經上面的檢查,signerRole === expectedRole。
  const credentialSaid = input.manifest[signerRole!].credential_said;
  const chainResult = verifyVleiChainSandbox(credentialSaid);
  checks.push({
    name: 'vLEI 鏈(sandbox TEL)',
    ok: chainResult.ok,
    reasonCode: chainResult.ok ? undefined : CODES.VLEI_CHAIN_BROKEN,
    detail: chainResult.detail,
  });
  if (!chainResult.ok) return { ok: false, checks, payload };

  // 4) Status List(credentials 清單;F6:傳入預期清單 URI + now,並要求 credential 的 status 參照 URI
  //    與被查清單一致——同鑰簽的 mandates token 不得冒充 credentials token,陳舊 token 亦拒)。
  const statusEntry = (payload.status as { status_list?: { idx?: number; uri?: string } } | undefined)?.status_list;
  const statusIssuerKey = resolvePublicKeyFromManifest(input.manifest)(input.manifest.fab.aid);
  const credentialsListToken = readStatusListToken('credentials');
  let statusOk = false;
  let statusDetail: string | undefined;
  if (statusEntry?.idx == null || statusEntry.uri !== statusListUri('credentials') || !statusIssuerKey || !credentialsListToken) {
    statusDetail = 'status.status_list.idx 缺失、uri 非 credentials 清單,或 Status List Token 尚未產生';
  } else {
    const result = await checkStatusBit(credentialsListToken, statusEntry.idx, statusIssuerKey, statusListUri('credentials'), { now: nowMs });
    statusOk = result.ok && !result.revoked;
    statusDetail = result.error ?? (result.revoked ? `idx=${statusEntry.idx} 已撤銷` : undefined);
  }
  checks.push({
    name: '撤銷狀態(Status List)',
    ok: statusOk,
    reasonCode: statusOk ? undefined : CODES.CREDENTIAL_REVOKED,
    detail: statusDetail,
  });
  if (!statusOk) return { ok: false, checks, payload };

  // 5) M2 mandate 完整性(F5:簽章 + iss 綁預期角色 + typ + aud + 必要 claims;jose 亦驗 exp/nbf)。
  const mandateResult = await verifyMandateForComparison(input.mandateJwt, input.manifest);
  if (!mandateResult.ok || !mandateResult.payload) {
    checks.push({ name: 'M2 mandate 完整性(簽章/typ/aud/必要 claims)', ok: false, reasonCode: CODES.MANDATE_SIG_INVALID, detail: mandateResult.error });
    return { ok: false, checks, payload };
  }
  checks.push({ name: 'M2 mandate 完整性(簽章/typ/aud/必要 claims)', ok: true });

  // 6) F5:mandate 撤銷狀態(mandates Token Status List;被撤 mandate 不得再授權任何揭露)。
  const mStatus = mandateResult.payload.status?.status_list;
  const mandatesListToken = readStatusListToken('mandates');
  const mandateStatusIssuerKey = resolvePublicKeyFromManifest(input.manifest)(input.manifest.fab.aid);
  let mandateStatusOk = false;
  let mandateStatusDetail: string | undefined;
  if (mStatus?.idx == null || mStatus.uri !== statusListUri('mandates') || !mandateStatusIssuerKey || !mandatesListToken) {
    mandateStatusDetail = 'mandate status.status_list.idx 缺失、uri 非 mandates 清單,或清單尚未產生';
  } else {
    const r = await checkStatusBit(mandatesListToken, mStatus.idx, mandateStatusIssuerKey, statusListUri('mandates'), { now: nowMs });
    mandateStatusOk = r.ok && !r.revoked;
    mandateStatusDetail = r.error ?? (r.revoked ? `mandate idx=${mStatus.idx} 已撤銷` : undefined);
  }
  checks.push({
    name: 'mandate 撤銷狀態(mandates Status List)',
    ok: mandateStatusOk,
    reasonCode: mandateStatusOk ? undefined : CODES.MANDATE_REVOKED,
    detail: mandateStatusDetail,
  });
  if (!mandateStatusOk) return { ok: false, checks, payload };

  // 7) F8:雙向約束——從實際提交之 disclosures 推導 claim 名(payload 內非協定保留 key),逐一比對
  //    mandate.allowed_claims。舊版只看硬編 PCF_AGGREGATE_SD_FIELDS,授權簽發者新增揭露之新 claim 會 fail-open。
  const allowedClaims = mandateResult.payload.allowed_claims;
  const disclosedAppClaims = Object.keys(payload).filter((k) => !RESERVED_CLAIM_NAMES.has(k));
  const overreach = disclosedAppClaims.filter((f) => !allowedClaims.includes(f));
  const boundaryOk = overreach.length === 0;
  checks.push({
    name: '雙向約束:揭露 claims ⊆ mandate.allowed_claims',
    ok: boundaryOk,
    reasonCode: boundaryOk ? undefined : CODES.CLAIM_NOT_IN_MANDATE,
    detail: boundaryOk ? undefined : `逾越 mandate 範圍之揭露欄位:${overreach.join(', ')}`,
  });
  if (!boundaryOk) return { ok: false, checks, payload };

  // 8) F4:閘道 receipt key-binding(最後一項,前 7 項失敗會先返回,不影響既有失敗語意)。
  const receiptResult = await verifyGatewayReceipt(input.receipt, {
    presentationSdJwt: input.presentationSdJwt,
    mandateJti: mandateResult.payload.jti,
    manifest: input.manifest,
    nowMs,
  });
  checks.push({
    name: '閘道 receipt 綁定(key-binding:presentation_hash/mandate_jti/request_nonce/aud/iat)',
    ok: receiptResult.ok,
    reasonCode: receiptResult.ok ? undefined : CODES.RECEIPT_INVALID,
    detail: receiptResult.error,
  });
  if (!receiptResult.ok) return { ok: false, checks, payload };

  return { ok: true, checks, payload };
}
