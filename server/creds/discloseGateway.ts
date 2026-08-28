/**
 * 幕 3 委任查驗 + 幕 4 越界攔截 — POST /api/disclose 核心管線(架構決策 §4)。
 *
 * 驗證順序(指揮官裁決,impl-spec §0 衝突#1;CLAUDE.md:15 / 規格v2:145 一致版本):
 *   mandate 簽章 → iss/aud/exp/jti → delegate_kid 對 request 簽章 → Token Status List
 *   → request_nonce → 三個可信布林 context → query_cap → Cedar(逐 claim)→ 挑 disclosures。
 * 每一步失敗都經 server/audit.ts 唯一入口寫入 DENY(或 REPLAY_DETECTED)——連拒絕都留痕。
 *
 * 交易紀律:query_cap 檢查 + 扣次 + presentations 寫入 + audit 同一筆 better-sqlite3 transaction
 * (僅 PERMIT 路徑;presentations 表語意即「出示紀錄」,DENY 路徑無出示,不佔用 nonce)。
 * request_nonce 重放偵測以 presentations 表 UNIQUE(mandate_id, request_nonce) 為最終防線:
 * 先以 SELECT 快速偵測既有重放(符合 impl-spec 步驟順序),INSERT 若仍撞唯一鍵(理論上的併發
 * 賽跑殘餘窗口)→ transaction 整筆回滾,REPLAY audit 以獨立 transaction 補寫。
 *
 * H1 修正(Phase 2 總驗收):額度檢查原本讀「管線開頭載入的 mandateRow.queries_used」,扣次卻在
 * 後面的交易裡,中間隔著 await(presentSelectedDisclosures)——併發時多個請求都讀到同一個舊值,
 * 實測剩餘 2、併發 6 得到 5 個 PERMIT、queries_used 衝到 13(cap 10)。重放有 UNIQUE 兜底,
 * 額度沒有。現改為在交易內(BEGIN IMMEDIATE)重讀當前 queries_used 再比對 cap,超額即在交易內
 * throw 讓整筆回滾 → 429 QUERY_CAP_EXCEEDED。步驟 8 的前置檢查保留(快速失敗、理由碼一致)。
 *
 * M1 修正:request_jws 加新鮮度窗(iat 必須落在 REQUEST_MAX_AGE_SEC 內)——DENY 路徑不佔 nonce,
 * 沒有新鮮度窗時一份被拒的 request_jws 可長期保存,待條件變好(例如聚合完成)再重放取得 PERMIT。
 * 時間基準可由呼叫端注入(DiscloseOptions.now),測試不依賴真實時間流逝。
 */
import { decodeJwt, decodeProtectedHeader, jwtVerify, errors as joseErrors } from 'jose';
import type Database from 'better-sqlite3';
import { readManifest, resolvePublicKeyFromManifest } from '../manifest';
import { resolveWorkloadPublicKeyByKid } from '../keys';
import { checkStatusBit, readStatusListToken } from '../statuslist';
import { getCredential } from './store';
import { presentSelectedDisclosures } from './presenter';
import { recordDecision } from '../audit';
import { getMandateByJti, incrementMandateQueriesUsed, type MandateRow } from './mandateStore';
import { authorizeDiscloseClaim } from '../policy/cedar';
import { tagForClaim, isSelectableDisclosure, GRANULARITY_RANK } from '../policy/claims';
import { GATEWAY_AUD, MANDATE_ISSUER_ROLE } from './mandate';
import { CODES, type ReasonCode } from '../../shared/codes';
import type { DiscloseRequestPayload, MandateId, MandatePayload, PcfAggregateCaseId, TrustedContext } from '../../shared/types';

const ACTION = 'DiscloseClaim';

/** M1:request_jws 新鮮度窗(秒)。iat 過舊 → 視為過期請求;過新(超過容許時鐘偏移)亦拒。 */
export const REQUEST_MAX_AGE_SEC = 300;
/** 允許的時鐘偏移(秒):iat 稍微超前不算攻擊,但不得無限制。 */
const REQUEST_CLOCK_SKEW_SEC = 60;

/** 交易內額度超限(H1):以例外中止交易讓整筆回滾,由呼叫端轉成 429 QUERY_CAP_EXCEEDED。 */
class QueryCapExceededError extends Error {}

export interface DiscloseOptions {
  /** 新鮮度判定的時間基準(epoch 毫秒);預設 Date.now()。測試以此注入固定時間。 */
  now?: number;
}

export interface DiscloseSuccess {
  kind: 'success';
  presentation: string;
  caseId: PcfAggregateCaseId;
  mandateId: string;
  policyId: 'P1';
}

export interface DiscloseFailure {
  kind: 'error';
  httpStatus: number;
  reasonCode: ReasonCode;
  /** 前端顯示用之 decision 標籤(對齊 shared/types.ts DecisionEffect)。 */
  decision: 'DENY' | 'REPLAY_DETECTED';
  policyId?: 'P1' | 'P2';
}

export type DiscloseResult = DiscloseSuccess | DiscloseFailure;

function isUniqueConstraintError(e: unknown): boolean {
  return e instanceof Error && /UNIQUE constraint failed/i.test(e.message);
}

/** 每一步失敗都經 recordDecision 入鏈(DENY 或 REPLAY_DETECTED),回傳給路由的統一結果物件。 */
function denyWithAudit(
  db: Database.Database,
  params: {
    reasonCode: ReasonCode;
    httpStatus: number;
    policyId?: 'P1' | 'P2';
    caseId?: string;
    mandateId?: string;
    context?: unknown;
    effect?: 'DENY' | 'REPLAY_DETECTED';
  },
): DiscloseFailure {
  const effect = params.effect ?? 'DENY';
  recordDecision(db, {
    action: ACTION,
    effect,
    reason_code: params.reasonCode,
    policy_id: params.policyId,
    case_id: params.caseId,
    mandate_id: params.mandateId,
    context: params.context,
  });
  return { kind: 'error', httpStatus: params.httpStatus, reasonCode: params.reasonCode, decision: effect, policyId: params.policyId };
}

/**
 * 驗 mandate JWT 簽章 + iss/aud/exp/jti。
 *
 * M2 修正(C1 同源):簽發者必須是該 mandate 的預期 ECR 角色(M1=鴻鋼財務主管、M2=Bruck 永續長,
 * AID 動態自 manifest 取)。舊版只給 jose {audience},且「header.kid 取鑰」與「payload.iss」從不
 * 互相校驗——manifest 內任何一把鑰(甚至法人 LE 鑰)都能簽出一張被接受的委任狀。此處先把 kid
 * 釘死在預期角色 AID(決定用哪把公鑰驗章),再以 jose issuer 選項要求 payload.iss 等於同一 AID。
 */
async function verifyMandateToken(
  token: string,
  mandateId: string,
): Promise<{ ok: true; payload: MandatePayload } | { ok: false; reasonCode: ReasonCode }> {
  const manifest = readManifest();
  if (!manifest) return { ok: false, reasonCode: CODES.MANDATE_SIG_INVALID };
  const issuerRole = MANDATE_ISSUER_ROLE[mandateId as MandateId];
  const expectedIssuerAid = issuerRole ? manifest[issuerRole]?.aid : undefined;
  if (!expectedIssuerAid) return { ok: false, reasonCode: CODES.MANDATE_SIG_INVALID };
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(token);
  } catch {
    return { ok: false, reasonCode: CODES.MANDATE_SIG_INVALID };
  }
  // 實際驗章鑰必須是預期角色的 ECR 鑰(不接受「拿別把鑰簽、把 iss 寫成 ECR」的組合)。
  if (header.kid !== expectedIssuerAid) return { ok: false, reasonCode: CODES.MANDATE_SIG_INVALID };
  const publicKey = resolvePublicKeyFromManifest(manifest)(expectedIssuerAid);
  if (!publicKey) return { ok: false, reasonCode: CODES.MANDATE_SIG_INVALID };
  try {
    const { payload } = await jwtVerify(token, publicKey, { audience: GATEWAY_AUD, issuer: expectedIssuerAid });
    return { ok: true, payload: payload as unknown as MandatePayload };
  } catch (e) {
    if (e instanceof joseErrors.JWSSignatureVerificationFailed || e instanceof joseErrors.JWSInvalid) {
      return { ok: false, reasonCode: CODES.MANDATE_SIG_INVALID };
    }
    // iss 不符 = 簽發者身分問題(M2 修正),與效期/受眾問題分開歸類。
    if (e instanceof joseErrors.JWTClaimValidationFailed && e.claim === 'iss') {
      return { ok: false, reasonCode: CODES.MANDATE_SIG_INVALID };
    }
    // JWTExpired / JWTClaimValidationFailed(aud/jti 等)歸類為 iss/aud/exp/jti 驗證失敗。
    return { ok: false, reasonCode: CODES.MANDATE_EXPIRED };
  }
}

/** 驗 request_jws 簽章:header.kid 須等於 mandate.delegate_kid,且能解出對應 workload 公鑰。 */
async function verifyDelegateSignature(
  requestJws: string,
  delegateKid: string,
): Promise<{ ok: true; payload: DiscloseRequestPayload } | { ok: false }> {
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(requestJws);
  } catch {
    return { ok: false };
  }
  if (header.kid !== delegateKid) return { ok: false };
  const publicKey = resolveWorkloadPublicKeyByKid(delegateKid);
  if (!publicKey) return { ok: false };
  try {
    const { payload } = await jwtVerify(requestJws, publicKey);
    return { ok: true, payload: payload as unknown as DiscloseRequestPayload };
  } catch {
    return { ok: false };
  }
}

function isValidDiscloseRequestShape(p: unknown): p is DiscloseRequestPayload {
  if (!p || typeof p !== 'object') return false;
  const r = p as Record<string, unknown>;
  return (
    typeof r.mandate_id === 'string' &&
    (r.case_id === 'A' || r.case_id === 'B') &&
    Array.isArray(r.requested_claims) &&
    r.requested_claims.length > 0 &&
    r.requested_claims.every((c) => typeof c === 'string') &&
    typeof r.request_nonce === 'string' &&
    r.request_nonce.length > 0 &&
    // M1:iat 為必填(缺 iat 就沒有新鮮度可言,不得放行)。
    typeof r.iat === 'number' &&
    Number.isFinite(r.iat)
  );
}

/**
 * M1:request_jws 新鮮度窗。iat 早於 now-REQUEST_MAX_AGE_SEC → 過期(被拒後長期保存、
 * 待條件變好再重放的路徑就此關閉);iat 晚於 now+REQUEST_CLOCK_SKEW_SEC → 未來票,同樣拒絕。
 * nowMs 由呼叫端注入,測試不必依賴真實時間流逝、也不引入會在未來某日翻紅的固定日期。
 */
function isFreshRequest(iatSec: number, nowMs: number): boolean {
  const nowSec = Math.floor(nowMs / 1000);
  return iatSec <= nowSec + REQUEST_CLOCK_SKEW_SEC && nowSec - iatSec <= REQUEST_MAX_AGE_SEC;
}

/** 幕 3/4 主管線。輸入為 request_jws 原始字串(尚不信任內容)。 */
export async function processDiscloseRequest(
  db: Database.Database,
  requestJws: unknown,
  options: DiscloseOptions = {},
): Promise<DiscloseResult> {
  const nowMs = options.now ?? Date.now();
  // 步驟 1:結構性解析(不信任內容),取出候選 mandate_id(= mandate jti)以便查表。
  if (typeof requestJws !== 'string' || !requestJws) {
    return denyWithAudit(db, { reasonCode: CODES.DISCLOSE_REQUEST_INVALID, httpStatus: 400 });
  }
  let unsafePayload: Record<string, unknown>;
  try {
    unsafePayload = decodeJwt(requestJws) as Record<string, unknown>;
  } catch {
    return denyWithAudit(db, { reasonCode: CODES.DISCLOSE_REQUEST_INVALID, httpStatus: 400 });
  }
  const candidateMandateJti = unsafePayload.mandate_id;
  if (typeof candidateMandateJti !== 'string' || !candidateMandateJti) {
    return denyWithAudit(db, { reasonCode: CODES.DISCLOSE_REQUEST_INVALID, httpStatus: 400 });
  }

  const mandateRow: MandateRow | undefined = getMandateByJti(db, candidateMandateJti);
  if (!mandateRow || !mandateRow.token) {
    return denyWithAudit(db, { reasonCode: CODES.MANDATE_NOT_FOUND, httpStatus: 404 });
  }

  // 步驟 2+3:mandate JWT 簽章 + iss(綁預期 ECR 角色)/aud/exp/jti。
  const mandateVerify = await verifyMandateToken(mandateRow.token, mandateRow.id);
  if (!mandateVerify.ok) {
    return denyWithAudit(db, { reasonCode: mandateVerify.reasonCode, httpStatus: 403, mandateId: mandateRow.id });
  }
  const mandatePayload = mandateVerify.payload;

  // 步驟 4:delegate_kid 對 request 簽章。
  const delegateVerify = await verifyDelegateSignature(requestJws, mandatePayload.delegate_kid);
  if (!delegateVerify.ok) {
    return denyWithAudit(db, { reasonCode: CODES.DELEGATE_KEY_MISMATCH, httpStatus: 403, mandateId: mandateRow.id });
  }
  const requestPayload = delegateVerify.payload;
  if (!isValidDiscloseRequestShape(requestPayload)) {
    return denyWithAudit(db, { reasonCode: CODES.DISCLOSE_REQUEST_INVALID, httpStatus: 400, mandateId: mandateRow.id });
  }

  // 步驟 4b(M1):新鮮度窗——過期或未來票的 request_jws 一律拒,理由碼 DISCLOSE_REQUEST_INVALID。
  if (!isFreshRequest(requestPayload.iat, nowMs)) {
    return denyWithAudit(db, {
      reasonCode: CODES.DISCLOSE_REQUEST_INVALID,
      httpStatus: 400,
      mandateId: mandateRow.id,
      caseId: requestPayload.case_id,
      context: { iat: requestPayload.iat, max_age_sec: REQUEST_MAX_AGE_SEC },
    });
  }

  // 步驟 5:Token Status List(mandates 清單)。
  const manifest = readManifest();
  const statusIssuerKey = manifest ? resolvePublicKeyFromManifest(manifest)(manifest.hunggang.aid) : undefined;
  const mandateStatusListToken = readStatusListToken('mandates');
  if (!manifest || !statusIssuerKey || !mandateStatusListToken) {
    return denyWithAudit(db, {
      reasonCode: CODES.MANDATE_REVOKED,
      httpStatus: 403,
      mandateId: mandateRow.id,
      caseId: requestPayload.case_id,
    });
  }
  const statusResult = await checkStatusBit(mandateStatusListToken, mandatePayload.status.status_list.idx, statusIssuerKey);
  if (!statusResult.ok || statusResult.revoked) {
    return denyWithAudit(db, {
      reasonCode: CODES.MANDATE_REVOKED,
      httpStatus: 403,
      mandateId: mandateRow.id,
      caseId: requestPayload.case_id,
      context: { error: statusResult.error },
    });
  }

  // 步驟 6:request_nonce 重放偵測(presentations 表僅在 PERMIT 時寫入,見檔頭註解)。
  const existingPresentation = db
    .prepare('SELECT id FROM presentations WHERE mandate_id = ? AND request_nonce = ?')
    .get(mandateRow.id, requestPayload.request_nonce);
  if (existingPresentation) {
    return denyWithAudit(db, {
      reasonCode: CODES.REPLAY_DETECTED,
      httpStatus: 409,
      effect: 'REPLAY_DETECTED',
      mandateId: mandateRow.id,
      caseId: requestPayload.case_id,
      context: { request_nonce: requestPayload.request_nonce },
    });
  }

  // 步驟 7:三個可信布林(至此皆已通過,故一律 true)。
  const trustedContext: TrustedContext = { mandate_status_ok: true, delegate_key_ok: true, replay_ok: true };

  // 步驟 8:query_cap 前置檢查(快速失敗)。真正的把關在下方交易內重讀 queries_used(H1)——
  // 此處讀的是管線開頭的快照,併發時可能已過時,不得作為唯一防線。
  if (mandatePayload.query_cap != null && mandateRow.queries_used >= mandatePayload.query_cap) {
    return denyWithAudit(db, {
      reasonCode: CODES.QUERY_CAP_EXCEEDED,
      httpStatus: 429,
      mandateId: mandateRow.id,
      caseId: requestPayload.case_id,
    });
  }

  // 步驟 9:Cedar 逐 claim 授權。
  // L1:mandate 的上限改讀 mandate.max_granularity(不再硬填 batch);Phase 2 只有 batch 一級,
  // 故兩邊仍為 0,但未來新增 machine-level 時政策比較是有意義的,不是恆真式。
  const mandateAllowedClaims = mandatePayload.allowed_claims;
  const mandateMaxGranularityRank = GRANULARITY_RANK[mandatePayload.max_granularity] ?? GRANULARITY_RANK.batch;
  for (const claim of requestPayload.requested_claims) {
    const result = authorizeDiscloseClaim({
      claim,
      tag: tagForClaim(claim),
      // 本階段可揭露的資料粒度只有 batch(machine-level 不存在於任何已簽發憑證)。
      granularityRank: GRANULARITY_RANK.batch,
      mandateAllowedClaims,
      mandateMaxGranularityRank,
      trustedContext,
    });
    if (!result.allow) {
      const isP2 = result.matchedPolicies.includes('P2');
      return denyWithAudit(db, {
        reasonCode: isP2 ? CODES.POLICY_P2_CONFIDENTIAL : CODES.CLAIM_NOT_IN_MANDATE,
        httpStatus: 403,
        policyId: isP2 ? 'P2' : undefined,
        mandateId: mandateRow.id,
        caseId: requestPayload.case_id,
        context: { claim, matchedPolicies: result.matchedPolicies },
      });
    }
  }

  // 步驟 10:全 PERMIT → 挑 disclosures。
  const aggRow = getCredential(db, `pcf_aggregate-${requestPayload.case_id}`);
  if (!aggRow) {
    return denyWithAudit(db, {
      reasonCode: CODES.PCF_AGGREGATE_NOT_ISSUED,
      httpStatus: 400,
      mandateId: mandateRow.id,
      caseId: requestPayload.case_id,
    });
  }
  const presentationFrame: Record<string, boolean> = {};
  for (const claim of requestPayload.requested_claims) {
    if (isSelectableDisclosure(claim)) presentationFrame[claim] = true;
  }
  const presentation = await presentSelectedDisclosures(aggRow.sd_jwt, presentationFrame as never);

  // 交易:query_cap 重讀比對(H1)+ recordDecision(PERMIT) + presentations 寫入(以 UNIQUE 作最終
  // 防重放防線) + query_cap 扣次。以 BEGIN IMMEDIATE 執行:交易一開始就取得寫鎖,額度的
  // 「讀-比對-扣」在同一把鎖內完成,跨連線併發也無法各自讀到同一個舊值再各自扣。
  try {
    const tx = db.transaction(() => {
      if (mandatePayload.query_cap != null) {
        const current = db.prepare('SELECT queries_used FROM mandates WHERE id = ?').get(mandateRow.id) as
          | { queries_used: number }
          | undefined;
        if (!current || current.queries_used >= mandatePayload.query_cap) throw new QueryCapExceededError();
      }
      const { decisionId } = recordDecision(db, {
        action: ACTION,
        effect: 'PERMIT',
        reason_code: CODES.POLICY_P1_PERMIT,
        policy_id: 'P1',
        case_id: requestPayload.case_id,
        mandate_id: mandateRow.id,
        context: trustedContext,
      });
      db.prepare(
        'INSERT INTO presentations (mandate_id, request_nonce, requested_claims, presentation, decision_id) VALUES (?, ?, ?, ?, ?)',
      ).run(mandateRow.id, requestPayload.request_nonce, JSON.stringify(requestPayload.requested_claims), presentation, decisionId);
      incrementMandateQueriesUsed(db, mandateRow.id);
    });
    tx.immediate();
  } catch (e) {
    if (e instanceof QueryCapExceededError) {
      // H1:交易已整筆回滾(未寫 presentation、未扣次),額度用罄一律 429。
      return denyWithAudit(db, {
        reasonCode: CODES.QUERY_CAP_EXCEEDED,
        httpStatus: 429,
        mandateId: mandateRow.id,
        caseId: requestPayload.case_id,
      });
    }
    if (isUniqueConstraintError(e)) {
      // 併發賽跑殘餘窗口:UNIQUE 撞鍵 → 整筆交易已回滾,REPLAY audit 以獨立交易補寫。
      return denyWithAudit(db, {
        reasonCode: CODES.REPLAY_DETECTED,
        httpStatus: 409,
        effect: 'REPLAY_DETECTED',
        mandateId: mandateRow.id,
        caseId: requestPayload.case_id,
        context: { request_nonce: requestPayload.request_nonce },
      });
    }
    throw e;
  }

  return { kind: 'success', presentation, caseId: requestPayload.case_id, mandateId: mandateRow.id, policyId: 'P1' };
}
