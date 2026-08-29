/**
 * M1/M2 mandate 簽發(幕 3 前置;架構決策 §4:POST /api/mandates)。
 * 格式:compact signed JWT(jose,EdDSA),header { typ:"mandate+jwt", alg:"EdDSA", kid }。
 * 簽署者經 server/keys.ts 之 sandbox ECR 鑰(M1=鴻鋼財務主管、M2=Brand 永續長);
 * delegate_kid 綁定對應 workload 公鑰(M1=fab-workload、M2=brand-workload)。
 *
 * M2 allowed_claims:幕 3 disclose 消費對象是 pcf_aggregate,而規格v2:155-157 列的是
 * pcf_upstream 欄位名,故做欄位映射後採 server/policy/claims.ts 之 M2_ALLOWED_CLAIMS——
 * 映射表與「揭露欄位中只能有一個排放數字」的理由見該常數定義處(H2)。
 *
 * L2 修正(Phase 2 總驗收):效期不再硬寫死 2026-09-30——該日一到,所有 disclose 會變成
 * MANDATE_EXPIRED,demo 直接掛掉。改為「敘事日期與『簽發日 + MANDATE_MIN_REMAINING_DAYS』
 * 取較晚者」:敘事日期還沒接近時畫面上仍是規格的固定日期,接近後自動延展,永不過期。
 */
import crypto from 'node:crypto';
import { SignJWT } from 'jose';
import { loadSandboxKey, loadWorkloadKey, type SandboxRole, type WorkloadName } from '../keys';
import { statusListUri } from '../statuslist';
import { M2_ALLOWED_CLAIMS } from '../policy/claims';
import { PCF_UPSTREAM_PUBLIC_FIELDS, PCF_UPSTREAM_CUSTOMS_SD_FIELDS } from '../../shared/types';
import type { MandateId, MandatePayload } from '../../shared/types';

/** disclose 閘道之受眾(M1/M2 皆以此為 aud;impl-spec §2 request_jws payload 亦引用同一閘道)。 */
export const GATEWAY_AUD = 'fab-gateway';

/**
 * F4(Codex adversarial review)閘道 PERMIT receipt 之常數——閘道(鴻鋼)以 LE 鑰對每次 PERMIT
 * 簽出一份 receipt,綁定 presentation_hash + mandate_jti + request_nonce + audience + issued_at。
 * Brand 端(/api/verify 與 verify-offline)以此 receipt 抓「擷取的 presentation 換 nonce/配對他 mandate
 * 重放」。常數放在無 DB 依賴的 mandate.ts,供閘道(discloseGateway)簽章端與 Brand 驗證端共用同一定義。
 */
export const RECEIPT_TYP = 'gateway-receipt+jwt';
/** receipt 受眾:Brand 驗證方——綁 audience,使發給 Brand 的 receipt 無法挪作他用。 */
export const RECEIPT_AUDIENCE = 'brand-verifier';

/** mandates Token Status List 之固定 idx(獨立於 credentials 清單,見 impl-spec §0):M1=0、M2=1。 */
export const MANDATE_STATUS_IDX: Record<MandateId, number> = { M1: 0, M2: 1 };

/**
 * 每張 mandate 唯一合法的簽發角色(規格v2 §5.1/5.2;M2 修正:閘道以此綁定 mandate 的 iss
 * 與實際驗章鑰)。角色鍵同時是 server/keys.ts 的 SandboxRole 與 manifest 的角色鍵。
 */
export const MANDATE_ISSUER_ROLE: Record<MandateId, SandboxRole> = {
  M1: 'fab_cfo', // 鴻鋼財務主管 ECR
  M2: 'brand_cso', // Brand 永續長 ECR
};

/** L2:mandate 自簽發日起至少保有的效期天數(避免敘事日期過期後 demo 全面 MANDATE_EXPIRED)。 */
const MANDATE_MIN_REMAINING_DAYS = 180;

/** 取「規格敘事日期」與「簽發日 + 最低剩餘天數」之較晚者(YYYY-MM-DD)。 */
function resolveValidUntil(narrativeValidUntil: string, nowMs: number): string {
  const narrativeMs = Date.parse(`${narrativeValidUntil}T00:00:00Z`);
  const floorMs = nowMs + MANDATE_MIN_REMAINING_DAYS * 24 * 60 * 60 * 1000;
  return new Date(Math.max(narrativeMs, floorMs)).toISOString().slice(0, 10);
}

interface MandateDefinition {
  issuerRole: SandboxRole;
  delegateName: WorkloadName;
  allowedClaims: string[];
  policyVersion: string;
  validFrom: string;
  validUntil: string;
  queryCap?: number;
  purpose?: string;
  agentId?: string;
  /** scope_tools / max_amount / policy_thresholds 等 M1 專屬欄位(Phase 5 用),存 mandates.extra_json。 */
  extra?: Record<string, unknown>;
}

const MANDATE_DEFS: Record<MandateId, MandateDefinition> = {
  // M1(規格v2 §5.1;幕 3/4 無直接依賴,主要供幕 5 放行管線消費)。
  M1: {
    issuerRole: MANDATE_ISSUER_ROLE.M1,
    delegateName: 'fab-workload',
    allowedClaims: [...PCF_UPSTREAM_PUBLIC_FIELDS.filter((f) => !f.endsWith('_hash')), ...PCF_UPSTREAM_CUSTOMS_SD_FIELDS],
    policyVersion: 'pol-2026-08-v2',
    validFrom: '2026-08-01',
    validUntil: '2026-09-30',
    agentId: 'agent-stable-001',
    extra: {
      scope_tools: ['verify_vc', 'check_wallet_risk', 'emit_release_credential'],
      max_amount: 50000,
      policy_thresholds: { carbon_max: 2.0, wallet_risk_max: 40, min_sources: 2 },
    },
  },
  // M2(規格v2 §5.2;幕 3/4 主線——Agent-2 出示查驗請求之委任狀)。
  M2: {
    issuerRole: MANDATE_ISSUER_ROLE.M2,
    delegateName: 'brand-workload',
    allowedClaims: [...M2_ALLOWED_CLAIMS],
    policyVersion: 'pol-2026-08-v2',
    validFrom: '2026-08-01',
    validUntil: '2026-09-30',
    queryCap: 10,
    purpose: 'CBAM_quarterly_declaration',
  },
};

export interface MandateIssuance {
  id: MandateId;
  jti: string;
  token: string;
  payload: MandatePayload;
  issuerParty: SandboxRole;
  delegateKid: string;
  allowedClaims: string[];
  maxGranularity: 'batch';
  queryCap?: number;
  policyVersion: string;
  mandateNonce: string;
  purpose?: string;
  agentId?: string;
  extra?: Record<string, unknown>;
  statusIdx: number;
  statusUri: string;
  validFrom: string;
  validUntil: string;
}

/** 簽出 M1 或 M2(sandbox ECR 鑰;delegate_kid 綁定對應 workload 公鑰)。不寫入 DB——由呼叫端負責原子落庫。 */
export async function issueMandate(id: MandateId): Promise<MandateIssuance> {
  const def = MANDATE_DEFS[id];
  const signingKey = loadSandboxKey(def.issuerRole);
  const delegateKey = loadWorkloadKey(def.delegateName);
  const jti = crypto.randomUUID();
  const mandateNonce = crypto.randomBytes(16).toString('base64url');
  const statusIdx = MANDATE_STATUS_IDX[id];
  const statusUri = statusListUri('mandates');

  const nowMs = Date.now();
  const nowSec = Math.floor(nowMs / 1000);
  // L2:效期上界取「規格敘事日期」與「簽發日 + 180 天」較晚者,demo 不會因為過了敘事日期而全面過期。
  const validUntil = resolveValidUntil(def.validUntil, nowMs);
  const validFromSec = Math.floor(new Date(`${def.validFrom}T00:00:00Z`).getTime() / 1000);
  const validUntilSec = Math.floor(new Date(`${validUntil}T00:00:00Z`).getTime() / 1000);

  const payload: MandatePayload = {
    jti,
    iss: signingKey.kid,
    aud: GATEWAY_AUD,
    delegate_kid: delegateKey.kid,
    allowed_claims: def.allowedClaims,
    max_granularity: 'batch',
    policy_version: def.policyVersion,
    mandate_nonce: mandateNonce,
    valid_from: def.validFrom,
    valid_until: validUntil,
    status: { status_list: { idx: statusIdx, uri: statusUri } },
    iat: nowSec,
    nbf: validFromSec,
    exp: validUntilSec,
    query_cap: def.queryCap,
    purpose: def.purpose,
    agent_id: def.agentId,
  };

  const token = await new SignJWT(payload as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg: 'EdDSA', typ: 'mandate+jwt', kid: signingKey.kid })
    .sign(signingKey.privateKey);

  return {
    id,
    jti,
    token,
    payload,
    issuerParty: def.issuerRole,
    delegateKid: delegateKey.kid,
    allowedClaims: def.allowedClaims,
    maxGranularity: 'batch',
    queryCap: def.queryCap,
    policyVersion: def.policyVersion,
    mandateNonce,
    purpose: def.purpose,
    agentId: def.agentId,
    extra: def.extra,
    statusIdx,
    statusUri,
    validFrom: def.validFrom,
    validUntil,
  };
}
