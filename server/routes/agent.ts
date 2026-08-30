/**
 * 幕 5 門檻與付款閘道(架構決策 §4;phase-briefs/phase-3a.md):POST /api/agent/run?case=A|B|C|Cp。
 *
 * 跑在 FAB 布廠的 Agent-1(fab-workload 鑰,藍圖幕 5 節)——M1(財務主管 ECR 鑰簽)委任 Agent-1
 * 「付染整費前檢查」;驗序照 discloseGateway.ts 之 M2 結構(CLAUDE.md 明列):
 *   mandate 簽章(財務主管 ECR)→ iss/aud/exp/jti → delegate_kid 對 request(fab-workload)簽章
 *   → Token Status List(mandates)→ request_nonce → 三個可信布林 → P3 五要件 → Cedar 二次確認。
 * 因 Agent-1 與本閘道同屬 FAB 信任邊界(不像 Agent-2 是外部品牌方跨網路呼叫),本檔於同一次
 * 請求內自行以 fab-workload 鑰組出並簽署「request」再驗證——機制與 M2 完全相同(真實 Ed25519
 * 簽章 + 驗章,非模擬),demonstrably 對齊 delegate_kid 綁定執行者之設計;request_nonce 由呼叫端
 * (前端/測試)提供,使重放偵測可控。
 *
 * P3 五要件(每項獨立布林 + 理由碼;fail-fast——前項不過,後項標記為未評估 ok:null,供前端
 * 逐列渲染「綠/紅/灰」):
 *   ① identity_ok      — DYE vLEI 鏈(sandbox verify)+ pcf_dyeing-<underlying case> 簽章/效期/Status List
 *   ② subcontractor_listed — verifyScopeCert(ccs_scope_cert)通過 ∧ pcf_dyeing.ccs_scope_ref 一致
 *                             ∧ DYE LEI ∈ associated_subcontractors
 *   ③ carbon_total_g ≤ carbon_max_g — pcf_aggregate.pcf_total × 1000(整數 gCO2e/kg)
 *   ④ invoice_ok       — invoice 驗章(DYE 公鑰)+ amount ≤ max_amount + payee ∈ allowed_counterparties
 *   ⑤ wallet_risk      — risk_signals 雙來源:兩者皆 > wallet_risk_max → MULTI_SOURCE_CONFIRMED(擋);
 *                         僅一來源 → SINGLE_SOURCE_ONLY(只記錄,不升級,不擋)
 * 全過 → 建 Dossier(fab-workload 鑰簽 JWS;PENDING_HUMAN)。任一擋下 → recordDecision(DENY)入鏈。
 * 每一步(含 M1 驗證失敗、重放)皆經 server/audit.ts 之 recordDecision 寫入 decisions + audit_chain
 * 同一交易——CLAUDE.md 鐵律:所有 PERMIT/DENY/RELEASE/REPLAY_DETECTED 皆須如此。
 *
 * 案 C/Cp 之染整/聚合輸入與案 A 相同(spec v3.1 §7:C/C′ 碳排同 A,差異只在收款帳戶)——
 * 本檔以 underlyingCase() 映射到實際簽發的 pcf_dyeing-A/pcf_aggregate-A,invoice 則按完整案件
 * 鍵(A/B/C/Cp)各自簽發(payee_wallet 依 seed.cases[case] 而異)。
 */
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import type { FastifyInstance } from 'fastify';
import { SignJWT, jwtVerify, decodeProtectedHeader, errors as joseErrors } from 'jose';
import type Database from 'better-sqlite3';
import { ROOT, openDb } from '../db';
import { readManifest, resolvePublicKeyFromManifest } from '../manifest';
import { loadWorkloadKey, resolveWorkloadPublicKeyByKid } from '../keys';
import { verifyCompactSdJwt } from '../creds/verifier';
import { verifyVleiChainSandbox } from '../creds/verifyPresentation';
import { checkStatusBit, statusListUri } from '../statuslist';
import { safeReadOrRefreshStatusListToken } from '../creds/statusGuard';
import { getCredential, type CredentialRow } from '../creds/store';
import { getMandate, insertMandateIfAbsent, type MandateRow } from '../creds/mandateStore';
import { issueMandate, GATEWAY_AUD } from '../creds/mandate';
import { issuePcfAggregate, PCF_AGGREGATE_VCT } from '../creds/pcfAggregate';
import { PCF_DYEING_VCT } from '../creds/pcfDyeing';
import { ensureCcsScopeCert, verifyScopeCert, isSubcontractorListed } from '../creds/ccsScopeCert';
import { ensureInvoice, verifyInvoice, type AgentCaseId } from '../creds/invoice';
import { recordDecision } from '../audit';
import { authorizeEmitReleaseCredential } from '../policy/cedar';
import { CODES, type ReasonCode } from '../../shared/codes';
import type { Manifest, MandatePayload, PcfDyeingPayload, PcfAggregatePayload, PrecursorRef } from '../../shared/types';

const ACTION = 'RunAgentP3';

/** M1 唯一合法簽發角色(spec v3 §5.1:FAB 財務部;比照 mandate.ts MANDATE_ISSUER_ROLE.M1)。 */
const M1_ISSUER_ROLE = 'fab_cfo';

/** Agent-1(fab-workload)對 FAB 閘道之 request——結構/驗序比照 shared/types.ts DiscloseRequestPayload。 */
const AGENT_RUN_REQUEST_TYP = 'agent-run+jwt';
/** Dossier JWS 之 header.typ(fab-workload 鑰簽)。 */
export const DOSSIER_TYP = 'dossier+jwt';

/** M1.agent_workload.version(spec v3 §5.1;非計算值,固定版本標籤,不由 seed 提供)。 */
const AGENT_WORKLOAD_VERSION = 'v0.3';

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function isUniqueConstraintError(e: unknown): boolean {
  return e instanceof Error && /UNIQUE constraint failed/i.test(e.message);
}

function parseCaseId(v: unknown): AgentCaseId | null {
  return v === 'A' || v === 'B' || v === 'C' || v === 'Cp' ? v : null;
}

/** C/Cp 之染整/聚合輸入與 A 相同(spec v3.1 §7);B 自成一案。 */
function underlyingCase(caseId: AgentCaseId): 'A' | 'B' {
  return caseId === 'B' ? 'B' : 'A';
}

/** build_hash = 目前 git commit(spec v3 §5.1 M1.agent_workload.build_hash);讀不到時明確標記,不寫死。 */
function gitCommitHash(): string {
  const r = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf-8' });
  return r.status === 0 && r.stdout ? r.stdout.trim() : 'unknown';
}

/** 幕 5 案件鍵→中文標籤(前端顯示用,亦可能被路由 400 訊息引用)。 */
export const AGENT_CASE_IDS: AgentCaseId[] = ['A', 'B', 'C', 'Cp'];

/** 冪等取得(必要時先簽發並入庫)M1——比照 routes/mandates.ts 之邏輯(本路由不依賴前端先呼叫 /api/mandates)。 */
async function ensureMandateM1(db: Database.Database): Promise<MandateRow> {
  const existing = getMandate(db, 'M1');
  if (existing?.token) return existing;
  const issuance = await issueMandate('M1');
  const { row } = insertMandateIfAbsent(db, {
    id: issuance.id,
    jti: issuance.jti,
    issuerParty: issuance.issuerParty,
    aud: issuance.payload.aud,
    purpose: issuance.purpose,
    agentId: issuance.agentId,
    delegateKid: issuance.delegateKid,
    allowedClaims: issuance.allowedClaims,
    maxGranularity: issuance.maxGranularity,
    queryCap: issuance.queryCap,
    policyVersion: issuance.policyVersion,
    mandateNonce: issuance.mandateNonce,
    extra: issuance.extra,
    token: issuance.token,
    statusIdx: issuance.statusIdx,
    statusUri: issuance.statusUri,
    validFrom: issuance.validFrom,
    validUntil: issuance.validUntil,
  });
  return row;
}

/**
 * 驗 M1 mandate JWT 簽章 + iss/aud/exp/jti——比照 discloseGateway.ts verifyMandateToken()
 * 之 M2 驗序,特化為 M1/財務主管 ECR(該檔為私有函式,不匯出;CLAUDE.md 要求「結構照」而非
 * 強制共用同一函式,兩處各自對應之預期簽發角色不同,重複此段以避免跨檔耦合)。
 */
async function verifyMandateM1(
  token: string,
  manifest: Manifest,
): Promise<{ ok: true; payload: MandatePayload } | { ok: false; reasonCode: ReasonCode }> {
  const expectedIssuerAid = manifest[M1_ISSUER_ROLE]?.aid;
  if (!expectedIssuerAid) return { ok: false, reasonCode: CODES.MANDATE_SIG_INVALID };
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(token);
  } catch {
    return { ok: false, reasonCode: CODES.MANDATE_SIG_INVALID };
  }
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
    if (e instanceof joseErrors.JWTClaimValidationFailed && e.claim === 'iss') {
      return { ok: false, reasonCode: CODES.MANDATE_SIG_INVALID };
    }
    return { ok: false, reasonCode: CODES.MANDATE_EXPIRED };
  }
}

interface AgentRunRequestPayload {
  mandate_id: string;
  case_id: AgentCaseId;
  request_nonce: string;
  iat: number;
}

/** Agent-1 以 fab-workload 鑰組出並簽署本次 request(見檔頭註解:與 M2 request_jws 同構)。 */
async function buildAndSignAgentRequest(args: { mandateJti: string; caseId: AgentCaseId; requestNonce: string; nowMs: number }): Promise<string> {
  const key = loadWorkloadKey('fab-workload');
  return new SignJWT({
    mandate_id: args.mandateJti,
    case_id: args.caseId,
    request_nonce: args.requestNonce,
    iat: Math.floor(args.nowMs / 1000),
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: AGENT_RUN_REQUEST_TYP, kid: key.kid })
    .sign(key.privateKey);
}

/** 驗 request 簽章:header.kid 須等於 mandate.delegate_kid,且能解出對應 workload 公鑰(fab-workload)。 */
async function verifyAgentRequestSignature(
  requestJws: string,
  delegateKid: string,
): Promise<{ ok: true; payload: AgentRunRequestPayload } | { ok: false }> {
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(requestJws);
  } catch {
    return { ok: false };
  }
  if (header.typ !== AGENT_RUN_REQUEST_TYP || header.kid !== delegateKid) return { ok: false };
  const publicKey = resolveWorkloadPublicKeyByKid(delegateKid);
  if (!publicKey) return { ok: false };
  try {
    const { payload } = await jwtVerify(requestJws, publicKey);
    return { ok: true, payload: payload as unknown as AgentRunRequestPayload };
  } catch {
    return { ok: false };
  }
}

interface StoredCredentialOk {
  ok: true;
  payload: Record<string, unknown>;
}
interface StoredCredentialFail {
  ok: false;
  reasonCode: ReasonCode;
  detail: string;
}

/**
 * 消費 FAB 自有已簽發憑證(pcf_dyeing / pcf_aggregate)前之共用驗證:簽章 + 釘住簽發者角色/vct
 * + 效期(nbf/exp,有界 skew)+ credentials Token Status List 撤銷位(fail-closed,statusGuard.ts)。
 * 比照 server/creds/pcfAggregate.ts verifyInput() 與 discloseGateway.ts verifyAggregateForDisclosure()
 * 之既有模式——即便是 FAB 自己簽發、存在自家 DB 的憑證,仍不假設 DB row 未被竄改,一律真驗。
 */
async function verifyStoredCredential(
  sdJwt: string,
  expectedVct: string,
  expectedRoleAid: string | undefined,
  manifest: Manifest,
  nowMs: number,
): Promise<StoredCredentialOk | StoredCredentialFail> {
  const verifyResult = await verifyCompactSdJwt(sdJwt, resolvePublicKeyFromManifest(manifest));
  if (!verifyResult.ok || !verifyResult.payload) {
    return { ok: false, reasonCode: verifyResult.reasonCode ?? CODES.CREDENTIAL_SIG_INVALID, detail: verifyResult.error ?? '簽章驗證失敗' };
  }
  const payload = verifyResult.payload as unknown as Record<string, unknown>;
  if (!expectedRoleAid || verifyResult.kid !== expectedRoleAid || payload.vct !== expectedVct || payload.iss !== verifyResult.kid) {
    return {
      ok: false,
      reasonCode: CODES.VCT_ISSUER_UNAUTHORIZED,
      detail: `vct/角色綁定不符(vct=${String(payload.vct)} kid=${String(verifyResult.kid)} 預期 AID=${String(expectedRoleAid)})`,
    };
  }
  const nowSec = Math.floor(nowMs / 1000);
  const skewSec = 60;
  const nbf = typeof payload.nbf === 'number' ? payload.nbf : undefined;
  const exp = typeof payload.exp === 'number' ? payload.exp : undefined;
  if (nbf != null && nowSec + skewSec < nbf) return { ok: false, reasonCode: CODES.CREDENTIAL_EXPIRED, detail: '尚未生效(nbf)' };
  if (exp != null && nowSec - skewSec > exp) return { ok: false, reasonCode: CODES.CREDENTIAL_EXPIRED, detail: '已過期(exp)' };

  const statusEntry = (payload.status as { status_list?: { idx?: number; uri?: string } } | undefined)?.status_list;
  // Status List Token 由 FAB LE 鑰簽署(閘道為 data/status/ 兩份清單的發布方)。
  const issuerKey = resolvePublicKeyFromManifest(manifest)(manifest.fab.aid);
  const token = issuerKey ? await safeReadOrRefreshStatusListToken('credentials', issuerKey, nowMs) : null;
  if (statusEntry?.idx == null || statusEntry.uri !== statusListUri('credentials') || !issuerKey || !token) {
    return { ok: false, reasonCode: CODES.CREDENTIAL_REVOKED, detail: 'status 參照或 credentials 清單缺失/損毀(fail-closed)' };
  }
  const bit = await checkStatusBit(token, statusEntry.idx, issuerKey, statusListUri('credentials'), { now: nowMs });
  if (!bit.ok || bit.revoked) return { ok: false, reasonCode: CODES.CREDENTIAL_REVOKED, detail: bit.error ?? `idx=${statusEntry.idx} 已撤銷` };
  return { ok: true, payload };
}

interface CheckOutcome {
  ok: boolean;
  reasonCode?: ReasonCode;
  detail?: string;
  meta?: Record<string, unknown>;
}

/** ① identity_ok:pcf_dyeing 簽章/型別/效期/Status List + DYE vLEI 鏈(sandbox verify)。 */
async function checkIdentity(
  dyeRow: CredentialRow,
  manifest: Manifest,
  nowMs: number,
): Promise<CheckOutcome & { payload?: PcfDyeingPayload }> {
  const cred = await verifyStoredCredential(dyeRow.sd_jwt, PCF_DYEING_VCT, manifest.dye?.aid, manifest, nowMs);
  if (!cred.ok) return { ok: false, reasonCode: cred.reasonCode, detail: cred.detail };
  const chain = verifyVleiChainSandbox(manifest.dye.credential_said);
  if (!chain.ok) {
    return { ok: false, reasonCode: CODES.VLEI_CHAIN_BROKEN, detail: chain.detail ?? 'DYE vLEI 鏈查驗失敗' };
  }
  return { ok: true, payload: cred.payload as unknown as PcfDyeingPayload };
}

/** ② subcontractor_listed:ccs_scope_cert 有效 + ccs_scope_ref 一致(sc_no 與 hash)+ DYE LEI 在分包商清單內。 */
async function checkSubcontractor(
  dyeingPayload: PcfDyeingPayload,
  scopeCertRow: CredentialRow,
  manifest: Manifest,
  nowMs: number,
): Promise<CheckOutcome> {
  const scopeResult = await verifyScopeCert(scopeCertRow.sd_jwt, { now: nowMs });
  if (!scopeResult.ok || !scopeResult.payload) {
    return { ok: false, reasonCode: scopeResult.reasonCode ?? CODES.SCOPE_CERT_INVALID, detail: scopeResult.error ?? 'ccs_scope_cert 驗證失敗' };
  }
  const scopeCertPayload = scopeResult.payload;
  const ref = dyeingPayload.ccs_scope_ref;
  if (!ref?.sc_no || ref.sc_no !== scopeCertPayload.sc_no) {
    return { ok: false, reasonCode: CODES.CCS_SUBCONTRACTOR_NOT_LISTED, detail: 'pcf_dyeing.ccs_scope_ref.sc_no 與入庫 ccs_scope_cert 不一致' };
  }
  if (!ref.hash || ref.hash !== sha256Hex(scopeCertRow.sd_jwt)) {
    return {
      ok: false,
      reasonCode: CODES.SCOPE_CERT_INVALID,
      detail: 'ccs_scope_ref.hash 與現況 ccs_scope_cert 不符(SC 已重簽/替換,provenance 斷鏈)',
    };
  }
  if (!isSubcontractorListed(scopeCertPayload, manifest.dye.lei, dyeingPayload.process)) {
    return { ok: false, reasonCode: CODES.CCS_SUBCONTRACTOR_NOT_LISTED, detail: '染整廠(DYE)不在布廠 ccs_scope_cert 之 associated_subcontractors 內' };
  }
  return { ok: true };
}

/**
 * P1-3(Codex review):消費 pcf_aggregate 前斷言其 precursor_refs 對得上「現況」三張輸入
 * (tc_rcs、pcf_upstream-<case>、pcf_dyeing-<case>)之 sha256(sd_jwt)——幕 6 撤銷重簽
 * (pcf_dyeing reissue=1)或任何測試/維運重簽動作發生後,若未重聚合,既有 pcf_aggregate-<case>
 * 仍持有陳舊 precursor 指紋,但其 pcf_total 已不代表「現況」染整/上游輸入的碳排,不得沿用
 * 陳舊聚合值續走付款管線(可組出「現況 dyeing hash + 陳舊碳總量」的全綠 Dossier)。
 * 重聚合後三者 hash 會重新一致,故正常路徑不受影響。
 */
function checkAggregateFreshness(
  precursorRefs: PrecursorRef[] | undefined,
  underlying: 'A' | 'B',
  db: Database.Database,
): { ok: true } | { ok: false; reasonCode: ReasonCode; detail: string } {
  const expectedIds = ['tc_rcs', `pcf_upstream-${underlying}`, `pcf_dyeing-${underlying}`];
  for (const id of expectedIds) {
    const row = getCredential(db, id);
    if (!row) return { ok: false, reasonCode: CODES.AGGREGATE_STALE, detail: `現況缺 ${id} 憑證,無法核對 precursor` };
    const ref = precursorRefs?.find((r) => r.id === id);
    if (!ref?.hash || ref.hash !== sha256Hex(row.sd_jwt)) {
      return {
        ok: false,
        reasonCode: CODES.AGGREGATE_STALE,
        detail: `pcf_aggregate.precursor_refs[${id}].hash 與現況憑證不符(陳舊聚合,重簽輸入後需重聚合)`,
      };
    }
  }
  return { ok: true };
}

/** ③ carbon_total_g ≤ carbon_max_g(整數 gCO2e/kg;Cedar 不支援浮點,Codex 審查定案)。 */
async function checkCarbonThreshold(
  aggRow: CredentialRow,
  manifest: Manifest,
  nowMs: number,
  carbonMaxG: number,
  underlying: 'A' | 'B',
  db: Database.Database,
): Promise<CheckOutcome & { carbonTotalG?: number }> {
  const cred = await verifyStoredCredential(aggRow.sd_jwt, PCF_AGGREGATE_VCT, manifest.fab?.aid, manifest, nowMs);
  if (!cred.ok) return { ok: false, reasonCode: cred.reasonCode, detail: cred.detail };
  const payload = cred.payload as unknown as PcfAggregatePayload;

  const freshness = checkAggregateFreshness(payload.precursor_refs, underlying, db);
  if (!freshness.ok) return { ok: false, reasonCode: freshness.reasonCode, detail: freshness.detail };

  const carbonTotalG = Math.round(payload.pcf_total * 1000);
  if (carbonTotalG > carbonMaxG) {
    return {
      ok: false,
      reasonCode: CODES.CARBON_OVER_THRESHOLD,
      detail: `carbon_total_g(${carbonTotalG})> carbon_max_g(${carbonMaxG})`,
      carbonTotalG,
      meta: { carbon_total_g: carbonTotalG, carbon_max_g: carbonMaxG },
    };
  }
  return { ok: true, carbonTotalG, meta: { carbon_total_g: carbonTotalG, carbon_max_g: carbonMaxG } };
}

/**
 * P1-2(Codex review):M1 的授權限額必須從**已驗證的簽章 payload**讀,不得讀未簽的
 * mandates.extra_json——extra_json 若被改/陳舊,同一枚合法 M1 簽章即可放行更高金額/更寬鬆
 * 碳排門檻/別的交易對手方。缺任一欄視為 M1 payload 不完整,一律拒絕(fail-closed)。
 */
interface M1Limits {
  max_amount: number;
  allowed_counterparties: string[];
  policy_thresholds: { carbon_max: number; wallet_risk_max: number; min_sources: number };
  /** P1-B(Codex review 第二輪):M1 約定幣別(簽章內),供 checkInvoiceOk 比對 invoice.currency。 */
  currency: string;
}

function extractM1Limits(payload: MandatePayload): M1Limits | null {
  if (
    typeof payload.max_amount !== 'number' ||
    !Array.isArray(payload.allowed_counterparties) ||
    !payload.policy_thresholds ||
    typeof payload.policy_thresholds.carbon_max !== 'number' ||
    typeof payload.policy_thresholds.wallet_risk_max !== 'number' ||
    typeof payload.policy_thresholds.min_sources !== 'number' ||
    typeof payload.currency !== 'string' ||
    !payload.currency
  ) {
    return null;
  }
  return {
    max_amount: payload.max_amount,
    allowed_counterparties: payload.allowed_counterparties,
    policy_thresholds: payload.policy_thresholds,
    currency: payload.currency,
  };
}

/** P1-A(Codex review 第二輪):放行時要付的錢必須源自「已驗證的 invoice」——這些欄位存進
 * Dossier payload(fab-workload 簽章保護),human-sign 據此建電匯指令,不再另讀 seed 常數。 */
interface VerifiedInvoiceFacts {
  invoiceNo: string;
  amount: number;
  currency: string;
  payerLei: string;
  payeeLei: string;
  payeeWallet: string;
}

/**
 * ④ invoice_ok:invoice 驗章(DYE 公鑰)+ amount ≤ max_amount + payer_lei===FAB LEI +
 * currency===M1 約定幣別 + payee ∈ allowed_counterparties。
 * Opus 獨立驗證 L2:金額超限與收款方不符為兩種不同的政策違反,理由碼分開(AMOUNT_OVER_LIMIT /
 * COUNTERPARTY_NOT_ALLOWED),不得共用同一碼——避免前端/稽核紀錄無法區分「超額」與「付錯人」。
 * Codex review 第二輪 P1-B:僅驗金額與 payee LEI 不夠——payer_lei≠FAB 或 currency≠約定幣別的
 * 合法 DYE 簽發票仍會過關(付款人不是布廠、或幣別對不上),故補這兩項各自獨立理由碼
 * (PAYER_NOT_ALLOWED / CURRENCY_MISMATCH)。limits 一律來自 extractM1Limits(已驗證簽章 payload)。
 */
async function checkInvoiceOk(invoiceRow: CredentialRow, limits: M1Limits, fabLei: string): Promise<CheckOutcome & { facts?: VerifiedInvoiceFacts }> {
  const v = await verifyInvoice(invoiceRow.sd_jwt);
  if (!v.ok || !v.payload) return { ok: false, reasonCode: v.reasonCode ?? CODES.INVOICE_INVALID, detail: v.error ?? 'invoice 驗證失敗' };
  const payload = v.payload;
  const facts: VerifiedInvoiceFacts = {
    invoiceNo: payload.invoice_no,
    amount: payload.amount,
    currency: payload.currency,
    payerLei: payload.payer_lei,
    payeeLei: payload.payee_lei,
    payeeWallet: payload.payee_wallet,
  };
  if (payload.amount > limits.max_amount) {
    return { ok: false, reasonCode: CODES.AMOUNT_OVER_LIMIT, detail: `amount(${payload.amount})> mandate.max_amount(${limits.max_amount})`, facts };
  }
  if (payload.payer_lei !== fabLei) {
    return { ok: false, reasonCode: CODES.PAYER_NOT_ALLOWED, detail: `invoice.payer_lei(${payload.payer_lei})≠ FAB LEI(${fabLei})`, facts };
  }
  if (payload.currency !== limits.currency) {
    return { ok: false, reasonCode: CODES.CURRENCY_MISMATCH, detail: `invoice.currency(${payload.currency})≠ mandate 約定幣別(${limits.currency})`, facts };
  }
  if (!limits.allowed_counterparties.includes(payload.payee_lei)) {
    return {
      ok: false,
      reasonCode: CODES.COUNTERPARTY_NOT_ALLOWED,
      detail: `payee_lei(${payload.payee_lei})不在 mandate.allowed_counterparties 內`,
      facts,
    };
  }
  return { ok: true, facts, meta: { amount: payload.amount, currency: payload.currency, payee_wallet: payload.payee_wallet } };
}

interface RiskSignalRow {
  provider: string;
  score: number;
  labels: string;
}

/**
 * ⑤ wallet_risk:risk_signals 雙來源——distinct provider 中「> wallet_risk_max」者達
 * M1 簽章內 min_sources 門檻 → MULTI_SOURCE_CONFIRMED(擋,ok:false);達 1 但未達門檻 →
 * SINGLE_SOURCE_ONLY(只記錄不升級,ok:true 但仍附理由碼供 UI 標示)。
 * P1-4(Codex review):查詢鍵改為**已驗證 invoice 的 payee_wallet**(account_ref),不得只用
 * case_id——舊版只用 case_id 會讓「合法 DYE 簽、但 payee_wallet 指向別的(高風險)帳戶」的
 * invoice 仍套用該 case 表面上的低風險分數過關,等同無視 invoice 實際指定的收款目的地。
 * Codex review 第二輪 P2-E:改以 **distinct provider** 聚合(同 provider 多列只算一個來源,
 * 取該 provider 之最高分代表)——舊版逐列計數,seed 對 A/B 共用帳戶已重複 provider_a 兩列時
 * 會被誤算成兩個獨立來源、誤觸 MULTI_SOURCE_CONFIRMED;min_sources 亦改讀 M1 簽章內
 * policy_thresholds.min_sources(而非寫死 2),與 P1-2 之「限額必須來自簽章」原則一致。
 */
function checkWalletRisk(
  db: Database.Database,
  accountRef: string,
  walletRiskMax: number,
  minSources: number,
): CheckOutcome & { walletRisk: number; confirming: number } {
  const rows = db.prepare('SELECT provider, score, labels FROM risk_signals WHERE account_ref = ? ORDER BY provider').all(accountRef) as RiskSignalRow[];
  const signals = rows.map((r) => ({ provider: r.provider, score: r.score, labels: JSON.parse(r.labels) as string[] }));
  const scoreByProvider = new Map<string, number>();
  for (const s of signals) {
    scoreByProvider.set(s.provider, Math.max(scoreByProvider.get(s.provider) ?? 0, s.score));
  }
  const confirming = [...scoreByProvider.values()].filter((score) => score > walletRiskMax).length;
  const walletRisk = signals.reduce((max, s) => Math.max(max, s.score), 0);
  const meta = { wallet_risk: walletRisk, risk_sources_confirming: confirming, distinct_providers: scoreByProvider.size, signals };
  if (confirming >= minSources) {
    return { ok: false, reasonCode: CODES.MULTI_SOURCE_CONFIRMED, detail: `${confirming} 個獨立來源皆確認收款帳戶高風險(門檻 ${minSources})`, walletRisk, confirming, meta };
  }
  if (confirming >= 1) {
    return { ok: true, reasonCode: CODES.SINGLE_SOURCE_ONLY, detail: '僅一來源確認高風險,只記錄不升級', walletRisk, confirming, meta };
  }
  return { ok: true, walletRisk, confirming, meta };
}

/**
 * P2-7(Codex review):P3 五要件 id 之權威列舉——POST /api/human-sign 據此斷言 Dossier
 * payload.checks 恰為此五項(無缺無重複)且皆 ok:true,不得只檢查「非空陣列皆 true」
 * (否則湊數/重複/缺項的 Dossier 亦會通過)。
 */
export const AGENT_CHECK_IDS = ['identity', 'subcontractor', 'carbon_threshold', 'invoice', 'wallet_risk'] as const;
export type AgentCheckId = (typeof AGENT_CHECK_IDS)[number];

interface AgentCheckResult {
  id: AgentCheckId;
  label: string;
  ok: boolean | null;
  reason_code?: ReasonCode;
  detail?: string;
  meta?: Record<string, unknown>;
}

const CHECK_LABELS: Record<AgentCheckResult['id'], string> = {
  identity: 'DYE 身分(vLEI 鏈 + pcf_dyeing 簽章/效期/Status List)',
  subcontractor: '染整廠在布廠 SC 分包商清單',
  carbon_threshold: '聚合碳排 ≤ 品牌合約門檻',
  invoice: '發票驗章 + 金額/收款方在委任範圍',
  wallet_risk: '收款帳戶風險(雙來源)',
};

export function registerAgentRoutes(app: FastifyInstance): void {
  app.post('/api/agent/run', async (req, reply) => {
    const query = (req.query ?? {}) as { case?: string };
    const body = (req.body ?? {}) as { case_id?: string; request_nonce?: string };
    const caseId = parseCaseId(query.case ?? body.case_id);
    if (!caseId) {
      return reply.code(400).send({ error: 'case 必須是 "A"、"B"、"C" 或 "Cp"', reason_code: CODES.INVALID_CASE_ID });
    }

    const manifest = readManifest();
    if (!manifest) return reply.code(404).send({ error: 'manifest 尚未產生(先跑 make setup)' });

    const db = openDb();
    const nowMs = Date.now();
    try {
      const mandateRow = await ensureMandateM1(db);
      if (!mandateRow.token) return reply.code(500).send({ error: 'M1 mandate 缺 token' });

      // 步驟 1+2:M1 簽章(財務主管 ECR)+ iss/aud/exp/jti。
      const mandateVerify = await verifyMandateM1(mandateRow.token, manifest);
      if (!mandateVerify.ok) {
        recordDecision(db, { action: ACTION, effect: 'DENY', reason_code: mandateVerify.reasonCode, case_id: caseId, mandate_id: mandateRow.id });
        return reply.code(403).send({ decision: 'DENY', reason_code: mandateVerify.reasonCode, case_id: caseId });
      }
      const mandatePayload = mandateVerify.payload;

      // P2-F(Codex review 第二輪):mandateRow.jti(DB 未簽欄位)必須與簽章 payload.jti 一致——
      // 若 mandates.jti 被竄改/陳舊但 token 本身仍是合法簽章(內含不同的 jti),下游會用
      // 「未簽的 row jti」簽 request 與 Dossier(mandate_jti),使 CFO 核可被歸到祂沒簽過的
      // mandate id。verifyMandateM1 只驗 token 本身合法,不會發現這個脫鉤,須在此另外斷言。
      if (!mandatePayload.jti || mandatePayload.jti !== mandateRow.jti) {
        recordDecision(db, { action: ACTION, effect: 'DENY', reason_code: CODES.MANDATE_SIG_INVALID, case_id: caseId, mandate_id: mandateRow.id });
        return reply.code(403).send({ decision: 'DENY', reason_code: CODES.MANDATE_SIG_INVALID, case_id: caseId });
      }

      // 步驟 3:delegate_kid 對 request(fab-workload)簽章。
      const requestNonce = typeof body.request_nonce === 'string' && body.request_nonce ? body.request_nonce : crypto.randomUUID();
      const requestJws = await buildAndSignAgentRequest({ mandateJti: mandateRow.jti, caseId, requestNonce, nowMs });
      const delegateVerify = await verifyAgentRequestSignature(requestJws, mandatePayload.delegate_kid);
      if (!delegateVerify.ok) {
        recordDecision(db, { action: ACTION, effect: 'DENY', reason_code: CODES.DELEGATE_KEY_MISMATCH, case_id: caseId, mandate_id: mandateRow.id });
        return reply.code(403).send({ decision: 'DENY', reason_code: CODES.DELEGATE_KEY_MISMATCH, case_id: caseId });
      }

      // 步驟 4:mandates Token Status List(idx 0)。
      // P1-1(Codex review):改用 fail-closed 之 safeReadOrRefreshStatusListToken——
      // 舊版 readFreshStatusListToken 在 data/status/mandates.jwt 缺失/簽章失效/損毀時會
      // 靜默重建全 0(無撤銷)清單,已撤銷的 M1 會被誤判為未撤銷、付款管線續走(fail-open,
      // 同 Phase 2.5 P1-b 之洞,只是換到 mandates 清單)。safeRead 只在既有清單「成功解碼且
      // 驗章通過」時才續簽(保留現有 bits、換新 iat),缺/壞一律回 null → 下方 fail-closed 拒絕。
      const statusIssuerKey = resolvePublicKeyFromManifest(manifest)(manifest.fab.aid);
      const mandateStatusToken = statusIssuerKey ? await safeReadOrRefreshStatusListToken('mandates', statusIssuerKey, nowMs) : null;
      const mandateStatusUri = mandatePayload.status?.status_list?.uri;
      if (!statusIssuerKey || !mandateStatusToken || mandateStatusUri !== statusListUri('mandates')) {
        recordDecision(db, { action: ACTION, effect: 'DENY', reason_code: CODES.MANDATE_REVOKED, case_id: caseId, mandate_id: mandateRow.id });
        return reply.code(403).send({ decision: 'DENY', reason_code: CODES.MANDATE_REVOKED, case_id: caseId });
      }
      const statusResult = await checkStatusBit(
        mandateStatusToken,
        mandatePayload.status.status_list.idx,
        statusIssuerKey,
        statusListUri('mandates'),
        { now: nowMs },
      );
      if (!statusResult.ok || statusResult.revoked) {
        recordDecision(db, {
          action: ACTION,
          effect: 'DENY',
          reason_code: CODES.MANDATE_REVOKED,
          case_id: caseId,
          mandate_id: mandateRow.id,
          context: { error: statusResult.error },
        });
        return reply.code(403).send({ decision: 'DENY', reason_code: CODES.MANDATE_REVOKED, case_id: caseId });
      }

      // 步驟 5:request_nonce 重放偵測(dossiers 表 UNIQUE(mandate_id, request_nonce)為最終防線)。
      const existingDossier = db.prepare('SELECT id FROM dossiers WHERE mandate_id = ? AND request_nonce = ?').get(mandateRow.id, requestNonce);
      if (existingDossier) {
        recordDecision(db, {
          action: ACTION,
          effect: 'REPLAY_DETECTED',
          reason_code: CODES.REPLAY_DETECTED,
          case_id: caseId,
          mandate_id: mandateRow.id,
          context: { request_nonce: requestNonce },
        });
        return reply.code(409).send({ decision: 'REPLAY_DETECTED', reason_code: CODES.REPLAY_DETECTED, case_id: caseId });
      }

      // 步驟 6:三個可信布林(至此皆已通過)——Cedar 只消費這些布林,不直接讀 mandate/SC 狀態。
      // trustedContext 目前僅供文件對齊(mandate_status_ok/delegate_key_ok/replay_ok 皆為 true),
      // 五要件之布林另於下方組給 Cedar。

      // 步驟 7:準備該案輸入(冪等;缺就先簽,已存在就沿用——不改動 Phase 2.5 已驗過之聚合行為)。
      const underlying = underlyingCase(caseId);
      let aggRow = getCredential(db, `pcf_aggregate-${underlying}`);
      if (!aggRow) {
        try {
          await issuePcfAggregate(db, underlying);
        } catch (e) {
          return reply.code(500).send({ error: `pcf_aggregate-${underlying} 簽發失敗:${errorMessage(e)}` });
        }
        aggRow = getCredential(db, `pcf_aggregate-${underlying}`);
      }
      if (!aggRow) return reply.code(500).send({ error: `pcf_aggregate-${underlying} 簽發後仍讀不到` });
      const dyeRow = getCredential(db, `pcf_dyeing-${underlying}`);
      if (!dyeRow) {
        return reply.code(400).send({ error: `pcf_dyeing-${underlying} 尚未簽發(先跑幕 2)`, reason_code: CODES.PCF_AGGREGATE_NOT_ISSUED });
      }
      const { row: scopeCertRow } = await ensureCcsScopeCert(db);
      const { row: invoiceRow } = await ensureInvoice(db, caseId);

      // P1-2(Codex review):限額一律讀已驗證的簽章 payload(mandatePayload),不讀未簽的
      // mandates.extra_json——見 extractM1Limits() 之說明。
      const m1Limits = extractM1Limits(mandatePayload);
      if (!m1Limits) {
        return reply.code(500).send({ error: 'M1 mandate 簽章 payload 缺 max_amount/allowed_counterparties/policy_thresholds(先跑 make setup 重簽 M1)' });
      }
      const carbonMaxG = Math.round(m1Limits.policy_thresholds.carbon_max * 1000);

      // 步驟 8:P3 五要件(fail-fast;未評估之後續項以 ok:null 標記,供前端灰階渲染)。
      const checks: AgentCheckResult[] = [];
      let overallOk = true;
      let overallReasonCode: ReasonCode | undefined;

      const identity = await checkIdentity(dyeRow, manifest, nowMs);
      checks.push({ id: 'identity', label: CHECK_LABELS.identity, ok: identity.ok, reason_code: identity.reasonCode, detail: identity.detail });
      if (!identity.ok) {
        overallOk = false;
        overallReasonCode = identity.reasonCode;
      }

      let subcontractor: CheckOutcome | null = null;
      if (overallOk && identity.payload) {
        subcontractor = await checkSubcontractor(identity.payload, scopeCertRow, manifest, nowMs);
        checks.push({
          id: 'subcontractor',
          label: CHECK_LABELS.subcontractor,
          ok: subcontractor.ok,
          reason_code: subcontractor.reasonCode,
          detail: subcontractor.detail,
        });
        if (!subcontractor.ok) {
          overallOk = false;
          overallReasonCode = subcontractor.reasonCode;
        }
      } else {
        checks.push({ id: 'subcontractor', label: CHECK_LABELS.subcontractor, ok: null });
      }

      let carbon: (CheckOutcome & { carbonTotalG?: number }) | null = null;
      if (overallOk) {
        carbon = await checkCarbonThreshold(aggRow, manifest, nowMs, carbonMaxG, underlying, db);
        checks.push({ id: 'carbon_threshold', label: CHECK_LABELS.carbon_threshold, ok: carbon.ok, reason_code: carbon.reasonCode, detail: carbon.detail, meta: carbon.meta });
        if (!carbon.ok) {
          overallOk = false;
          overallReasonCode = carbon.reasonCode;
        }
      } else {
        checks.push({ id: 'carbon_threshold', label: CHECK_LABELS.carbon_threshold, ok: null });
      }

      let invoiceCheck: (CheckOutcome & { facts?: VerifiedInvoiceFacts }) | null = null;
      if (overallOk) {
        invoiceCheck = await checkInvoiceOk(invoiceRow, m1Limits, manifest.fab.lei);
        checks.push({ id: 'invoice', label: CHECK_LABELS.invoice, ok: invoiceCheck.ok, reason_code: invoiceCheck.reasonCode, detail: invoiceCheck.detail, meta: invoiceCheck.meta });
        if (!invoiceCheck.ok) {
          overallOk = false;
          overallReasonCode = invoiceCheck.reasonCode;
        }
      } else {
        checks.push({ id: 'invoice', label: CHECK_LABELS.invoice, ok: null });
      }

      // P1-4(Codex review):風險查詢鍵改用已驗證 invoice 的 payee_wallet(account_ref),
      // 不再只用 case_id——見 checkWalletRisk() 之說明。
      let risk: (CheckOutcome & { walletRisk: number; confirming: number }) | null = null;
      if (overallOk) {
        const accountRef = invoiceCheck?.facts?.payeeWallet;
        if (!accountRef) {
          // 不應發生(invoiceCheck.ok===true 時恆帶 facts.payeeWallet);fail-closed 兜底。
          overallOk = false;
          overallReasonCode = CODES.INVOICE_INVALID;
          checks.push({ id: 'wallet_risk', label: CHECK_LABELS.wallet_risk, ok: null });
        } else {
          risk = checkWalletRisk(db, accountRef, m1Limits.policy_thresholds.wallet_risk_max, m1Limits.policy_thresholds.min_sources);
          checks.push({ id: 'wallet_risk', label: CHECK_LABELS.wallet_risk, ok: risk.ok, reason_code: risk.reasonCode, detail: risk.detail, meta: risk.meta });
          // SINGLE_SOURCE_ONLY(案 Cp):不擋放行,但「只記錄」——獨立記一筆稽核,不影響 overallOk。
          if (risk.ok && risk.reasonCode === CODES.SINGLE_SOURCE_ONLY) {
            recordDecision(db, {
              action: ACTION,
              effect: 'PERMIT',
              reason_code: CODES.SINGLE_SOURCE_ONLY,
              case_id: caseId,
              mandate_id: mandateRow.id,
              context: { wallet_risk: risk.walletRisk, risk_sources_confirming: risk.confirming, account_ref: accountRef, note: '只記錄不升級(自我約束)' },
            });
          }
          if (!risk.ok) {
            overallOk = false;
            overallReasonCode = risk.reasonCode;
          }
        }
      } else {
        checks.push({ id: 'wallet_risk', label: CHECK_LABELS.wallet_risk, ok: null });
      }

      // 步驟 9:Cedar 二次確認(P3 政策僅消費後端算好的布林/mandate 資料欄位;不直接讀 SC/mandate 狀態)。
      if (overallOk && carbon && invoiceCheck && risk) {
        const cedarResult = authorizeEmitReleaseCredential({
          carbonMaxG,
          maxAmount: m1Limits.max_amount,
          context: {
            mandate_status_ok: true,
            identity_ok: true,
            subcontractor_listed: true,
            carbon_total_g: carbon.carbonTotalG ?? carbonMaxG + 1,
            invoice_ok: true,
            wallet_risk: risk.walletRisk,
            risk_sources_confirming: risk.confirming,
            amount: invoiceCheck.facts?.amount ?? m1Limits.max_amount + 1,
          },
        });
        if (!cedarResult.allow) {
          // 防禦性兜底:context 由上面已算好的布林/數值組成,理論上不應與 Cedar 政策結果相左。
          overallOk = false;
          overallReasonCode = CODES.CARBON_OVER_THRESHOLD;
        }
      }

      if (!overallOk) {
        recordDecision(db, {
          action: ACTION,
          effect: 'DENY',
          reason_code: overallReasonCode ?? CODES.CARBON_OVER_THRESHOLD,
          case_id: caseId,
          mandate_id: mandateRow.id,
          context: { checks },
        });
        return reply.code(403).send({ decision: 'DENY', reason_code: overallReasonCode, case_id: caseId, checks });
      }

      // P1-A(Codex review 第二輪):放行時要付的錢必須源自這次已驗證的 invoice——不應在此
      // 才發現缺 facts(overallOk 僅在 invoiceCheck.ok===true 時維持,該分支恆回傳 facts),
      // fail-closed 兜底以防未來重構破壞這個不變量。
      if (!invoiceCheck?.facts) {
        return reply.code(500).send({ error: 'invoice 已驗證但缺 facts(不應發生)' });
      }
      const invoiceFacts = invoiceCheck.facts;

      // 步驟 10:全過 → 建 Dossier(fab-workload 鑰簽 JWS;PENDING_HUMAN)。
      const dossierId = crypto.randomUUID();
      const buildHash = gitCommitHash();
      const dossierPayload = {
        dossier_id: dossierId,
        build_hash: buildHash,
        version: AGENT_WORKLOAD_VERSION,
        case_id: caseId,
        mandate_jti: mandateRow.jti,
        checks: checks.map((c) => ({ id: c.id, ok: c.ok, reason_code: c.reason_code })),
        credential_hashes: {
          pcf_dyeing: sha256Hex(dyeRow.sd_jwt),
          pcf_aggregate: sha256Hex(aggRow.sd_jwt),
          invoice: sha256Hex(invoiceRow.sd_jwt),
        },
        // P1-A:已驗證 invoice 的付款事實(受本 JWS 之 fab-workload 簽章保護)——human-sign
        // 據此建電匯指令,不再另讀 seed.transaction.dyeing_service(避免核准與付款脫鉤)。
        invoice: {
          invoice_no: invoiceFacts.invoiceNo,
          amount: invoiceFacts.amount,
          currency: invoiceFacts.currency,
          payer_lei: invoiceFacts.payerLei,
          payee_lei: invoiceFacts.payeeLei,
        },
      };
      const workloadKey = loadWorkloadKey('fab-workload');
      const dossierJws = await new SignJWT(dossierPayload)
        .setProtectedHeader({ alg: 'EdDSA', typ: DOSSIER_TYP, kid: workloadKey.kid })
        .setIssuedAt(Math.floor(nowMs / 1000))
        .sign(workloadKey.privateKey);

      try {
        const tx = db.transaction(() => {
          const { decisionId } = recordDecision(db, {
            action: ACTION,
            effect: 'PERMIT',
            reason_code: CODES.POLICY_P3_PERMIT,
            case_id: caseId,
            mandate_id: mandateRow.id,
            context: { checks, dossier_id: dossierId },
          });
          db.prepare(
            `INSERT INTO dossiers (id, case_id, mandate_id, mandate_jti, request_nonce, jws, status, decision_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, 'PENDING_HUMAN', ?, datetime('now'))`,
          ).run(dossierId, caseId, mandateRow.id, mandateRow.jti, requestNonce, dossierJws, decisionId);
        });
        tx.immediate();
      } catch (e) {
        if (isUniqueConstraintError(e)) {
          recordDecision(db, {
            action: ACTION,
            effect: 'REPLAY_DETECTED',
            reason_code: CODES.REPLAY_DETECTED,
            case_id: caseId,
            mandate_id: mandateRow.id,
            context: { request_nonce: requestNonce },
          });
          return reply.code(409).send({ decision: 'REPLAY_DETECTED', reason_code: CODES.REPLAY_DETECTED, case_id: caseId });
        }
        throw e;
      }

      return {
        decision: 'PERMIT',
        case_id: caseId,
        checks,
        dossier: {
          id: dossierId,
          status: 'PENDING_HUMAN',
          jws: dossierJws,
          build_hash: buildHash,
          version: AGENT_WORKLOAD_VERSION,
          mandate_jti: mandateRow.jti,
        },
      };
    } finally {
      db.close();
    }
  });
}
