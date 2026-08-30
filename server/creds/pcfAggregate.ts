/**
 * pcf_aggregate — FAB 布廠聚合 PCF VC(幕 2 核心;架構決策 §4:POST /api/aggregate)。
 *
 * 資料流(全數真實密碼學運算,不得跳過任一步;v3.1):
 *   1) ensureInputs():取得(必要時先簽發並入庫)該案四項輸入——tc_rcs(CB)、ccs_scope_cert
 *      (CB;seed 時應已簽發,此處為保險冪等)、pcf_upstream-<case>(YARN)、pcf_dyeing-<case>(DYE)。
 *   2) FAB 以持有者身分消費前,tc_rcs / pcf_upstream / pcf_dyeing 三張外部憑證皆必先以
 *      server/creds/verifier.ts 對 manifest 公鑰驗章;**驗章通過後再釘住簽發者角色**——
 *      實際驗章鑰(header.kid,verifyCompactSdJwt 回傳之 kid)必須等於該 vct 唯一被授權的角色
 *      AID(tc_rcs=cb、pcf_upstream=yarn、pcf_dyeing=dye),不符即 VCT_ISSUER_UNAUTHORIZED
 *      (Opus 獨立驗證 HIGH #1:僅檢查「manifest 內任一角色簽的都算」會讓 FAB/YARN 自簽 tc_rcs
 *      通過驗證);接著查 credentials Status List 撤銷位(idx 依各憑證 status.status_list),
 *      已撤銷即 CREDENTIAL_REVOKED(HIGH/MEDIUM #3:聚合消費前對四張輸入一律查撤銷位,不得只查
 *      ccs_scope_cert)。ccs_scope_cert 另以 verifyScopeCert()驗簽章(同樣釘住 cb 角色)+ 效期 +
 *      Token Status List——任一驗不過丟 UpstreamVerificationError 或 AggregateGuardError,不得略過。
 *   3) 聚合前核對(v3.1;不符任一項即 AggregateGuardError,理由碼與其他 DENY 一樣入稽核鏈):
 *      ① pcf_upstream.tc_ref.hash == sha256(tc_rcs sd_jwt)
 *      ② tc_rcs.seller_lei == manifest.yarn.lei
 *      ③ tc_rcs.buyer_lei == manifest.fab.lei
 *      ④ tc_rcs.tcProductCertifiedWeight >= pcf_upstream.quantity_kg
 *      (①~④不符 → TC_REF_MISMATCH)
 *      ⑤ pcf_dyeing.ccs_scope_ref.sc_no == ccs_scope_cert.sc_no(不符 → CCS_SUBCONTRACTOR_NOT_LISTED)
 *        且 .hash == sha256(ccs_scope_cert sd_jwt)(sc_no 同但 SC 已重簽/替換 → SCOPE_CERT_INVALID)
 *        且 DYE LEI ∈ ccs_scope_cert.associated_subcontractors(不符 → CCS_SUBCONTRACTOR_NOT_LISTED)
 *   4) 依 spec v3.1 §4.4 三段公式程式計算——見 computeAggregateBreakdown()(純函式,供
 *      scripts/test.ts 直接複驗):紗(外部)× 損耗加成 + 自家織布用電 × 台灣電網 + 染整(外部)。
 *      全案不得寫死聚合結果。tcProductStandardLabelGrade 由 tc_rcs 之 label grade 推導,不再自填。
 *   5) 經 server/keys.ts 載入 FAB sandbox LE AID 鑰簽發;precursor_refs 留三張外部憑證的
 *      id + sha256(sd_jwt)(tc_rcs、pcf_upstream、pcf_dyeing),不含任何上游明細欄位;
 *      公開層另帶 ccs_scope_ref;移除 hs6(不放稅則碼)。
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type Database from 'better-sqlite3';
import type { DisclosureFrame } from '@sd-jwt/core';
import type { SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc';
import { ROOT } from '../db';
import { loadSandboxKey, type SandboxRole } from '../keys';
import { buildIssuerInstance } from './issuer';
import { verifyCompactSdJwt } from './verifier';
import { checkStatusBit, statusListUri, revokeStatusIndex } from '../statuslist';
import { safeReadOrRefreshStatusListToken } from './statusGuard';
import { readManifest, resolvePublicKeyFromManifest } from '../manifest';
import { getCredential, insertCredentialIfAbsent, upsertCredential, type CredentialRow } from './store';
import { issuePcfUpstream, round4 } from './pcfUpstream';
import { issuePcfDyeing } from './pcfDyeing';
import { ensureTcRcs } from './tcRcs';
import { ensureCcsScopeCert, verifyScopeCert, isSubcontractorListed } from './ccsScopeCert';
import { appendAudit } from '../audit';
import { CODES, type ReasonCode } from '../../shared/codes';
import {
  PCF_AGGREGATE_BRAND_SD_FIELDS,
  PCF_AGGREGATE_AUDIT_SD_FIELDS,
  type CcsScopeRef,
  type PcfCaseId,
  type PcfAggregatePayload,
  type PrecursorRef,
} from '../../shared/types';

export const PCF_AGGREGATE_VCT = 'https://carbon-cred-demo.local/vct/pcf_aggregate';

/**
 * 外部輸入憑證驗章/角色綁定/撤銷檢查失敗——依範圍鐵則「消費前必先驗章,驗不過就以理由碼回錯,
 * 不得跳過」。reasonCode 依觸發項而異:簽章本身不合法 → CREDENTIAL_SIG_INVALID;簽章合法但
 * 簽發者不是該 vct 唯一被授權角色 → VCT_ISSUER_UNAUTHORIZED(HIGH #1);已撤銷 → CREDENTIAL_REVOKED
 * (MEDIUM #3)。
 */
export class UpstreamVerificationError extends Error {
  reasonCode: ReasonCode;
  constructor(message: string, reasonCode: ReasonCode = CODES.CREDENTIAL_SIG_INVALID) {
    super(message);
    this.reasonCode = reasonCode;
  }
}

/** v3.1 聚合前核對(tc_ref/ccs_scope_ref 綁定、分包商清單)失敗——理由碼依觸發項而異。 */
export class AggregateGuardError extends Error {
  reasonCode: ReasonCode;
  constructor(message: string, reasonCode: ReasonCode) {
    super(message);
    this.reasonCode = reasonCode;
  }
}

interface AggregateDefaults {
  issued_at: string;
  valid_from: string;
  valid_until: string;
  pcf_period: string;
  yarn_loss_factor: number;
  knitting_electricity_kwh_per_kg: number;
  verification: string;
  pcf_method: string;
  pcf_factor_source: string;
  confidential: {
    plant_total_output_t_per_month: number;
    capacity_utilization: number;
    other_customers: string;
    brand_allocation_share: number;
    monthly_utility_commitments_kwh: number[];
  };
}

interface SeedData {
  transaction: {
    downstream_product: string;
    downstream_origin: string;
    fabric_quantity_kg: number;
    contract_carbon_max: number;
  };
  emission_factor_table: { grid_tw_kg_per_kwh: number };
  aggregate_defaults: AggregateDefaults;
  status_list_idx: { credentials: Record<string, number> };
}

function readSeed(): SeedData {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8'));
}

function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function sha256HexJson(value: unknown): string {
  return sha256Hex(JSON.stringify(value));
}

export interface AggregateBreakdown {
  pcfYarn: number;
  pcfKnitting: number;
  pcfDyeing: number;
  total: number;
}

/**
 * 純函式:三段聚合(spec v3.1 §4.4 公式)——
 *   紗 = 上游 pcf_total × 針織損耗加成;織布 = 自家針織用電 × 台灣電網;染整 = 外部 pcf_dyeing.pcf_total。
 * 無副作用、不觸碰 DB/鑰檔,供 scripts/test.ts 以獨立算式交叉驗證(A 7.9251 / B 10.8987)。
 */
export function computeAggregateBreakdown(
  yarnTotal: number,
  dyeingTotal: number,
  c: { yarnLossFactor: number; knittingKwhPerKg: number; gridTw: number },
): AggregateBreakdown {
  const pcfYarn = round4(yarnTotal * c.yarnLossFactor);
  const pcfKnitting = round4(c.knittingKwhPerKg * c.gridTw);
  const pcfDyeing = round4(dyeingTotal);
  return { pcfYarn, pcfKnitting, pcfDyeing, total: round4(pcfYarn + pcfKnitting + pcfDyeing) };
}

export interface PcfAggregateIssuance {
  id: string;
  caseId: PcfCaseId;
  sdJwt: string;
  payload: PcfAggregatePayload;
  breakdown: AggregateBreakdown;
  precursorRefs: PrecursorRef[];
  issuedAt: string;
  validFrom: string;
  validUntil: string;
  issuerParty: 'fab';
  holderParty: 'fab';
  statusIdx: number;
  statusUri: string;
  /** 品牌合約碳排門檻(data/seed.json transaction.contract_carbon_max,非法定;供前端疊層熱點圖畫門檻線,不寫死於元件內)。 */
  contractCarbonMax: number;
}

/**
 * 取得(必要時先簽發並入庫)單張外部輸入憑證,回傳落庫勝者的 sd_jwt。
 * 併發競態修法沿用 v2(Codex 審查發現 1):insertCredentialIfAbsent 原子 INSERT OR IGNORE + 重讀,
 * 不論本次簽發是否贏得競態,一律回傳 DB 落庫勝者,確保 precursor_refs.hash 永遠對得上 DB 現況。
 */
async function ensureInput(
  db: Database.Database,
  id: string,
  type: string,
  issue: () => Promise<{
    id: string;
    caseId: PcfCaseId;
    issuerParty: string;
    holderParty: string;
    sdJwt: string;
    payload: unknown;
    statusIdx: number;
    statusUri: string;
    issuedAt: string;
    validFrom: string;
    validUntil: string;
  }>,
): Promise<{ sdJwt: string }> {
  const existing = getCredential(db, id);
  if (existing) return { sdJwt: existing.sd_jwt };

  const issuance = await issue();
  const { row } = insertCredentialIfAbsent(db, {
    id: issuance.id,
    type,
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
  return { sdJwt: row.sd_jwt };
}

interface EnsuredInputs {
  tcRcsSdJwt: string;
  upstreamSdJwt: string;
  dyeingSdJwt: string;
  ccsScopeCertSdJwt: string;
}

/** 取得(必要時先簽)該案四項輸入:tc_rcs、ccs_scope_cert(CB;皆冪等)、pcf_upstream(YARN)、pcf_dyeing(DYE)。 */
async function ensureInputs(db: Database.Database, caseId: PcfCaseId): Promise<EnsuredInputs> {
  const { row: tcRcsRow } = await ensureTcRcs(db);
  const { row: scopeCertRow } = await ensureCcsScopeCert(db);
  const upstream = await ensureInput(db, `pcf_upstream-${caseId}`, 'pcf_upstream', () => issuePcfUpstream(db, caseId));
  const dyeing = await ensureInput(db, `pcf_dyeing-${caseId}`, 'pcf_dyeing', () => issuePcfDyeing(db, caseId));
  return { tcRcsSdJwt: tcRcsRow.sd_jwt, upstreamSdJwt: upstream.sdJwt, dyeingSdJwt: dyeing.sdJwt, ccsScopeCertSdJwt: scopeCertRow.sd_jwt };
}

/**
 * 消費前驗章(manifest 公鑰)+ 釘住簽發者角色(HIGH #1)+ 查撤銷位(MEDIUM #3);
 * 任一不過即丟 UpstreamVerificationError,不得跳過。回傳已驗證 payload。
 *
 * expectedRole:該 vct 唯一被授權簽發之角色(比照 verifyPresentation.ts 的 VCT_ISSUER_ROLE
 * 模式)——只驗簽章通過不夠,manifest 內任一角色的鑰都能簽出「驗章通過」的 token,必須另外核對
 * 實際驗章鑰(verifyResult.kid)是否等於該角色之 AID,否則 FAB/YARN 可自簽 tc_rcs 這類本應
 * 唯 CB 能簽的憑證並蒙混過關(PoC 已證實)。
 */
async function verifyInput(sdJwt: string, label: string, expectedRole: SandboxRole): Promise<Record<string, unknown>> {
  const manifest = readManifest();
  if (!manifest) throw new Error('manifest 尚未產生(先跑 make setup)');
  const verifyResult = await verifyCompactSdJwt(sdJwt, resolvePublicKeyFromManifest(manifest));
  if (!verifyResult.ok || !verifyResult.payload) {
    throw new UpstreamVerificationError(`外部輸入憑證 ${label} 驗章失敗,拒絕消費:${verifyResult.error ?? '未知錯誤'}`);
  }
  const expectedAid = manifest[expectedRole]?.aid;
  if (!expectedAid || verifyResult.kid !== expectedAid) {
    throw new UpstreamVerificationError(
      `外部輸入憑證 ${label} 簽發者(kid=${verifyResult.kid ?? '(無)'})不是唯一被授權角色 ${expectedRole}(AID=${expectedAid ?? '(無)'})`,
      CODES.VCT_ISSUER_UNAUTHORIZED,
    );
  }

  // MEDIUM #3:消費前查 credentials Status List 撤銷位(idx 依該憑證自身 status.status_list),
  // 被撤的輸入不得撐起新聚合——不得只查 ccs_scope_cert(verifyScopeCert 已內建),tc_rcs/
  // pcf_upstream/pcf_dyeing 亦須查。
  //
  // Opus 獨立驗證 A(對齊 Codex P1-b 原話「only refresh a successfully decoded existing list and
  // otherwise deny」):**不得**呼叫 server/statuslist.ts 之 readFreshStatusListToken——該函式在
  // 清單檔缺失或無法解碼時,會靜默以「全 0(無撤銷)」重建一份新清單並回傳,是 fail-open。但也**不能**
  // 只做一次性讀檔就判定撤銷——on-disk 清單之 iat 固定在 setup/demo-reset 當下,閒置超過
  // ttl+skew(360s)後會被 checkStatusBit 判定陳舊(stale ≠ 撤銷),若不續簽會讓合法未撤銷的輸入
  // 持續假性失敗(黏著,直到有人打 GET /status/credentials 或跑 disclose 才會被動刷新)。
  // 改用 ./statusGuard.ts 之 safeReadOrRefreshStatusListToken:只有「既有清單能成功解碼且驗章
  // 通過」才允許刷新(保留現有 bits、換新 iat 消除 staleness);清單檔缺失或解碼/驗章失敗一律
  // fail-closed 回 null,不得重建為全 0。
  const statusEntry = (verifyResult.payload as { status?: { status_list?: { idx?: number; uri?: string } } }).status?.status_list;
  const nowMs = Date.now();
  const statusIssuerKey = resolvePublicKeyFromManifest(manifest)(manifest.fab.aid); // Status List Token 由 FAB LE 鑰簽署
  const credentialsToken = statusIssuerKey ? await safeReadOrRefreshStatusListToken('credentials', statusIssuerKey, nowMs) : null;
  if (statusEntry?.idx == null || statusEntry.uri !== statusListUri('credentials') || !statusIssuerKey || !credentialsToken) {
    throw new UpstreamVerificationError(
      `外部輸入憑證 ${label} status 參照或 credentials 清單缺失/損毀(fail-closed,拒絕消費)`,
      CODES.CREDENTIAL_REVOKED,
    );
  }
  const bit = await checkStatusBit(credentialsToken, statusEntry.idx, statusIssuerKey, statusListUri('credentials'), { now: nowMs });
  if (!bit.ok || bit.revoked) {
    throw new UpstreamVerificationError(`外部輸入憑證 ${label} 已撤銷(idx=${statusEntry.idx}):${bit.error ?? '未知錯誤'}`, CODES.CREDENTIAL_REVOKED);
  }

  return verifyResult.payload as Record<string, unknown>;
}

/**
 * 簽出 pcf_aggregate(FAB sandbox LE AID 鑰)並原子落庫(insertCredentialIfAbsent:先到者落庫,
 * 後到者棄用自己剛簽的 token,一律以落庫勝者重建回傳值——breakdown 為純函式計算,不受競態影響)。
 *
 * opts.reissue(幕 6 撤銷後重簽;phase-brief 3b §0.3 規格疑義裁定 supersede 語意):改用備援
 * idxKey `${id}-reissue`(data/seed.json 之 `pcf_aggregate-A-reissue: 11`)簽發新 aggregate,
 * 並在落庫前先以 revokeStatusIndex() 翻銷「舊 slot」(id 本身原始 idx,如 A 案的 idx 2)——使
 * 撤銷前留存的舊 presentation 對舊 aggregate 之查驗失敗(CREDENTIAL_REVOKED),新 aggregate 則
 * 持新 idx 生效。id 本身不變(`pcf_aggregate-${caseId}`),以 upsertCredential 覆蓋落庫(非
 * insertCredentialIfAbsent 之「已存在就不重簽」冪等語意)。
 */
export async function issuePcfAggregate(
  db: Database.Database,
  caseId: PcfCaseId,
  opts: { reissue?: boolean } = {},
): Promise<PcfAggregateIssuance> {
  const seed = readSeed();
  const agg = seed.aggregate_defaults;

  // 1) 取得(必要時先簽)該案四項輸入。
  const inputs = await ensureInputs(db, caseId);

  // 2) 三張外部憑證(tc_rcs、pcf_upstream、pcf_dyeing)消費前皆先驗章 + 釘住簽發者角色 + 查撤銷位;
  //    ccs_scope_cert 另以 verifyScopeCert 驗(簽章 + 角色 + 效期 + Token Status List)。
  const tcRcsPayload = await verifyInput(inputs.tcRcsSdJwt, 'tc_rcs', 'cb');
  const upstreamPayload = await verifyInput(inputs.upstreamSdJwt, `pcf_upstream-${caseId}`, 'yarn');
  const dyeingPayload = await verifyInput(inputs.dyeingSdJwt, `pcf_dyeing-${caseId}`, 'dye');
  const scopeCertResult = await verifyScopeCert(inputs.ccsScopeCertSdJwt);
  if (!scopeCertResult.ok || !scopeCertResult.payload) {
    throw new AggregateGuardError(`ccs_scope_cert 驗證失敗,拒絕消費:${scopeCertResult.error ?? '未知錯誤'}`, CODES.SCOPE_CERT_INVALID);
  }
  const scopeCertPayload = scopeCertResult.payload;

  const manifest = readManifest();
  if (!manifest?.yarn?.lei || !manifest?.fab?.lei || !manifest?.dye?.lei) {
    throw new Error('manifest 缺 yarn/fab/dye 角色(先跑 make setup)——聚合前核對需要三者 LEI');
  }

  // 3) v3.1 聚合前核對 ①~④:tc_ref 綁定與買賣雙方、數量勾稽——不符即 TC_REF_MISMATCH。
  const tcRef = upstreamPayload.tc_ref as { id?: string; hash?: string } | undefined;
  if (!tcRef?.hash || tcRef.hash !== sha256Hex(inputs.tcRcsSdJwt)) {
    throw new AggregateGuardError('pcf_upstream.tc_ref.hash 與入庫 tc_rcs 之 sha256(sd_jwt) 不符', CODES.TC_REF_MISMATCH);
  }
  if (tcRcsPayload.seller_lei !== manifest.yarn.lei) {
    throw new AggregateGuardError('tc_rcs.seller_lei 與信任鏈之紗廠(YARN)LEI 不符', CODES.TC_REF_MISMATCH);
  }
  if (tcRcsPayload.buyer_lei !== manifest.fab.lei) {
    throw new AggregateGuardError('tc_rcs.buyer_lei 與信任鏈之布廠(FAB)LEI 不符', CODES.TC_REF_MISMATCH);
  }
  const certifiedWeight = Number(tcRcsPayload.tcProductCertifiedWeight);
  const quantityKg = Number(upstreamPayload.quantity_kg);
  if (!(certifiedWeight >= quantityKg)) {
    throw new AggregateGuardError(
      `tc_rcs.tcProductCertifiedWeight(${certifiedWeight})< pcf_upstream.quantity_kg(${quantityKg})`,
      CODES.TC_REF_MISMATCH,
    );
  }

  // 4) v3.1 聚合前核對 ⑤:ccs_scope_ref 一致(sc_no **與** hash;Codex 審查 P1-c:scope cert 若以
  //    相同 sc_no 重簽/替換,舊 pcf_dyeing 仍指向舊 token——只比 sc_no 會遮蔽斷掉的 provenance 連結,
  //    必須另比對 hash === sha256(現況 ccs_scope_cert sd_jwt))+ DYE LEI 在分包商清單內。
  const dyeingScopeRef = dyeingPayload.ccs_scope_ref as { sc_no?: string; hash?: string } | undefined;
  if (!dyeingScopeRef?.sc_no || dyeingScopeRef.sc_no !== scopeCertPayload.sc_no) {
    throw new AggregateGuardError('pcf_dyeing.ccs_scope_ref.sc_no 與入庫 ccs_scope_cert 不一致', CODES.CCS_SUBCONTRACTOR_NOT_LISTED);
  }
  if (!dyeingScopeRef.hash || dyeingScopeRef.hash !== sha256Hex(inputs.ccsScopeCertSdJwt)) {
    throw new AggregateGuardError(
      'pcf_dyeing.ccs_scope_ref.hash 與入庫 ccs_scope_cert 之 sha256(sd_jwt) 不符(sc_no 相同但 SC 已重簽/替換,provenance 斷鏈)',
      CODES.SCOPE_CERT_INVALID,
    );
  }
  const dyeingProcess = String(dyeingPayload.process ?? '');
  if (!isSubcontractorListed(scopeCertPayload, manifest.dye.lei, dyeingProcess)) {
    throw new AggregateGuardError('染整廠(DYE)不在布廠 ccs_scope_cert 之 associated_subcontractors 內', CODES.CCS_SUBCONTRACTOR_NOT_LISTED);
  }

  const yarnTotal = upstreamPayload.pcf_total;
  const dyeingTotal = dyeingPayload.pcf_total;
  if (typeof yarnTotal !== 'number' || typeof dyeingTotal !== 'number') {
    throw new UpstreamVerificationError('外部輸入憑證缺少品牌層揭露值(pcf_total),無法計算聚合');
  }

  // 5) 程式計算三段聚合(spec v3.1 §4.4;純函式,不寫死結果)。
  const breakdown = computeAggregateBreakdown(yarnTotal, dyeingTotal, {
    yarnLossFactor: agg.yarn_loss_factor,
    knittingKwhPerKg: agg.knitting_electricity_kwh_per_kg,
    gridTw: seed.emission_factor_table.grid_tw_kg_per_kwh,
  });

  const precursorRefs: PrecursorRef[] = [
    { id: 'tc_rcs', hash: sha256Hex(inputs.tcRcsSdJwt) },
    { id: `pcf_upstream-${caseId}`, hash: sha256Hex(inputs.upstreamSdJwt) },
    { id: `pcf_dyeing-${caseId}`, hash: sha256Hex(inputs.dyeingSdJwt) },
  ];
  const aggregateScopeRef: CcsScopeRef = { sc_no: scopeCertPayload.sc_no, hash: sha256Hex(inputs.ccsScopeCertSdJwt) };

  // 6) 經 server/keys.ts 載入 FAB sandbox LE AID 鑰簽發。
  const key = loadSandboxKey('fab');
  const id = `pcf_aggregate-${caseId}`;
  const reissue = opts.reissue === true;
  const idxKey = reissue ? `${id}-reissue` : id;
  const statusIdx = seed.status_list_idx.credentials[idxKey];
  if (typeof statusIdx !== 'number') throw new Error(`seed.status_list_idx.credentials 缺 ${idxKey}`);
  const statusUri = statusListUri('credentials');

  const issuedAtSec = Math.floor(new Date(`${agg.issued_at}T00:00:00Z`).getTime() / 1000);
  const validFromSec = Math.floor(new Date(`${agg.valid_from}T00:00:00Z`).getTime() / 1000);
  const validUntilSec = Math.floor(new Date(`${agg.valid_until}T00:00:00Z`).getTime() / 1000);

  const payload: PcfAggregatePayload = {
    vct: PCF_AGGREGATE_VCT,
    iss: key.kid,
    iat: issuedAtSec,
    nbf: validFromSec,
    exp: validUntilSec,
    status: { status_list: { idx: statusIdx, uri: statusUri } },
    product: seed.transaction.downstream_product,
    origin: seed.transaction.downstream_origin,
    // tcProductStandardLabelGrade 由 tc_rcs 之 label grade 推導(有效 ccs_scope_cert 已於上方核對),不再自填。
    tcProductStandardLabelGrade: String(tcRcsPayload.tcProductStandardLabelGrade ?? ''),
    zdhc_incheck_level: String(dyeingPayload.zdhc_incheck_level ?? ''),
    ccs_scope_ref: aggregateScopeRef,
    precursor_refs: precursorRefs,
    plant_total_output_hash: sha256HexJson(agg.confidential.plant_total_output_t_per_month),
    capacity_utilization_hash: sha256HexJson(agg.confidential.capacity_utilization),
    other_customers_hash: sha256HexJson(agg.confidential.other_customers),
    brand_allocation_share_hash: sha256HexJson(agg.confidential.brand_allocation_share),
    monthly_utility_commitments_hash: sha256HexJson(agg.confidential.monthly_utility_commitments_kwh),
    pcf_total: breakdown.total,
    pcf_period: agg.pcf_period,
    pcf_method: agg.pcf_method,
    tcProductRawMaterialPercentage: Number(tcRcsPayload.tcProductRawMaterialPercentage ?? 0),
    verification: agg.verification,
    quantity_kg: seed.transaction.fabric_quantity_kg,
    pcf_yarn: breakdown.pcfYarn,
    pcf_knitting: breakdown.pcfKnitting,
    pcf_dyeing: breakdown.pcfDyeing,
    yarn_loss_factor: agg.yarn_loss_factor,
    knitting_electricity_kwh_per_kg: agg.knitting_electricity_kwh_per_kg,
    pcf_factor_source: agg.pcf_factor_source,
  };

  // 型別限制註記同 pcfUpstream.ts:_sd 為固定欄位名稱字串,執行期原樣傳入 pack()。
  const disclosureFrame = {
    _sd: [...PCF_AGGREGATE_BRAND_SD_FIELDS, ...PCF_AGGREGATE_AUDIT_SD_FIELDS],
  } as unknown as DisclosureFrame<SdJwtVcPayload>;

  const instance = buildIssuerInstance(key);
  const sdJwt = await instance.issue(payload as unknown as SdJwtVcPayload, disclosureFrame, { header: { kid: key.kid } });

  const credentialRecord = {
    id,
    type: 'pcf_aggregate',
    caseId,
    issuerParty: 'fab' as const,
    holderParty: 'fab' as const,
    sdJwt,
    payload,
    statusIdx,
    statusUri,
    issuedAt: agg.issued_at,
    validFrom: agg.valid_from,
    validUntil: agg.valid_until,
  };

  let row: CredentialRow;
  if (reissue) {
    // supersede 語意:先翻銷舊 slot(id 本身原始 idx)——只有在上方所有驗證/核對皆已通過、
    // 新 aggregate 也已成功簽出之後才動清單檔,驗證失敗的路徑不觸碰 Token Status List。
    const oldIdx = seed.status_list_idx.credentials[id];
    if (typeof oldIdx !== 'number') throw new Error(`seed.status_list_idx.credentials 缺 ${id}(舊 slot,reissue 無法翻銷)`);
    await revokeStatusIndex('credentials', oldIdx);
    // P1-5(Codex 審查):reissue 翻銷舊 slot 亦屬撤銷動作,須入鏈(不得只有 CLI/API 兩個
    // 呼叫端留痕、supersede 路徑卻悄悄漏記)。
    appendAudit(db, 'admin:revoke', { list: 'credentials', idx: oldIdx, actor: 'aggregate-reissue-supersede', id, case_id: caseId });
    upsertCredential(db, credentialRecord);
    const got = getCredential(db, id);
    if (!got) throw new Error(`reissue 落庫後讀不回憑證(id=${id})——不應發生`);
    row = got;
  } else {
    // 原子落庫:不論本次簽發是否贏得競態,一律回傳落庫勝者版本。
    row = insertCredentialIfAbsent(db, credentialRecord).row;
  }
  const finalPayload = JSON.parse(row.payload_json) as PcfAggregatePayload;

  return {
    id: row.id,
    caseId,
    sdJwt: row.sd_jwt,
    payload: finalPayload,
    breakdown,
    precursorRefs: finalPayload.precursor_refs,
    issuedAt: agg.issued_at,
    validFrom: agg.valid_from,
    validUntil: agg.valid_until,
    issuerParty: 'fab',
    holderParty: 'fab',
    statusIdx,
    statusUri,
    contractCarbonMax: seed.transaction.contract_carbon_max,
  };
}
