/**
 * pcf_aggregate — FAB 布廠聚合 PCF VC(幕 2 核心;架構決策 §4:POST /api/aggregate)。
 *
 * 資料流(全數真實密碼學運算,不得跳過任一步):
 *   1) 取得該案兩張外部輸入憑證(已入庫則直接讀;未簽發則沿用幕 1/前置邏輯先簽,不另造假憑證)
 *      ——見 ensureInputs():tc_carbon_upstream-<case>(YARN)與 pcf_dyeing-<case>(DYE)。
 *   2) FAB 以持有者身分消費前,兩張皆必先以 server/creds/verifier.ts 對 manifest 公鑰驗章;
 *      驗不過丟 UpstreamVerificationError(reasonCode = CODES.CREDENTIAL_SIG_INVALID),不得略過。
 *   3) 依 spec v3 §4.4 三段公式程式計算——見 computeAggregateBreakdown()(純函式,供
 *      scripts/test.ts 直接複驗):紗(外部)× 損耗加成 + 自家織布用電 × 台灣電網 + 染整(外部)。
 *      全案不得寫死聚合結果。
 *   4) 經 server/keys.ts 載入 FAB sandbox LE AID 鑰簽發;precursor_refs 僅留兩張外部憑證的
 *      id + sha256(sd_jwt),不含任何上游明細欄位。
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type Database from 'better-sqlite3';
import type { DisclosureFrame } from '@sd-jwt/core';
import type { SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc';
import { ROOT } from '../db';
import { loadSandboxKey } from '../keys';
import { buildIssuerInstance } from './issuer';
import { verifyCompactSdJwt } from './verifier';
import { statusListUri } from '../statuslist';
import { readManifest, resolvePublicKeyFromManifest } from '../manifest';
import { getCredential, insertCredentialIfAbsent } from './store';
import { issueTcCarbonUpstream, round4 } from './tcCarbonUpstream';
import { issuePcfDyeing } from './pcfDyeing';
import { CODES, type ReasonCode } from '../../shared/codes';
import {
  PCF_AGGREGATE_BRAND_SD_FIELDS,
  PCF_AGGREGATE_AUDIT_SD_FIELDS,
  type PcfCaseId,
  type PcfAggregatePayload,
  type PrecursorRef,
} from '../../shared/types';

export const PCF_AGGREGATE_VCT = 'https://carbon-cred-demo.local/vct/pcf_aggregate';

/** 外部輸入憑證驗章失敗——依範圍鐵則「消費前必先驗章,驗不過就以理由碼回錯,不得跳過」。 */
export class UpstreamVerificationError extends Error {
  reasonCode: ReasonCode = CODES.CREDENTIAL_SIG_INVALID;
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
    downstream_hs6: string;
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
 * 純函式:三段聚合(spec v3 §4.4 公式)——
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

/** 取得(必要時先簽)該案兩張外部輸入憑證:紗(YARN)與染整(DYE)。 */
async function ensureInputs(db: Database.Database, caseId: PcfCaseId): Promise<{ upstreamSdJwt: string; dyeingSdJwt: string }> {
  const upstream = await ensureInput(db, `tc_carbon_upstream-${caseId}`, 'tc_carbon_upstream', () => issueTcCarbonUpstream(caseId));
  const dyeing = await ensureInput(db, `pcf_dyeing-${caseId}`, 'pcf_dyeing', () => issuePcfDyeing(caseId));
  return { upstreamSdJwt: upstream.sdJwt, dyeingSdJwt: dyeing.sdJwt };
}

/** 消費前驗章(manifest 公鑰);驗不過即丟 UpstreamVerificationError,不得跳過。回傳已驗證 payload。 */
async function verifyInput(sdJwt: string, label: string): Promise<Record<string, unknown>> {
  const manifest = readManifest();
  if (!manifest) throw new Error('manifest 尚未產生(先跑 make setup)');
  const verifyResult = await verifyCompactSdJwt(sdJwt, resolvePublicKeyFromManifest(manifest));
  if (!verifyResult.ok || !verifyResult.payload) {
    throw new UpstreamVerificationError(`外部輸入憑證 ${label} 驗章失敗,拒絕消費:${verifyResult.error ?? '未知錯誤'}`);
  }
  return verifyResult.payload as Record<string, unknown>;
}

/**
 * 簽出 pcf_aggregate(FAB sandbox LE AID 鑰)並原子落庫(insertCredentialIfAbsent:先到者落庫,
 * 後到者棄用自己剛簽的 token,一律以落庫勝者重建回傳值——breakdown 為純函式計算,不受競態影響)。
 */
export async function issuePcfAggregate(db: Database.Database, caseId: PcfCaseId): Promise<PcfAggregateIssuance> {
  const seed = readSeed();
  const agg = seed.aggregate_defaults;

  // 1) 取得(必要時先簽)該案兩張外部輸入憑證。
  const { upstreamSdJwt, dyeingSdJwt } = await ensureInputs(db, caseId);

  // 2) 兩張消費前皆必先驗章(manifest 公鑰);驗不過即中止。
  const upstreamPayload = await verifyInput(upstreamSdJwt, `tc_carbon_upstream-${caseId}`);
  const dyeingPayload = await verifyInput(dyeingSdJwt, `pcf_dyeing-${caseId}`);

  const yarnTotal = upstreamPayload.pcf_total;
  const dyeingTotal = dyeingPayload.pcf_total;
  if (typeof yarnTotal !== 'number' || typeof dyeingTotal !== 'number') {
    throw new UpstreamVerificationError('外部輸入憑證缺少品牌層揭露值(pcf_total),無法計算聚合');
  }

  // 3) 程式計算三段聚合(spec v3 §4.4;純函式,不寫死結果)。
  const breakdown = computeAggregateBreakdown(yarnTotal, dyeingTotal, {
    yarnLossFactor: agg.yarn_loss_factor,
    knittingKwhPerKg: agg.knitting_electricity_kwh_per_kg,
    gridTw: seed.emission_factor_table.grid_tw_kg_per_kwh,
  });

  const precursorRefs: PrecursorRef[] = [
    { id: `tc_carbon_upstream-${caseId}`, hash: sha256Hex(upstreamSdJwt) },
    { id: `pcf_dyeing-${caseId}`, hash: sha256Hex(dyeingSdJwt) },
  ];

  // 4) 經 server/keys.ts 載入 FAB sandbox LE AID 鑰簽發。
  const key = loadSandboxKey('fab');
  const id = `pcf_aggregate-${caseId}`;
  const statusIdx = seed.status_list_idx.credentials[id];
  if (typeof statusIdx !== 'number') throw new Error(`seed.status_list_idx.credentials 缺 ${id}`);
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
    hs6: seed.transaction.downstream_hs6,
    origin: seed.transaction.downstream_origin,
    tcProductStandardLabelGrade: String(upstreamPayload.tcProductStandardLabelGrade ?? ''),
    zdhc_incheck_level: String(dyeingPayload.zdhc_incheck_level ?? ''),
    precursor_refs: precursorRefs,
    plant_total_output_hash: sha256HexJson(agg.confidential.plant_total_output_t_per_month),
    capacity_utilization_hash: sha256HexJson(agg.confidential.capacity_utilization),
    other_customers_hash: sha256HexJson(agg.confidential.other_customers),
    brand_allocation_share_hash: sha256HexJson(agg.confidential.brand_allocation_share),
    monthly_utility_commitments_hash: sha256HexJson(agg.confidential.monthly_utility_commitments_kwh),
    pcf_total: breakdown.total,
    pcf_period: agg.pcf_period,
    pcf_method: agg.pcf_method,
    tcProductRawMaterialPercentage: Number(upstreamPayload.tcProductRawMaterialPercentage ?? 0),
    verification: agg.verification,
    quantity_kg: seed.transaction.fabric_quantity_kg,
    pcf_yarn: breakdown.pcfYarn,
    pcf_knitting: breakdown.pcfKnitting,
    pcf_dyeing: breakdown.pcfDyeing,
    yarn_loss_factor: agg.yarn_loss_factor,
    knitting_electricity_kwh_per_kg: agg.knitting_electricity_kwh_per_kg,
    pcf_factor_source: agg.pcf_factor_source,
  };

  // 型別限制註記同 tcCarbonUpstream.ts:_sd 為固定欄位名稱字串,執行期原樣傳入 pack()。
  const disclosureFrame = {
    _sd: [...PCF_AGGREGATE_BRAND_SD_FIELDS, ...PCF_AGGREGATE_AUDIT_SD_FIELDS],
  } as unknown as DisclosureFrame<SdJwtVcPayload>;

  const instance = buildIssuerInstance(key);
  const sdJwt = await instance.issue(payload as unknown as SdJwtVcPayload, disclosureFrame, { header: { kid: key.kid } });

  // 原子落庫:不論本次簽發是否贏得競態,一律回傳落庫勝者版本。
  const { row } = insertCredentialIfAbsent(db, {
    id,
    type: 'pcf_aggregate',
    caseId,
    issuerParty: 'fab',
    holderParty: 'fab',
    sdJwt,
    payload,
    statusIdx,
    statusUri,
    issuedAt: agg.issued_at,
    validFrom: agg.valid_from,
    validUntil: agg.valid_until,
  });
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
