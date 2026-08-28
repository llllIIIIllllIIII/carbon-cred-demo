/**
 * pcf_aggregate — 鴻鋼扣件 PCF VC(幕 2 核心;架構決策 §4:POST /api/aggregate)。
 *
 * 資料流(全數真實密碼學運算,不得跳過任一步):
 *   1) 取得該案 pcf_upstream(已入庫則直接讀;未簽發則沿用幕 1 issuePcfUpstream 邏輯先簽,
 *      不另造假憑證)——見 ensureUpstreamCredential()。
 *   2) 鴻鋼以持有者身分「出示」其持有的完整上游 SD-JWT(含全部揭露),消費前必先以
 *      server/creds/verifier.ts 對 manifest 公鑰驗章;驗不過丟 UpstreamVerificationError
 *      (reasonCode = CODES.CREDENTIAL_SIG_INVALID),不得略過此步。
 *   3) 從驗證後之揭露值(specific_direct_embedded_emissions / specific_indirect_embedded_emissions)
 *      + data/seed.json 之鴻鋼自家製程係數,依規格v2 §4.3 公式程式計算聚合——見
 *      computeAggregateBreakdown()(純函式,無副作用,供 scripts/test.ts 直接複驗)。
 *      公式(規格v2:100):聚合值 = 前驅物投入係數 × (上游 direct + indirect) + 自身 direct + 自身 indirect
 *      (案 A 範例:1.05 × 1.05 + 0.08 + 0.33 ≈ 1.5125)。全案不得寫死聚合結果。
 *   4) 經 server/keys.ts 載入鴻鋼 sandbox LE AID 鑰簽發 pcf_aggregate;precursor_ref 僅留
 *      上游憑證 id + sha256(sd_jwt) 兩個欄位(藍圖:150,不含上游任何明細欄位)。
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
import { issuePcfUpstream } from './pcfUpstream';
import { CODES, type ReasonCode } from '../../shared/codes';
import {
  PCF_AGGREGATE_CUSTOMS_SD_FIELDS,
  PCF_AGGREGATE_CUSTOMER_SD_FIELDS,
  type PcfAggregateCaseId,
  type PcfAggregatePayload,
  type PrecursorRef,
} from '../../shared/types';

export const PCF_AGGREGATE_VCT = 'https://carbon-cred-demo.local/vct/pcf_aggregate';

/** 案件於 credentials Token Status List 之固定 idx(pcf_upstream 佔用 0=A、1=B;本憑證接續 2=A、3=B)。 */
export const PCF_AGGREGATE_STATUS_IDX: Record<PcfAggregateCaseId, number> = { A: 2, B: 3 };

/** 上游憑證驗章失敗——依範圍鐵則「消費前必先驗章,驗不過就以理由碼回錯,不得跳過」。 */
export class UpstreamVerificationError extends Error {
  reasonCode: ReasonCode = CODES.CREDENTIAL_SIG_INVALID;
}

interface AggregateDefaults {
  precursor_input_ratio_t_per_t: number;
  self_direct: number;
  self_indirect: number;
  carbon_price_paid_origin: string;
  issued_at: string;
  valid_from: string;
  valid_until: string;
}

interface SeedData {
  transaction: { downstream_cn_code: string; contract_carbon_max: number };
  aggregate_defaults: AggregateDefaults;
}

function readSeed(): SeedData {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8'));
}

function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/** 去除浮點乘加誤差(輸入皆為 2 位小數,結果最多 4 位小數即為精確值)。 */
function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

export interface AggregateBreakdown {
  precursorContribution: number;
  selfDirect: number;
  selfIndirect: number;
  total: number;
}

/**
 * 純函式:上游揭露值(direct+indirect)+ 自家製程係數 → 聚合值(規格v2 §4.3 公式)。
 * 無副作用、不觸碰 DB/鑰檔,供 scripts/test.ts 以獨立算式交叉驗證。
 */
export function computeAggregateBreakdown(
  upstreamDirect: number,
  upstreamIndirect: number,
  coeffs: { precursorInputRatio: number; selfDirect: number; selfIndirect: number },
): AggregateBreakdown {
  const precursorContribution = round4(coeffs.precursorInputRatio * (upstreamDirect + upstreamIndirect));
  const selfDirect = round4(coeffs.selfDirect);
  const selfIndirect = round4(coeffs.selfIndirect);
  const total = round4(precursorContribution + selfDirect + selfIndirect);
  return { precursorContribution, selfDirect, selfIndirect, total };
}

export interface PcfAggregateIssuance {
  id: string;
  caseId: PcfAggregateCaseId;
  sdJwt: string;
  payload: PcfAggregatePayload;
  breakdown: AggregateBreakdown;
  precursorRef: PrecursorRef;
  issuedAt: string;
  validFrom: string;
  validUntil: string;
  issuerParty: 'hunggang';
  holderParty: 'hunggang';
  statusIdx: number;
  statusUri: string;
  /** 買方合約碳排門檻(data/seed.json transaction.contract_carbon_max,非法定;L3 修正,供前端疊層熱點圖畫門檻線,不寫死於元件內)。 */
  contractCarbonMax: number;
}

/**
 * 取得(必要時依幕 1 邏輯先簽發並入庫)該案 pcf_upstream,回傳其 sd_jwt。
 * Codex 審查發現 1(併發競態)修法:先前「讀→await 簽章→無條件 upsert」在兩個併發請求下會各自簽出
 * 內容相同、位元組不同的 SD-JWT(隨機 disclosure 鹽),upsert 互相覆蓋,導致此處回傳值與「稍後實際
 * 落庫」的版本不一致——本函式與呼叫端(issuePcfAggregate)之間的 precursor_ref.hash 就可能對不上
 * DB 裡最終那份上游憑證。改用 insertCredentialIfAbsent(原子 INSERT OR IGNORE + 重讀):不論本次簽發
 * 是否贏得競態,一律回傳落庫勝者的 sd_jwt,確保 precursor_ref 永遠對得上 DB 現況。
 */
async function ensureUpstreamCredential(db: Database.Database, caseId: PcfAggregateCaseId): Promise<{ sdJwt: string }> {
  const id = `pcf_upstream-${caseId}`;
  const existing = getCredential(db, id);
  if (existing) return { sdJwt: existing.sd_jwt };

  const issuance = await issuePcfUpstream(caseId);
  const { row } = insertCredentialIfAbsent(db, {
    id: issuance.id,
    type: 'pcf_upstream',
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

/**
 * 簽出 pcf_aggregate(鴻鋼 sandbox LE AID 鑰)並原子落庫(遺留 c 之修法)。
 * 舊版本函式本身不寫 DB,落庫責任丟給呼叫端(route)以非原子 upsertCredential 處理——
 * 與 ensureUpstreamCredential() 修復 pcf_upstream 併發競態前的舊寫法相同缺陷:兩個併發
 * 呼叫各自簽出內容相同、位元組不同的 SD-JWT(隨機 disclosure 鹽),upsert 互相覆蓋,
 * 導致回應與最終落庫版本不一致。改為函式內直接呼叫 insertCredentialIfAbsent(比照
 * ensureUpstreamCredential 之原子 get-or-create 模式):先到者落庫,後到者棄用自己剛簽的
 * token,一律以 DB 落庫勝者(row)重建回傳值——breakdown 為純函式計算,兩邊呼叫必然算出
 * 相同數值,不受競態影響,故沿用本次計算結果;sdJwt/payload/precursorRef 則一律改用落庫
 * 勝者版本,確保呼叫端(route)不需要、也不應該再自行 upsertCredential。
 */
export async function issuePcfAggregate(db: Database.Database, caseId: PcfAggregateCaseId): Promise<PcfAggregateIssuance> {
  const seed = readSeed();
  const agg = seed.aggregate_defaults;

  // 1) 取得(必要時先簽)該案上游憑證。
  const upstream = await ensureUpstreamCredential(db, caseId);

  // 2) 消費前必先驗章(manifest 公鑰);驗不過即中止,不得跳過。
  const manifest = readManifest();
  if (!manifest) throw new Error('manifest 尚未產生(先跑 make setup)');
  const verifyResult = await verifyCompactSdJwt(upstream.sdJwt, resolvePublicKeyFromManifest(manifest));
  if (!verifyResult.ok || !verifyResult.payload) {
    throw new UpstreamVerificationError(`上游 pcf_upstream 驗章失敗,拒絕消費:${verifyResult.error ?? '未知錯誤'}`);
  }
  const upstreamPayload = verifyResult.payload as Record<string, unknown>;
  const upstreamDirect = upstreamPayload.specific_direct_embedded_emissions;
  const upstreamIndirect = upstreamPayload.specific_indirect_embedded_emissions;
  if (typeof upstreamDirect !== 'number' || typeof upstreamIndirect !== 'number') {
    throw new UpstreamVerificationError('上游憑證缺少客戶層揭露值(specific_direct/indirect_embedded_emissions),無法計算聚合');
  }

  // 3) 程式計算聚合(規格v2 §4.3;純函式,不寫死結果)。
  const breakdown = computeAggregateBreakdown(upstreamDirect, upstreamIndirect, {
    precursorInputRatio: agg.precursor_input_ratio_t_per_t,
    selfDirect: agg.self_direct,
    selfIndirect: agg.self_indirect,
  });

  const precursorRef: PrecursorRef = { id: `pcf_upstream-${caseId}`, hash: sha256Hex(upstream.sdJwt) };

  // 4) 經 server/keys.ts 載入鴻鋼 sandbox LE AID 鑰簽發。
  const key = loadSandboxKey('hunggang');
  const statusIdx = PCF_AGGREGATE_STATUS_IDX[caseId];
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
    cn_code: seed.transaction.downstream_cn_code,
    precursor_ref: precursorRef,
    carbon_total_tco2e_per_t: breakdown.total,
    precursor_contribution_tco2e_per_t: breakdown.precursorContribution,
    self_direct_tco2e_per_t: breakdown.selfDirect,
    self_indirect_tco2e_per_t: breakdown.selfIndirect,
    carbon_price_paid_origin: agg.carbon_price_paid_origin,
  };

  // 同 pcfUpstream.ts 之型別限制註記:SdJwtVcPayload 隱含索引簽章使 Frame<> 條件型別與具名
  // payload 型別互斥(套件本身的已知型別限制,純型別層面);_sd 陣列為固定欄位名稱字串,
  // 執行期原樣傳入 pack(),故以型別斷言繞過。
  const disclosureFrame = {
    _sd: [...PCF_AGGREGATE_CUSTOMS_SD_FIELDS, ...PCF_AGGREGATE_CUSTOMER_SD_FIELDS],
  } as unknown as DisclosureFrame<SdJwtVcPayload>;

  const instance = buildIssuerInstance(key);
  const sdJwt = await instance.issue(payload as unknown as SdJwtVcPayload, disclosureFrame, { header: { kid: key.kid } });

  // 原子落庫(遺留 c):不論本次簽發是否贏得競態,一律回傳落庫勝者版本。
  const { row } = insertCredentialIfAbsent(db, {
    id: `pcf_aggregate-${caseId}`,
    type: 'pcf_aggregate',
    caseId,
    issuerParty: 'hunggang',
    holderParty: 'hunggang',
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
    precursorRef: finalPayload.precursor_ref,
    issuedAt: agg.issued_at,
    validFrom: agg.valid_from,
    validUntil: agg.valid_until,
    issuerParty: 'hunggang',
    holderParty: 'hunggang',
    statusIdx,
    statusUri,
    contractCarbonMax: seed.transaction.contract_carbon_max,
  };
}
