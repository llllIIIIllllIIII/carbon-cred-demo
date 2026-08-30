/**
 * pcf_dyeing — DYE 染整工段 SD-JWT VC(幕 2 輸入/幕 5 付款對象/幕 6 撤銷主線;
 * 架構決策 §4:POST /api/issue/dyeing?case=A|B[&reissue=1])。
 * A/B 差異全部來自本憑證:cases[case].heat_source / renewable_share + dyeing_defaults +
 * emission_factor_table 程式計算(不寫死結果)。reissue=1 = 幕 6 撤銷後重簽:改用
 * seed.status_list_idx 之 `pcf_dyeing-A-reissue` idx 與下一個月的 pcf_period。
 * v3.1:公開層加 ccs_scope_ref = { sc_no, hash: sha256(ccs_scope_cert sd_jwt) }(自入庫的
 * ccs_scope_cert 計算,染整廠不得在沒有 SC 參照下撐起 RCS 宣告)與 ccs_subcontractor_status
 * (CCS-101 C5.2.1:associated——列於布廠 SC 下受稽核)。
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import type Database from 'better-sqlite3';
import type { DisclosureFrame } from '@sd-jwt/core';
import type { SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc';
import { ROOT } from '../db';
import { loadSandboxKey } from '../keys';
import { buildIssuerInstance } from './issuer';
import { statusListUri } from '../statuslist';
import { round4 } from './pcfUpstream';
import { ensureCcsScopeCert } from './ccsScopeCert';
import {
  PCF_DYEING_BRAND_SD_FIELDS,
  PCF_DYEING_AUDIT_SD_FIELDS,
  type CcsScopeRef,
  type HeatSource,
  type PcfCaseId,
  type PcfDyeingPayload,
} from '../../shared/types';

export const PCF_DYEING_VCT = 'https://carbon-cred-demo.local/vct/pcf_dyeing';

interface EmissionFactorTable {
  grid_tw_kg_per_kwh: number;
  natural_gas_kg_per_mj: number;
  coal_kg_per_mj: number;
  boiler_efficiency: { natural_gas: number; coal: number };
}

interface DyeingDefaults {
  issued_at: string;
  valid_from: string;
  valid_until: string;
  pcf_period: string;
  process: string;
  facility_country: string;
  zdhc_incheck_level: string;
  heat_mj_per_kg: number;
  electricity_kwh_per_kg: number;
  pcf_method: string;
  pcf_factor_source: string;
  confidential: { boiler_model: string; fuel_contract: string; chemical_inventory: string; ppa_price: string };
  ccs_subcontractor_status: string;
}

interface SeedData {
  emission_factor_table: EmissionFactorTable;
  dyeing_defaults: DyeingDefaults;
  cases: Record<string, { heat_source: HeatSource; renewable_share: number }>;
  status_list_idx: { credentials: Record<string, number> };
}

function readSeed(): SeedData {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8'));
}

function sha256Hex(value: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

/** raw string 之 SHA-256 hex——用於 ccs_scope_ref.hash = sha256(ccs_scope_cert 之 compact SD-JWT 字串)。 */
function sha256HexOfString(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/** YYYY-MM 遞增一個月(幕 6 重簽之新報告期,不寫死具體月份字串)。 */
function nextPeriod(period: string): string {
  const [y, m] = period.split('-').map(Number);
  const next = new Date(Date.UTC(y, m, 1)); // m 為 1-based,直接傳入 Date 即為下個月
  return `${next.getUTCFullYear()}-${String(next.getUTCMonth() + 1).padStart(2, '0')}`;
}

export interface DyeingBreakdown {
  direct: number;
  indirect: number;
  total: number;
}

/**
 * 純函式:染整段排放(spec v3 §4.3)——
 *   direct = 熱能需求 ÷ 鍋爐效率 × 燃料係數;indirect = 用電 × 台灣電網 × (1 − 綠電比)。
 * 無副作用,供 scripts/test.ts 以獨立算式交叉驗證(A: 3.0294/0.5972/3.6266;B: 5.747/0.8532/6.6002)。
 */
export function computeDyeing(
  d: { heat_mj_per_kg: number; electricity_kwh_per_kg: number },
  ef: EmissionFactorTable,
  heatSource: HeatSource,
  renewableShare: number,
): DyeingBreakdown {
  const fuel = heatSource === 'coal' ? ef.coal_kg_per_mj : ef.natural_gas_kg_per_mj;
  const direct = round4((d.heat_mj_per_kg / ef.boiler_efficiency[heatSource]) * fuel);
  const indirect = round4(d.electricity_kwh_per_kg * ef.grid_tw_kg_per_kwh * (1 - renewableShare));
  return { direct, indirect, total: round4(direct + indirect) };
}

export interface PcfDyeingIssuance {
  id: string;
  caseId: PcfCaseId;
  sdJwt: string;
  payload: PcfDyeingPayload;
  breakdown: DyeingBreakdown;
  issuedAt: string;
  validFrom: string;
  validUntil: string;
  issuerParty: 'dye';
  holderParty: 'fab';
  statusIdx: number;
  statusUri: string;
  reissue: boolean;
}

/**
 * 簽出 pcf_dyeing(DYE sandbox LE AID 鑰;caseId 決定熱源/綠電比;reissue 用備援 idx 與新報告期)。
 * db 用於取得(必要時先簽發並入庫)ccs_scope_ref 綁定之 ccs_scope_cert——染整廠不得在沒有
 * SC 參照下撐起 RCS 宣告(v3.1)。
 */
export async function issuePcfDyeing(db: Database.Database, caseId: PcfCaseId, opts: { reissue?: boolean } = {}): Promise<PcfDyeingIssuance> {
  const seed = readSeed();
  const caseData = seed.cases[caseId];
  if (!caseData || (caseId !== 'A' && caseId !== 'B')) throw new Error(`未知案件 case_id=${caseId}(pcf_dyeing 僅支援 A/B)`);
  const d = seed.dyeing_defaults;
  const key = loadSandboxKey('dye');

  // v3.1:ccs_scope_ref 自入庫(必要時先簽)的 ccs_scope_cert 計算。
  const { row: scopeCertRow } = await ensureCcsScopeCert(db);
  const scopeCertPayload = JSON.parse(scopeCertRow.payload_json) as { sc_no: string };
  const ccsScopeRef: CcsScopeRef = { sc_no: scopeCertPayload.sc_no, hash: sha256HexOfString(scopeCertRow.sd_jwt) };

  const reissue = opts.reissue === true;
  const id = `pcf_dyeing-${caseId}`;
  const idxKey = reissue ? `${id}-reissue` : id;
  const statusIdx = seed.status_list_idx.credentials[idxKey];
  if (typeof statusIdx !== 'number') throw new Error(`seed.status_list_idx.credentials 缺 ${idxKey}`);
  const statusUri = statusListUri('credentials');

  const pcfPeriod = reissue ? nextPeriod(d.pcf_period) : d.pcf_period;

  const issuedAtSec = Math.floor(new Date(`${d.issued_at}T00:00:00Z`).getTime() / 1000);
  const validFromSec = Math.floor(new Date(`${d.valid_from}T00:00:00Z`).getTime() / 1000);
  const validUntilSec = Math.floor(new Date(`${d.valid_until}T00:00:00Z`).getTime() / 1000);

  const breakdown = computeDyeing(d, seed.emission_factor_table, caseData.heat_source, caseData.renewable_share);

  const payload: PcfDyeingPayload = {
    vct: PCF_DYEING_VCT,
    iss: key.kid,
    iat: issuedAtSec,
    nbf: validFromSec,
    exp: validUntilSec,
    status: { status_list: { idx: statusIdx, uri: statusUri } },
    process: d.process,
    facility_country: d.facility_country,
    zdhc_incheck_level: d.zdhc_incheck_level,
    ccs_subcontractor_status: d.ccs_subcontractor_status,
    ccs_scope_ref: ccsScopeRef,
    boiler_model_hash: sha256Hex(d.confidential.boiler_model),
    fuel_contract_hash: sha256Hex(d.confidential.fuel_contract),
    chemical_inventory_hash: sha256Hex(d.confidential.chemical_inventory),
    ppa_price_hash: sha256Hex(d.confidential.ppa_price),
    emission_factor_table_hash: sha256Hex(seed.emission_factor_table),
    pcf_total: breakdown.total,
    heat_source: caseData.heat_source,
    renewable_share: caseData.renewable_share,
    pcf_period: pcfPeriod,
    pcf_method: d.pcf_method,
    heat_mj_per_kg: d.heat_mj_per_kg,
    electricity_kwh_per_kg: d.electricity_kwh_per_kg,
    boiler_efficiency: seed.emission_factor_table.boiler_efficiency[caseData.heat_source],
    pcf_direct: breakdown.direct,
    pcf_indirect: breakdown.indirect,
    pcf_factor_source: d.pcf_factor_source,
  };

  // 型別限制註記同 pcfUpstream.ts:_sd 為固定欄位名稱字串,執行期原樣傳入 pack()。
  const disclosureFrame = {
    _sd: [...PCF_DYEING_BRAND_SD_FIELDS, ...PCF_DYEING_AUDIT_SD_FIELDS],
  } as unknown as DisclosureFrame<SdJwtVcPayload>;

  const instance = buildIssuerInstance(key);
  const sdJwt = await instance.issue(payload as unknown as SdJwtVcPayload, disclosureFrame, { header: { kid: key.kid } });

  return {
    id,
    caseId,
    sdJwt,
    payload,
    breakdown,
    issuedAt: d.issued_at,
    validFrom: d.valid_from,
    validUntil: d.valid_until,
    issuerParty: 'dye',
    holderParty: 'fab',
    statusIdx,
    statusUri,
    reissue,
  };
}
