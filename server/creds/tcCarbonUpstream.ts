/**
 * tc_carbon_upstream — YARN 紗廠「TC + 碳」SD-JWT VC(幕 1 核心;架構決策 §4:POST /api/issue/upstream)。
 * TC 有的欄位用 Textile Exchange 官方 camelCase 鍵名原樣(ASR-104);pcf_* 為我方延伸
 * (TC 本身無碳數據)。以 data/seed.json 之 upstream_defaults 預填簽發;A/B 兩案紗憑證相同
 * (差異在染整段),但仍各簽一張(status idx 依 seed.status_list_idx)。
 * issued_at/valid_from/valid_until 直接取自 seed(回填約三個月前,非簽發當日臨時產生)。
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import type { DisclosureFrame } from '@sd-jwt/core';
import type { SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc';
import { ROOT } from '../db';
import { loadSandboxKey } from '../keys';
import { buildIssuerInstance } from './issuer';
import { statusListUri } from '../statuslist';
import {
  TC_UPSTREAM_BRAND_SD_FIELDS,
  TC_UPSTREAM_AUDIT_SD_FIELDS,
  type PcfCaseId,
  type TcCarbonUpstreamPayload,
} from '../../shared/types';

export const TC_CARBON_UPSTREAM_VCT = 'https://carbon-cred-demo.local/vct/tc_carbon_upstream';

interface EmissionFactorTable {
  grid_tw_kg_per_kwh: number;
  grid_vn_kg_per_kwh: number;
  natural_gas_kg_per_mj: number;
  coal_kg_per_mj: number;
  boiler_efficiency: { natural_gas: number; coal: number };
}

interface UpstreamDefaults {
  issued_at: string;
  valid_from: string;
  valid_until: string;
  pcf_period: string;
  tcNo: string;
  inputTcNo: string;
  tcStandard: string;
  tcProductStandardLabelGrade: string;
  tcCertifiedRawMaterialCountryOrArea: string;
  sellerTeId: string;
  buyerTeId: string;
  tcShipmentDate: string;
  tcShipmentNo: string;
  tcProductLastProcessorName: string;
  tcProductLastProcessorCountry: string;
  pcf_direct: number;
  electricity_kwh_per_kg: number;
  pcf_method: string;
  pcf_factor_source: string;
  confidential: { invoice_refs: string; unit_price: string; energy_invoice: string; recycler_name: string };
}

interface SeedData {
  transaction: {
    upstream_tc_product_category_code: string;
    upstream_tc_product_detail_code: string;
    upstream_raw_material_code: string;
    upstream_raw_material_pct: number;
    yarn_quantity_kg: number;
  };
  emission_factor_table: EmissionFactorTable;
  upstream_defaults: UpstreamDefaults;
  status_list_idx: { credentials: Record<string, number> };
}

function readSeed(): SeedData {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8'));
}

/** SHA-256 commitment hash(hex)——機密原始資料永不進憑證,只留此雜湊。 */
function sha256Hex(value: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

/** 去除浮點乘加誤差(計算保留 4 位小數即為精確值;顯示 2 位由前端處理)。 */
export function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

export interface TcCarbonUpstreamIssuance {
  id: string;
  caseId: PcfCaseId;
  sdJwt: string;
  payload: TcCarbonUpstreamPayload;
  issuedAt: string;
  validFrom: string;
  validUntil: string;
  issuerParty: 'yarn';
  holderParty: 'fab';
  statusIdx: number;
  statusUri: string;
}

/** 簽出 tc_carbon_upstream(YARN sandbox LE AID 鑰;A/B 內容相同、idx 依 seed.status_list_idx)。 */
export async function issueTcCarbonUpstream(caseId: PcfCaseId): Promise<TcCarbonUpstreamIssuance> {
  const seed = readSeed();
  if (caseId !== 'A' && caseId !== 'B') throw new Error(`未知案件 case_id=${caseId}(tc_carbon_upstream 僅支援 A/B)`);
  const d = seed.upstream_defaults;
  const key = loadSandboxKey('yarn');

  const id = `tc_carbon_upstream-${caseId}`;
  const statusIdx = seed.status_list_idx.credentials[id];
  if (typeof statusIdx !== 'number') throw new Error(`seed.status_list_idx.credentials 缺 ${id}`);
  const statusUri = statusListUri('credentials');

  const issuedAtSec = Math.floor(new Date(`${d.issued_at}T00:00:00Z`).getTime() / 1000);
  const validFromSec = Math.floor(new Date(`${d.valid_from}T00:00:00Z`).getTime() / 1000);
  const validUntilSec = Math.floor(new Date(`${d.valid_until}T00:00:00Z`).getTime() / 1000);

  // pcf_indirect = 用電強度 × 越南電網係數;pcf_total = direct + indirect(程式計算,不寫死)。
  const pcfIndirect = round4(d.electricity_kwh_per_kg * seed.emission_factor_table.grid_vn_kg_per_kwh);
  const pcfTotal = round4(d.pcf_direct + pcfIndirect);

  const payload: TcCarbonUpstreamPayload = {
    vct: TC_CARBON_UPSTREAM_VCT,
    iss: key.kid,
    iat: issuedAtSec,
    nbf: validFromSec,
    exp: validUntilSec,
    status: { status_list: { idx: statusIdx, uri: statusUri } },
    tcNo: d.tcNo,
    tcStandard: d.tcStandard,
    tcProductStandardLabelGrade: d.tcProductStandardLabelGrade,
    tcProductCategoryCode: seed.transaction.upstream_tc_product_category_code,
    tcProductDetailCode: seed.transaction.upstream_tc_product_detail_code,
    tcCertifiedRawMaterialCountryOrArea: d.tcCertifiedRawMaterialCountryOrArea,
    sellerTeId: d.sellerTeId,
    buyerTeId: d.buyerTeId,
    tcShipmentInvoiceReferences_hash: sha256Hex(d.confidential.invoice_refs),
    unit_price_hash: sha256Hex(d.confidential.unit_price),
    energy_invoice_hash: sha256Hex(d.confidential.energy_invoice),
    recycler_name_hash: sha256Hex(d.confidential.recycler_name),
    emission_factor_table_hash: sha256Hex(seed.emission_factor_table),
    tcProductRawMaterialCode: seed.transaction.upstream_raw_material_code,
    tcProductRawMaterialPercentage: seed.transaction.upstream_raw_material_pct,
    tcProductCertifiedWeight: seed.transaction.yarn_quantity_kg,
    tcShipmentDate: d.tcShipmentDate,
    tcShipmentNo: d.tcShipmentNo,
    inputTcNo: d.inputTcNo,
    tcProductLastProcessorName: d.tcProductLastProcessorName,
    tcProductLastProcessorCountry: d.tcProductLastProcessorCountry,
    pcf_total: pcfTotal,
    pcf_period: d.pcf_period,
    pcf_method: d.pcf_method,
    pcf_direct: d.pcf_direct,
    pcf_indirect: pcfIndirect,
    electricity_kwh_per_kg: d.electricity_kwh_per_kg,
    pcf_factor_source: d.pcf_factor_source,
  };

  // @sd-jwt/sd-jwt-vc 的 SdJwtVcPayload 帶隱含索引簽章(經 SdJwtPayload = Record<string, unknown>),
  // 導致其 Frame<> 條件型別與具名 payload 型別互斥(套件本身的已知型別限制,純型別層面,
  // 不影響執行期行為)——_sd 陣列內容為固定欄位名稱字串,執行期原樣傳入 pack(),故以型別斷言繞過。
  const disclosureFrame = {
    _sd: [...TC_UPSTREAM_BRAND_SD_FIELDS, ...TC_UPSTREAM_AUDIT_SD_FIELDS],
  } as unknown as DisclosureFrame<SdJwtVcPayload>;

  const instance = buildIssuerInstance(key);
  const sdJwt = await instance.issue(payload as unknown as SdJwtVcPayload, disclosureFrame, { header: { kid: key.kid } });

  return {
    id,
    caseId,
    sdJwt,
    payload,
    issuedAt: d.issued_at,
    validFrom: d.valid_from,
    validUntil: d.valid_until,
    issuerParty: 'yarn',
    holderParty: 'fab',
    statusIdx,
    statusUri,
  };
}
