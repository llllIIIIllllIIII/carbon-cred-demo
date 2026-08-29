/**
 * pcf_upstream — Thép Việt 產品碳足跡 SD-JWT VC(幕 1 核心;架構決策 §4:POST /api/issue/upstream)。
 * 以 data/seed.json 之案件 A/B 資料預填簽發;issued_at/valid_from/valid_until 直接取自
 * seed(2026-05-29 起,涵蓋 2026-Q3)——回填約三個月前,非簽發當日臨時產生(規格v2:273)。
 *
 * 欄位三分法(出處見 shared/types.ts 之常數註解 → 規格v2:89-94):
 *   公開層 / 海關層(SD)/ 客戶層(SD)/ 永不揭露(→ commitment hash)。
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
  PCF_UPSTREAM_CUSTOMS_SD_FIELDS,
  PCF_UPSTREAM_CUSTOMER_SD_FIELDS,
  type PcfUpstreamCaseId,
  type PcfUpstreamPayload,
} from '../../shared/types';

export const PCF_UPSTREAM_VCT = 'https://carbon-cred-demo.local/vct/pcf_upstream';

/** 案件於 credentials Token Status List 之固定 idx(0=A、1=B;idx≥2 留給未來憑證,如 pcf_aggregate)。 */
export const PCF_UPSTREAM_STATUS_IDX: Record<PcfUpstreamCaseId, number> = { A: 0, B: 1 };

interface SeedData {
  transaction: { upstream_cn_code: string; quantity_t: number; country_of_origin: string };
  pcf_defaults: {
    issued_at: string;
    valid_from: string;
    valid_until: string;
    electricity_mix_ref: string;
    installation_unlocode: string;
    dqr: number;
    primary_data_share: number;
    carbon_price_paid_origin: string;
    confidential: {
      machine_energy: string;
      ppa_contract: string;
      recipe: string;
      customer_list: string;
      capacity_utilization: number;
    };
    emission_factor_table: {
      electricity_vn_2025_kg_per_kwh: number;
      eaf_route_direct_t_per_t: number;
      bf_bof_route_direct_t_per_t: number;
    };
  };
  cases: Record<string, { production_route: 'EAF' | 'BF-BOF'; direct: number; indirect: number }>;
}

function readSeed(): SeedData {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8'));
}

/** SHA-256 commitment hash(hex)——機密原始資料永不進憑證,只留此雜湊。 */
function sha256Hex(value: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

export interface PcfUpstreamIssuance {
  id: string;
  caseId: PcfUpstreamCaseId;
  sdJwt: string;
  payload: PcfUpstreamPayload;
  issuedAt: string;
  validFrom: string;
  validUntil: string;
  issuerParty: 'yarn';
  holderParty: 'fab';
  statusIdx: number;
  statusUri: string;
}

/** 簽出 pcf_upstream(Thép Việt sandbox LE AID 鑰;caseId 決定 production_route/direct/indirect)。 */
export async function issuePcfUpstream(caseId: PcfUpstreamCaseId): Promise<PcfUpstreamIssuance> {
  const seed = readSeed();
  const caseData = seed.cases[caseId];
  if (!caseData) throw new Error(`未知案件 case_id=${caseId}(pcf_upstream 僅支援 A/B)`);
  const d = seed.pcf_defaults;
  const key = loadSandboxKey('yarn');

  const statusIdx = PCF_UPSTREAM_STATUS_IDX[caseId];
  const statusUri = statusListUri('credentials');

  const issuedAtSec = Math.floor(new Date(`${d.issued_at}T00:00:00Z`).getTime() / 1000);
  const validFromSec = Math.floor(new Date(`${d.valid_from}T00:00:00Z`).getTime() / 1000);
  const validUntilSec = Math.floor(new Date(`${d.valid_until}T00:00:00Z`).getTime() / 1000);

  // emission_factor_table_hash 含 capacity_utilization(規格v2:94,2026-08 訪談 Q5 增列)。
  const emissionFactorTableForHash = {
    electricity_vn_2025_kg_per_kwh: d.emission_factor_table.electricity_vn_2025_kg_per_kwh,
    eaf_route_direct_t_per_t: d.emission_factor_table.eaf_route_direct_t_per_t,
    bf_bof_route_direct_t_per_t: d.emission_factor_table.bf_bof_route_direct_t_per_t,
    capacity_utilization: d.confidential.capacity_utilization,
  };

  const payload: PcfUpstreamPayload = {
    vct: PCF_UPSTREAM_VCT,
    iss: key.kid,
    iat: issuedAtSec,
    nbf: validFromSec,
    exp: validUntilSec,
    status: { status_list: { idx: statusIdx, uri: statusUri } },
    cn_code: seed.transaction.upstream_cn_code,
    quantity_t: seed.transaction.quantity_t,
    country_of_origin: seed.transaction.country_of_origin,
    machine_energy_hash: sha256Hex(d.confidential.machine_energy),
    ppa_contract_hash: sha256Hex(d.confidential.ppa_contract),
    recipe_hash: sha256Hex(d.confidential.recipe),
    customer_list_hash: sha256Hex(d.confidential.customer_list),
    emission_factor_table_hash: sha256Hex(emissionFactorTableForHash),
    specific_direct_embedded_emissions: caseData.direct,
    production_route: caseData.production_route,
    carbon_price_paid_origin: d.carbon_price_paid_origin,
    specific_indirect_embedded_emissions: caseData.indirect,
    electricity_mix_ref: d.electricity_mix_ref,
    installation_unlocode: d.installation_unlocode,
    dqr: d.dqr,
    primary_data_share: d.primary_data_share,
  };

  // @sd-jwt/sd-jwt-vc 的 SdJwtVcPayload 帶隱含索引簽章(經 SdJwtPayload = Record<string, unknown>),
  // 導致其 Frame<> 條件型別與具索引簽章的 payload 型別互斥(套件本身的已知型別限制,純型別層面,
  // 不影響執行期行為)——_sd 陣列內容為固定欄位名稱字串,執行期原樣傳入 pack(),故以型別斷言繞過。
  const disclosureFrame = {
    _sd: [...PCF_UPSTREAM_CUSTOMS_SD_FIELDS, ...PCF_UPSTREAM_CUSTOMER_SD_FIELDS],
  } as unknown as DisclosureFrame<SdJwtVcPayload>;

  const instance = buildIssuerInstance(key);
  const sdJwt = await instance.issue(payload as unknown as SdJwtVcPayload, disclosureFrame, { header: { kid: key.kid } });

  return {
    id: `pcf_upstream-${caseId}`,
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
