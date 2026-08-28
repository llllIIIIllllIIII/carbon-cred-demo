/** 共用型別:憑證 / 委任 / 決策(Phase 0 基礎版,後續幕次擴充)。 */

/** Token Status List 引用(draft-ietf-oauth-status-list-21):credential 與 mandate 一律以此結構掛撤銷參照。 */
export interface StatusListRefEntry {
  idx: number;
  uri: string;
}

export interface CredentialStatus {
  status_list: StatusListRefEntry;
}

/** manifest.json 之單一角色(公開材料;私鑰永不在此)。 */
export interface ManifestRole {
  alias: string;
  aid: string;
  lei: string;
  legal_name: string;
  kind: 'le' | 'ecr';
  credential_said: string;
  presentation_file: string;
  public_key: string; // CESR qb64 verkey(D 開頭)
}

export type Manifest = Record<string, ManifestRole>;

/** 委任狀共通欄位(M1/M2;spec §5)。 */
export interface MandateBase {
  jti: string;
  iss: string;
  aud: string;
  delegate_kid: string;
  allowed_claims: string[];
  max_granularity: 'batch';
  policy_version: string;
  mandate_nonce: string;
  valid_from: string;
  valid_until: string;
  status: CredentialStatus;
}

/** 'M1' | 'M2'(db/schema.sql mandates.id 之固定值;非 mandate.jti)。 */
export type MandateId = 'M1' | 'M2';

/**
 * mandate 簽發時之完整 compact JWT payload(幕 3 前置;架構決策 §4:POST /api/mandates)——
 * MandateBase 的展示用 valid_from/valid_until(ISO 日期字串)之外,另附 JWT 註冊聲明
 * iat/nbf/exp(epoch seconds),供閘道以 jose jwtVerify 驗 iss/aud/exp/jti(impl-spec §0 驗證順序)。
 * query_cap/purpose/agent_id 為選配(M1/M2 內容不完全相同;規格v2 §5.1/5.2)。
 */
export interface MandatePayload extends MandateBase {
  iat: number;
  nbf: number;
  exp: number;
  query_cap?: number;
  purpose?: string;
  agent_id?: string;
}

/**
 * disclose request(幕 3/4)之 compact JWS payload——由 bruck-workload(或 hunggang-workload)鑰
 * 簽章,header.kid 須等於對應 mandate.delegate_kid(impl-spec §2)。
 */
export interface DiscloseRequestPayload {
  /** 對應 mandate 之 jti(非 db mandates.id)。 */
  mandate_id: string;
  case_id: PcfAggregateCaseId;
  requested_claims: string[];
  request_nonce: string;
  iat: number;
}

/** Cedar 前之可信 context 布林(後端預驗證產出;政策僅消費布林)。 */
export interface TrustedContext {
  mandate_status_ok: boolean;
  delegate_key_ok: boolean;
  replay_ok: boolean;
}

export type DecisionEffect = 'PERMIT' | 'DENY' | 'RELEASE' | 'REPLAY_DETECTED';

/**
 * pcf_upstream(Thép Việt 產品碳足跡 SD-JWT VC,幕 1)欄位三分法——
 * 出處:docs/demo情境設定與合成資料規格-v2.md:89-94。
 *
 * 公開層(非 SD 明文):cn_code/quantity_t/country_of_origin/簽發者(iss)/簽發日(iat)/
 *   status.status_list,加上四個機密項目的 commitment hash(「當一般 claim」— 藍圖:123 —
 *   不可撕、恆常可見,因為 hash 本身不洩漏原始資料)。
 * 海關層(SD 可撕,法定):specific_direct_embedded_emissions/production_route/carbon_price_paid_origin。
 * 客戶層(SD 可撕,合約):specific_indirect_embedded_emissions/electricity_mix_ref/
 *   installation_unlocode/dqr/primary_data_share。
 * 永不揭露(規格v2:94,含 2026-08 訪談 Q5 新增之 capacity_utilization):
 *   機台級能耗結構/PPA/配方/客戶名單 → 各自 SHA-256 commitment hash;
 *   排放係數表(含 capacity_utilization)→ emission_factor_table_hash。
 */
export const PCF_UPSTREAM_PUBLIC_FIELDS = [
  'cn_code',
  'quantity_t',
  'country_of_origin',
  'machine_energy_hash',
  'ppa_contract_hash',
  'recipe_hash',
  'customer_list_hash',
  'emission_factor_table_hash',
] as const;

export const PCF_UPSTREAM_CUSTOMS_SD_FIELDS = [
  'specific_direct_embedded_emissions',
  'production_route',
  'carbon_price_paid_origin',
] as const;

export const PCF_UPSTREAM_CUSTOMER_SD_FIELDS = [
  'specific_indirect_embedded_emissions',
  'electricity_mix_ref',
  'installation_unlocode',
  'dqr',
  'primary_data_share',
] as const;

/** 永不進憑證的機密項目名稱(僅供前端說明文字使用;數值本身不存在於憑證任何層)。 */
export const PCF_UPSTREAM_CONFIDENTIAL_FIELDS = ['machine_energy', 'ppa_contract', 'recipe', 'customer_list', 'capacity_utilization'] as const;

export type PcfUpstreamCaseId = 'A' | 'B';

/** pcf_aggregate 案件同一組 A/B(語意別名,讀起來對應幕 2 情境)。 */
export type PcfAggregateCaseId = PcfUpstreamCaseId;

/** pcf_upstream 完整 claims 形狀(簽發時之未過濾版本;三分法欄位皆在同一物件內,SD 與否由 disclosureFrame 決定)。 */
export interface PcfUpstreamPayload {
  vct: string;
  iss: string;
  iat: number;
  nbf: number;
  exp: number;
  status: CredentialStatus;
  cn_code: string;
  quantity_t: number;
  country_of_origin: string;
  machine_energy_hash: string;
  ppa_contract_hash: string;
  recipe_hash: string;
  customer_list_hash: string;
  emission_factor_table_hash: string;
  specific_direct_embedded_emissions: number;
  production_route: 'EAF' | 'BF-BOF';
  carbon_price_paid_origin: string;
  specific_indirect_embedded_emissions: number;
  electricity_mix_ref: string;
  installation_unlocode: string;
  dqr: number;
  primary_data_share: number;
}

/**
 * pcf_aggregate(鴻鋼扣件 PCF VC,幕 2)欄位設計——出處:demo情境設定與合成資料規格-v2.md §4.3
 * (98-102 行)、2026-08-26-專案架構決策.md §4(POST /api/aggregate)。
 * 聚合值 = 前驅物內含排放(上游 direct+indirect 客戶層揭露值) × 投入係數 + 自身 direct + 自身 indirect
 * (規格v2:100,如 1.05×1.05+0.08+0.33≈1.51)。本憑證即 Tier-N 最小揭露之終點:
 * 不含上游任何明細欄位(specific_direct_embedded_emissions/production_route/
 * specific_indirect_embedded_emissions 等一律不出現),只留 precursor_ref 這個參照指紋。
 *
 * 公開層(非 SD 明文):cn_code(下游 CN code)、簽發者(iss)/簽發日(iat)/status.status_list、
 *   precursor_ref(上游憑證 id + sha256 hash)。
 * 買方合約層(SD 可撕,合約用途,非法定):carbon_total_tco2e_per_t(聚合總值,對應買方合約
 *   ≤2.00 tCO2e/t 的 direct+indirect 門檻;規格v2:20、74——CBAM 正式期鋼鐵類申報僅計 direct,
 *   本欄位含 indirect,不對應 CBAM 申報,不得標示為海關層)。
 * 客戶層(SD 可撕,合約用途,供幕 3 M2 mandate 之下游查驗;疊層熱點圖三段真值來源):
 *   precursor_contribution_tco2e_per_t、self_direct_tco2e_per_t、self_indirect_tco2e_per_t、
 *   carbon_price_paid_origin(台灣碳費;規格v2:101)。
 */
export const PCF_AGGREGATE_PUBLIC_FIELDS = ['cn_code', 'precursor_ref'] as const;

export const PCF_AGGREGATE_CUSTOMS_SD_FIELDS = ['carbon_total_tco2e_per_t'] as const;

export const PCF_AGGREGATE_CUSTOMER_SD_FIELDS = [
  'precursor_contribution_tco2e_per_t',
  'self_direct_tco2e_per_t',
  'self_indirect_tco2e_per_t',
  'carbon_price_paid_origin',
] as const;

/** 上游憑證參照指紋(藍圖:150:「precursor_ref = 上游 VC 的 id + hash,不含上游任何明細欄位」)。 */
export interface PrecursorRef {
  id: string;
  hash: string;
}

/** pcf_aggregate 完整 claims 形狀(簽發時之未過濾版本;SD 與否由 disclosureFrame 決定)。 */
export interface PcfAggregatePayload {
  vct: string;
  iss: string;
  iat: number;
  nbf: number;
  exp: number;
  status: CredentialStatus;
  cn_code: string;
  precursor_ref: PrecursorRef;
  carbon_total_tco2e_per_t: number;
  precursor_contribution_tco2e_per_t: number;
  self_direct_tco2e_per_t: number;
  self_indirect_tco2e_per_t: number;
  carbon_price_paid_origin: string;
}
