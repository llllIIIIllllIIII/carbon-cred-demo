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
 * disclose request(幕 3/4)之 compact JWS payload——由 brand-workload(或 fab-workload)鑰
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

/** 揭露三層 tag(spec v3 §0.2 #7:公開/品牌/稽核;confidential 僅指紋)。 */
export type ClaimTag = 'public' | 'brand' | 'audit' | 'confidential' | 'unknown';

/**
 * tc_carbon_upstream(YARN 紗廠「TC + 碳」SD-JWT VC,幕 1)欄位三分法——spec v3 §4.2。
 * TC 有的欄位用 Textile Exchange 官方 camelCase 鍵名原樣(ASR-104);pcf_* 為我方延伸
 * (TC 本身無碳數據)。A/B 兩案紗憑證相同(差異在染整段)。
 */
export const TC_UPSTREAM_PUBLIC_FIELDS = [
  'tcNo',
  'tcStandard',
  'tcProductStandardLabelGrade',
  'tcProductCategoryCode',
  'tcProductDetailCode',
  'tcCertifiedRawMaterialCountryOrArea',
  'sellerTeId',
  'buyerTeId',
  'tcShipmentInvoiceReferences_hash',
  'unit_price_hash',
  'energy_invoice_hash',
  'recycler_name_hash',
  'emission_factor_table_hash',
] as const;

export const TC_UPSTREAM_BRAND_SD_FIELDS = [
  'tcProductRawMaterialCode',
  'tcProductRawMaterialPercentage',
  'tcProductCertifiedWeight',
  'tcShipmentDate',
  'tcShipmentNo',
  'inputTcNo',
  'tcProductLastProcessorName',
  'tcProductLastProcessorCountry',
  'pcf_total',
  'pcf_period',
  'pcf_method',
] as const;

export const TC_UPSTREAM_AUDIT_SD_FIELDS = ['pcf_direct', 'pcf_indirect', 'electricity_kwh_per_kg', 'pcf_factor_source'] as const;

/** 永不進憑證明文的機密項目名稱(數值只以 *_hash commitment 存在)。 */
export const TC_UPSTREAM_CONFIDENTIAL_FIELDS = ['invoice_refs', 'unit_price', 'energy_invoice', 'recycler_name'] as const;

/** pcf_dyeing(DYE 染整工段 SD-JWT VC;spec v3 §4.3)——A/B 差異全部來自此憑證。 */
export const PCF_DYEING_PUBLIC_FIELDS = [
  'process',
  'facility_country',
  'zdhc_incheck_level',
  'boiler_model_hash',
  'fuel_contract_hash',
  'chemical_inventory_hash',
  'ppa_price_hash',
  'emission_factor_table_hash',
] as const;

export const PCF_DYEING_BRAND_SD_FIELDS = ['pcf_total', 'heat_source', 'renewable_share', 'pcf_period', 'pcf_method'] as const;

export const PCF_DYEING_AUDIT_SD_FIELDS = [
  'heat_mj_per_kg',
  'electricity_kwh_per_kg',
  'boiler_efficiency',
  'pcf_direct',
  'pcf_indirect',
  'pcf_factor_source',
] as const;

export const PCF_DYEING_CONFIDENTIAL_FIELDS = ['boiler_model', 'fuel_contract', 'chemical_inventory', 'ppa_price'] as const;

/**
 * pcf_aggregate(FAB 布廠聚合 PCF VC,幕 2 產出/幕 3 查驗對象;spec v3 §4.4)。
 * 三段聚合:紗(外部)× 損耗加成 + 自家織布用電 + 染整(外部);precursor_refs 只留兩張
 * 外部憑證的 id + sha256(sd_jwt),不含任何上游明細。品牌層六欄 = M2 allowed_claims,
 * 排放數字恰一個(pcf_total);pcf_yarn/pcf_knitting/pcf_dyeing 為 NEVER_DISCLOSABLE(H2)。
 */
export const PCF_AGGREGATE_PUBLIC_FIELDS = [
  'product',
  'hs6',
  'origin',
  'tcProductStandardLabelGrade',
  'zdhc_incheck_level',
  'precursor_refs',
  'plant_total_output_hash',
  'capacity_utilization_hash',
  'other_customers_hash',
  'brand_allocation_share_hash',
  'monthly_utility_commitments_hash',
] as const;

/** = M2 六欄(品牌層;spec v3 §5.2)。 */
export const PCF_AGGREGATE_BRAND_SD_FIELDS = [
  'pcf_total',
  'pcf_period',
  'pcf_method',
  'tcProductRawMaterialPercentage',
  'verification',
  'quantity_kg',
] as const;

export const PCF_AGGREGATE_AUDIT_SD_FIELDS = [
  'pcf_yarn',
  'pcf_knitting',
  'pcf_dyeing',
  'yarn_loss_factor',
  'knitting_electricity_kwh_per_kg',
  'pcf_factor_source',
] as const;

export const PCF_AGGREGATE_CONFIDENTIAL_FIELDS = [
  'plant_total_output',
  'capacity_utilization',
  'other_customers',
  'brand_allocation_share',
  'monthly_utility_commitments',
  'utility_invoice_ref',
] as const;

export type HeatSource = 'natural_gas' | 'coal';

export type PcfCaseId = 'A' | 'B';

/** 舊名別名(v2 遺留呼叫端);新程式一律用 PcfCaseId。 */
export type PcfUpstreamCaseId = PcfCaseId;
export type PcfAggregateCaseId = PcfCaseId;

/** 外部憑證參照指紋(id + sha256(sd_jwt),不含上游任何明細欄位)。 */
export interface PrecursorRef {
  id: string;
  hash: string;
}

/** tc_carbon_upstream 完整 claims 形狀(簽發時之未過濾版本;SD 與否由 disclosureFrame 決定)。 */
export interface TcCarbonUpstreamPayload {
  vct: string;
  iss: string;
  iat: number;
  nbf: number;
  exp: number;
  status: CredentialStatus;
  tcNo: string;
  tcStandard: string;
  tcProductStandardLabelGrade: string;
  tcProductCategoryCode: string;
  tcProductDetailCode: string;
  tcCertifiedRawMaterialCountryOrArea: string;
  sellerTeId: string;
  buyerTeId: string;
  tcShipmentInvoiceReferences_hash: string;
  unit_price_hash: string;
  energy_invoice_hash: string;
  recycler_name_hash: string;
  emission_factor_table_hash: string;
  tcProductRawMaterialCode: string;
  tcProductRawMaterialPercentage: number;
  tcProductCertifiedWeight: number;
  tcShipmentDate: string;
  tcShipmentNo: string;
  inputTcNo: string;
  tcProductLastProcessorName: string;
  tcProductLastProcessorCountry: string;
  pcf_total: number;
  pcf_period: string;
  pcf_method: string;
  pcf_direct: number;
  pcf_indirect: number;
  electricity_kwh_per_kg: number;
  pcf_factor_source: string;
}

/** pcf_dyeing 完整 claims 形狀(簽發時之未過濾版本)。 */
export interface PcfDyeingPayload {
  vct: string;
  iss: string;
  iat: number;
  nbf: number;
  exp: number;
  status: CredentialStatus;
  process: string;
  facility_country: string;
  zdhc_incheck_level: string;
  boiler_model_hash: string;
  fuel_contract_hash: string;
  chemical_inventory_hash: string;
  ppa_price_hash: string;
  emission_factor_table_hash: string;
  pcf_total: number;
  heat_source: HeatSource;
  renewable_share: number;
  pcf_period: string;
  pcf_method: string;
  heat_mj_per_kg: number;
  electricity_kwh_per_kg: number;
  boiler_efficiency: number;
  pcf_direct: number;
  pcf_indirect: number;
  pcf_factor_source: string;
}

/** pcf_aggregate 完整 claims 形狀(簽發時之未過濾版本;SD 與否由 disclosureFrame 決定)。 */
export interface PcfAggregatePayload {
  vct: string;
  iss: string;
  iat: number;
  nbf: number;
  exp: number;
  status: CredentialStatus;
  product: string;
  hs6: string;
  origin: string;
  tcProductStandardLabelGrade: string;
  zdhc_incheck_level: string;
  precursor_refs: PrecursorRef[];
  plant_total_output_hash: string;
  capacity_utilization_hash: string;
  other_customers_hash: string;
  brand_allocation_share_hash: string;
  monthly_utility_commitments_hash: string;
  pcf_total: number;
  pcf_period: string;
  pcf_method: string;
  tcProductRawMaterialPercentage: number;
  verification: string;
  quantity_kg: number;
  pcf_yarn: number;
  pcf_knitting: number;
  pcf_dyeing: number;
  yarn_loss_factor: number;
  knitting_electricity_kwh_per_kg: number;
  pcf_factor_source: string;
}
