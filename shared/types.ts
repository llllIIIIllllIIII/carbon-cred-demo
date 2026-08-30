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
  /**
   * M1 專屬授權限額(Codex review P1-2):必須在**簽章 payload** 內,不得只留在未簽的
   * mandates.extra_json——否則同一枚合法 M1 簽章配合被竄改的 DB 欄位即可放行更高金額、
   * 更寬鬆碳排門檻,或別的交易對手方。server/routes/agent.ts 之 P3 管線一律從已驗證的
   * MandatePayload 讀這三欄,不讀 extra_json。M2 無此三欄,恆為 undefined。
   */
  max_amount?: number;
  allowed_counterparties?: string[];
  policy_thresholds?: { carbon_max: number; wallet_risk_max: number; min_sources: number };
  /** Codex review 第二輪 P1-B:M1 約定幣別(USD),供 invoice_ok 比對 invoice.currency,同上理由簽章保護。 */
  currency?: string;
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
 * tc_rcs(CB 認證機構簽發的 Transaction Certificate,幕 1;spec v3.1 §4.2a)欄位三分法。
 * 欄位用 Textile Exchange 官方 camelCase 鍵名原樣(ASR-104);TC 本身沒有碳數據(碳在 pcf_upstream)。
 * A/B 兩案同一張(idx 9);seller_lei/buyer_lei 由 issuer 於簽發時自 manifest 取,不寫死。
 */
export const TC_RCS_PUBLIC_FIELDS = [
  'tcNo',
  'tcStandard',
  'tcProductStandardLabelGrade',
  'tcProductCategoryCode',
  'tcProductDetailCode',
  'tcCertifiedRawMaterialCountryOrArea',
  'sellerTeId',
  'buyerTeId',
  'seller_lei',
  'buyer_lei',
  'volume_reconciled',
  'tcShipmentInvoiceReferences_hash',
] as const;

export const TC_RCS_BRAND_SD_FIELDS = [
  'tcProductRawMaterialCode',
  'tcProductRawMaterialPercentage',
  'tcProductCertifiedWeight',
  'tcShipmentDate',
  'tcShipmentNo',
  'inputTcNo',
  'tcProductLastProcessorName',
  'tcProductLastProcessorCountry',
] as const;

/** pcf_upstream 之 tc_ref(公開層)——綁定 tc_rcs 之 id/tcNo/簽發者 LEI/雜湊。 */
export interface TcRef {
  id: string;
  tcNo: string;
  issuer_lei: string;
  hash: string;
}

/** pcf_dyeing / pcf_aggregate 之 ccs_scope_ref(公開層)——綁定 ccs_scope_cert 之編號/雜湊。 */
export interface CcsScopeRef {
  sc_no: string;
  hash: string;
}

/** ccs_scope_cert.associated_subcontractors 之單一分包商(CCS-101 C5.2.1:附屬分包商,列於委託組織 SC 下受稽核)。 */
export interface AssociatedSubcontractor {
  lei: string;
  name: string;
  process: string;
  audited: boolean;
}

/**
 * ccs_scope_cert(CB 認證機構簽發之布廠 Scope Certificate,seed 時簽;spec v3.1 §4.5)——
 * 全部公開層(非 SD);holder_lei/cb_lei/associated_subcontractors[].lei 由 issuer 於簽發時自
 * manifest 取,不寫死;idx 10;一年效期。
 */
export const CCS_SCOPE_CERT_FIELDS = [
  'sc_no',
  'holder_lei',
  'holder_name',
  'standards',
  'processes',
  'associated_subcontractors',
  'cb_lei',
  'cb_name',
  'valid_from',
  'valid_until',
] as const;

/**
 * pcf_upstream(YARN 紗廠碳足跡 SD-JWT VC,幕 1;spec v3.1 §4.2b)欄位三分法——
 * 公開層帶 tc_ref 綁定 tc_rcs(4.2a);簽發前必先取入庫 tc_rcs,不存在則拒簽(TC_REF_MISMATCH)。
 * A/B 兩案紗憑證相同(差異在染整段)。
 */
export const PCF_UPSTREAM_PUBLIC_FIELDS = [
  'tc_ref',
  'product_code',
  'country_of_origin',
  'unit_price_hash',
  'energy_invoice_hash',
  'recycler_name_hash',
  'emission_factor_table_hash',
] as const;

export const PCF_UPSTREAM_BRAND_SD_FIELDS = ['pcf_total', 'pcf_period', 'pcf_method', 'quantity_kg'] as const;

export const PCF_UPSTREAM_AUDIT_SD_FIELDS = ['pcf_direct', 'pcf_indirect', 'electricity_kwh_per_kg', 'pcf_factor_source'] as const;

/** 永不進憑證明文的機密項目名稱(數值只以 *_hash commitment 存在)。 */
export const PCF_UPSTREAM_CONFIDENTIAL_FIELDS = ['unit_price', 'energy_invoice', 'recycler_name'] as const;

/** pcf_dyeing(DYE 染整工段 SD-JWT VC;spec v3.1 §4.3)——A/B 差異全部來自此憑證。 */
export const PCF_DYEING_PUBLIC_FIELDS = [
  'process',
  'facility_country',
  'zdhc_incheck_level',
  'ccs_subcontractor_status',
  'ccs_scope_ref',
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
 * pcf_aggregate(FAB 布廠聚合 PCF VC,幕 2 產出/幕 3 查驗對象;spec v3.1 §4.4)。
 * 三段聚合:紗(外部)× 損耗加成 + 自家織布用電 + 染整(外部);precursor_refs 留三張
 * 外部憑證(tc_rcs、pcf_upstream、pcf_dyeing)的 id + sha256(sd_jwt),不含任何上游明細。
 * 品牌層六欄 = M2 allowed_claims,排放數字恰一個(pcf_total);pcf_yarn/pcf_knitting/pcf_dyeing
 * 為 NEVER_DISCLOSABLE(H2)。不放稅則碼(移除 hs6);tcProductStandardLabelGrade 由 tc_rcs + 有效
 * ccs_scope_cert 推導,不再自填。
 */
export const PCF_AGGREGATE_PUBLIC_FIELDS = [
  'product',
  'origin',
  'tcProductStandardLabelGrade',
  'zdhc_incheck_level',
  'ccs_scope_ref',
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

/** tc_rcs 完整 claims 形狀(簽發時之未過濾版本;SD 與否由 disclosureFrame 決定;spec v3.1 §4.2a)。 */
export interface TcRcsPayload {
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
  seller_lei: string;
  buyer_lei: string;
  volume_reconciled: boolean;
  tcShipmentInvoiceReferences_hash: string;
  tcProductRawMaterialCode: string;
  tcProductRawMaterialPercentage: number;
  tcProductCertifiedWeight: number;
  tcShipmentDate: string;
  tcShipmentNo: string;
  inputTcNo: string;
  tcProductLastProcessorName: string;
  tcProductLastProcessorCountry: string;
}

/** ccs_scope_cert 完整 claims 形狀(全部公開層,無 SD;spec v3.1 §4.5)。 */
export interface CcsScopeCertPayload {
  vct: string;
  iss: string;
  iat: number;
  nbf: number;
  exp: number;
  status: CredentialStatus;
  sc_no: string;
  holder_lei: string;
  holder_name: string;
  standards: string[];
  processes: Array<{ code: string; name: string; site: string }>;
  associated_subcontractors: AssociatedSubcontractor[];
  cb_lei: string;
  cb_name: string;
  valid_from: string;
  valid_until: string;
}

/** pcf_upstream 完整 claims 形狀(簽發時之未過濾版本;SD 與否由 disclosureFrame 決定;spec v3.1 §4.2b)。 */
export interface PcfUpstreamPayload {
  vct: string;
  iss: string;
  iat: number;
  nbf: number;
  exp: number;
  status: CredentialStatus;
  tc_ref: TcRef;
  product_code: string;
  country_of_origin: string;
  unit_price_hash: string;
  energy_invoice_hash: string;
  recycler_name_hash: string;
  emission_factor_table_hash: string;
  pcf_total: number;
  pcf_period: string;
  pcf_method: string;
  quantity_kg: number;
  pcf_direct: number;
  pcf_indirect: number;
  electricity_kwh_per_kg: number;
  pcf_factor_source: string;
}

/** pcf_dyeing 完整 claims 形狀(簽發時之未過濾版本;spec v3.1 §4.3)。 */
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
  ccs_subcontractor_status: string;
  ccs_scope_ref: CcsScopeRef;
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

/** pcf_aggregate 完整 claims 形狀(簽發時之未過濾版本;SD 與否由 disclosureFrame 決定;spec v3.1 §4.4)。 */
export interface PcfAggregatePayload {
  vct: string;
  iss: string;
  iat: number;
  nbf: number;
  exp: number;
  status: CredentialStatus;
  product: string;
  origin: string;
  tcProductStandardLabelGrade: string;
  zdhc_incheck_level: string;
  ccs_scope_ref: CcsScopeRef;
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
