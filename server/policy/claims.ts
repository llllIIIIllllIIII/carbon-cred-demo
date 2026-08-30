/**
 * pcf_aggregate 揭露欄位標籤表(幕 3/4 Cedar P1/P2 用)——把「欄位名稱」對應到揭露層級 tag
 * (public / brand / audit / confidential;spec v3 §0.2 #7),供 server/policy/cedar.ts 組
 * resource entity 的 tag/claim/granularity_rank 屬性。
 *
 * H2 算術洩漏防線(Phase 2 總驗收,v3 維持):三段聚合分項 pcf_yarn / pcf_knitting / pcf_dyeing
 * 任兩項與 pcf_total 相減即還原第三項與布廠自家織布強度——故跨組織 presentation 只能有一個
 * 排放數字(pcf_total),三個分項既不進 M2.allowed_claims(政策層),presenter 亦硬拒(挑
 * disclosure 層)。三段疊層熱點圖走 Tab 2 伺服端真值,不經 presentation。
 *
 * CONFIDENTIAL_CLAIM_NAMES(spec v3 §6 P2 註解)不論是否為 pcf_aggregate 的實際欄位皆標記
 * confidential——幕 4「越界索取 plant_total_output」demo 的重點正是:Agent-2 索取一個從未
 * 出現在任何可揭露層的欄位名稱,閘道仍必須辨識並以 P2 擋下(而非回「查無此欄位」這種較沒
 * 說服力的錯誤),POLICY_P2_CONFIDENTIAL 才是正確理由碼。
 */
import {
  PCF_AGGREGATE_PUBLIC_FIELDS,
  PCF_AGGREGATE_BRAND_SD_FIELDS,
  PCF_AGGREGATE_AUDIT_SD_FIELDS,
  type ClaimTag,
} from '../../shared/types';

export type { ClaimTag };

/**
 * spec v3 §6 P2 註解列舉之機密標籤欄位(12 項)——即便不曾出現於任何已簽發憑證明文,
 * 仍須辨識並標記(憑證內只有對應 *_hash commitment)。
 */
export const CONFIDENTIAL_CLAIM_NAMES = [
  'plant_total_output',
  'capacity_utilization',
  'other_customers',
  'brand_allocation_share',
  'monthly_utility_commitments',
  'utility_invoice_ref',
  'chemical_inventory',
  'fuel_contract',
  'boiler_model',
  'ppa_price',
  'recycler_name',
  'unit_price',
] as const;

const PCF_AGGREGATE_CLAIM_TAGS: Record<string, ClaimTag> = {
  ...Object.fromEntries(PCF_AGGREGATE_PUBLIC_FIELDS.map((k) => [k, 'public' as const])),
  ...Object.fromEntries(PCF_AGGREGATE_BRAND_SD_FIELDS.map((k) => [k, 'brand' as const])),
  ...Object.fromEntries(PCF_AGGREGATE_AUDIT_SD_FIELDS.map((k) => [k, 'audit' as const])),
};

/** pcf_aggregate 可揭露之全部欄位(公開層 + 品牌層 SD + 稽核層 SD)。 */
export const PCF_AGGREGATE_ALL_FIELDS: string[] = Object.keys(PCF_AGGREGATE_CLAIM_TAGS);

/**
 * 跨組織揭露的絕對排除名單(H2,v3 對象):三段聚合分項。任兩項相減即可還原第三項與
 * 布廠自家織布強度,故三者不得出現在任何跨組織 presentation 內——既不進任何 allowed_claims
 * (政策層),presenter 亦硬拒(挑 disclosure 層)。這三欄仍以 SD 形式留在 pcf_aggregate
 * 憑證內(FAB 自持,幕 2 疊層圖走伺服端 aggregate API 真值),只是永遠挑不出來給下游。
 */
export const NEVER_DISCLOSABLE_CLAIMS = ['pcf_yarn', 'pcf_knitting', 'pcf_dyeing'] as const;

export function isNeverDisclosable(claim: string): boolean {
  return (NEVER_DISCLOSABLE_CLAIMS as readonly string[]).includes(claim);
}

/**
 * M2 allowed_claims(spec v3 §5.2)= pcf_aggregate 品牌層六欄,恰為:
 * pcf_total、pcf_period、pcf_method、tcProductRawMaterialPercentage、verification、quantity_kg
 * ——排放數字恰一個(pcf_total),單憑 presentation 無法以加減還原任何分項。
 */
export const M2_ALLOWED_CLAIMS: string[] = [...PCF_AGGREGATE_BRAND_SD_FIELDS];

/** 是否為 pcf_aggregate 的 SD(可挑選揭露)欄位;public 層欄位恆常可見,不需要(也不能)被挑選。 */
export function isSelectableDisclosure(claim: string): boolean {
  const tag = PCF_AGGREGATE_CLAIM_TAGS[claim];
  return tag === 'brand' || tag === 'audit';
}

/** 欄位名稱 → 揭露層級 tag(機密名單優先於 pcf_aggregate 欄位表;皆不符則為 unknown)。 */
export function tagForClaim(claim: string): ClaimTag {
  if ((CONFIDENTIAL_CLAIM_NAMES as readonly string[]).includes(claim)) return 'confidential';
  return PCF_AGGREGATE_CLAIM_TAGS[claim] ?? 'unknown';
}

/** granularity rank(僅 batch 一級;plant-level / machine-level 資料本就不存在於任何可揭露憑證中)。 */
export const GRANULARITY_RANK = { batch: 0 } as const;
