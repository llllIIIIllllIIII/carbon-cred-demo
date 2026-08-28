/**
 * pcf_aggregate 揭露欄位標籤表(幕 3/4 Cedar P1/P2 用)——把「欄位名稱」對應到揭露層級 tag,
 * 供 server/policy/cedar.ts 組 resource entity 的 tag/claim/granularity_rank 屬性。
 *
 * 幕 3 disclose 消費對象是該案 pcf_aggregate(規格v2:155-157 之欄位名列的是 pcf_upstream 欄位,
 * 故須做欄位映射,見 M2_ALLOWED_CLAIMS)。
 *
 * H2 修正(Phase 2 總驗收):舊版把 M2_ALLOWED_CLAIMS 設為「pcf_aggregate 七欄扣 precursor」,
 * 同時放行 carbon_total(1.5125)、self_direct(0.08)、self_indirect(0.33) 三個排放數字——
 * 因聚合公式是三者相加(shared/types.ts §4.3),買方一減就還原被擋下的
 * precursor_contribution(1.5125−0.08−0.33=1.1025),再 ÷ 投入係數即得上游合計(1.05)。
 * 這是**算術洩漏**,不是揭露政策問題:最小揭露被完全繞過。改回規格v2:155-157 的語意——
 * allowed_claims 內**只能有一個排放數字**(買方該看到的聚合值,§4.2:102「歐盟 Agent 只看得到
 * 聚合值」),三個分項欄位一律不得由 M2 揭露(NEVER_DISCLOSABLE_CLAIMS)。
 *
 * CONFIDENTIAL_CLAIM_NAMES(規格v2 §6 P2 註解)不論是否為 pcf_aggregate 的實際欄位皆標記
 * confidential——幕 4「越界索取 machine_energy」demo 的重點正是:Agent-2 索取一個從未出現在
 * 任何已簽發憑證裡的欄位名稱,閘道仍必須辨識並以 P2 擋下(而非回「查無此欄位」這種較沒
 * 說服力的錯誤),POLICY_P2_CONFIDENTIAL 才是正確理由碼。
 */
import { PCF_AGGREGATE_PUBLIC_FIELDS, PCF_AGGREGATE_CUSTOMS_SD_FIELDS, PCF_AGGREGATE_CUSTOMER_SD_FIELDS } from '../../shared/types';

export type ClaimTag = 'public' | 'customs' | 'customer' | 'confidential' | 'unknown';

/** 規格v2 §6 P2 註解列舉之機密標籤欄位——即便不曾出現於任何已簽發憑證,仍須辨識並標記。 */
export const CONFIDENTIAL_CLAIM_NAMES = ['machine_energy', 'ppa_contract', 'recipe', 'customer_list', 'capacity_utilization'] as const;

const PCF_AGGREGATE_CLAIM_TAGS: Record<string, ClaimTag> = {
  ...Object.fromEntries(PCF_AGGREGATE_PUBLIC_FIELDS.map((k) => [k, 'public' as const])),
  ...Object.fromEntries(PCF_AGGREGATE_CUSTOMS_SD_FIELDS.map((k) => [k, 'customs' as const])),
  ...Object.fromEntries(PCF_AGGREGATE_CUSTOMER_SD_FIELDS.map((k) => [k, 'customer' as const])),
};

/** pcf_aggregate 可揭露之全部欄位(7 個:2 公開層 + 1 海關層 SD + 4 客戶層 SD)。 */
export const PCF_AGGREGATE_ALL_FIELDS: string[] = Object.keys(PCF_AGGREGATE_CLAIM_TAGS);

/**
 * 跨組織揭露的絕對排除名單(H2 + 遺留 b + L4 縱深防禦):聚合公式的三個分項。
 * 任何兩項相加減即可還原第三項與上游合計,故三者不得同時、也不得個別出現在跨組織
 * presentation 內——既不進 M2.allowed_claims(政策層),presenter 亦硬拒(挑 disclosure 層)。
 * 這三欄仍以 SD 形式留在 pcf_aggregate 憑證內(鴻鋼自持,幕 2 疊層圖走伺服端 aggregate API
 * 真值,不經 disclose presentation),只是永遠挑不出來給下游。
 */
export const NEVER_DISCLOSABLE_CLAIMS = [
  'precursor_contribution_tco2e_per_t',
  'self_direct_tco2e_per_t',
  'self_indirect_tco2e_per_t',
] as const;

export function isNeverDisclosable(claim: string): boolean {
  return (NEVER_DISCLOSABLE_CLAIMS as readonly string[]).includes(claim);
}

/**
 * M2 allowed_claims(規格v2:155-157 → pcf_aggregate 欄位映射):
 *   cn_code                            → cn_code(公開層,同名)
 *   quantity_t / country_of_origin     → pcf_aggregate 無對應欄位(批量與原產地屬 pcf_upstream/invoice),省略
 *   specific_direct_embedded_emissions → carbon_total_tco2e_per_t(§4.2:102「聚合值」= 買方該看到的唯一排放數字)
 *   production_route                   → pcf_aggregate 無對應欄位(上游製程路徑不下傳),省略
 *   carbon_price_paid_origin           → carbon_price_paid_origin(同名,台灣碳費)
 *   (另加 precursor_ref:公開層之上游參照指紋,只有 id + hash,無排放數字,不構成算術洩漏)
 * 結果:揭露欄位中排放數字恰為 1 個 → 單憑 presentation 無法以加減還原
 * precursor_contribution(1.1025)或上游合計(1.05)。
 */
export const M2_ALLOWED_CLAIMS: string[] = PCF_AGGREGATE_ALL_FIELDS.filter((f) => !isNeverDisclosable(f));

/** 是否為 pcf_aggregate 的 SD(可挑選揭露)欄位;public 層欄位恆常可見,不需要(也不能)被挑選。 */
export function isSelectableDisclosure(claim: string): boolean {
  const tag = PCF_AGGREGATE_CLAIM_TAGS[claim];
  return tag === 'customs' || tag === 'customer';
}

/** 欄位名稱 → 揭露層級 tag(機密名單優先於 pcf_aggregate 欄位表;皆不符則為 unknown)。 */
export function tagForClaim(claim: string): ClaimTag {
  if ((CONFIDENTIAL_CLAIM_NAMES as readonly string[]).includes(claim)) return 'confidential';
  return PCF_AGGREGATE_CLAIM_TAGS[claim] ?? 'unknown';
}

/** granularity rank(Phase 2 僅有 batch 一級;machine-level 資料本就不存在於任何可揭露憑證中)。 */
export const GRANULARITY_RANK = { batch: 0 } as const;
