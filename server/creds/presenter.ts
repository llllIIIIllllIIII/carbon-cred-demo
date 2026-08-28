/**
 * SD-JWT VC 出示(presentation)包裝——幕 3 閘道以持有人身分從 pcf_aggregate 挑選
 * disclosures(architecture:「是挑 disclosure,不是過濾 JSON」)。只需與簽發/驗證共用的
 * hasher 設定以重算 disclosure digest,不需簽章鑰(本檔不觸碰任何私鑰)。
 *
 * L4 縱深防禦(Phase 2 總驗收):聚合分項三欄(NEVER_DISCLOSABLE_CLAIMS)在 tag 表上屬
 * customer 層、isSelectableDisclosure() 回 true,先前唯一防線是 mandate.allowed_claims——
 * 一旦某張 mandate 被誤設(或未來新增第三張),分項就會被挑出來、下游即可用加減還原上游
 * (H2 的算術洩漏)。故在「挑 disclosure」這一層再擋一次:presentSelectedDisclosures 硬拒,
 * 不看 mandate 寫什麼。presentRawDisclosures 為不套用 deny-list 的低階入口,僅供測試模擬
 * 「閘道被繞過/惡意 presenter」以驗證 Bruck 端雙向約束仍能攔下,正式路徑不得使用。
 */
import { SDJwtVcInstance, type SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc';
import type { PresentationFrame } from '@sd-jwt/core';
import { HASH_ALG, sha256Hasher } from './primitives';
import { isNeverDisclosable, NEVER_DISCLOSABLE_CLAIMS } from '../policy/claims';

/** 挑選了永不可跨組織揭露之欄位(L4:presenter 端硬 deny-list;正式路徑不應發生)。 */
export class NeverDisclosableClaimError extends Error {}

function buildPresenterInstance(): SDJwtVcInstance {
  return new SDJwtVcInstance({ hasher: sha256Hasher, hashAlg: HASH_ALG });
}

/** 低階入口:不套用 deny-list,原樣挑選 presentationFrame 指定之揭露(僅供對抗性測試使用)。 */
export async function presentRawDisclosures(
  sdJwtCompact: string,
  presentationFrame: PresentationFrame<SdJwtVcPayload>,
): Promise<string> {
  const instance = buildPresenterInstance();
  return instance.present(sdJwtCompact, presentationFrame);
}

/**
 * 從 compact SD-JWT 挑選 presentationFrame 指定之揭露,組回新的 compact SD-JWT presentation。
 * 挑到 NEVER_DISCLOSABLE_CLAIMS 任一欄即丟 NeverDisclosableClaimError(不靜默略過:靜默會讓
 * 呼叫端以為自己拿到了完整結果,錯誤設定就此埋在 demo 裡)。
 */
export async function presentSelectedDisclosures(
  sdJwtCompact: string,
  presentationFrame: PresentationFrame<SdJwtVcPayload>,
): Promise<string> {
  const denied = Object.keys(presentationFrame as Record<string, unknown>).filter((claim) => isNeverDisclosable(claim));
  if (denied.length > 0) {
    throw new NeverDisclosableClaimError(
      `presenter 硬性拒絕:${denied.join('、')} 屬永不可跨組織揭露欄位(聚合分項,可被加減還原上游;` +
        `全名單:${NEVER_DISCLOSABLE_CLAIMS.join('、')})`,
    );
  }
  return presentRawDisclosures(sdJwtCompact, presentationFrame);
}
