/**
 * SD-JWT VC 驗證包裝——僅做簽章 + 揭露完整性驗證(RFC 9901 core)。
 * Token Status List 與 vLEI 鏈查驗屬幕 3 Bruck 端管線(架構決策 §4:POST /api/verify),
 * 不在本檔範圍;此處 disableStatusVerification:true 只證明「這把鑰真的簽過這包 claims」,
 * 供幕 1 Tab 1 展示 verify() 通過與竄改後驗證失敗(DoD,藍圖:133)。
 *
 * L1 修正(Phase 1 總驗收):失敗原因分三類,不再一律回同一個理由碼——
 *   解析失敗(header/payload 非合法 JWT)→ CREDENTIAL_PARSE_ERROR;
 *   簽發者未登錄於 manifest(找不到 kid 對應公鑰)→ ISSUER_UNKNOWN;
 *   簽章或揭露完整性不符(其餘情況,含竄改後驗證失敗)→ CREDENTIAL_SIG_INVALID。
 */
import crypto from 'node:crypto';
import { decodeProtectedHeader } from 'jose';
import { SDJwtVcInstance, type SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc';
import { HASH_ALG, sha256Hasher, toVerifier } from './primitives';
import { CODES, type ReasonCode } from '../../shared/codes';

export interface VerifyResult {
  ok: boolean;
  payload?: SdJwtVcPayload;
  header?: Record<string, unknown>;
  /**
   * C1 修正(Phase 2 總驗收):實際用來驗章的 kid(= protected header 的 kid,對應解出的公鑰)。
   * 上層(verifyPresentation 的 vct↔AID 綁定)必須拿這個值比對,不得只信 payload.iss——
   * 兩者脫鉤時,攻擊者可用自己的鑰簽章、把 iss 填成他人 AID 通過綁定檢查(已由 PoC 證實)。
   * 只在 ok:true 時有意義(ok:false 代表這把鑰沒簽過這包 claims)。
   */
  kid?: string;
  error?: string;
  reasonCode?: ReasonCode;
}

function buildVerifierInstance(publicKey: crypto.KeyObject): SDJwtVcInstance {
  return new SDJwtVcInstance({
    hasher: sha256Hasher,
    hashAlg: HASH_ALG,
    verifier: toVerifier(publicKey),
  });
}

/** 依 instance.verify() 拋出之錯誤訊息粗分類:解析層(header/payload 非合法 JWT)vs 簽章/揭露層(預設)。 */
function classifyVerifyError(e: unknown): ReasonCode {
  const message = e instanceof Error ? e.message : String(e);
  if (/Invalid JWT as input|Unexpected token|is not valid JSON|JSON\.parse/i.test(message)) {
    return CODES.CREDENTIAL_PARSE_ERROR;
  }
  return CODES.CREDENTIAL_SIG_INVALID;
}

/**
 * 驗證 compact SD-JWT(含 disclosures)。resolvePublicKey 依 unverified header 的 kid
 * 解出對應公鑰(公開材料,如 manifest.json 之 verkey);找不到公鑰或簽章/揭露驗證失敗
 * 一律回傳 { ok:false }, 不丟例外中斷呼叫端路由;reasonCode 供路由對應回傳理由碼。
 */
export async function verifyCompactSdJwt(
  sdJwtCompact: string,
  resolvePublicKey: (kid: string | undefined) => crypto.KeyObject | undefined,
): Promise<VerifyResult> {
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(sdJwtCompact);
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e), reasonCode: CODES.CREDENTIAL_PARSE_ERROR };
  }

  const publicKey = resolvePublicKey(header.kid);
  if (!publicKey) {
    return {
      ok: false,
      error: `找不到 kid=${header.kid ?? '(無)'} 對應的公鑰(manifest 未登錄此簽發者)`,
      reasonCode: CODES.ISSUER_UNKNOWN,
    };
  }

  try {
    const instance = buildVerifierInstance(publicKey);
    const result = await instance.verify(sdJwtCompact, { disableStatusVerification: true });
    // kid 回傳「實際解出驗章公鑰所用的 kid」——驗章已通過,故這把鑰確實簽過這包 claims(C1)。
    return { ok: true, payload: result.payload, header: result.header, kid: header.kid };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e), reasonCode: classifyVerifyError(e) };
  }
}
