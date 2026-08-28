/**
 * 竄改示範工具(幕 1 DoD,藍圖:133:「手動改 payload 一個 byte → 驗證失敗」;
 * 此失敗畫面留著,幕 6 之前有人問就秀)。純字串操作,不觸碰任何鑰、不做任何簽章/驗章捷徑;
 * 供 scripts/test.ts 與 POST /api/creds/tamper-demo(Tab 1「竄改示範」按鈕)共用同一邏輯。
 *
 * H1 修正(Phase 1 總驗收):原實作直接在 base64url 編碼後的 payload 字串中點翻一個字元,
 * 該位置實測恆落在 customer_list_hash 欄位值中間的 `_` 字元上——翻轉後 base64url 解碼會產生
 * 不合法的 UTF-8 位元組,payload 連 JSON.parse 都過不了,驗證器在還沒驗簽前就先報
 * 「Invalid JWT as input」(解析層錯誤),走不到簽章比對,示範失去說服力。
 * 改法:先解碼 payload 成 JSON,只翻動其中一個 hex commitment hash 字元(或退而求其次翻動
 * 一個非時間欄位數值的個位數),確保修改後仍是合法 UTF-8 / JSON,再重新編碼回 base64url——
 * 如此驗證器一定能成功解析 payload,接著才在比對簽章時失敗,回報簽章層錯誤(Invalid JWT
 * Signature 類),對照示範才有意義。
 */
const HEX_CHARS = '0123456789abcdef';
/** commitment hash / hash 類欄位皆為小寫 hex 字串,長度 ≥16 才判定為可竄改對象(排除短數值字面量)。 */
const HEX_FIELD_RE = /^[0-9a-f]{16,}$/;
/** 時間欄位跳過,避免竄改觸發「已過期/尚未生效」而非「簽章不符」,模糊了示範重點。 */
const TEMPORAL_FIELD_KEYS = new Set(['iat', 'nbf', 'exp']);

function flipHexChar(value: string): string {
  const i = Math.floor(value.length / 2);
  const hexIdx = HEX_CHARS.indexOf(value[i].toLowerCase());
  if (hexIdx === -1) return value;
  return value.slice(0, i) + HEX_CHARS[(hexIdx + 1) % HEX_CHARS.length] + value.slice(i + 1);
}

/** 在 claims 物件(含一層巢狀,如 pcf_aggregate 的 precursor_ref)中找第一個 hex hash 欄位並翻轉一個字元。 */
function tamperFirstHexField(claims: Record<string, unknown>): string | null {
  for (const [key, value] of Object.entries(claims)) {
    if (typeof value === 'string' && HEX_FIELD_RE.test(value)) {
      claims[key] = flipHexChar(value);
      return key;
    }
  }
  for (const [key, value] of Object.entries(claims)) {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const nested = value as Record<string, unknown>;
      for (const [subKey, subValue] of Object.entries(nested)) {
        if (typeof subValue === 'string' && HEX_FIELD_RE.test(subValue)) {
          nested[subKey] = flipHexChar(subValue);
          return `${key}.${subKey}`;
        }
      }
    }
  }
  return null;
}

/** 找不到 hex 欄位時的退路:改動第一個非時間欄位數值的個位數(仍保持合法 JSON/型別)。 */
function tamperFirstNumericField(claims: Record<string, unknown>): string | null {
  for (const [key, value] of Object.entries(claims)) {
    if (typeof value === 'number' && !TEMPORAL_FIELD_KEYS.has(key)) {
      claims[key] = value + 1;
      return key;
    }
  }
  return null;
}

/**
 * 竄改 compact SD-JWT 的 payload 段落一個位元組(保持 UTF-8/JSON 合法):header/signature/
 * disclosures 不動,只動已簽章的 payload 內容,使原簽章對不上新 payload → 驗證器回報簽章層
 * 錯誤(而非解析層錯誤)。
 */
export function tamperPayloadByte(sdJwtCompact: string): string {
  const tildeIdx = sdJwtCompact.indexOf('~');
  const jwtPart = tildeIdx === -1 ? sdJwtCompact : sdJwtCompact.slice(0, tildeIdx);
  const rest = tildeIdx === -1 ? '' : sdJwtCompact.slice(tildeIdx);
  const [header, payload, signature] = jwtPart.split('.');
  if (!header || !payload || !signature) throw new Error('不是合法的 compact SD-JWT(header.payload.signature 三段缺一)');

  let claims: Record<string, unknown>;
  try {
    claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8')) as Record<string, unknown>;
  } catch (e) {
    throw new Error(`payload 段無法解析為 JSON,無法示範竄改:${e instanceof Error ? e.message : String(e)}`);
  }

  const tamperedField = tamperFirstHexField(claims) ?? tamperFirstNumericField(claims);
  if (!tamperedField) throw new Error('payload 內找不到可竄改的欄位(需至少一個 hex hash 或非時間數值欄位)');

  const tamperedPayload = Buffer.from(JSON.stringify(claims), 'utf-8').toString('base64url');
  return `${header}.${tamperedPayload}.${signature}${rest}`;
}
