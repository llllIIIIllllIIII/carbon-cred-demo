/**
 * 理由碼常數(全案唯一來源)。
 * 介面文案一律繁體中文;理由碼一律引用此處英文常數,不得散落字串字面值。
 */
export const CODES = {
  // 輸入驗證(Codex 審查發現 2:case_id 缺值/打錯字不得靜默塌成合法值)
  INVALID_CASE_ID: 'INVALID_CASE_ID',
  // Phase 2:POST /api/mandates body 非 "M1"|"M2"(比照 INVALID_CASE_ID 模式)
  INVALID_MANDATE_ID: 'INVALID_MANDATE_ID',
  // Phase 2:POST /api/disclose 的 request_jws 無法解析,或結構缺必要欄位
  DISCLOSE_REQUEST_INVALID: 'DISCLOSE_REQUEST_INVALID',
  // Phase 2:request_jws 內 mandate_id(=mandate jti)查無對應 mandate
  MANDATE_NOT_FOUND: 'MANDATE_NOT_FOUND',
  // Phase 2:該案 pcf_aggregate 尚未簽發(disclose 不自動代簽,依幕序先跑幕 2)
  PCF_AGGREGATE_NOT_ISSUED: 'PCF_AGGREGATE_NOT_ISSUED',

  // 政策決策
  POLICY_P1_PERMIT: 'POLICY_P1_PERMIT',
  POLICY_P2_CONFIDENTIAL: 'POLICY_P2_CONFIDENTIAL',
  CLAIM_NOT_IN_MANDATE: 'CLAIM_NOT_IN_MANDATE',

  // mandate 驗證
  MANDATE_REVOKED: 'MANDATE_REVOKED',
  MANDATE_EXPIRED: 'MANDATE_EXPIRED',
  MANDATE_SIG_INVALID: 'MANDATE_SIG_INVALID',
  DELEGATE_KEY_MISMATCH: 'DELEGATE_KEY_MISMATCH',
  QUERY_CAP_EXCEEDED: 'QUERY_CAP_EXCEEDED',

  // 重放防護
  REPLAY_DETECTED: 'REPLAY_DETECTED',
  // F4(Codex adversarial review):presentation 無 key-binding,改由閘道簽章 receipt 綁定
  // presentation_hash+mandate_jti+request_nonce+aud+iat;receipt 缺失/簽章壞/綁定不符/逾新鮮度 → 拒
  RECEIPT_INVALID: 'RECEIPT_INVALID',

  // 憑證層
  CREDENTIAL_REVOKED: 'CREDENTIAL_REVOKED',
  // F3(Codex adversarial review):disclose 前驗被揭露 aggregate 自身效期,過期/未生效 → 拒
  CREDENTIAL_EXPIRED: 'CREDENTIAL_EXPIRED',
  CREDENTIAL_SIG_INVALID: 'CREDENTIAL_SIG_INVALID',
  CREDENTIAL_PARSE_ERROR: 'CREDENTIAL_PARSE_ERROR',
  ISSUER_UNKNOWN: 'ISSUER_UNKNOWN',
  // Phase 2 遺留(a):vct 與實際簽發者 AID 不符其被授權角色(例如 pcf_aggregate 未由FAB LE AID 簽)
  VCT_ISSUER_UNAUTHORIZED: 'VCT_ISSUER_UNAUTHORIZED',
  VLEI_CHAIN_BROKEN: 'VLEI_CHAIN_BROKEN',

  // 幕 5 放行管線
  CARBON_OVER_THRESHOLD: 'CARBON_OVER_THRESHOLD',
  MULTI_SOURCE_CONFIRMED: 'MULTI_SOURCE_CONFIRMED',
  SINGLE_SOURCE_ONLY: 'SINGLE_SOURCE_ONLY',
  RELEASE_APPROVED: 'RELEASE_APPROVED',

  // 稽核
  AUDIT_CHAIN_TAMPERED: 'AUDIT_CHAIN_TAMPERED',
  DEPENDS_REVOKED: 'DEPENDS_REVOKED',
} as const;

export type ReasonCode = (typeof CODES)[keyof typeof CODES];
