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
  // v3.1(聚合前核對):pcf_upstream.tc_ref.hash 對不上 tc_rcs、seller_lei/buyer_lei 不符、
  // 或 tcProductCertifiedWeight < quantity_kg;pcf_upstream 簽發時入庫 tc_rcs 缺失時亦回此碼
  TC_REF_MISMATCH: 'TC_REF_MISMATCH',
  // v3.1:pcf_dyeing.ccs_scope_ref.sc_no 與 ccs_scope_cert 不一致,或 DYE LEI 不在
  // ccs_scope_cert.associated_subcontractors 內(幕 2 聚合前核對;幕 5 P3 context.subcontractor_listed=false)
  CCS_SUBCONTRACTOR_NOT_LISTED: 'CCS_SUBCONTRACTOR_NOT_LISTED',
  // v3.1:ccs_scope_cert 驗章/效期/Token Status List 任一不通過
  SCOPE_CERT_INVALID: 'SCOPE_CERT_INVALID',

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

  // 幕 5 放行管線(Phase 3a)
  CARBON_OVER_THRESHOLD: 'CARBON_OVER_THRESHOLD',
  MULTI_SOURCE_CONFIRMED: 'MULTI_SOURCE_CONFIRMED',
  SINGLE_SOURCE_ONLY: 'SINGLE_SOURCE_ONLY',
  RELEASE_APPROVED: 'RELEASE_APPROVED',
  // P3 五要件全過、Dossier 已建立(對照 POLICY_P1_PERMIT 之整體 PERMIT 標記)
  POLICY_P3_PERMIT: 'POLICY_P3_PERMIT',
  // invoice_ok ①:發票驗章失敗、簽發者非 DYE、或 vct 型別不符
  INVOICE_INVALID: 'INVOICE_INVALID',
  // invoice_ok ②(Opus 獨立驗證 L2):發票金額超過 mandate.max_amount——與③payee 不符分開歸類,
  // 避免「金額超限」與「收款方不對」共用同一理由碼、語意含混
  AMOUNT_OVER_LIMIT: 'AMOUNT_OVER_LIMIT',
  // invoice_ok ③:收款方 LEI 不在 mandate.allowed_counterparties
  COUNTERPARTY_NOT_ALLOWED: 'COUNTERPARTY_NOT_ALLOWED',
  // POST /api/human-sign:dossier_id 查無對應 Dossier
  DOSSIER_NOT_FOUND: 'DOSSIER_NOT_FOUND',
  // POST /api/human-sign:Dossier 狀態非 PENDING_HUMAN(已放行、或依據已撤銷)不得再簽
  DOSSIER_NOT_RELEASABLE: 'DOSSIER_NOT_RELEASABLE',
  // Codex review P1-3:消費 pcf_aggregate 前,其 precursor_refs 對不上「現況」tc_rcs/
  // pcf_upstream/pcf_dyeing 之 sha256(sd_jwt)——重簽輸入後未重聚合,聚合值已陳舊,不得沿用續走。
  AGGREGATE_STALE: 'AGGREGATE_STALE',
  // Codex review 第二輪 P1-B:invoice.payer_lei ≠ FAB LEI(合法 DYE 簽發票但付款人不是布廠)
  PAYER_NOT_ALLOWED: 'PAYER_NOT_ALLOWED',
  // Codex review 第二輪 P1-B:invoice.currency ≠ M1 簽章內約定幣別(USD)
  CURRENCY_MISMATCH: 'CURRENCY_MISMATCH',

  // 稽核
  AUDIT_CHAIN_TAMPERED: 'AUDIT_CHAIN_TAMPERED',
  DEPENDS_REVOKED: 'DEPENDS_REVOKED',
} as const;

export type ReasonCode = (typeof CODES)[keyof typeof CODES];

/**
 * Dossier 狀態機(幕 5;server/routes/agent.ts 建立 → POST /api/human-sign 轉態;
 * 幕 6 撤銷 pcf_dyeing 後既有 Dossier 標 DEPENDS_REVOKED,非本 phase 範圍但先留欄位)。
 */
export const DOSSIER_STATUS = {
  PENDING_HUMAN: 'PENDING_HUMAN',
  RELEASED: 'RELEASED',
  DEPENDS_REVOKED: 'DEPENDS_REVOKED',
} as const;

export type DossierStatus = (typeof DOSSIER_STATUS)[keyof typeof DOSSIER_STATUS];
