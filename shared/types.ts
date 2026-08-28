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

/** Cedar 前之可信 context 布林(後端預驗證產出;政策僅消費布林)。 */
export interface TrustedContext {
  mandate_status_ok: boolean;
  delegate_key_ok: boolean;
  replay_ok: boolean;
}

export type DecisionEffect = 'PERMIT' | 'DENY' | 'RELEASE' | 'REPLAY_DETECTED';
