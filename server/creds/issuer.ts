/**
 * SD-JWT VC 簽發包裝(RFC 9901 core + IETF SD-JWT VC profile;@sd-jwt/sd-jwt-vc)。
 * 不宣稱符合 W3C VC 2.0(CLAUDE.md 範圍鐵則)。簽章鑰一律由呼叫端經 server/keys.ts 取得,
 * 本檔不直接讀鑰檔或 .vlei/state.json。
 */
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { SigningKey } from '../keys';
import { HASH_ALG, sha256Hasher, randomSalt, toSigner } from './primitives';

/** 建立以指定 sandbox/workload 鑰簽發之 SD-JWT VC instance(header.kid = key.kid)。 */
export function buildIssuerInstance(key: SigningKey): SDJwtVcInstance {
  return new SDJwtVcInstance({
    hasher: sha256Hasher,
    hashAlg: HASH_ALG,
    saltGenerator: randomSalt,
    signer: toSigner(key),
    signAlg: 'EdDSA',
  });
}
