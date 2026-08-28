/**
 * SD-JWT 底層原語(hasher / saltGenerator / signer / verifier adapters)——
 * 全案 SD-JWT 簽發與驗證共用同一份實作:雜湊固定 sha-256(IANA_HASH_ALGORITHMS 之一),
 * 簽章固定 EdDSA(Ed25519,經 server/keys.ts 之 SigningKey / KeyObject,不在此檔碰觸鑰檔)。
 */
import crypto from 'node:crypto';
import type { Signer, Verifier } from '@sd-jwt/core';
import type { SigningKey } from '../keys';

/** _sd_alg 固定值。 */
export const HASH_ALG = 'sha-256';

/** Hasher:對 disclosure 編碼字串取 SHA-256 digest bytes。 */
export function sha256Hasher(data: string | ArrayBuffer): Uint8Array {
  const buf = typeof data === 'string' ? Buffer.from(data) : Buffer.from(data);
  return new Uint8Array(crypto.createHash('sha256').update(buf).digest());
}

/** SaltGenerator:每個 disclosure 一組隨機鹽(base64url,長度由呼叫端決定)。 */
export function randomSalt(length: number): string {
  return crypto.randomBytes(length).toString('base64url');
}

/** Signer adapter:signing input(header.payload)→ raw Ed25519 簽章(base64url,JWS EdDSA 格式)。 */
export function toSigner(key: SigningKey): Signer {
  return async (data: string) => crypto.sign(null, Buffer.from(data), key.privateKey).toString('base64url');
}

/** Verifier adapter:以指定公鑰驗 raw Ed25519 簽章;驗證失敗一律回 false,不丟例外。 */
export function toVerifier(publicKey: crypto.KeyObject): Verifier {
  return async (data: string, sig: string) => {
    try {
      return crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'));
    } catch {
      return false;
    }
  };
}
