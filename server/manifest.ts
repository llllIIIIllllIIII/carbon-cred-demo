/**
 * data/vlei/manifest.json 讀取與公鑰解析(公開材料;server/routes/issue.ts、
 * server/creds/pcfAggregate.ts 共用,避免各自重複實作)。
 * manifest 內只有公開 verkey/aid/lei 等公開材料;私鑰一律經 server/keys.ts 取得,
 * 本檔不碰觸 .vlei/state.json 或 data/keys/。
 */
import fs from 'node:fs';
import path from 'node:path';
import type { KeyObject } from 'node:crypto';
import { ROOT } from './db';
import { publicKeyFromQb64 } from './keys';
import type { Manifest } from '../shared/types';

export const MANIFEST_PATH = path.join(ROOT, 'data', 'vlei', 'manifest.json');

/** 讀取 manifest.json;尚未產生(未跑 make setup)時回傳 null。 */
export function readManifest(): Manifest | null {
  if (!fs.existsSync(MANIFEST_PATH)) return null;
  return JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf-8'));
}

/** 依 unverified header.kid 於 manifest 內查對應公鑰(找不到回傳 undefined,供 verifyCompactSdJwt 使用)。 */
export function resolvePublicKeyFromManifest(manifest: Manifest): (kid: string | undefined) => KeyObject | undefined {
  return (kid) => {
    const role = Object.values(manifest).find((r) => r.aid === kid);
    return role ? publicKeyFromQb64(role.public_key) : undefined;
  };
}
