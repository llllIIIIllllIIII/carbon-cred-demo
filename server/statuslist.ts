/**
 * Token Status List(draft-ietf-oauth-status-list-21)— 首選套件 @owf/token-status-list。
 *
 * 正式檔案:data/status/mandates.jwt、data/status/credentials.jwt——
 * compact signed JWT,header.typ="statuslist+jwt",payload 含 sub/iat/exp/ttl 與
 * status_list = { bits: 1, lst: base64url(zlib 壓縮位元陣列) }。
 * 簽章鑰:鴻鋼 LE 鑰(閘道為兩份清單的發布方/host,經 server/keys.ts 載入)。
 * 驗證方必先驗 compact JWS 簽章,再解碼 payload.status_list.bits/lst。
 * 裸 JSON bit array 僅可作為明確標示的 fallback,不得出現於正式流程。
 */
import fs from 'node:fs';
import path from 'node:path';
import { StatusList, createHeaderAndPayload, JWT_STATUS_LIST_TYPE } from '@owf/token-status-list';
import { SignJWT } from 'jose';
import { ROOT } from './db';
import { loadSandboxKey } from './keys';

export const STATUS_DIR = path.join(ROOT, 'data', 'status');
export const STATUS_MEDIA_TYPE = 'application/statuslist+jwt';
export const STATUS_BASE_URI = process.env.STATUS_BASE_URI ?? 'http://localhost:3000/status';
export const STATUS_LIST_SIZE = 64;
export const STATUS_TTL_SECONDS = 300;

export type StatusListName = 'mandates' | 'credentials';
export const STATUS_LIST_NAMES: StatusListName[] = ['mandates', 'credentials'];

export function statusListUri(name: StatusListName): string {
  return `${STATUS_BASE_URI}/${name}`;
}

export function statusListFile(name: StatusListName): string {
  return path.join(STATUS_DIR, `${name}.jwt`);
}

/** 以目前 bit 狀態(0=有效, 1=撤銷)重簽重寫 Status List Token。回傳 compact JWT。 */
export async function buildAndWriteStatusList(name: StatusListName, statuses?: number[]): Promise<string> {
  const bits = statuses ?? new Array<number>(STATUS_LIST_SIZE).fill(0);
  const list = new StatusList(bits, 1);
  const now = Math.floor(Date.now() / 1000);
  const { header, payload } = createHeaderAndPayload(
    list,
    { sub: statusListUri(name), iat: now, exp: now + 60 * 60 * 24 * 180, ttl: STATUS_TTL_SECONDS },
    { alg: 'EdDSA', typ: JWT_STATUS_LIST_TYPE },
  );
  const signer = loadSandboxKey('hunggang');
  const jwt = await new SignJWT(payload as Record<string, unknown>)
    .setProtectedHeader({ ...header, kid: signer.kid })
    .sign(signer.privateKey);
  fs.mkdirSync(STATUS_DIR, { recursive: true });
  fs.writeFileSync(statusListFile(name), jwt);
  return jwt;
}

/** 讀取正式 Status List Token(compact JWT 字串);不存在回 null。 */
export function readStatusListToken(name: StatusListName): string | null {
  const f = statusListFile(name);
  return fs.existsSync(f) ? fs.readFileSync(f, 'utf-8').trim() : null;
}
