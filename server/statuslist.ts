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
import type { KeyObject } from 'node:crypto';
import { StatusList, createHeaderAndPayload, getListFromStatusListJWT, JWT_STATUS_LIST_TYPE, StatusType } from '@owf/token-status-list';
import { SignJWT, jwtVerify, decodeProtectedHeader } from 'jose';
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

export interface StatusBitCheckResult {
  /** 簽章驗證與 lst 解碼皆成功(不代表未撤銷,見 revoked)。 */
  ok: boolean;
  revoked: boolean;
  error?: string;
}

/**
 * 驗證方共用入口(幕 3 Bruck 端 / 閘道 mandate 撤銷查驗皆呼叫此函式)——
 * 先驗 compact JWS 簽章(issuerPublicKey,取自 manifest 公開材料),簽章不過直接回錯,
 * 不解碼任何內容;簽章通過後檢查 header.typ(L3:draft-ietf-oauth-status-list-21 要求
 * typ="statuslist+jwt",不驗 typ 等於接受任何同鑰簽出的 JWT 冒充狀態清單),
 * 最後才用 @owf/token-status-list 解碼 status_list.bits/lst 查 idx。
 */
export async function checkStatusBit(token: string, idx: number, issuerPublicKey: KeyObject): Promise<StatusBitCheckResult> {
  try {
    await jwtVerify(token, issuerPublicKey);
  } catch (e) {
    return { ok: false, revoked: false, error: `Status List Token 簽章驗證失敗:${e instanceof Error ? e.message : String(e)}` };
  }
  try {
    const header = decodeProtectedHeader(token);
    if (header.typ !== JWT_STATUS_LIST_TYPE) {
      return { ok: false, revoked: false, error: `Status List Token header.typ 不是 "${JWT_STATUS_LIST_TYPE}"(typ=${header.typ ?? '(無)'})` };
    }
  } catch (e) {
    return { ok: false, revoked: false, error: `Status List Token header 解析失敗:${e instanceof Error ? e.message : String(e)}` };
  }
  try {
    const list = getListFromStatusListJWT(token);
    const status = list.getStatus(idx);
    return { ok: true, revoked: status !== StatusType.Valid };
  } catch (e) {
    return { ok: false, revoked: false, error: `status_list.bits/lst 解碼失敗:${e instanceof Error ? e.message : String(e)}` };
  }
}
