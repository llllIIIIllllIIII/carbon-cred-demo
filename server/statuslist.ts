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
import { SignJWT, jwtVerify, decodeProtectedHeader, decodeJwt } from 'jose';
import { ROOT } from './db';
import { loadSandboxKey } from './keys';

export const STATUS_DIR = path.join(ROOT, 'data', 'status');
export const STATUS_MEDIA_TYPE = 'application/statuslist+jwt';
export const STATUS_BASE_URI = process.env.STATUS_BASE_URI ?? 'http://localhost:3000/status';
export const STATUS_LIST_SIZE = 64;
export const STATUS_TTL_SECONDS = 300;
/** F6:狀態清單新鮮度/簽發時鐘之有界容許偏移(秒)。 */
export const STATUS_CLOCK_SKEW_SEC = 60;

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
  const signer = loadSandboxKey('fab');
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

export interface CheckStatusBitOptions {
  /** 新鮮度判定時間基準(epoch 毫秒);預設 Date.now()。測試以此注入固定時間,不寫死日期。 */
  now?: number;
  /** 有界時鐘偏移(秒);預設 STATUS_CLOCK_SKEW_SEC。 */
  skewSec?: number;
}

/**
 * 驗證方共用入口(幕 3 Brand 端 / 閘道 mandate/credential 撤銷查驗皆呼叫此函式)——
 * 依序:
 *   1. 先驗 compact JWS 簽章(issuerPublicKey,取自 manifest 公開材料),簽章不過直接回錯。
 *   2. header.typ 必須為 "statuslist+jwt"(L3:不驗 typ 等於接受任何同鑰簽出的 JWT 冒充狀態清單)。
 *   3. F6(Codex adversarial review)跨清單替換防線:payload.sub 必須等於**預期清單 URI**
 *      (expectedSub)——同一把鴻鋼鑰同時簽 mandates 與 credentials 兩份清單,不驗 sub 就能拿
 *      credentials token 當 mandates 查、反之亦然。呼叫端一律傳入「被查引用之 status.status_list.uri」。
 *   4. F6 陳舊防線:驗 iat 新鮮度(now - iat ≤ ttl + skew)與未來偏移(iat - now ≤ skew),並驗 exp;
 *      快取到 180 天 exp 前無視 5 分鐘 ttl 一律接受的舊行為就此關閉。now 由呼叫端注入(測試不寫死日期)。
 *   5. 最後才用 @owf/token-status-list 解碼 status_list.bits/lst 查 idx。
 *
 * 注意:先前實作驗完簽章後**丟棄已驗 payload**、再以 getListFromStatusListJWT() 重新解碼原始 token,
 * 且完全不檢查 sub / iat——本版改為以「已驗章之 payload」判斷 sub/iat/exp,再查 bit。
 */
export async function checkStatusBit(
  token: string,
  idx: number,
  issuerPublicKey: KeyObject,
  expectedSub: string,
  options: CheckStatusBitOptions = {},
): Promise<StatusBitCheckResult> {
  let verified: Record<string, unknown>;
  try {
    const { payload } = await jwtVerify(token, issuerPublicKey);
    verified = payload as Record<string, unknown>;
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
  // F6:sub 必須與被查清單一致(拒絕跨清單替換)。
  if (verified.sub !== expectedSub) {
    return {
      ok: false,
      revoked: false,
      error: `Status List Token sub(${String(verified.sub ?? '(無)')})≠ 預期清單 URI(${expectedSub})——拒絕跨清單替換`,
    };
  }
  // F6:新鮮度 + exp(有界 skew)。
  const nowSec = Math.floor((options.now ?? Date.now()) / 1000);
  const skew = options.skewSec ?? STATUS_CLOCK_SKEW_SEC;
  const iat = typeof verified.iat === 'number' ? verified.iat : undefined;
  const ttl = typeof verified.ttl === 'number' ? verified.ttl : STATUS_TTL_SECONDS;
  const exp = typeof verified.exp === 'number' ? verified.exp : undefined;
  if (iat == null) return { ok: false, revoked: false, error: 'Status List Token 缺 iat,無新鮮度可判斷' };
  if (iat - nowSec > skew) return { ok: false, revoked: false, error: `Status List Token iat 在未來(iat 超前 ${iat - nowSec}s)` };
  if (nowSec - iat > ttl + skew) {
    return { ok: false, revoked: false, error: `Status List Token 已陳舊(iat 距今 ${nowSec - iat}s，超過 ttl ${ttl}s + skew ${skew}s)——需重新取得新鮮清單` };
  }
  if (exp != null && nowSec > exp + skew) return { ok: false, revoked: false, error: `Status List Token 已過期(exp)` };
  try {
    const list = getListFromStatusListJWT(token);
    const status = list.getStatus(idx);
    return { ok: true, revoked: status !== StatusType.Valid };
  } catch (e) {
    return { ok: false, revoked: false, error: `status_list.bits/lst 解碼失敗:${e instanceof Error ? e.message : String(e)}` };
  }
}

/** 從既有 token 重建 0/1 bit 狀態陣列(重簽時保留撤銷位元)。解析失敗回 undefined(改為全新全 0)。 */
function extractStatuses(token: string): number[] | undefined {
  try {
    const list = getListFromStatusListJWT(token);
    const out: number[] = [];
    for (let i = 0; i < STATUS_LIST_SIZE; i++) out.push(list.getStatus(i) === StatusType.Valid ? 0 : 1);
    return out;
  } catch {
    return undefined;
  }
}

/** 判斷 token 是否已接近/超過 ttl(提前 skew 秒重簽,避免驗證端邊界剛好落在 ttl+skew 外)。 */
function statusTokenIsStale(token: string, nowSec: number, skewSec = STATUS_CLOCK_SKEW_SEC): boolean {
  try {
    const p = decodeJwt(token) as Record<string, unknown>;
    const iat = typeof p.iat === 'number' ? p.iat : 0;
    const ttl = typeof p.ttl === 'number' ? p.ttl : STATUS_TTL_SECONDS;
    return nowSec - iat > ttl - skewSec;
  } catch {
    return true;
  }
}

/**
 * 閘道(清單發布方=鴻鋼)專用:讀取正式 Status List Token,若已接近/超過 ttl 則以鴻鋼鑰**重簽**
 * (保留現有 bit 狀態、只換新 iat)再回傳,使 `make dev` 長時間執行後 disclose/verify 仍拿到新鮮清單
 * (F6 的 ttl 新鮮度檢查因此不會把 demo 卡死)。
 *
 * ⚠ Brand 端(驗證方,server/creds/verifyPresentation.ts / scripts/verify-offline.ts)**不得**呼叫本函式:
 * 驗證方不持鑰、不簽章(CLAUDE.md:25),只讀 readStatusListToken() 拿發布方已簽好的清單。
 */
export async function readFreshStatusListToken(name: StatusListName, nowMs: number = Date.now()): Promise<string | null> {
  const existing = readStatusListToken(name);
  const nowSec = Math.floor(nowMs / 1000);
  if (existing && !statusTokenIsStale(existing, nowSec)) return existing;
  const statuses = existing ? extractStatuses(existing) : undefined;
  return buildAndWriteStatusList(name, statuses);
}
