/**
 * Token Status List(draft-ietf-oauth-status-list-21)— 首選套件 @owf/token-status-list。
 *
 * 正式檔案:data/status/mandates.jwt、data/status/credentials.jwt——
 * compact signed JWT,header.typ="statuslist+jwt",payload 含 sub/iat/exp/ttl 與
 * status_list = { bits: 1, lst: base64url(zlib 壓縮位元陣列) }。
 * 簽章鑰:FAB LE 鑰(閘道為兩份清單的發布方/host,經 server/keys.ts 載入)。
 * 驗證方必先驗 compact JWS 簽章,再解碼 payload.status_list.bits/lst。
 * 裸 JSON bit array 僅可作為明確標示的 fallback,不得出現於正式流程。
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto, { type KeyObject } from 'node:crypto';
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
 *      (expectedSub)——同一把FAB鑰同時簽 mandates 與 credentials 兩份清單,不驗 sub 就能拿
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

const LOCK_RETRY_MS = 20;
/** 鎖檔逾時視為前一行程異常中止遺留,清除後重試(避免永久卡死;非常見路徑)。 */
const LOCK_STALE_MS = 5000;
const LOCK_TIMEOUT_MS = 10000;

function lockFilePath(name: StatusListName): string {
  return path.join(STATUS_DIR, `.${name}.lock`);
}

/**
 * P1-3(Codex 審查):狀態清單 read-modify-write 之跨請求/跨行程序列化。
 * 「讀現況 bits → 算新 bits → 簽章 → 寫檔」若在兩個 revoke(同行程內併發的 API 請求,或
 * API 與另一 `make revoke` CLI 行程併發)之間交錯執行,會讓兩者都讀到同一份原始清單、各自
 * 算出不同的新清單,最後寫入者悄悄覆蓋另一個的撤銷結果。以獨占建立鎖檔(`fs` 'wx' flag,
 * 跨行程有效、不需新依賴)序列化同一清單名稱的臨界區,取鎖失敗則忙等重試。
 */
export async function withStatusListLock<T>(name: StatusListName, fn: () => Promise<T>): Promise<T> {
  const lockPath = lockFilePath(name);
  fs.mkdirSync(STATUS_DIR, { recursive: true });
  // P2-7(Codex 審查第二輪):鎖檔內容寫入唯一 owner token(pid + 隨機值)——原實作 stale
  // 回收後,原持有者恢復執行時的 finally 仍無條件刪鎖:若合法持鎖者恰好暫停超過
  // LOCK_STALE_MS(GC 停頓/磁碟緩慢等),另一行程判定 stale 並接管、寫入自己的鎖,原持有者
  // 恢復後的 finally 會把「新持有者的鎖」一併刪掉,讓第三個行程也能闖入臨界區(鎖形同虛設)。
  // 改為:釋放前重讀鎖檔內容,只刪「內容仍是自己 owner token」的鎖。
  const ownerToken = `${process.pid}-${crypto.randomUUID()}`;
  const start = Date.now();
  for (;;) {
    try {
      fs.writeFileSync(lockPath, ownerToken, { flag: 'wx' });
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
      try {
        if (Date.now() - fs.statSync(lockPath).mtimeMs > LOCK_STALE_MS) {
          fs.rmSync(lockPath, { force: true });
          continue;
        }
      } catch {
        continue; // 鎖檔已被持有者釋放,立即重試取鎖
      }
      if (Date.now() - start > LOCK_TIMEOUT_MS) {
        throw new Error(`取得 ${name} 狀態清單鎖逾時(另一撤銷/續簽操作進行中?)`);
      }
      await new Promise((r) => setTimeout(r, LOCK_RETRY_MS));
    }
  }
  try {
    return await fn();
  } finally {
    try {
      if (fs.readFileSync(lockPath, 'utf-8') === ownerToken) {
        fs.rmSync(lockPath, { force: true });
      }
      // 內容不符(已被 stale 回收機制接管)——不得刪除,避免波及新持有者;不拋錯,讓
      // fn() 之結果/例外原樣傳遞給呼叫端。
    } catch {
      // 鎖檔已不存在(可能已被自己或他人清除)——無需動作。
    }
  }
}

/**
 * 閘道(清單發布方=FAB)專用:讀取正式 Status List Token,若已接近/超過 ttl 則以FAB鑰**重簽**
 * (保留現有 bit 狀態、只換新 iat)再回傳,使 `make dev` 長時間執行後 disclose/verify 仍拿到新鮮清單
 * (F6 的 ttl 新鮮度檢查因此不會把 demo 卡死)。既有「檔案缺失/無法解碼則從全 0 重建」語意不變
 * (CLAUDE.md 明列不動此發布路徑語意);P1-3 修法僅為 read-modify-write 加鎖(純併發安全,取鎖後
 * 重讀一次以免覆蓋掉等鎖期間已完成的另一次撤銷/續簽)。
 *
 * ⚠ Brand 端(驗證方,server/creds/verifyPresentation.ts / scripts/verify-offline.ts)**不得**呼叫本函式:
 * 驗證方不持鑰、不簽章(CLAUDE.md:25),只讀 readStatusListToken() 拿發布方已簽好的清單。
 */
export async function readFreshStatusListToken(name: StatusListName, nowMs: number = Date.now()): Promise<string | null> {
  const existing = readStatusListToken(name);
  const nowSec = Math.floor(nowMs / 1000);
  if (existing && !statusTokenIsStale(existing, nowSec)) return existing;
  return withStatusListLock(name, async () => {
    const fresh = readStatusListToken(name);
    if (fresh && !statusTokenIsStale(fresh, Math.floor(Date.now() / 1000))) return fresh;
    const statuses = fresh ? extractStatuses(fresh) : undefined;
    return buildAndWriteStatusList(name, statuses);
  });
}

/**
 * 幕 6 撤銷管理端寫入路徑(清單發布方=FAB 專用;供 scripts/revoke.ts 之 `make revoke` 與
 * server/creds/pcfAggregate.ts reissue supersede 語意共用):翻轉指定 idx 為撤銷(1),保留
 * 其餘既有 bit 狀態,並以 FAB LE 鑰重簽整份清單、寫回 data/status/<name>.jwt——不重啟服務即生效
 * (消費端每次現讀本檔,無快取)。與 readFreshStatusListToken 同屬「發布方自己持鑰改自己發布之
 * 清單」信任邊界,不同於消費端 fail-closed 讀取路徑(server/creds/statusGuard.ts)。輸出仍是
 * compact 已簽章 JWT,裸 JSON bit array 不得出現於正式流程。
 *
 * P1-2(Codex 審查):**撤銷操作本身 fail-closed**——與 readFreshStatusListToken(合法的「缺檔則
 * 視為全新清單」語意)不同,revoke 是「在既有清單基礎上翻一個 bit」的動作,若既有清單缺失、
 * 簽章驗不過(可能遭竄改)或無法解碼,一律拒絕操作、不寫檔,不得從全 0 重建(等同悄悄抹除
 * 既有撤銷狀態,或把偽造清單的 bits 用合法簽章洗白)。
 * P1-3(Codex 審查):read-modify-write 以 withStatusListLock 序列化,見上方說明。
 */
export async function revokeStatusIndex(name: StatusListName, idx: number): Promise<string> {
  if (!Number.isInteger(idx) || idx < 0 || idx >= STATUS_LIST_SIZE) {
    throw new Error(`idx 超出範圍(0~${STATUS_LIST_SIZE - 1}):${idx}`);
  }
  return withStatusListLock(name, async () => {
    const existing = readStatusListToken(name);
    if (!existing) {
      throw new Error(
        `撤銷操作拒絕(fail-closed):data/status/${name}.jwt 不存在——不得從全 0 重建(等同抹除既有撤銷狀態)。請先跑 make setup/make demo-reset。`,
      );
    }
    const issuerKey = loadSandboxKey('fab').publicKey;
    let verifiedPayload: Record<string, unknown>;
    try {
      const { payload } = await jwtVerify(existing, issuerKey);
      verifiedPayload = payload as Record<string, unknown>;
    } catch (e) {
      throw new Error(
        `撤銷操作拒絕(fail-closed):既有 ${name}.jwt 簽章驗證失敗,拒絕以未經驗證/可能遭竄改之清單為基礎撤銷:${e instanceof Error ? e.message : String(e)}`,
      );
    }
    // P1-3(Codex 審查第二輪):credentials.jwt 與 mandates.jwt 由同一把 FAB 鑰簽署——若檔案
    // 內容意外/惡意被置換成「另一份清單的合法 token」,簽章仍驗得過。除簽章外必須另斷言
    // header.typ 與 payload.sub 對得上「這份清單自己」,否則會把 mandates 的 bits 用合法簽章
    // 洗白寫進 credentials.jwt,悄悄抹除既有 credential 撤銷狀態(反之亦然)。
    let header: ReturnType<typeof decodeProtectedHeader>;
    try {
      header = decodeProtectedHeader(existing);
    } catch (e) {
      throw new Error(`撤銷操作拒絕(fail-closed):既有 ${name}.jwt header 解析失敗:${e instanceof Error ? e.message : String(e)}`);
    }
    if (header.typ !== JWT_STATUS_LIST_TYPE) {
      throw new Error(`撤銷操作拒絕(fail-closed):既有 ${name}.jwt header.typ 不是 "${JWT_STATUS_LIST_TYPE}"(typ=${header.typ ?? '(無)'})`);
    }
    const expectedSub = statusListUri(name);
    if (verifiedPayload.sub !== expectedSub) {
      throw new Error(
        `撤銷操作拒絕(fail-closed):既有 ${name}.jwt 之 payload.sub(${String(verifiedPayload.sub ?? '(無)')})≠ 預期清單 URI(${expectedSub})——疑似跨清單 token 置換,拒絕以此為基礎撤銷。`,
      );
    }
    const statuses = extractStatuses(existing);
    if (!statuses) {
      throw new Error(`撤銷操作拒絕(fail-closed):既有 ${name}.jwt 簽章有效但 status_list.bits/lst 無法解碼,拒絕以此為基礎撤銷。`);
    }
    const next = [...statuses];
    next[idx] = 1;
    return buildAndWriteStatusList(name, next);
  });
}
