/**
 * 安全版「讀取（必要時刷新）Token Status List Token」——供消費端(撤銷查驗方)使用。
 *
 * 背景(Opus 獨立驗證回合 A/B;Codex 審查 P1-b 原話「only refresh a successfully decoded
 * existing list and otherwise deny」):server/statuslist.ts 之 readFreshStatusListToken()
 * 在清單檔缺失或無法解碼時,會靜默以「全 0(無撤銷)」重建一份新清單並回傳——這對它原始的呼叫端
 * (清單發布方 FAB 自己續簽/刊登清單)是合理設計,但撤銷查驗消費端(server/creds/pcfAggregate.ts
 * 之 verifyInput()、server/creds/ccsScopeCert.ts 之 verifyScopeCert())若共用同一函式,缺檔/損毀
 * 就等於「視為全部未撤銷」,是 fail-open。
 *
 * 本檔提供 safeReadOrRefreshStatusListToken():
 *   1. 清單檔缺失 → 回 null(呼叫端 fail-closed)。
 *   2. 清單檔存在但簽章驗證失敗、header.typ 不符、或 bits 解碼失敗(損毀)→ 回 null(fail-closed)。
 *   3. 清單檔存在且成功解碼、簽章通過:
 *      a. 未陳舊(iat 在 ttl+skew 內)→ 原樣回傳,不必刷新。
 *      b. 已陳舊 → **保留現有 bits**、只換新 iat 續簽(呼叫 server/statuslist.ts 已匯出之
 *         buildAndWriteStatusList),避免 make dev 現場閒置超過 ttl(300s)+skew(60s)後,
 *         合法且未撤銷的輸入被誤判為「撤銷」(staleness ≠ 撤銷)。
 * 不修改 server/statuslist.ts(CLAUDE.md 明列不動清單);JWT_STATUS_LIST_TYPE/StatusList/
 * createHeaderAndPayload/getListFromStatusListJWT/StatusType 皆由 @owf/token-status-list
 * 直接匯入(既有相依套件,非新增)。
 */
import type { KeyObject } from 'node:crypto';
import { jwtVerify, decodeProtectedHeader } from 'jose';
import { JWT_STATUS_LIST_TYPE, StatusType, getListFromStatusListJWT } from '@owf/token-status-list';
import {
  readStatusListToken,
  buildAndWriteStatusList,
  withStatusListLock,
  STATUS_LIST_SIZE,
  STATUS_TTL_SECONDS,
  STATUS_CLOCK_SKEW_SEC,
  type StatusListName,
} from '../statuslist';

/** 判斷既有(已驗證通過)清單是否已陳舊、需要刷新——邏輯對齊 server/statuslist.ts 之
 * statusTokenIsStale(該函式未匯出,故此處以已驗證之 payload 獨立重算,不重複讀檔/驗章)。 */
function isStale(payload: Record<string, unknown>, nowSec: number, skewSec: number = STATUS_CLOCK_SKEW_SEC): boolean {
  const iat = typeof payload.iat === 'number' ? payload.iat : 0;
  const ttl = typeof payload.ttl === 'number' ? payload.ttl : STATUS_TTL_SECONDS;
  return nowSec - iat > ttl - skewSec;
}

/**
 * 讀取(必要時刷新)Token Status List Token;缺檔或無法解碼一律回 null,呼叫端須視為
 * fail-closed(不得因此放行撤銷查驗)。
 */
export async function safeReadOrRefreshStatusListToken(
  name: StatusListName,
  issuerPublicKey: KeyObject,
  nowMs: number = Date.now(),
): Promise<string | null> {
  const existing = readStatusListToken(name);
  if (!existing) return null; // fail-closed:清單檔缺失

  let verifiedPayload: Record<string, unknown>;
  try {
    const header = decodeProtectedHeader(existing);
    if (header.typ !== JWT_STATUS_LIST_TYPE) return null; // fail-closed:typ 不符(非狀態清單 token)
    const { payload } = await jwtVerify(existing, issuerPublicKey);
    verifiedPayload = payload as Record<string, unknown>;
  } catch {
    return null; // fail-closed:簽章驗證失敗或無法解碼(損毀)
  }

  const nowSec = Math.floor(nowMs / 1000);
  if (!isStale(verifiedPayload, nowSec)) return existing; // 新鮮:直接沿用,不必刷新

  // 陳舊,但「既有清單已成功解碼且驗章通過」——保留現有 bits、只換新 iat 續簽,不得重建為全 0。
  // P1-3(Codex 審查):此續簽亦是 read-modify-write,與 server/statuslist.ts 之
  // revokeStatusIndex()共用同一把跨行程鎖(withStatusListLock),避免這裡的續簽 write 與另一
  // 行程的撤銷 write 交錯、悄悄覆蓋對方——取鎖後重讀一次現況(可能在等鎖期間已被撤銷或續簽
  // 過),避免用等鎖前讀到的舊 statuses 覆蓋掉新變化。
  return withStatusListLock(name, async () => {
    const freshest = readStatusListToken(name) ?? existing;
    let statuses: number[];
    try {
      const list = getListFromStatusListJWT(freshest);
      statuses = [];
      for (let i = 0; i < STATUS_LIST_SIZE; i++) statuses.push(list.getStatus(i) === StatusType.Valid ? 0 : 1);
    } catch {
      return null; // fail-closed:bits 解碼失敗
    }
    return buildAndWriteStatusList(name, statuses);
  });
}
