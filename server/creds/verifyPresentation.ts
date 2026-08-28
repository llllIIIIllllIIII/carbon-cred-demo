/**
 * Bruck 端驗證核心(幕 3 DoD)——POST /api/verify 與 scripts/verify-offline.ts 共用同一函式,
 * 避免雙寫(impl-spec §3)。
 *
 * 鐵則(CLAUDE.md:25):只讀 token、manifest 公鑰、data/vlei/、data/status/;不得呼叫閘道 API、
 * 不得讀他方 DB 資料——本檔不 import server/db.ts 的 openDb()/openDbIfExists(),不碰
 * db/demo.sqlite。
 *
 * H3 修正(Phase 2 總驗收):vLEI 鏈查驗仍以 sandbox verify(child_process)執行真實查驗,
 * 但 --dir 改指 data/vlei/public-state/(server/keys.ts 匯出之公開子集,不含任何私鑰種子),
 * 不再指向 repo 根而讀到 `.vlei/state.json`。先前雖然驗證本身只消費公開材料(沒用到 seed),
 * 讀取範圍仍逾越 CLAUDE.md:25、也與前端「只讀 token/manifest/data/vlei/data/status」的文案
 * 不符;現在該文案為真。查驗強度不變(SAID 重算 + 簽章 + TEL 撤銷 + 邊 I2I 全部照跑)。
 *
 * 檢查項(impl-spec §3,每項獨立布林 + 失敗理由碼):
 *   1. SD-JWT 簽章 + 揭露完整性(verifyCompactSdJwt)。
 *   2. vct ↔ 簽發者 AID 綁定(遺留 a + C1):pcf_aggregate 只認鴻鋼 LE AID、pcf_upstream 只認
 *      Thép Việt LE AID——AID 動態自 manifest 取,不硬編;**以實際驗章鑰(header.kid)為準**,
 *      並要求 payload.iss 與實際簽章者一致;不符 → VCT_ISSUER_UNAUTHORIZED。
 *   3. vLEI 鏈(sandbox verify child_process;查的是**實際簽章者**對應的角色 SAID)。
 *   4. Status List(credentials 清單;先驗 JWS 簽章再解碼查 idx)。
 *   5. 雙向約束(幕 3 DoD):presentation 揭露的 claims ⊆ M2 mandate_jwt.allowed_claims,
 *      違者 → CLAIM_NOT_IN_MANDATE。
 */
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { jwtVerify, decodeProtectedHeader } from 'jose';
import { ROOT, VLEI_PUBLIC_STATE_DIR } from '../db';
import { verifyCompactSdJwt } from './verifier';
import { resolvePublicKeyFromManifest } from '../manifest';
import { checkStatusBit, readStatusListToken } from '../statuslist';
import { PCF_AGGREGATE_VCT } from './pcfAggregate';
import { PCF_UPSTREAM_VCT } from './pcfUpstream';
import { PCF_AGGREGATE_CUSTOMS_SD_FIELDS, PCF_AGGREGATE_CUSTOMER_SD_FIELDS } from '../../shared/types';
import { CODES, type ReasonCode } from '../../shared/codes';
import type { Manifest, MandatePayload } from '../../shared/types';

/** vct → 唯一被授權簽發該 vct 的角色(manifest 鍵)——遺留(a)之綁定表,動態查 AID,不硬編字面值。 */
const VCT_ISSUER_ROLE: Record<string, string> = {
  [PCF_AGGREGATE_VCT]: 'hunggang',
  [PCF_UPSTREAM_VCT]: 'thepviet',
};

const PCF_AGGREGATE_SD_FIELDS: readonly string[] = [...PCF_AGGREGATE_CUSTOMS_SD_FIELDS, ...PCF_AGGREGATE_CUSTOMER_SD_FIELDS];

/** M2 mandate 之唯一合法簽發角色(Bruck 永續長 ECR;M2 修正:mandate iss 必須綁預期角色)。 */
const M2_ISSUER_ROLE = 'bruck_cso';

/** manifest 反查:AID → 角色鍵(C1:由**實際驗章鑰**決定角色,而非由 payload 宣稱值決定)。 */
function roleOfAid(manifest: Manifest, aid: string): string | undefined {
  return Object.entries(manifest).find(([, r]) => r.aid === aid)?.[0];
}

export interface VerifyCheck {
  name: string;
  ok: boolean;
  reasonCode?: ReasonCode;
  detail?: string;
}

export interface VerifyPresentationResult {
  ok: boolean;
  checks: VerifyCheck[];
  payload?: Record<string, unknown>;
}

export interface VerifyPresentationInput {
  presentationSdJwt: string;
  mandateJwt: string;
  manifest: Manifest;
}

/**
 * vLEI 鏈查驗(真實 sandbox verify:SAID 重算 + 簽章 + LEI 檢核碼 + TEL 撤銷狀態 + 邊 I2I)。
 * H3:--dir 指向公開狀態目錄(不含私鑰種子);該目錄由 scripts/seed.ts(make setup /
 * make demo-reset)經 server/keys.ts 產生,缺檔時明確回報,不靜默當成「鏈壞掉」。
 */
function verifyVleiChainSandbox(credentialSaid: string): { ok: boolean; detail?: string } {
  const publicState = path.join(VLEI_PUBLIC_STATE_DIR, '.vlei', 'state.json');
  if (!fs.existsSync(publicState)) {
    return { ok: false, detail: `vLEI 公開狀態不存在(${path.relative(ROOT, publicState)})——先跑 make demo-reset(scripts/seed.ts)` };
  }
  const py = path.join(ROOT, '.venv', 'bin', 'python');
  const sb = path.join(ROOT, 'vendor', 'vlei-sandbox', 'scripts', 'vlei_sandbox.py');
  const r = spawnSync(py, [sb, '--dir', VLEI_PUBLIC_STATE_DIR, 'verify', '--said', credentialSaid], { encoding: 'utf-8' });
  const ok = r.status === 0 && r.stdout.includes('chain verified');
  return { ok, detail: ok ? undefined : (r.stderr || r.stdout || `exit=${r.status}`).slice(0, 300) };
}

/**
 * 驗 M2 mandate_jwt 簽章(供第 5 項雙向約束比對 allowed_claims;僅供本地比對用,不重跑完整閘道管線)。
 * M2 修正(C1 同源):簽章鑰必須是 Bruck 永續長 ECR AID(manifest 動態取),且 payload.iss 必須
 * 等於該 AID——header.kid 取鑰卻不校驗 iss,等於讓任何 manifest 內的鑰都能簽出「M2 委任狀」。
 */
async function verifyMandateForComparison(
  mandateJwt: string,
  manifest: Manifest,
): Promise<{ ok: boolean; payload?: MandatePayload; error?: string }> {
  const expectedIssuerAid = manifest[M2_ISSUER_ROLE]?.aid;
  if (!expectedIssuerAid) return { ok: false, error: `manifest 缺少 ${M2_ISSUER_ROLE} 角色,無法確認 M2 mandate 簽發者` };
  try {
    const header = decodeProtectedHeader(mandateJwt);
    if (header.kid !== expectedIssuerAid) {
      return { ok: false, error: `M2 mandate 簽章鑰(kid=${header.kid ?? '(無)'})非 Bruck 永續長 ECR AID(${expectedIssuerAid})` };
    }
    const key = resolvePublicKeyFromManifest(manifest)(expectedIssuerAid);
    if (!key) return { ok: false, error: `找不到 mandate 簽發者公鑰(kid=${expectedIssuerAid})` };
    // issuer 選項:payload.iss 必須等於實際驗章鑰對應之 AID(簽章者身分 = 宣稱簽發者)。
    const { payload } = await jwtVerify(mandateJwt, key, { issuer: expectedIssuerAid });
    return { ok: true, payload: payload as unknown as MandatePayload };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/** Bruck 端驗證主流程——依序執行 5 項檢查,任一失敗即回傳(已完成之檢查全數附在 checks 內)。 */
export async function verifyPresentation(input: VerifyPresentationInput): Promise<VerifyPresentationResult> {
  const checks: VerifyCheck[] = [];

  // 1) SD-JWT 簽章 + 揭露完整性。
  const sigResult = await verifyCompactSdJwt(input.presentationSdJwt, resolvePublicKeyFromManifest(input.manifest));
  checks.push({
    name: 'SD-JWT 簽章與揭露完整性',
    ok: sigResult.ok,
    reasonCode: sigResult.reasonCode,
    detail: sigResult.error,
  });
  if (!sigResult.ok || !sigResult.payload) return { ok: false, checks };
  const payload = sigResult.payload as unknown as Record<string, unknown>;

  // 2) vct ↔ 簽發者 AID 綁定(遺留 a + C1)。
  //    C1:綁定的對象是「實際驗過章的鑰」(sigResult.kid),不是 payload 宣稱的 iss。
  //    舊版只比對 payload.iss,而取鑰走 header.kid,兩者從不互相校驗——攻擊者用自己的鑰簽章、
  //    把 iss 填成鴻鋼 AID 即可通過全部檢查(PoC 已證實可偽造 carbon_total)。此處三個條件同時要求:
  //      (i) 實際簽章者 = 該 vct 唯一被授權的角色 AID;(ii) payload.iss = 實際簽章者(不得脫鉤)。
  const vct = typeof payload.vct === 'string' ? payload.vct : undefined;
  const expectedRole = vct ? VCT_ISSUER_ROLE[vct] : undefined;
  const expectedAid = expectedRole ? input.manifest[expectedRole]?.aid : undefined;
  const signerAid = sigResult.kid; // 實際解出公鑰、且驗章通過的那把鑰
  const claimedIss = typeof payload.iss === 'string' ? payload.iss : undefined;
  const signerRole = signerAid ? roleOfAid(input.manifest, signerAid) : undefined;
  const vctOk = !!expectedRole && !!expectedAid && !!signerAid && signerAid === expectedAid && claimedIss === signerAid;
  checks.push({
    name: 'vct↔簽發者 AID 綁定(以實際驗章鑰為準)',
    ok: vctOk,
    reasonCode: vctOk ? undefined : CODES.VCT_ISSUER_UNAUTHORIZED,
    detail: vctOk
      ? undefined
      : `vct=${vct ?? '(無)'} 實際簽章者=${signerAid ?? '(無)'}(角色=${signerRole ?? '未登錄'}) ` +
        `宣稱 iss=${claimedIss ?? '(無)'} 預期角色=${expectedRole ?? '未知 vct'} 預期AID=${expectedAid ?? '(無)'}`,
  });
  if (!vctOk) return { ok: false, checks, payload };

  // 3) vLEI 鏈(sandbox verify)——查的是**實際簽章者**對應角色的憑證 SAID(C1:不得用 payload 宣稱值,
  //    否則等於拿被冒充方的憑證去驗攻擊者的簽章)。經上面的檢查,signerRole === expectedRole。
  const credentialSaid = input.manifest[signerRole!].credential_said;
  const chainResult = verifyVleiChainSandbox(credentialSaid);
  checks.push({
    name: 'vLEI 鏈(sandbox TEL)',
    ok: chainResult.ok,
    reasonCode: chainResult.ok ? undefined : CODES.VLEI_CHAIN_BROKEN,
    detail: chainResult.detail,
  });
  if (!chainResult.ok) return { ok: false, checks, payload };

  // 4) Status List(credentials 清單)。
  const statusEntry = (payload.status as { status_list?: { idx?: number } } | undefined)?.status_list;
  const statusIssuerKey = resolvePublicKeyFromManifest(input.manifest)(input.manifest.hunggang.aid);
  const credentialsListToken = readStatusListToken('credentials');
  let statusOk = false;
  let statusDetail: string | undefined;
  if (statusEntry?.idx == null || !statusIssuerKey || !credentialsListToken) {
    statusDetail = 'status.status_list.idx 缺失或 Status List Token 尚未產生';
  } else {
    const result = await checkStatusBit(credentialsListToken, statusEntry.idx, statusIssuerKey);
    statusOk = result.ok && !result.revoked;
    statusDetail = result.error ?? (result.revoked ? `idx=${statusEntry.idx} 已撤銷` : undefined);
  }
  checks.push({
    name: '撤銷狀態(Status List)',
    ok: statusOk,
    reasonCode: statusOk ? undefined : CODES.CREDENTIAL_REVOKED,
    detail: statusDetail,
  });
  if (!statusOk) return { ok: false, checks, payload };

  // 5) 雙向約束:presentation 揭露的 claims ⊆ M2 mandate_jwt.allowed_claims。
  const mandateResult = await verifyMandateForComparison(input.mandateJwt, input.manifest);
  if (!mandateResult.ok || !mandateResult.payload) {
    checks.push({ name: 'M2 mandate 簽章驗證(供邊界比對用)', ok: false, reasonCode: CODES.MANDATE_SIG_INVALID, detail: mandateResult.error });
    return { ok: false, checks, payload };
  }
  checks.push({ name: 'M2 mandate 簽章驗證(供邊界比對用)', ok: true });

  const allowedClaims = mandateResult.payload.allowed_claims;
  const disclosedSdFields = PCF_AGGREGATE_SD_FIELDS.filter((f) => f in payload);
  const overreach = disclosedSdFields.filter((f) => !allowedClaims.includes(f));
  const boundaryOk = overreach.length === 0;
  checks.push({
    name: '雙向約束:揭露 claims ⊆ mandate.allowed_claims',
    ok: boundaryOk,
    reasonCode: boundaryOk ? undefined : CODES.CLAIM_NOT_IN_MANDATE,
    detail: boundaryOk ? undefined : `逾越 mandate 範圍之揭露欄位:${overreach.join(', ')}`,
  });
  if (!boundaryOk) return { ok: false, checks, payload };

  return { ok: true, checks, payload };
}
