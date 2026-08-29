/**
 * 幕 1/2 前置路由(架構決策 §4):
 *   POST /api/issue/upstream — 經 server/keys.ts 載入 YARN sandbox LE AID 鑰簽 tc_carbon_upstream;
 *     機密欄僅 commitment hash;簽發結果寫入 credentials 表。**冪等**(M2 修正,見下)。
 *   POST /api/issue/dyeing?case=A|B[&reissue=1] — 經 key loader 載入 DYE LE 鑰簽 pcf_dyeing;
 *     排放由係數表計算(熱源/鍋爐效率/綠電比)。reissue=1 = 幕 6 撤銷後重簽:改用備援 idx 與
 *     新報告期,並**替換**DB 既有那筆(upsert)——此為撤銷重簽語意,非一般冪等路徑。
 *   POST /api/creds/verify — Tab 1 demo 用之通用 SD-JWT 驗證(僅簽章 + 揭露完整性;
 *     Token Status List/vLEI 鏈屬幕 3 Brand 端管線,不在此檔範圍)。
 *   POST /api/creds/tamper-demo — 竄改 payload 1 byte,供前端接著打 /api/creds/verify
 *     展示 DoD 要求的失敗畫面(藍圖:133)。
 * 本檔不直接讀鑰檔或 .vlei/state.json;金鑰一律經 server/keys.ts / issuePcfUpstream 取得。
 *
 * M2 修正(Phase 1 總驗收):重複呼叫本路由(同一 case_id)過去會用新的隨機 disclosure 鹽重簽
 * 一份內容相同但 sd_jwt 逐位元不同的 pcf_upstream,並直接覆蓋 credentials 表既有那筆——若該
 * case 已被拿去簽過 pcf_aggregate,pcf_aggregate 內 precursor_ref.hash 就對不上「現在」DB 裡的
 * 上游 sd_jwt,信任鏈靜默斷裂。改為冪等:該 case 已存在 credentials 表就直接回既有憑證
 * (reused:true),不重簽、不覆寫。要重來一組全新資料一律走 make demo-reset(清 DB 重 seed),
 * 不提供 force 參數繞過冪等。
 *
 * Codex 審查發現 1(併發競態)修法:上面的冪等檢查本身是「讀→await 簽章→upsert」,兩個併發請求仍
 * 可能都讀到「未入庫」而各自簽出不同 token。改用 server/creds/store.ts 的 insertCredentialIfAbsent
 * (原子 INSERT OR IGNORE + 重讀落庫勝者)——回應一律以落庫勝者為準,自己輸掉競態就視同 reused。
 *
 * Codex 審查發現 2(case_id 靜默塌縮)修法:過去 `case_id === 'B' ? 'B' : 'A'` 會讓缺值或打錯字
 * 一律塌成 'A' 並真簽發憑證。改為顯式驗證,非 'A'/'B' 一律 400 + CODES.INVALID_CASE_ID。
 */
import type { FastifyInstance } from 'fastify';
import { openDb } from '../db';
import { readManifest, resolvePublicKeyFromManifest } from '../manifest';
import { issueTcCarbonUpstream } from '../creds/tcCarbonUpstream';
import { issuePcfDyeing } from '../creds/pcfDyeing';
import { verifyCompactSdJwt } from '../creds/verifier';
import { tamperPayloadByte } from '../creds/tamper';
import { getCredential, insertCredentialIfAbsent, upsertCredential } from '../creds/store';
import { CODES } from '../../shared/codes';
import type { PcfCaseId } from '../../shared/types';

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function parseCaseId(caseId: unknown): PcfCaseId | null {
  return caseId === 'A' || caseId === 'B' ? caseId : null;
}

export function registerIssueRoutes(app: FastifyInstance): void {
  app.post('/api/issue/upstream', async (req, reply) => {
    const body = (req.body ?? {}) as { case_id?: string };
    const caseId = parseCaseId(body.case_id);
    if (!caseId) {
      return reply.code(400).send({ error: 'case_id 必須是 "A" 或 "B"', reason_code: CODES.INVALID_CASE_ID });
    }
    const id = `tc_carbon_upstream-${caseId}`;

    const db = openDb();
    try {
      // 冪等:該案已簽發過就直接回既有憑證,不重簽(否則會打斷任何已引用其 hash 的 pcf_aggregate)。
      const existing = getCredential(db, id);
      if (existing) {
        return {
          id: existing.id,
          case_id: caseId,
          sd_jwt: existing.sd_jwt,
          claims: JSON.parse(existing.payload_json) as Record<string, unknown>,
          issued_at: existing.issued_at,
          valid_from: existing.valid_from,
          valid_until: existing.valid_until,
          issuer_party: existing.issuer_party,
          holder_party: existing.holder_party,
          reused: true,
        };
      }

      let issuance: Awaited<ReturnType<typeof issueTcCarbonUpstream>>;
      try {
        issuance = await issueTcCarbonUpstream(caseId);
      } catch (e) {
        return reply.code(500).send({ error: errorMessage(e) });
      }

      // 併發防護(發現 1):原子 get-or-create——回應一律以落庫勝者為準,自己輸了就丟棄剛簽的 token。
      let row: ReturnType<typeof insertCredentialIfAbsent>['row'];
      let reused: boolean;
      try {
        const result = insertCredentialIfAbsent(db, {
          id: issuance.id,
          type: 'tc_carbon_upstream',
          caseId: issuance.caseId,
          issuerParty: issuance.issuerParty,
          holderParty: issuance.holderParty,
          sdJwt: issuance.sdJwt,
          payload: issuance.payload,
          statusIdx: issuance.statusIdx,
          statusUri: issuance.statusUri,
          issuedAt: issuance.issuedAt,
          validFrom: issuance.validFrom,
          validUntil: issuance.validUntil,
        });
        row = result.row;
        reused = result.reused;
      } catch (e) {
        return reply.code(500).send({ error: `DB 寫入失敗:${errorMessage(e)}(先跑 make setup / make seed)` });
      }

      return {
        id: row.id,
        case_id: caseId,
        sd_jwt: row.sd_jwt,
        claims: JSON.parse(row.payload_json) as Record<string, unknown>,
        issued_at: row.issued_at,
        valid_from: row.valid_from,
        valid_until: row.valid_until,
        issuer_party: row.issuer_party,
        holder_party: row.holder_party,
        reused,
      };
    } finally {
      db.close();
    }
  });

  app.post('/api/issue/dyeing', async (req, reply) => {
    const query = (req.query ?? {}) as { case?: string; reissue?: string };
    const body = (req.body ?? {}) as { case_id?: string };
    const caseId = parseCaseId(query.case ?? body.case_id);
    if (!caseId) {
      return reply.code(400).send({ error: 'case 必須是 "A" 或 "B"', reason_code: CODES.INVALID_CASE_ID });
    }
    const reissue = query.reissue === '1';
    const id = `pcf_dyeing-${caseId}`;

    const db = openDb();
    try {
      // 一般路徑冪等(同 upstream);reissue 為幕 6 撤銷後重簽,必須替換既有那筆。
      if (!reissue) {
        const existing = getCredential(db, id);
        if (existing) {
          return {
            id: existing.id,
            case_id: caseId,
            sd_jwt: existing.sd_jwt,
            claims: JSON.parse(existing.payload_json) as Record<string, unknown>,
            issued_at: existing.issued_at,
            valid_from: existing.valid_from,
            valid_until: existing.valid_until,
            issuer_party: existing.issuer_party,
            holder_party: existing.holder_party,
            reused: true,
          };
        }
      }

      let issuance: Awaited<ReturnType<typeof issuePcfDyeing>>;
      try {
        issuance = await issuePcfDyeing(caseId, { reissue });
      } catch (e) {
        return reply.code(500).send({ error: errorMessage(e) });
      }

      try {
        const rec = {
          id: issuance.id,
          type: 'pcf_dyeing',
          caseId: issuance.caseId,
          issuerParty: issuance.issuerParty,
          holderParty: issuance.holderParty,
          sdJwt: issuance.sdJwt,
          payload: issuance.payload,
          statusIdx: issuance.statusIdx,
          statusUri: issuance.statusUri,
          issuedAt: issuance.issuedAt,
          validFrom: issuance.validFrom,
          validUntil: issuance.validUntil,
        };
        if (reissue) {
          upsertCredential(db, rec);
          const row = getCredential(db, id);
          if (!row) throw new Error('reissue 落庫後讀不回憑證');
          return {
            id: row.id,
            case_id: caseId,
            sd_jwt: row.sd_jwt,
            claims: JSON.parse(row.payload_json) as Record<string, unknown>,
            issued_at: row.issued_at,
            valid_from: row.valid_from,
            valid_until: row.valid_until,
            issuer_party: row.issuer_party,
            holder_party: row.holder_party,
            reissued: true,
          };
        }
        const { row, reused } = insertCredentialIfAbsent(db, rec);
        return {
          id: row.id,
          case_id: caseId,
          sd_jwt: row.sd_jwt,
          claims: JSON.parse(row.payload_json) as Record<string, unknown>,
          issued_at: row.issued_at,
          valid_from: row.valid_from,
          valid_until: row.valid_until,
          issuer_party: row.issuer_party,
          holder_party: row.holder_party,
          reused,
        };
      } catch (e) {
        return reply.code(500).send({ error: `DB 寫入失敗:${errorMessage(e)}(先跑 make setup / make seed)` });
      }
    } finally {
      db.close();
    }
  });

  app.post('/api/creds/verify', async (req, reply) => {
    const body = (req.body ?? {}) as { sd_jwt?: string };
    if (!body.sd_jwt) return reply.code(400).send({ error: '缺少 sd_jwt' });
    const manifest = readManifest();
    if (!manifest) return reply.code(404).send({ error: 'manifest 尚未產生(先跑 make setup)' });

    // L1 修正:理由碼區分解析失敗(CREDENTIAL_PARSE_ERROR)/簽發者未登錄(ISSUER_UNKNOWN)/
    // 簽章或揭露不符(CREDENTIAL_SIG_INVALID)——由 verifyCompactSdJwt 分類產出,本路由原樣回傳。
    const result = await verifyCompactSdJwt(body.sd_jwt, resolvePublicKeyFromManifest(manifest));
    return {
      valid: result.ok,
      reason_code: result.ok ? undefined : result.reasonCode,
      error: result.error,
      payload: result.payload,
    };
  });

  app.post('/api/creds/tamper-demo', async (req, reply) => {
    const body = (req.body ?? {}) as { sd_jwt?: string };
    if (!body.sd_jwt) return reply.code(400).send({ error: '缺少 sd_jwt' });
    try {
      return { sd_jwt: tamperPayloadByte(body.sd_jwt) };
    } catch (e) {
      return reply.code(400).send({ error: errorMessage(e) });
    }
  });
}
