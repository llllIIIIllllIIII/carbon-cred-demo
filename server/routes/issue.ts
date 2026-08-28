/**
 * 幕 1 路由(架構決策 §4):
 *   POST /api/issue/upstream — 經 server/keys.ts 載入 Thép Việt sandbox LE AID 鑰簽 pcf_upstream;
 *     機密欄僅 commitment hash;簽發結果寫入 credentials 表。**冪等**(M2 修正,見下)。
 *   POST /api/creds/verify — Tab 1 demo 用之通用 SD-JWT 驗證(僅簽章 + 揭露完整性;
 *     Token Status List/vLEI 鏈屬幕 3 Bruck 端管線,不在此檔範圍)。
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
 */
import type { FastifyInstance } from 'fastify';
import { openDb } from '../db';
import { readManifest, resolvePublicKeyFromManifest } from '../manifest';
import { issuePcfUpstream } from '../creds/pcfUpstream';
import { verifyCompactSdJwt } from '../creds/verifier';
import { tamperPayloadByte } from '../creds/tamper';
import { getCredential, upsertCredential } from '../creds/store';
import type { PcfUpstreamCaseId } from '../../shared/types';

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function registerIssueRoutes(app: FastifyInstance): void {
  app.post('/api/issue/upstream', async (req, reply) => {
    const body = (req.body ?? {}) as { case_id?: string };
    const caseId: PcfUpstreamCaseId = body.case_id === 'B' ? 'B' : 'A';
    const id = `pcf_upstream-${caseId}`;

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

      let issuance: Awaited<ReturnType<typeof issuePcfUpstream>>;
      try {
        issuance = await issuePcfUpstream(caseId);
      } catch (e) {
        return reply.code(500).send({ error: errorMessage(e) });
      }

      try {
        upsertCredential(db, {
          id: issuance.id,
          type: 'pcf_upstream',
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
      } catch (e) {
        return reply.code(500).send({ error: `DB 寫入失敗:${errorMessage(e)}(先跑 make setup / make seed)` });
      }

      return {
        id: issuance.id,
        case_id: issuance.caseId,
        sd_jwt: issuance.sdJwt,
        claims: issuance.payload,
        issued_at: issuance.issuedAt,
        valid_from: issuance.validFrom,
        valid_until: issuance.validUntil,
        issuer_party: issuance.issuerParty,
        holder_party: issuance.holderParty,
        reused: false,
      };
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
