/**
 * 幕 2 路由(架構決策 §4):
 *   POST /api/aggregate — 讀該案上游 pcf_upstream(未簽發則依幕 1 邏輯先簽)→ 以持有者身分
 *     消費前先驗上游簽章(manifest 公鑰,驗不過回 CODES.CREDENTIAL_SIG_INVALID,不得跳過)→
 *     程式計算聚合(規格v2 §4.3)→ 經 server/keys.ts 載入鴻鋼 sandbox LE AID 鑰簽 pcf_aggregate →
 *     入 credentials 表。pcf_aggregate 不含上游任何明細欄位,precursor_ref 僅留上游憑證
 *     id + sha256 hash(藍圖:150)。
 * 本檔不直接讀鑰檔或 .vlei/state.json;金鑰一律經 server/keys.ts / issuePcfAggregate 取得。
 *
 * Codex 審查發現 2(case_id 靜默塌縮)修法:過去 `case_id === 'B' ? 'B' : 'A'` 會讓缺值或打錯字
 * 一律塌成 'A' 並真簽發憑證。改為顯式驗證,非 'A'/'B' 一律 400 + CODES.INVALID_CASE_ID。
 */
import type { FastifyInstance } from 'fastify';
import { openDb } from '../db';
import { issuePcfAggregate, UpstreamVerificationError } from '../creds/pcfAggregate';
import { CODES } from '../../shared/codes';
import type { PcfAggregateCaseId } from '../../shared/types';

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function parseCaseId(caseId: unknown): PcfAggregateCaseId | null {
  return caseId === 'A' || caseId === 'B' ? caseId : null;
}

export function registerAggregateRoutes(app: FastifyInstance): void {
  app.post('/api/aggregate', async (req, reply) => {
    const body = (req.body ?? {}) as { case_id?: string };
    const caseId = parseCaseId(body.case_id);
    if (!caseId) {
      return reply.code(400).send({ error: 'case_id 必須是 "A" 或 "B"', reason_code: CODES.INVALID_CASE_ID });
    }

    const db = openDb();
    try {
      // issuePcfAggregate 內部已原子落庫(遺留 c:insertCredentialIfAbsent,比照 store.ts 模式)——
      // 本路由不得再自行 upsertCredential,否則會用「這次呼叫者自己的版本」覆寫落庫勝者,
      // 重新引入遺留 c 要修的併發競態。
      let issuance: Awaited<ReturnType<typeof issuePcfAggregate>>;
      try {
        issuance = await issuePcfAggregate(db, caseId);
      } catch (e) {
        if (e instanceof UpstreamVerificationError) {
          return reply.code(502).send({ error: e.message, reason_code: e.reasonCode });
        }
        return reply.code(500).send({ error: errorMessage(e) });
      }

      return {
        id: issuance.id,
        case_id: issuance.caseId,
        sd_jwt: issuance.sdJwt,
        claims: issuance.payload,
        breakdown: {
          precursor_contribution_tco2e_per_t: issuance.breakdown.precursorContribution,
          self_direct_tco2e_per_t: issuance.breakdown.selfDirect,
          self_indirect_tco2e_per_t: issuance.breakdown.selfIndirect,
          carbon_total_tco2e_per_t: issuance.breakdown.total,
        },
        precursor_ref: issuance.precursorRef,
        issued_at: issuance.issuedAt,
        valid_from: issuance.validFrom,
        valid_until: issuance.validUntil,
        issuer_party: issuance.issuerParty,
        holder_party: issuance.holderParty,
        // L3 修正:合約碳排門檻改由後端提供(data/seed.json),前端疊層熱點圖不再寫死 2.0。
        contract_carbon_max: issuance.contractCarbonMax,
      };
    } finally {
      db.close();
    }
  });
}
