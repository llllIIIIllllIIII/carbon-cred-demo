/**
 * 幕 2 路由(架構決策 §4):
 *   POST /api/aggregate — 讀該案兩張外部輸入憑證 tc_carbon_upstream 與 pcf_dyeing(未簽發則依
 *     前置邏輯先簽)→ 以持有者身分消費前兩張皆先驗章(manifest 公鑰,驗不過回
 *     CODES.CREDENTIAL_SIG_INVALID,不得跳過)→ 程式計算三段聚合(spec v3 §4.4)→ 經
 *     server/keys.ts 載入 FAB sandbox LE AID 鑰簽 pcf_aggregate → 入 credentials 表。
 *     pcf_aggregate 不含上游任何明細欄位,precursor_refs 僅留兩張外部憑證 id + sha256 hash。
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

      // F1(Codex adversarial review):**不**回完整可再揭露的 SD-JWT,也不回含三個永不揭露分項欄位名
      // 的完整 claims payload。pcf_aggregate 是 FAB 內部簽發物;若把完整 token 交給任意(未授權)跨組織
      // 呼叫者,對方即可持有並自行 present pcf_yarn / pcf_knitting / pcf_dyeing(NEVER_DISCLOSABLE 三欄),
      // 繞過 /api/disclose 的 mandate + Cedar 逐 claim 最小揭露邊界。
      // 跨組織揭露一律走 POST /api/disclose;此端點只回「FAB 自有閘道頁」所需之內部檢視(三段疊層圖真值 +
      // 公開/品牌層卡片欄位),不含任何可被他方持有、再揭露的簽章 token。
      return {
        id: issuance.id,
        case_id: issuance.caseId,
        // 三段疊層熱點圖真值(FAB 自己的資料,顯示於 FAB 自有閘道頁)——非可攜、非簽章 token。
        breakdown: {
          pcf_yarn: issuance.breakdown.pcfYarn,
          pcf_knitting: issuance.breakdown.pcfKnitting,
          pcf_dyeing: issuance.breakdown.pcfDyeing,
          pcf_total: issuance.breakdown.total,
        },
        // 憑證卡顯示用之公開/品牌層欄位(明列,非整包 claims;三個永不揭露分項只在 breakdown 出現)。
        product: issuance.payload.product,
        hs6: issuance.payload.hs6,
        origin: issuance.payload.origin,
        quantity_kg: issuance.payload.quantity_kg,
        precursor_refs: issuance.precursorRefs,
        status: issuance.payload.status.status_list,
        issued_at: issuance.issuedAt,
        valid_from: issuance.validFrom,
        valid_until: issuance.validUntil,
        issuer_party: issuance.issuerParty,
        holder_party: issuance.holderParty,
        // L3 修正:合約碳排門檻改由後端提供(data/seed.json),前端疊層熱點圖不再寫死門檻值。
        contract_carbon_max: issuance.contractCarbonMax,
      };
    } finally {
      db.close();
    }
  });
}
