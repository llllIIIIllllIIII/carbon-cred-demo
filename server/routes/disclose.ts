/**
 * 幕 3 委任查驗 + 幕 4 越界攔截路由(架構決策 §4):POST /api/disclose。
 * 全部驗證/Cedar/交易邏輯在 server/creds/discloseGateway.ts;本檔僅負責 HTTP 轉譯。
 */
import type { FastifyInstance } from 'fastify';
import { openDb } from '../db';
import { processDiscloseRequest } from '../creds/discloseGateway';

export function registerDiscloseRoutes(app: FastifyInstance): void {
  app.post('/api/disclose', async (req, reply) => {
    const body = (req.body ?? {}) as { request_jws?: string };
    const db = openDb();
    try {
      const result = await processDiscloseRequest(db, body.request_jws);
      if (result.kind === 'success') {
        return {
          decision: 'PERMIT',
          policy_id: result.policyId,
          presentation: result.presentation,
          mandate_id: result.mandateId,
          case_id: result.caseId,
        };
      }
      return reply.code(result.httpStatus).send({
        decision: result.decision,
        reason_code: result.reasonCode,
        policy_id: result.policyId,
      });
    } finally {
      db.close();
    }
  });
}
