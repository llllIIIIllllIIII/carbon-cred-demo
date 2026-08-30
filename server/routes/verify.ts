/**
 * 幕 3 Brand 端路由(架構決策 §4):POST /api/verify — 線上呼叫版(Tab3 展示用);
 * 核心邏輯全在 server/creds/verifyPresentation.ts,與 scripts/verify-offline.ts 共用同一函式。
 */
import type { FastifyInstance } from 'fastify';
import { readManifest } from '../manifest';
import { verifyPresentation } from '../creds/verifyPresentation';

export function registerVerifyRoutes(app: FastifyInstance): void {
  app.post('/api/verify', async (req, reply) => {
    const body = (req.body ?? {}) as { presentation?: string; mandate_jwt?: string; receipt?: string };
    if (!body.presentation || !body.mandate_jwt) {
      return reply.code(400).send({ error: '缺少 presentation 或 mandate_jwt' });
    }
    const manifest = readManifest();
    if (!manifest) {
      return reply.code(404).send({ error: 'manifest 尚未產生(先跑 make setup)' });
    }
    const result = await verifyPresentation({
      presentationSdJwt: body.presentation,
      mandateJwt: body.mandate_jwt,
      manifest,
      // F4:閘道 receipt(隨 /api/disclose 回傳)——key-binding 驗證所需。
      receipt: body.receipt,
    });
    return { valid: result.ok, checks: result.checks, payload: result.payload };
  });
}
