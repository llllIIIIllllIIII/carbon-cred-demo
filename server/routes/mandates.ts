/**
 * 幕 3 前置路由(架構決策 §4):POST /api/mandates — 簽 M1 或 M2。
 * 冪等(比照 routes/issue.ts、routes/aggregate.ts 之 insertMandateIfAbsent 原子模式):
 * 同一 mandate 重複呼叫回落庫勝者的 token(reused:true),不重簽。
 */
import type { FastifyInstance } from 'fastify';
import { openDb } from '../db';
import { issueMandate } from '../creds/mandate';
import { insertMandateIfAbsent } from '../creds/mandateStore';
import { CODES } from '../../shared/codes';
import type { MandateId } from '../../shared/types';

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function parseMandateId(v: unknown): MandateId | null {
  return v === 'M1' || v === 'M2' ? v : null;
}

export function registerMandateRoutes(app: FastifyInstance): void {
  app.post('/api/mandates', async (req, reply) => {
    const body = (req.body ?? {}) as { mandate?: string };
    const mandateId = parseMandateId(body.mandate);
    if (!mandateId) {
      return reply.code(400).send({ error: 'mandate 必須是 "M1" 或 "M2"', reason_code: CODES.INVALID_MANDATE_ID });
    }

    const db = openDb();
    try {
      let issuance: Awaited<ReturnType<typeof issueMandate>>;
      try {
        issuance = await issueMandate(mandateId);
      } catch (e) {
        return reply.code(500).send({ error: errorMessage(e) });
      }

      let row: ReturnType<typeof insertMandateIfAbsent>['row'];
      let reused: boolean;
      try {
        const result = insertMandateIfAbsent(db, {
          id: issuance.id,
          jti: issuance.jti,
          issuerParty: issuance.issuerParty,
          aud: issuance.payload.aud,
          purpose: issuance.purpose,
          agentId: issuance.agentId,
          delegateKid: issuance.delegateKid,
          allowedClaims: issuance.allowedClaims,
          maxGranularity: issuance.maxGranularity,
          queryCap: issuance.queryCap,
          policyVersion: issuance.policyVersion,
          mandateNonce: issuance.mandateNonce,
          extra: issuance.extra,
          token: issuance.token,
          statusIdx: issuance.statusIdx,
          statusUri: issuance.statusUri,
          validFrom: issuance.validFrom,
          validUntil: issuance.validUntil,
        });
        row = result.row;
        reused = result.reused;
      } catch (e) {
        return reply.code(500).send({ error: `DB 寫入失敗:${errorMessage(e)}(先跑 make setup / make seed)` });
      }

      return {
        mandate_jwt: row.token,
        reused,
        summary: {
          jti: row.jti,
          allowed_claims: JSON.parse(row.allowed_claims) as string[],
          valid_until: row.valid_until,
          delegate_kid: row.delegate_kid,
          status: { idx: row.status_idx, uri: row.status_uri },
        },
      };
    } finally {
      db.close();
    }
  });
}
