/**
 * 幕 6 稽核與撤銷(架構決策 §4;phase-briefs/phase-3b.md):
 *   GET  /api/dossiers          — Dossier 列表,供 Audit 分頁渲染。查詢時對 PENDING_HUMAN/
 *                                  RELEASED 之列驗其 JWS(fab-workload 公鑰)取出凍結的
 *                                  credential_hashes,交給 server/routes/agent.ts 之
 *                                  checkDossierInputsCurrent 重驗現況(P1-1 修法:一律以凍結
 *                                  hash 查歷史版本,不看現況 case rows——即使該案已 reissue,
 *                                  舊 Dossier 凍結之已撤銷依據仍持續回報)。不過則附帶衍生欄位
 *                                  effective_status=DEPENDS_REVOKED——不竄改 Dossier 原 JWS,
 *                                  也不改動 DB 之 status 欄位(RELEASED 依然是 RELEASED;
 *                                  PENDING_HUMAN 之終態轉換僅在 human-sign 端發生)。
 *   POST /api/audit/revoke      — Audit 分頁「撤銷開關」之後端 API:與 scripts/revoke.ts
 *                                  (`make revoke`)共用同一份 server/statuslist.ts
 *                                  revokeStatusIndex() 邏輯;完成後經 server/audit.ts
 *                                  appendAudit() 入鏈(非 PERMIT/DENY/RELEASE/REPLAY_DETECTED
 *                                  之存取決策,故不經 recordDecision,但仍是 audit.ts 之
 *                                  稽核鏈寫入,verify-chain.ts 可驗)。
 *   GET  /api/status/:name/bits — 展示用端點:讀取 data/status/<name>.jwt、驗簽後解碼
 *                                  status_list.bits,附 idx→id 標籤(讀 data/seed.json
 *                                  status_list_idx)供 Audit 分頁畫 bit 條。/status/:name 之
 *                                  正式協定端點(compact signed JWT)不受影響、不改變語意。
 */
import fs from 'node:fs';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';
import { jwtVerify } from 'jose';
import { getListFromStatusListJWT, StatusType } from '@owf/token-status-list';
import { ROOT, openDb } from '../db';
import { readManifest, resolvePublicKeyFromManifest } from '../manifest';
import { readStatusListToken, revokeStatusIndex, STATUS_LIST_NAMES, STATUS_LIST_SIZE, type StatusListName } from '../statuslist';
import { appendAudit } from '../audit';
import { checkDossierInputsCurrent } from './agent';
import { verifyDossierJws } from './humanSign';
import { DOSSIER_STATUS } from '../../shared/codes';

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

interface DossierListRow {
  id: string;
  case_id: string;
  mandate_id: string;
  mandate_jti: string;
  jws: string;
  status: string;
  created_at: string;
  released_at: string | null;
}

export function registerAuditRoutes(app: FastifyInstance): void {
  app.get('/api/dossiers', async (_req, reply) => {
    const manifest = readManifest();
    if (!manifest) return reply.code(404).send({ error: 'manifest 尚未產生(先跑 make setup)' });

    const db = openDb();
    try {
      const rows = db
        .prepare('SELECT id, case_id, mandate_id, mandate_jti, jws, status, created_at, released_at FROM dossiers ORDER BY created_at ASC, id ASC')
        .all() as DossierListRow[];
      const nowMs = Date.now();
      const out: Array<Omit<DossierListRow, 'jws'> & { effective_status: string }> = [];
      for (const { jws, ...row } of rows) {
        let effectiveStatus = row.status;
        if (row.status === DOSSIER_STATUS.PENDING_HUMAN || row.status === DOSSIER_STATUS.RELEASED) {
          // P1-1(Codex 審查):不得以 case_id 查「現況」credentials rows——一律先驗 Dossier 自身
          // JWS 取出凍結的 credential_hashes,查歷史版本之現況撤銷位(見 agent.ts 說明)。
          const jwsVerify = await verifyDossierJws(jws);
          const check = jwsVerify.ok
            ? await checkDossierInputsCurrent(db, manifest, jwsVerify.payload.credential_hashes, nowMs)
            : { ok: false as const, detail: 'Dossier JWS 驗證失敗' };
          if (!check.ok) effectiveStatus = DOSSIER_STATUS.DEPENDS_REVOKED;
        }
        out.push({ ...row, effective_status: effectiveStatus });
      }
      return out;
    } finally {
      db.close();
    }
  });

  app.post('/api/audit/revoke', async (req, reply) => {
    const body = (req.body ?? {}) as { list?: string; idx?: number | string };
    const list = body.list;
    const idx = Number(body.idx);
    if (!list || !STATUS_LIST_NAMES.includes(list as StatusListName)) {
      return reply.code(400).send({ error: `list 必須是 ${STATUS_LIST_NAMES.join('|')}` });
    }
    if (!Number.isInteger(idx) || idx < 0 || idx >= STATUS_LIST_SIZE) {
      return reply.code(400).send({ error: `idx 必須是 0~${STATUS_LIST_SIZE - 1} 的整數` });
    }
    try {
      await revokeStatusIndex(list as StatusListName, idx);
    } catch (e) {
      return reply.code(500).send({ error: errorMessage(e) });
    }
    const db = openDb();
    try {
      appendAudit(db, 'admin:revoke', { list, idx });
    } finally {
      db.close();
    }
    return { ok: true, list, idx };
  });

  app.get('/api/status/:name/bits', async (req, reply) => {
    const { name } = req.params as { name: string };
    if (!STATUS_LIST_NAMES.includes(name as StatusListName)) {
      return reply.code(404).send({ error: 'unknown status list' });
    }
    const manifest = readManifest();
    if (!manifest) return reply.code(404).send({ error: 'manifest 尚未產生(先跑 make setup)' });
    const issuerKey = resolvePublicKeyFromManifest(manifest)(manifest.fab.aid);
    const token = readStatusListToken(name as StatusListName);
    if (!issuerKey || !token) return reply.code(404).send({ error: 'status list 尚未產生(先跑 make setup)' });
    try {
      const { payload } = await jwtVerify(token, issuerKey);
      const list = getListFromStatusListJWT(token);
      const bits: number[] = [];
      for (let i = 0; i < STATUS_LIST_SIZE; i++) bits.push(list.getStatus(i) === StatusType.Valid ? 0 : 1);
      const seed = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8')) as {
        status_list_idx: Record<string, Record<string, number>>;
      };
      const idxMap = seed.status_list_idx[name] ?? {};
      const labels = new Array<string>(STATUS_LIST_SIZE).fill('');
      for (const [id, idx] of Object.entries(idxMap)) {
        if (idx >= 0 && idx < STATUS_LIST_SIZE) labels[idx] = id;
      }
      return { name, sub: payload.sub, iat: payload.iat, bits, labels };
    } catch (e) {
      return reply.code(502).send({ error: `status list 解碼/驗章失敗:${errorMessage(e)}` });
    }
  });
}
