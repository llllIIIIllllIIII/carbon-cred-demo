import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import Fastify from 'fastify';
import { ROOT, openDbIfExists } from './db';
import { readStatusListToken, STATUS_MEDIA_TYPE, STATUS_LIST_NAMES, type StatusListName } from './statuslist';
import { registerIssueRoutes } from './routes/issue';
import { registerAggregateRoutes } from './routes/aggregate';
import { registerMandateRoutes } from './routes/mandates';
import { registerDiscloseRoutes } from './routes/disclose';
import { registerVerifyRoutes } from './routes/verify';
import { registerDemoRoutes } from './routes/demo';
import { registerPolicyRoutes } from './routes/policies';

const MANIFEST_PATH = path.join(ROOT, 'data', 'vlei', 'manifest.json');

export function buildServer() {
  const app = Fastify({ logger: false });

  app.get('/api/healthz', async () => ({ ok: true, service: 'carbon-cred-demo', ts: new Date().toISOString() }));

  // manifest 為公開材料(alias/aid/lei/credential_said/public_key);前端據此顯示 LEI 徽章,不寫死 SAID。
  app.get('/api/manifest', async (_req, reply) => {
    if (!fs.existsSync(MANIFEST_PATH)) {
      return reply.code(404).send({ error: 'manifest 尚未產生(先跑 make setup)' });
    }
    return reply.type('application/json').send(fs.readFileSync(MANIFEST_PATH, 'utf-8'));
  });

  // 稽核帶輪詢(Phase 0:表可為空)。
  app.get('/api/audit', async (req) => {
    const after = Number((req.query as { after?: string }).after ?? 0);
    const db = openDbIfExists();
    if (!db) return [];
    try {
      return db
        .prepare('SELECT seq, event_type, entry_hash, created_at FROM audit_chain WHERE seq > ? ORDER BY seq ASC LIMIT 200')
        .all(after);
    } finally {
      db.close();
    }
  });

  // Token Status List 端點:回 compact signed JWT(draft-ietf-oauth-status-list-21)。
  app.get('/status/:name', async (req, reply) => {
    const { name } = req.params as { name: string };
    if (!STATUS_LIST_NAMES.includes(name as StatusListName)) {
      return reply.code(404).send({ error: 'unknown status list' });
    }
    const token = readStatusListToken(name as StatusListName);
    if (!token) {
      return reply.code(404).send({ error: 'status list 尚未產生(先跑 make setup)' });
    }
    return reply.type(STATUS_MEDIA_TYPE).send(token);
  });

  registerIssueRoutes(app);
  registerAggregateRoutes(app);
  registerMandateRoutes(app);
  registerDiscloseRoutes(app);
  registerVerifyRoutes(app);
  registerDemoRoutes(app);
  registerPolicyRoutes(app);

  return app;
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  const app = buildServer();
  app
    .listen({ port: 3000, host: '127.0.0.1' })
    .then(() => console.log('API ready on http://localhost:3000 (healthz: /api/healthz)'))
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
}
