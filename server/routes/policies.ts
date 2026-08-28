/**
 * Phase 2 前端小補充(phase2-frontend-spec.md Tab2 §2):GET /api/policies——
 * 唯讀回傳 policies/p1.cedar、p2.cedar 原文,供 Gateway 決策面板高亮顯示規則原文。
 * 不讀 DB、不驗證、不寫入,純粹讀檔轉譯,不影響任何既有 route 行為。
 */
import fs from 'node:fs';
import path from 'node:path';
import type { FastifyInstance } from 'fastify';
import { ROOT } from '../db';

const POLICIES_DIR = path.join(ROOT, 'policies');

export function registerPolicyRoutes(app: FastifyInstance): void {
  app.get('/api/policies', async () => {
    return {
      p1: fs.readFileSync(path.join(POLICIES_DIR, 'p1.cedar'), 'utf-8'),
      p2: fs.readFileSync(path.join(POLICIES_DIR, 'p2.cedar'), 'utf-8'),
    };
  });
}
