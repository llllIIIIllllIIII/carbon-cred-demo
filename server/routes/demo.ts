/**
 * Phase 2 前端 demo 輔助路由(phase2-frontend-spec.md「workload 簽章取得(定案)」):
 * POST /api/demo/sign-disclose-request——模擬 Agent-2(Bruck 側)本地簽章。
 *
 * 瀏覽器不得持有 workload 私鑰(CLAUDE.md);此路由代為以 bruck-workload 鑰(經
 * server/keys.ts,一方一鑰)簽出 request_jws。前端仍須把簽好的 request_jws 完整
 * 送進 POST /api/disclose 走過整條驗證管線(mandate 簽章 → delegate_kid → Token
 * Status List → request_nonce → Cedar)——本路由不繞過、也不預先判定任何驗證結果,
 * 純粹是「private key 該放哪裡」的 demo 部署妥協,非正式 Agent-2 部署形態。
 *
 * ⚠ 正式部署必須移除此 route(M3,Phase 2 總驗收):這是一個**無認證的簽章 oracle**——
 * 任何能打到本機的呼叫者都能請 bruck-workload 鑰簽出 request_jws。demo 情境可接受
 * (實測無法藉此繞過任何驗證層:mandate 不存在/未聚合仍被擋,request_nonce 由伺服端亂數產生、
 * 呼叫者無法指定),但正式部署 Agent-2 應在 Bruck 側自行持鑰簽章,本路由不得存在。
 */
import crypto from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { SignJWT } from 'jose';
import { loadWorkloadKey } from '../keys';
import type { PcfAggregateCaseId } from '../../shared/types';

interface SignDiscloseRequestBody {
  mandate_id?: unknown;
  case_id?: unknown;
  requested_claims?: unknown;
}

function isValidCaseId(v: unknown): v is PcfAggregateCaseId {
  return v === 'A' || v === 'B';
}

function isValidBody(
  body: SignDiscloseRequestBody,
): body is { mandate_id: string; case_id: PcfAggregateCaseId; requested_claims: string[] } {
  return (
    typeof body.mandate_id === 'string' &&
    body.mandate_id.length > 0 &&
    isValidCaseId(body.case_id) &&
    Array.isArray(body.requested_claims) &&
    body.requested_claims.length > 0 &&
    body.requested_claims.every((c) => typeof c === 'string')
  );
}

/**
 * F2(Codex adversarial review)輕量硬化:此無認證簽章 oracle 之 route 註冊改為**受環境旗標守衛**——
 * production(NODE_ENV==='production')一律不註冊,demo(預設)維持既有行為。此路由確認無法繞過任一
 * 驗證層(mandate 不存在/未聚合仍被擋、request_nonce 伺服端亂數),故不加認證/rate-limit(單人 demo 情境);
 * 檔頭「正式部署必須移除」註解保留。DEMO_MODE=off 亦可強制關閉。
 */
export function isDemoSigningOracleEnabled(): boolean {
  if (process.env.DEMO_MODE === 'off') return false;
  return process.env.NODE_ENV !== 'production';
}

export function registerDemoRoutes(app: FastifyInstance): void {
  if (!isDemoSigningOracleEnabled()) return; // production:不註冊無認證簽章 oracle。
  app.post('/api/demo/sign-disclose-request', async (req, reply) => {
    const body = (req.body ?? {}) as SignDiscloseRequestBody;
    if (!isValidBody(body)) {
      return reply.code(400).send({
        error: 'demo 輔助路由:mandate_id(字串)/case_id("A"|"B")/requested_claims(非空字串陣列)缺一不可',
      });
    }

    const key = loadWorkloadKey('bruck-workload');
    const requestNonce = crypto.randomBytes(12).toString('base64url');
    const requestJws = await new SignJWT({
      mandate_id: body.mandate_id,
      case_id: body.case_id,
      requested_claims: body.requested_claims,
      request_nonce: requestNonce,
      iat: Math.floor(Date.now() / 1000),
    })
      .setProtectedHeader({ alg: 'EdDSA', kid: key.kid })
      .sign(key.privateKey);

    return { request_jws: requestJws, request_nonce: requestNonce };
  });
}
