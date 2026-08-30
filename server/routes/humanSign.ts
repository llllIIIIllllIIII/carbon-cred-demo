/**
 * 幕 5 人工放行(架構決策 §4;phase-briefs/phase-3a.md):POST /api/human-sign。
 * 輸入 dossier_id;僅 P3 五要件全過(status=PENDING_HUMAN)之 Dossier 可放行——以**財務主管
 * ECR 鑰**(server/keys.ts;fab-workload 不簽放行,scope_tools 亦無 sign_transaction)簽 release,
 * 產 mock USD 電匯指令 → 狀態轉 RELEASED;RELEASE 事件經 server/audit.ts recordDecision 與
 * dossiers 更新同一交易入鏈。對非 PENDING_HUMAN 之 Dossier(不存在、已放行、或依據已撤銷)
 * 一律 4xx 拒絕,且(P2-G)重放到已放行的 Dossier 亦經 recordDecision 入鏈。
 * 不建立錢包、不連 RPC、不產生鏈上位址或任何鏈上交易;付款停在 mock JSON,收款帳戶為合成字串。
 *
 * P1-A(Codex review 第二輪):電匯指令的 amount/currency/payer_lei/payee_lei 一律讀 Dossier
 * JWS payload.invoice(agent.ts 之 checkInvoiceOk 驗過的 invoice 事實,受 fab-workload 簽章
 * 保護)——不再讀 data/seed.json transaction.dyeing_service。舊版讀 seed 常數,會讓「金額低於
 * 門檻但≠seed」的合法發票被 P3 核准後,human-sign 卻付出 seed 寫死的金額(核准與付款脫鉤)。
 * rail(電匯管道)不屬於 invoice VC 欄位,仍讀 seed(非金額/身分事實,只是傳輸管道選擇)。
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { SignJWT, jwtVerify, decodeProtectedHeader } from 'jose';
import { ROOT, openDb } from '../db';
import { loadSandboxKey, loadWorkloadKey } from '../keys';
import { recordDecision } from '../audit';
import { AGENT_CHECK_IDS } from './agent';
import { CODES, DOSSIER_STATUS } from '../../shared/codes';

const ACTION = 'HumanSignRelease';
/** Codex review P1-5:同一 dossier 之併發放行競態——只有勝者（CAS UPDATE 影響列數 > 0）能記
 * RELEASE 入鏈並回 200,敗者(已被別的請求搶先轉態)回 409,不得雙重放行/重複產生電匯指令。 */
class LostReleaseRaceError extends Error {}
/** Dossier JWS 之 header.typ——比照 server/routes/agent.ts 建立 Dossier 時所用之常數字面值。 */
const DOSSIER_TYP = 'dossier+jwt';
/** release JWS 之 header.typ(財務主管 ECR 鑰簽)。 */
const RELEASE_TYP = 'release+jwt';

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function sha256Hex(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

interface DossierRow {
  id: string;
  case_id: string;
  mandate_id: string;
  mandate_jti: string;
  request_nonce: string;
  jws: string;
  status: string;
  decision_id: number | null;
  release_jws: string | null;
  payment_instruction_json: string | null;
  created_at: string;
  released_at: string | null;
}

/** rail(電匯管道)不屬於 invoice VC 欄位,仍讀 seed——非金額/身分事實,只是傳輸管道選擇。 */
function readDyeingServiceRail(): string {
  const seed = JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8')) as {
    transaction: { dyeing_service: { rail: string } };
  };
  return seed.transaction.dyeing_service.rail;
}

interface DossierJwsCheck {
  id?: string;
  ok?: boolean | null;
  reason_code?: string;
}

interface DossierJwsInvoiceFacts {
  invoice_no?: string;
  amount?: number;
  currency?: string;
  payer_lei?: string;
  payee_lei?: string;
}

interface DossierJwsPayload {
  dossier_id?: string;
  case_id?: string;
  mandate_jti?: string;
  checks?: DossierJwsCheck[];
  invoice?: DossierJwsInvoiceFacts;
  [k: string]: unknown;
}

/** P1-A:Dossier payload.invoice 必須含四個必要事實(amount/currency/payer_lei/payee_lei)才可信任。 */
function isValidInvoiceFacts(invoice: DossierJwsInvoiceFacts | undefined): invoice is Required<Pick<DossierJwsInvoiceFacts, 'amount' | 'currency' | 'payer_lei' | 'payee_lei'>> & DossierJwsInvoiceFacts {
  return (
    !!invoice &&
    typeof invoice.amount === 'number' &&
    invoice.amount > 0 &&
    typeof invoice.currency === 'string' &&
    !!invoice.currency &&
    typeof invoice.payer_lei === 'string' &&
    !!invoice.payer_lei &&
    typeof invoice.payee_lei === 'string' &&
    !!invoice.payee_lei
  );
}

/**
 * 放行前重驗 Dossier JWS 完整性(fab-workload 公鑰)——即便是 FAB 自己簽發、存在自家 DB 的
 * 物件,仍不假設 DB row 未被竄改(比照 server/routes/agent.ts verifyStoredCredential 之既有慣例)。
 * 回傳已驗證之 payload,供呼叫端另做「與 row 綁定」「五要件皆 ok:true」之縱深防禦重斷言(見下)。
 */
async function verifyDossierJws(jws: string): Promise<{ ok: true; payload: DossierJwsPayload } | { ok: false }> {
  try {
    const key = loadWorkloadKey('fab-workload');
    const header = decodeProtectedHeader(jws);
    if (header.typ !== DOSSIER_TYP || header.kid !== key.kid) return { ok: false };
    const { payload } = await jwtVerify(jws, key.publicKey);
    return { ok: true, payload: payload as DossierJwsPayload };
  } catch {
    return { ok: false };
  }
}

/**
 * P1-6(Codex review):Dossier JWS 完整性通過只證明「這是某次 agent/run 真簽出的 JWS」,不
 * 代表它是**這一列** row 的。若沒有把 payload 內的 dossier_id/case_id/mandate_jti 與 row 比對,
 * 一份從別的(甚至更早的合法)Dossier row 複製來的 JWS 貼進另一列 PENDING_HUMAN row 也會通過
 * 驗證並被放行——等同用 A 案的合法簽名放行 B 案的電匯。
 */
function payloadBoundToRow(payload: DossierJwsPayload, row: DossierRow): boolean {
  return payload.dossier_id === row.id && payload.case_id === row.case_id && payload.mandate_jti === row.mandate_jti;
}

/**
 * L1(Opus 獨立驗證,縱深防禦)+ P2-7(Codex review):status===PENDING_HUMAN 與 JWS 簽章完整性
 * 通過,理論上只有 server/routes/agent.ts 之 P3 五要件全過才會建卡——但放行前不應只信這兩項
 * 間接證據,必須獨立重新斷言 Dossier payload.checks **恰為**五項預期 check id(無缺無重複)
 * 且皆 ok:true。P2-7 修法前只檢查「非空陣列皆 true」,一份「缺 wallet_risk、以 invoice 重複
 * 湊數」但五項皆 true 的 Dossier 亦會通過——攻擊者可跳過任一真檢查,只要用另一項重複補滿數量。
 */
function checksAllPassed(payload: DossierJwsPayload): boolean {
  if (!Array.isArray(payload.checks) || payload.checks.length !== AGENT_CHECK_IDS.length) return false;
  const seenIds = new Set<string>();
  for (const c of payload.checks) {
    if (!c || typeof c.id !== 'string' || !(AGENT_CHECK_IDS as readonly string[]).includes(c.id)) return false;
    if (seenIds.has(c.id)) return false; // 重複補數
    seenIds.add(c.id);
    if (c.ok !== true) return false;
  }
  return seenIds.size === AGENT_CHECK_IDS.length; // 無缺項
}

export function registerHumanSignRoutes(app: FastifyInstance): void {
  app.post('/api/human-sign', async (req, reply) => {
    const body = (req.body ?? {}) as { dossier_id?: string };
    if (!body.dossier_id) return reply.code(400).send({ error: '缺少 dossier_id' });

    const db = openDb();
    try {
      const dossier = db.prepare('SELECT * FROM dossiers WHERE id = ?').get(body.dossier_id) as DossierRow | undefined;
      if (!dossier) {
        return reply.code(404).send({ error: `找不到 Dossier(id=${body.dossier_id})`, reason_code: CODES.DOSSIER_NOT_FOUND });
      }
      if (dossier.status !== DOSSIER_STATUS.PENDING_HUMAN) {
        // P2-G(Codex review 第二輪):「DENY 與重放也入鏈」鐵律——對已 RELEASED 的 Dossier
        // 再次 human-sign 是明確的重放(同一放行動作被重送),必須經 recordDecision 入鏈,
        // 不得只回 409 卻不留痕。其餘非 PENDING_HUMAN 狀態(如未來的 DEPENDS_REVOKED)
        // 不算「重放」,歸一般 DENY。
        const isReplay = dossier.status === DOSSIER_STATUS.RELEASED;
        recordDecision(db, {
          action: ACTION,
          effect: isReplay ? 'REPLAY_DETECTED' : 'DENY',
          reason_code: isReplay ? CODES.REPLAY_DETECTED : CODES.DOSSIER_NOT_RELEASABLE,
          case_id: dossier.case_id,
          mandate_id: dossier.mandate_id,
          context: { dossier_id: dossier.id, status: dossier.status },
        });
        return reply.code(409).send({
          error: `Dossier 狀態為 ${dossier.status},非 ${DOSSIER_STATUS.PENDING_HUMAN} 不得放行`,
          reason_code: isReplay ? CODES.REPLAY_DETECTED : CODES.DOSSIER_NOT_RELEASABLE,
          status: dossier.status,
        });
      }

      const dossierVerify = await verifyDossierJws(dossier.jws);
      if (!dossierVerify.ok) {
        recordDecision(db, {
          action: ACTION,
          effect: 'DENY',
          reason_code: CODES.CREDENTIAL_SIG_INVALID,
          case_id: dossier.case_id,
          mandate_id: dossier.mandate_id,
          context: { dossier_id: dossier.id },
        });
        return reply.code(500).send({ error: 'Dossier JWS 完整性驗證失敗(fab-workload 公鑰)', reason_code: CODES.CREDENTIAL_SIG_INVALID });
      }

      // P1-6(縱深防禦):簽章合法不代表這份 JWS 屬於這一列——斷言 payload 的 dossier_id/
      // case_id/mandate_jti 與 row 一致,不符即拒(疑似把別列的合法 JWS 複製貼上)。
      if (!payloadBoundToRow(dossierVerify.payload, dossier)) {
        recordDecision(db, {
          action: ACTION,
          effect: 'DENY',
          reason_code: CODES.CREDENTIAL_SIG_INVALID,
          case_id: dossier.case_id,
          mandate_id: dossier.mandate_id,
          context: { dossier_id: dossier.id, payload_dossier_id: dossierVerify.payload.dossier_id },
        });
        return reply.code(409).send({
          error: 'Dossier JWS 內容(dossier_id/case_id/mandate_jti)與此列不綁定,拒絕放行(疑似跨列複製)',
          reason_code: CODES.CREDENTIAL_SIG_INVALID,
        });
      }

      // L1(縱深防禦):簽章完整不代表可放行——獨立重新斷言 payload.checks 恰為五項預期
      // check id(無缺無重複)且皆 ok:true,不得只信「status===PENDING_HUMAN」這個資料庫欄位。
      if (!checksAllPassed(dossierVerify.payload)) {
        recordDecision(db, {
          action: ACTION,
          effect: 'DENY',
          reason_code: CODES.DOSSIER_NOT_RELEASABLE,
          case_id: dossier.case_id,
          mandate_id: dossier.mandate_id,
          context: { dossier_id: dossier.id, checks: dossierVerify.payload.checks },
        });
        return reply.code(409).send({
          error: 'Dossier payload.checks 未全數 ok:true,拒絕放行(僅五要件全過之 Dossier 可放行)',
          reason_code: CODES.DOSSIER_NOT_RELEASABLE,
        });
      }

      // P1-A(Codex review 第二輪):電匯的 amount/currency/payer/payee 一律讀 Dossier
      // payload.invoice(agent.ts checkInvoiceOk 驗過的事實,受 fab-workload 簽章保護)——
      // 不再讀 seed 常數,使核准的發票與實際付款的金額/幣別/收付款方保證一致。
      if (!isValidInvoiceFacts(dossierVerify.payload.invoice)) {
        recordDecision(db, {
          action: ACTION,
          effect: 'DENY',
          reason_code: CODES.CREDENTIAL_SIG_INVALID,
          case_id: dossier.case_id,
          mandate_id: dossier.mandate_id,
          context: { dossier_id: dossier.id },
        });
        return reply.code(500).send({
          error: 'Dossier payload.invoice 缺 amount/currency/payer_lei/payee_lei(不應發生,拒絕付款)',
          reason_code: CODES.CREDENTIAL_SIG_INVALID,
        });
      }
      const invoiceFacts = dossierVerify.payload.invoice;

      const paymentInstruction = {
        instruction_id: `PAY-${dossier.id}`,
        payer: invoiceFacts.payer_lei,
        payee: invoiceFacts.payee_lei,
        amount: invoiceFacts.amount,
        currency: invoiceFacts.currency,
        rail: readDyeingServiceRail(),
      };

      // 放行簽名權只在財務主管 ECR 鑰(spec v3 §7;fab-workload 只簽 Dossier,scope_tools 無 sign_transaction)。
      // P2-D(Codex review 第二輪):release_jws 除 dossier_hash/識別碼外,另納入
      // payment_instruction 的正規化 hash 一併簽入——舊版只認證 dossier 本身,指令(金額/幣別/
      // 收付款方/rail)被竄改後 release_jws 仍驗得過,消費方無法憑 release_jws 確認 CFO
      // 究竟核可了「哪一份」電匯指令。
      const cfoKey = loadSandboxKey('fab_cfo');
      const nowSec = Math.floor(Date.now() / 1000);
      const paymentInstructionHash = sha256Hex(JSON.stringify(paymentInstruction));
      const releasePayload = {
        dossier_id: dossier.id,
        case_id: dossier.case_id,
        mandate_jti: dossier.mandate_jti,
        dossier_hash: sha256Hex(dossier.jws),
        payment_instruction_hash: paymentInstructionHash,
      };
      const releaseJws = await new SignJWT(releasePayload)
        .setProtectedHeader({ alg: 'EdDSA', typ: RELEASE_TYP, kid: cfoKey.kid })
        .setIssuedAt(nowSec)
        .sign(cfoKey.privateKey);

      // P1-5(Codex review):狀態轉移原子化——兩個併發 /api/human-sign 可能都在上面讀到
      // PENDING_HUMAN、都通過驗證並各自簽出(有效的)release_jws;真正防雙重放行的是這裡的
      // CAS(compare-and-swap)UPDATE:WHERE status='PENDING_HUMAN' 只有先到者的 UPDATE 會
      // 影響到列(changes>0),後到者的 UPDATE 影響 0 列(此時 status 已是 RELEASED)。只有
      // 勝者才會走到 recordDecision(RELEASE)——兩者同包在一個 immediate transaction 內,
      // 敗者拋 LostReleaseRaceError 使交易整筆回滾(不留半套 UPDATE),外層 catch 轉 409。
      try {
        const tx = db.transaction(() => {
          const info = db
            .prepare(
              `UPDATE dossiers SET status = ?, release_jws = ?, payment_instruction_json = ?, released_at = datetime('now') WHERE id = ? AND status = ?`,
            )
            .run(DOSSIER_STATUS.RELEASED, releaseJws, JSON.stringify(paymentInstruction), dossier.id, DOSSIER_STATUS.PENDING_HUMAN);
          if (info.changes === 0) throw new LostReleaseRaceError();
          recordDecision(db, {
            action: ACTION,
            effect: 'RELEASE',
            reason_code: CODES.RELEASE_APPROVED,
            case_id: dossier.case_id,
            mandate_id: dossier.mandate_id,
            context: { dossier_id: dossier.id, payment_instruction: paymentInstruction },
          });
        });
        tx.immediate();
      } catch (e) {
        if (e instanceof LostReleaseRaceError) {
          return reply.code(409).send({
            error: `Dossier(id=${dossier.id})已由另一請求放行(併發競態,本次落敗,不重複產生電匯)`,
            reason_code: CODES.DOSSIER_NOT_RELEASABLE,
          });
        }
        throw e;
      }

      return {
        decision: 'RELEASE',
        dossier_id: dossier.id,
        status: DOSSIER_STATUS.RELEASED,
        release_jws: releaseJws,
        payment_instruction: paymentInstruction,
      };
    } catch (e) {
      return reply.code(500).send({ error: errorMessage(e) });
    } finally {
      db.close();
    }
  });
}
