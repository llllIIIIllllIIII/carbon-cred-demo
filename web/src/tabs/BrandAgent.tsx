import { useEffect, useState } from 'react';
import type { Manifest, DiscloseEvent } from '../App';
import { LeiBadge } from './badge';
import { PCF_UPSTREAM_CONFIDENTIAL_FIELDS } from '../../../shared/types';

type CaseId = 'A' | 'B';

interface MandateStatusRef {
  idx: number;
  uri: string;
}

interface MandateSummary {
  jti: string;
  allowed_claims: string[];
  valid_until: string;
  delegate_kid: string;
  status: MandateStatusRef;
}

interface MandateApiResponse {
  mandate_jwt: string;
  reused: boolean;
  summary: MandateSummary;
}

interface SignDiscloseResponse {
  request_jws: string;
  request_nonce: string;
}

interface DiscloseSuccessResponse {
  decision: 'PERMIT';
  policy_id: 'P1';
  presentation: string;
  /** F4:閘道 receipt——Brand 端本地驗證(/api/verify)以此驗 key-binding。 */
  receipt: string;
  mandate_id: string;
  case_id: CaseId;
}

interface DiscloseFailureResponse {
  decision: 'DENY' | 'REPLAY_DETECTED';
  reason_code: string;
  policy_id?: 'P1' | 'P2';
}

interface VerifyCheck {
  name: string;
  ok: boolean;
  reasonCode?: string;
  detail?: string;
}

interface VerifyApiResponse {
  valid: boolean;
  checks: VerifyCheck[];
  payload?: Record<string, unknown>;
}

interface DiscloseOutcome {
  decision: 'PERMIT' | 'DENY' | 'REPLAY_DETECTED';
  policyId?: 'P1' | 'P2';
  reasonCode: string;
  presentation?: string;
  requestedClaims: string[];
}

/**
 * M2.allowed_claims 之顯示標籤(server/policy/claims.ts M2_ALLOWED_CLAIMS 之對照)。
 * 聚合分項(precursor_contribution / self_direct / self_indirect)刻意不列:它們不在
 * allowed_claims 內,任兩項相加減就能還原第三項與上游合計(H2 算術洩漏),永不揭露。
 */
const FIELD_LABELS: Record<string, string> = {
  cn_code: '下游 CN Code',
  precursor_ref: 'Precursor 參照(上游 id + hash)',
  carbon_total_tco2e_per_t: '聚合總值(買方合約層;唯一的排放數字)',
  carbon_price_paid_origin: '原產地碳定價(客戶層)',
};

const REASON_HINTS: Record<string, string> = {
  PCF_AGGREGATE_NOT_ISSUED: '該案 pcf_aggregate 尚未簽發——請先至「鴻鋼閘道」分頁完成幕 2 聚合簽發。',
  POLICY_P2_CONFIDENTIAL: '機密標籤欄位(machine_energy 等)一律拒絕,不看 mandate 寫什麼(Cedar P2 forbid 優先於 permit)。',
  REPLAY_DETECTED: '同一 (mandate_id, request_nonce) 已出示過,判定為重放。',
  CLAIM_NOT_IN_MANDATE: '請求的欄位不在 mandate.allowed_claims 範圍內。',
};

function formatValue(value: unknown): string {
  if (value === undefined || value === null) return '(無)';
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

/** 純顯示用 JWT payload 解碼(不驗簽)——mandate_jwt 已由後端回傳給前端,非機密材料,僅為補上 summary 未附的 policy_version/mandate_nonce/valid_from 供畫面呈現。 */
function decodeJwtPayloadUnsafe(token: string): Record<string, unknown> {
  try {
    const part = token.split('.')[1] ?? '';
    const padded = part.replace(/-/g, '+').replace(/_/g, '/').padEnd(part.length + ((4 - (part.length % 4)) % 4), '=');
    return JSON.parse(atob(padded)) as Record<string, unknown>;
  } catch {
    return {};
  }
}

function Row({ label, value }: { label: string; value: unknown }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '4px 0', borderBottom: '1px solid #eee', fontSize: 13 }}>
      <span>{label}</span>
      <code style={{ fontSize: 12, textAlign: 'right', wordBreak: 'break-all', maxWidth: 380 }}>{formatValue(value)}</code>
    </div>
  );
}

function DecisionBadge({ decision }: { decision: 'PERMIT' | 'DENY' | 'REPLAY_DETECTED' }) {
  const color = decision === 'PERMIT' ? '#0a7a2f' : decision === 'REPLAY_DETECTED' ? '#b8860b' : '#c0392b';
  return (
    <span style={{ display: 'inline-block', padding: '2px 10px', borderRadius: 6, background: color, color: '#fff', fontWeight: 700, fontSize: 13 }}>
      {decision}
    </span>
  );
}

/** Tab 3 · Brand Agent(幕 3 委任查驗 ★核心 ＋ 幕 4 越界攔截 ★高潮 主場)。 */
export function BrandAgent({ manifest, onDisclose }: { manifest: Manifest | null; onDisclose: (e: DiscloseEvent) => void }) {
  const [caseId, setCaseId] = useState<CaseId>('A');
  const [mandateJwt, setMandateJwt] = useState<string | null>(null);
  const [mandateSummary, setMandateSummary] = useState<MandateSummary | null>(null);
  const [mandateBusy, setMandateBusy] = useState(false);
  const [mandateError, setMandateError] = useState<string | null>(null);

  const [discloseBusy, setDiscloseBusy] = useState(false);
  const [discloseError, setDiscloseError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<DiscloseOutcome | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerifyApiResponse | null>(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      setMandateBusy(true);
      setMandateError(null);
      try {
        const r = await fetch('/api/mandates', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mandate: 'M2' }),
        });
        const data = (await r.json()) as MandateApiResponse & { error?: string };
        if (!r.ok) throw new Error(data.error ?? 'M2 mandate 簽發失敗');
        if (!alive) return;
        setMandateJwt(data.mandate_jwt);
        setMandateSummary(data.summary);
      } catch (e) {
        if (alive) setMandateError(e instanceof Error ? e.message : String(e));
      } finally {
        if (alive) setMandateBusy(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  async function latestAuditSeq(): Promise<number | null> {
    try {
      const r = await fetch('/api/audit?after=0');
      const rows = (await r.json()) as Array<{ seq: number }>;
      return Array.isArray(rows) && rows.length > 0 ? rows[rows.length - 1].seq : null;
    } catch {
      return null;
    }
  }

  async function handleVerify(presentation: string, mandateToken: string, receipt: string) {
    const r = await fetch('/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // F4:一併送閘道 receipt,/api/verify 驗 key-binding(綁 presentation_hash/mandate_jti/nonce/aud/iat)。
      body: JSON.stringify({ presentation, mandate_jwt: mandateToken, receipt }),
    });
    const data = (await r.json()) as VerifyApiResponse;
    setVerifyResult(data);
  }

  async function handleDisclose(overreach: boolean) {
    if (!mandateSummary || !mandateJwt) return;
    setDiscloseBusy(true);
    setDiscloseError(null);
    setOutcome(null);
    setVerifyResult(null);
    try {
      const requestedClaims = overreach ? [...mandateSummary.allowed_claims, 'machine_energy'] : [...mandateSummary.allowed_claims];

      // 「workload 簽章取得」定案:瀏覽器不得持有 brand-workload 私鑰,經 demo 輔助 route
      // 代簽 request_jws(仍走 POST /api/disclose 完整驗證管線,不繞過任何驗證)。
      const signRes = await fetch('/api/demo/sign-disclose-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mandate_id: mandateSummary.jti, case_id: caseId, requested_claims: requestedClaims }),
      });
      const signData = (await signRes.json()) as SignDiscloseResponse & { error?: string };
      if (!signRes.ok) throw new Error(signData.error ?? 'demo 簽章輔助失敗');

      const discloseRes = await fetch('/api/disclose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ request_jws: signData.request_jws }),
      });
      const discloseData = (await discloseRes.json()) as DiscloseSuccessResponse | DiscloseFailureResponse;

      let nextOutcome: DiscloseOutcome;
      if (discloseData.decision === 'PERMIT') {
        nextOutcome = {
          decision: 'PERMIT',
          policyId: discloseData.policy_id,
          reasonCode: 'POLICY_P1_PERMIT',
          presentation: discloseData.presentation,
          requestedClaims,
        };
        setOutcome(nextOutcome);
        await handleVerify(discloseData.presentation, mandateJwt, discloseData.receipt);
      } else {
        nextOutcome = {
          decision: discloseData.decision,
          policyId: discloseData.policy_id,
          reasonCode: discloseData.reason_code,
          requestedClaims,
        };
        setOutcome(nextOutcome);
      }

      const auditSeq = await latestAuditSeq();
      onDisclose({
        auditSeq,
        requestedClaims,
        caseId,
        nonce: signData.request_nonce,
        decision: nextOutcome.decision,
        policyId: nextOutcome.policyId,
        reasonCode: nextOutcome.reasonCode,
        presentation: nextOutcome.presentation,
        at: new Date().toISOString(),
      });
    } catch (e) {
      setDiscloseError(e instanceof Error ? e.message : String(e));
    } finally {
      setDiscloseBusy(false);
    }
  }

  const mandateExtra = mandateJwt ? decodeJwtPayloadUnsafe(mandateJwt) : {};
  const allowedClaims = mandateSummary?.allowed_claims ?? [];

  return (
    <section>
      <LeiBadge role={manifest?.brand} fallback="Brand & Söhne GmbH" />
      <h2>Brand Agent · 委任查驗(幕 3)＋越界攔截(幕 4)</h2>
      <p style={{ color: '#666' }}>
        Agent-2 持 M2 mandate 出示查驗請求——鴻鋼閘道只回 mandate 範圍內的欄位;若加碼索取機密欄位,閘道 Cedar P2 一律拒絕,不看 mandate 寫什麼。
      </p>

      {mandateError && <p style={{ color: 'crimson' }}>{mandateError}</p>}

      <div style={{ border: '1px solid #1a3c6e', borderRadius: 8, padding: 16, marginTop: 12, background: '#fff', maxWidth: 640 }}>
        <h3 style={{ marginTop: 0 }}>M2 委任狀(Brand 永續長 ECR 鑰簽發)</h3>
        {mandateBusy && !mandateSummary && <p>簽發中…</p>}
        {mandateSummary && (
          <>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 10 }}>
              {allowedClaims.map((c) => (
                <span key={c} style={{ padding: '2px 8px', borderRadius: 12, background: '#eef4ff', border: '1px solid #1a3c6e', fontSize: 12 }}>
                  {FIELD_LABELS[c] ?? c}
                </span>
              ))}
            </div>
            <Row label="效期" value={`${formatValue(mandateExtra.valid_from)} ~ ${mandateSummary.valid_until}`} />
            <Row label="mandate_nonce" value={mandateExtra.mandate_nonce} />
            <Row label="policy_version" value={mandateExtra.policy_version} />
            <Row label="delegate_kid(brand-workload 公鑰摘要)" value={`${String(mandateSummary.delegate_kid).slice(0, 16)}…`} />
            <Row label="Token Status List" value={`idx=${mandateSummary.status.idx}`} />
            <details style={{ marginTop: 10 }}>
              <summary style={{ cursor: 'pointer' }}>原始 mandate_jwt</summary>
              <textarea readOnly value={mandateJwt ?? ''} style={{ width: '100%', height: 80, fontFamily: 'monospace', fontSize: 11, marginTop: 6 }} />
            </details>
          </>
        )}
      </div>

      <div style={{ marginTop: 16, display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
        <label>
          案件:
          <select value={caseId} onChange={(e) => setCaseId(e.target.value as CaseId)} disabled={discloseBusy} style={{ marginLeft: 6 }}>
            <option value="A">案 A</option>
            <option value="B">案 B</option>
          </select>
        </label>
        <button onClick={() => handleDisclose(false)} disabled={discloseBusy || !mandateSummary}>
          {discloseBusy ? '查驗中…' : '發出查驗請求 ▶'}
        </button>
        <button
          onClick={() => handleDisclose(true)}
          disabled={discloseBusy || !mandateSummary}
          style={{ background: '#c0392b', color: '#fff', border: '1px solid #7c2419', borderRadius: 6, padding: '6px 12px', cursor: 'pointer' }}
        >
          加碼索取 machine_energy ▶
        </button>
      </div>

      {discloseError && <p style={{ color: 'crimson' }}>{discloseError}</p>}

      {outcome && (
        <div style={{ marginTop: 16, maxWidth: 640 }}>
          <p style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <DecisionBadge decision={outcome.decision} />
            <code style={{ fontSize: 13 }}>{outcome.reasonCode}</code>
            {outcome.policyId && <span style={{ fontSize: 12, color: '#666' }}>命中 {outcome.policyId}</span>}
          </p>
          {REASON_HINTS[outcome.reasonCode] && <p style={{ fontSize: 12, color: '#666', marginTop: -6 }}>{REASON_HINTS[outcome.reasonCode]}</p>}
        </div>
      )}

      {outcome?.decision === 'PERMIT' && verifyResult?.payload && (
        <div style={{ border: '1px solid #0a7a2f', borderRadius: 8, padding: 16, marginTop: 12, background: '#fff', maxWidth: 640 }}>
          <h3 style={{ marginTop: 0 }}>Presentation(只含 M2.allowed_claims {allowedClaims.length} 欄)</h3>
          {allowedClaims.map((claim) =>
            claim in (verifyResult.payload as Record<string, unknown>) ? (
              <Row key={claim} label={FIELD_LABELS[claim] ?? claim} value={(verifyResult.payload as Record<string, unknown>)[claim]} />
            ) : null,
          )}
          <p style={{ fontSize: 12, marginTop: 10, marginBottom: 0, color: '#666' }}>
            上游明細欄位、機密欄位({PCF_UPSTREAM_CONFIDENTIAL_FIELDS.join('、')})與三個聚合分項
            (precursor_contribution / self_direct / self_indirect)
            <strong> 不存在於這份文件裡</strong>——不是遮罩,是這份 presentation 從未包含這些欄位。
            揭露欄位中的排放數字只有聚合總值一個,買方無法用加減還原上游合計。
          </p>
          <details style={{ marginTop: 12 }}>
            <summary style={{ cursor: 'pointer' }}>原始 presentation token(一個簽章、N 張可撕欄位)</summary>
            <textarea readOnly value={outcome.presentation ?? ''} style={{ width: '100%', height: 100, fontFamily: 'monospace', fontSize: 11, marginTop: 6 }} />
          </details>
        </div>
      )}

      {outcome?.decision === 'PERMIT' && verifyResult && (
        <div style={{ border: '1px solid #1a3c6e', borderRadius: 8, padding: 16, marginTop: 12, background: '#fff', maxWidth: 640 }}>
          <h3 style={{ marginTop: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
            Brand 端本地驗證
            <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 10, background: '#0d1b2a', color: '#cde3ff' }}>OFFLINE</span>
          </h3>
          <p style={{ fontSize: 12, color: '#666', marginTop: 0 }}>
            只讀 token、manifest 公鑰、data/vlei/、data/status/——不呼叫鴻鋼閘道 API(與 scripts/verify-offline.ts 同一驗證邏輯)。
          </p>
          {verifyResult.checks.map((c) => (
            <p key={c.name} style={{ margin: '4px 0', fontSize: 13, color: c.ok ? '#0a7a2f' : '#c0392b' }}>
              {c.ok ? '✓' : '✗'} {c.name}
              {!c.ok && c.reasonCode && <code style={{ marginLeft: 8 }}>{c.reasonCode}</code>}
              {!c.ok && c.detail && <span style={{ marginLeft: 8, fontSize: 12 }}>{c.detail}</span>}
            </p>
          ))}
          <p style={{ fontWeight: 700, marginTop: 10, color: verifyResult.valid ? '#0a7a2f' : '#c0392b' }}>
            {verifyResult.valid ? '✓ 全數通過(簽章 ✓ / vLEI 鏈 ✓ / 撤銷狀態 ✓)' : '✗ 驗證未全數通過'}
          </p>
        </div>
      )}
    </section>
  );
}
