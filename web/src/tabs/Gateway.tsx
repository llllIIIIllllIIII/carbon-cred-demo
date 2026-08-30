import { useEffect, useState } from 'react';
import type { Manifest, DiscloseEvent } from '../App';
import type { AssociatedSubcontractor, CcsScopeRef, PrecursorRef } from '../../../shared/types';
import { LeiBadge } from './badge';
import { StackChart } from '../components/StackChart';
import { DenyStamp } from '../components/DenyStamp';

type CaseId = 'A' | 'B';

interface AggregateBreakdown {
  pcf_yarn: number;
  pcf_knitting: number;
  pcf_dyeing: number;
  pcf_total: number;
}

interface AggregateResponse {
  id: string;
  case_id: CaseId;
  breakdown: AggregateBreakdown;
  // F1:/api/aggregate 不再回完整可再揭露的 sd_jwt / 整包 claims(避免跨組織持有並自行揭露三個
  // 永不揭露分項)。憑證卡改讀明列的公開/品牌層欄位;跨組織揭露一律走 POST /api/disclose。
  // v3.1:移除 hs6(不放稅則碼);加 ccs_scope_ref(布廠自己的 SC)。
  product: string;
  origin: string;
  ccs_scope_ref: CcsScopeRef;
  quantity_kg: number;
  precursor_refs: PrecursorRef[];
  status: { idx: number; uri: string };
  issued_at: string;
  valid_from: string;
  valid_until: string;
  /** 買方合約碳排門檻(L3 修正:改由後端 data/seed.json 提供,前端不再寫死)。 */
  contract_carbon_max?: number;
}

interface AggregateErrorResponse {
  error?: string;
  reason_code?: string;
}

interface ScopeCertResponse {
  claims: {
    sc_no: string;
    holder_name: string;
    cb_name: string;
    processes: Array<{ code: string; name: string; site: string }>;
    associated_subcontractors: AssociatedSubcontractor[];
  };
}

/** precursor_refs 固定順序(v3.1;spec §4.4):tc_rcs、pcf_upstream-<case>、pcf_dyeing-<case>。 */
const PRECURSOR_LABELS: Record<string, string> = { tc_rcs: 'TC(認證機構)', pcf_upstream: '紗(紗廠)', pcf_dyeing: '染整(染整廠)' };

function precursorLabel(id: string): string {
  const prefix = Object.keys(PRECURSOR_LABELS).find((p) => id === p || id.startsWith(`${p}-`));
  return prefix ? PRECURSOR_LABELS[prefix] : id;
}

/** A/B 差異只來自 pcf_dyeing 的燃料與綠電比(seed cases.A/B)。 */
const CASE_LABELS: Record<CaseId, string> = {
  A: '案 A · 染整燃料 natural_gas + 30% 綠電(較低碳)',
  B: '案 B · 染整燃料 coal、無綠電(較高碳,超過門檻)',
};

interface PoliciesResponse {
  p1: string;
  p2: string;
}

const REASON_LABELS_P2: Record<string, string> = {
  POLICY_P2_CONFIDENTIAL: '越界索取機密標籤欄位(全廠產量 plant_total_output 等)',
  REPLAY_DETECTED: '重放:同一 (mandate_id, request_nonce) 已出示過',
  CLAIM_NOT_IN_MANDATE: '請求欄位不在 mandate.allowed_claims 範圍內',
};

/** 幕 5:門檻與付款閘道(POST /api/agent/run;A/B 為主線,C/Cp 為收款帳戶風險雙來源輔線)。 */
type AgentCaseId = 'A' | 'B' | 'C' | 'Cp';

interface RiskSignal {
  provider: string;
  score: number;
  labels: string[];
}

interface AgentCheckResult {
  id: 'identity' | 'subcontractor' | 'carbon_threshold' | 'invoice' | 'wallet_risk';
  label: string;
  ok: boolean | null;
  reason_code?: string;
  detail?: string;
  meta?: {
    carbon_total_g?: number;
    carbon_max_g?: number;
    amount?: number;
    currency?: string;
    payee_wallet?: string;
    wallet_risk?: number;
    risk_sources_confirming?: number;
    signals?: RiskSignal[];
  };
}

interface AgentDossier {
  id: string;
  status: string;
  jws: string;
  build_hash: string;
  version: string;
  mandate_jti: string;
}

interface AgentRunResponse {
  decision: 'PERMIT' | 'DENY' | 'REPLAY_DETECTED';
  case_id: AgentCaseId;
  reason_code?: string;
  checks?: AgentCheckResult[];
  dossier?: AgentDossier;
  error?: string;
}

interface PaymentInstruction {
  instruction_id: string;
  payer: string;
  payee: string;
  amount: number;
  currency: string;
  rail: string;
}

interface HumanSignResponse {
  decision: 'RELEASE';
  dossier_id: string;
  status: string;
  release_jws: string;
  payment_instruction: PaymentInstruction;
  error?: string;
}

const AGENT_CASE_LABELS: Record<AgentCaseId, string> = {
  A: '案 A · 五要件全過 → 放行',
  B: '案 B · 染整燃煤,碳排超過門檻',
  C: "案 C · 收款帳戶風險雙來源確認 → 退回",
  Cp: "案 C′ · 收款帳戶風險僅單來源 → 只記錄",
};

const REASON_LABELS_P3: Record<string, string> = {
  CARBON_OVER_THRESHOLD: '聚合碳排(含染整段)超過品牌合約門檻',
  CCS_SUBCONTRACTOR_NOT_LISTED: '染整廠不在布廠 SC 分包商清單內',
  SCOPE_CERT_INVALID: 'ccs_scope_cert 驗章/效期/Status List 未通過',
  MULTI_SOURCE_CONFIRMED: '收款帳戶風險:兩來源皆確認高風險',
  SINGLE_SOURCE_ONLY: '收款帳戶風險:僅一來源確認,只記錄不升級',
  REPLAY_DETECTED: '重放:同一 (mandate_id, request_nonce) 已處理過',
  MANDATE_REVOKED: 'M1 委任狀已撤銷',
  DELEGATE_KEY_MISMATCH: 'request 簽章非 fab-workload 鑰',
  INVOICE_INVALID: '發票驗章失敗或型別/簽發者不符',
  COUNTERPARTY_NOT_ALLOWED: '發票金額超過委任上限,或收款方不在委任範圍內',
};

/** Tab 2 · 誠紡閘道(幕 2:聚合;架構決策 §4 POST /api/aggregate)。 */
export function Gateway({ manifest, lastDisclose }: { manifest: Manifest | null; lastDisclose?: DiscloseEvent | null }) {
  const [caseId, setCaseId] = useState<CaseId>('A');
  const [result, setResult] = useState<AggregateResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [policies, setPolicies] = useState<PoliciesResponse | null>(null);
  const [scopeCert, setScopeCert] = useState<ScopeCertResponse['claims'] | null>(null);

  // 幕 5:門檻與付款閘道。
  const [agentCaseId, setAgentCaseId] = useState<AgentCaseId>('A');
  const [agentBusy, setAgentBusy] = useState(false);
  const [agentError, setAgentError] = useState<string | null>(null);
  const [agentResult, setAgentResult] = useState<AgentRunResponse | null>(null);
  const [showSignConfirm, setShowSignConfirm] = useState(false);
  const [signBusy, setSignBusy] = useState(false);
  const [signError, setSignError] = useState<string | null>(null);
  const [releaseResult, setReleaseResult] = useState<HumanSignResponse | null>(null);

  useEffect(() => {
    let alive = true;
    fetch('/api/policies')
      .then((r) => (r.ok ? (r.json() as Promise<PoliciesResponse>) : null))
      .then((data) => {
        if (alive) setPolicies(data);
      })
      .catch(() => {});
    // v3.1:SC 小卡——ccs_scope_cert 由 CB 於 seed 時已簽發過,此處呼叫為冪等載入(reused)。
    fetch('/api/issue/scope-cert', { method: 'POST' })
      .then((r) => (r.ok ? (r.json() as Promise<ScopeCertResponse>) : null))
      .then((data) => {
        if (alive && data) setScopeCert(data.claims);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, []);

  async function handleAggregate() {
    setBusy(true);
    setError(null);
    try {
      const r = await fetch('/api/aggregate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ case_id: caseId }),
      });
      const data = (await r.json()) as AggregateResponse | AggregateErrorResponse;
      if (!r.ok) throw new Error('error' in data && data.error ? data.error : '聚合簽發失敗');
      setResult(data as AggregateResponse);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function handleAgentCaseChange(next: AgentCaseId) {
    setAgentCaseId(next);
    setAgentResult(null);
    setAgentError(null);
    setReleaseResult(null);
    setSignError(null);
  }

  async function handleRunAgent() {
    setAgentBusy(true);
    setAgentError(null);
    setAgentResult(null);
    setReleaseResult(null);
    try {
      const r = await fetch(`/api/agent/run?case=${agentCaseId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ request_nonce: crypto.randomUUID() }),
      });
      const data = (await r.json()) as AgentRunResponse;
      setAgentResult(data);
      if (!r.ok && !data.checks) throw new Error(data.error ?? `Agent-1 執行失敗(${data.reason_code ?? r.status})`);
    } catch (e) {
      setAgentError(e instanceof Error ? e.message : String(e));
    } finally {
      setAgentBusy(false);
    }
  }

  async function handleHumanSign() {
    if (!agentResult?.dossier) return;
    setSignBusy(true);
    setSignError(null);
    try {
      const r = await fetch('/api/human-sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dossier_id: agentResult.dossier.id }),
      });
      const data = (await r.json()) as HumanSignResponse;
      if (!r.ok) throw new Error(data.error ?? '人工放行失敗');
      setReleaseResult(data);
      setShowSignConfirm(false);
    } catch (e) {
      setSignError(e instanceof Error ? e.message : String(e));
    } finally {
      setSignBusy(false);
    }
  }

  return (
    <section>
      <LeiBadge role={manifest?.fab} fallback="誠紡實業股份有限公司" />
      <h2>誠紡閘道 · 聚合簽發(幕 2)</h2>
      <p style={{ color: '#666' }}>
        誠紡以持有者身分讀上游 pcf_upstream(紗,Sợi Xanh Việt)、外包 pcf_dyeing(染整,彩合染整)與認證機構簽發的 tc_rcs/ccs_scope_cert、驗過簽章之後,程式計算自身產品(胚布)的三段聚合碳足跡並簽發
        pcf_aggregate——<strong>下游拿到的憑證裡沒有紗廠是誰、沒有染整廠帳單,只有三個參照指紋</strong>。
      </p>

      <label style={{ marginRight: 12 }}>
        案件:
        <select value={caseId} onChange={(e) => setCaseId(e.target.value as CaseId)} disabled={busy} style={{ marginLeft: 6 }}>
          <option value="A">{CASE_LABELS.A}</option>
          <option value="B">{CASE_LABELS.B}</option>
        </select>
      </label>
      <button onClick={handleAggregate} disabled={busy}>
        {busy ? '聚合簽發中…' : '聚合簽發'}
      </button>

      {error && <p style={{ color: 'crimson' }}>{error}</p>}

      {result && (
        <>
          <h3>疊層熱點圖(紗 / 織布 / 染整)</h3>
          <StackChart
            yarn={result.breakdown.pcf_yarn}
            knitting={result.breakdown.pcf_knitting}
            dyeing={result.breakdown.pcf_dyeing}
            total={result.breakdown.pcf_total}
            thresholdMax={result.contract_carbon_max}
          />

          <div style={{ border: '1px solid #1a3c6e', borderRadius: 8, padding: 16, marginTop: 16, background: '#fff', maxWidth: 640 }}>
            <h3 style={{ marginTop: 0 }}>pcf_aggregate 憑證卡</h3>
            <p style={{ fontSize: 12, color: '#666' }}>🟢 公開層(非 SD 明文) · 🟡 品牌層(M2 合約層)</p>
            <Row label="🟢 產品" value={result.product} />
            <Row label="🟢 產地" value={result.origin} />
            <Row label="🟢 ccs_scope_ref · sc_no" value={result.ccs_scope_ref.sc_no} />
            <Row label="🟡 出貨重量 quantity_kg" value={`${result.quantity_kg} kg`} />
            <Row label="🟡 聚合總值 pcf_total(品牌合約層)" value={`${result.breakdown.pcf_total} kgCO₂e/kg`} />
            {result.precursor_refs.map((ref, i) => (
              <div key={ref.id}>
                <Row label={`🔗 參照指紋 #${i + 1} · ${precursorLabel(ref.id)} · id`} value={ref.id} />
                <Row label={`🔗 參照指紋 #${i + 1} · ${precursorLabel(ref.id)} · hash`} value={ref.hash} />
              </div>
            ))}
            <p style={{ fontSize: 12, marginTop: 10, marginBottom: 0, color: '#666' }}>
              precursor_refs 為三張外部憑證(TC、紗、染整)的 id + hash——不含上游任何明細(direct/indirect/生產路線等)。
            </p>
            <p style={{ fontSize: 12, marginTop: 10, marginBottom: 0, color: '#888' }}>
              pcf_aggregate 完整簽章 token 是誠紡內部簽發物,不由本端點對外交付——跨組織揭露一律走 Nordlicht 品牌
              Agent 的 <code>/api/disclose</code>(mandate + Cedar 逐 claim + 閘道 receipt)。
            </p>
          </div>

          {scopeCert && (
            <div style={{ border: '1px solid #6e5a1a', borderRadius: 8, padding: 16, marginTop: 16, background: '#fffdf5', maxWidth: 640 }}>
              <h3 style={{ marginTop: 0 }}>Scope Certificate {scopeCert.sc_no}(CB 簽)</h3>
              <Row label="持有者" value={scopeCert.holder_name} />
              <Row label="認證機構" value={scopeCert.cb_name} />
              <Row label="製程" value={scopeCert.processes.map((p) => p.name).join('、')} />
              {scopeCert.associated_subcontractors.map((s) => (
                <Row key={s.lei} label={`associated subcontractor · ${s.name}(${s.process})`} value={s.audited ? '✓ 已受稽核' : '未受稽核'} />
              ))}
              <p style={{ fontSize: 12, marginTop: 10, marginBottom: 0, color: '#666' }}>
                下游拿到的憑證裡沒有紗廠是誰、沒有染整廠帳單——只有這張 SC 證明染整廠是布廠委外分包商、受布廠稽核。
              </p>
            </div>
          )}
        </>
      )}

      {/* 幕 3/4:請求收件匣 + Cedar 決策面板(藍圖:70, 73)。資料來源為 Tab3 呼叫 /api/disclose
          後主動提升至 App 層的 lastDisclose 狀態——本 SPA 切分頁時前一分頁會卸載,故不倚賴
          Gateway 自身持有的 local state;底部 AuditStrip 仍以既有游標輪詢獨立顯示新事件。 */}
      <h3 style={{ marginTop: 32 }}>越界攔截判定(幕 4)· Cedar 決策面板</h3>
      {!lastDisclose ? (
        <p style={{ color: '#666' }}>
          尚無查驗請求——請至「Nordlicht 品牌 Agent」分頁按「發出查驗請求」或「加碼索取 全廠產量 plant_total_output」。
        </p>
      ) : (
        <>
          <div style={{ border: '1px solid #1a3c6e', borderRadius: 8, padding: '8px 12px', maxWidth: 640, background: '#f7f9ff', fontSize: 13 }}>
            請求收件匣 ▸ #req-{lastDisclose.auditSeq ?? '?'} from Brand-Agent · claims×{lastDisclose.requestedClaims.length} · nonce{' '}
            {lastDisclose.nonce.slice(0, 8)}… · 案{lastDisclose.caseId}
          </div>

          <div
            style={{
              position: 'relative',
              border: `1px solid ${lastDisclose.decision === 'PERMIT' ? '#0a7a2f' : '#c0392b'}`,
              borderRadius: 8,
              padding: 16,
              marginTop: 10,
              background: '#fff',
              maxWidth: 640,
            }}
          >
            <DenyStamp active={lastDisclose.decision !== 'PERMIT'} />
            <p style={{ margin: 0, fontWeight: 700, fontSize: 16, color: lastDisclose.decision === 'PERMIT' ? '#0a7a2f' : '#c0392b' }}>
              {lastDisclose.decision === 'PERMIT'
                ? `PERMIT · 命中 ${lastDisclose.policyId ?? 'P1'}`
                : `${lastDisclose.decision} ${lastDisclose.policyId ? `· 命中 ${lastDisclose.policyId}` : ''}`}
            </p>
            <p style={{ margin: '4px 0 0', fontSize: 13 }}>
              理由碼:<code>{lastDisclose.reasonCode}</code>
              {REASON_LABELS_P2[lastDisclose.reasonCode] && <span style={{ color: '#666' }}> — {REASON_LABELS_P2[lastDisclose.reasonCode]}</span>}
            </p>

            {policies && (
              <div style={{ display: 'flex', gap: 10, marginTop: 12, flexWrap: 'wrap' }}>
                <PolicyBlock
                  id="P1"
                  text={policies.p1}
                  highlighted={lastDisclose.policyId === 'P1' || lastDisclose.decision === 'PERMIT'}
                />
                <PolicyBlock id="P2" text={policies.p2} highlighted={lastDisclose.policyId === 'P2'} />
              </div>
            )}
          </div>
        </>
      )}

      {/* 幕 5:門檻與付款閘道(POST /api/agent/run → POST /api/human-sign)。跑在誠紡自己的
          Agent-1(fab-workload 鑰)——M1 委任「付染整費前檢查」;最後一步簽名權在財務主管 ECR 鑰,
          workload 鑰與角色鑰分離即本幕主角。 */}
      <h3 style={{ marginTop: 32 }}>門檻與付款閘道(幕 5)· Agent-1 → 財務主管 ECR 人簽</h3>
      <p style={{ color: '#666', maxWidth: 640 }}>
        Agent-1 持 M1 檢查:DYE 身分、染整廠是否在誠紡 SC 分包商清單、聚合碳排是否 ≤ 品牌合約門檻、發票、收款帳戶風險雙來源——五項全過才建
        Dossier,最後一步「以財務主管 ECR 金鑰簽署」才會產生 mock USD 電匯指令,不建立錢包、RPC 或鏈上交易。
      </p>

      <label style={{ marginRight: 12 }}>
        案件:
        <select
          value={agentCaseId}
          onChange={(e) => handleAgentCaseChange(e.target.value as AgentCaseId)}
          disabled={agentBusy}
          style={{ marginLeft: 6 }}
        >
          <option value="A">{AGENT_CASE_LABELS.A}</option>
          <option value="B">{AGENT_CASE_LABELS.B}</option>
          <option value="C">{AGENT_CASE_LABELS.C}</option>
          <option value="Cp">{AGENT_CASE_LABELS.Cp}</option>
        </select>
      </label>
      <button onClick={handleRunAgent} disabled={agentBusy}>
        {agentBusy ? '執行中…' : '執行 Agent-1(P3 五要件檢查)'}
      </button>

      {agentError && <p style={{ color: 'crimson' }}>{agentError}</p>}

      {agentResult?.checks && (
        <div style={{ marginTop: 12, maxWidth: 640 }}>
          {agentResult.checks.map((c) => (
            <div key={c.id}>
              <AgentCheckRow check={c} />
              {c.id === 'wallet_risk' && c.meta?.signals && c.meta.signals.length > 0 && (
                <div style={{ marginLeft: 12, marginBottom: 6 }}>
                  {c.meta.signals.map((s) => (
                    <div key={s.provider} style={{ fontSize: 12, color: s.score > 40 ? '#c0392b' : '#888' }}>
                      {s.provider}:分數 {s.score}
                      {s.labels.length > 0 ? ` · ${s.labels.join('、')}` : ''}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}

          {agentResult.decision === 'DENY' && agentResult.reason_code === 'CARBON_OVER_THRESHOLD' && (
            <p style={{ marginTop: 8, color: '#c0392b', fontWeight: 700 }}>轉人工:要求染整廠補件 / 重報(放行按鈕不渲染)。</p>
          )}
          {agentResult.decision === 'DENY' && agentResult.reason_code === 'MULTI_SOURCE_CONFIRMED' && (
            <p style={{ marginTop: 8, color: '#c0392b', fontWeight: 700 }}>收款帳戶風險兩來源皆確認高風險 → 退回(放行按鈕不渲染)。</p>
          )}
        </div>
      )}

      {agentResult?.dossier && (
        <div style={{ border: '1px solid #6e5a1a', borderRadius: 8, padding: 16, marginTop: 16, background: '#fffdf5', maxWidth: 640 }}>
          <h3 style={{ marginTop: 0 }}>Dossier {agentResult.dossier.id.slice(0, 8)}…(fab-workload 簽 JWS)</h3>
          <Row label="狀態" value={releaseResult?.status ?? agentResult.dossier.status} />
          <Row label="build_hash" value={agentResult.dossier.build_hash} />
          <Row label="version" value={agentResult.dossier.version} />
          <Row label="mandate_jti" value={agentResult.dossier.mandate_jti} />
          <Row label="jws(前 40 碼)" value={`${agentResult.dossier.jws.slice(0, 40)}…`} />

          {!releaseResult && (
            <button
              onClick={() => setShowSignConfirm(true)}
              style={{ marginTop: 10, padding: '8px 16px', background: '#6e5a1a', color: '#fff', border: 'none', borderRadius: 6, cursor: 'pointer', fontWeight: 700 }}
            >
              以財務主管 ECR 金鑰簽署
            </button>
          )}

          {releaseResult && (
            <div style={{ marginTop: 12, padding: 10, border: '1px solid #0a7a2f', borderRadius: 6, background: '#f2fbf4' }}>
              <p style={{ margin: 0, fontWeight: 700, color: '#0a7a2f' }}>RELEASED · mock USD 電匯指令(不建立錢包/RPC/鏈上交易)</p>
              <Row label="instruction_id" value={releaseResult.payment_instruction.instruction_id} />
              <Row label="payer → payee" value={`${releaseResult.payment_instruction.payer} → ${releaseResult.payment_instruction.payee}`} />
              <Row label="金額" value={`${releaseResult.payment_instruction.amount} ${releaseResult.payment_instruction.currency}`} />
              <Row label="rail" value={releaseResult.payment_instruction.rail} />
            </div>
          )}
        </div>
      )}

      {showSignConfirm && agentResult?.dossier && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.4)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 20,
          }}
        >
          <div style={{ background: '#fff', border: '3px solid #6e5a1a', borderRadius: 10, padding: 24, maxWidth: 420 }}>
            <h3 style={{ marginTop: 0, color: '#6e5a1a' }}>以財務主管 ECR 金鑰簽署放行?</h3>
            <p style={{ fontSize: 13, color: '#444' }}>
              本操作將以 FAB 財務主管之 sandbox ECR 鑰對 Dossier {agentResult.dossier.id.slice(0, 8)}… 簽署
              release,並產生 mock USD 電匯指令(付款人 FAB、收款人 DYE)。不建立錢包、RPC 或鏈上交易。
            </p>
            {signError && <p style={{ color: 'crimson' }}>{signError}</p>}
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', marginTop: 16 }}>
              <button onClick={() => setShowSignConfirm(false)} disabled={signBusy}>
                取消
              </button>
              <button
                onClick={handleHumanSign}
                disabled={signBusy}
                style={{ background: '#6e5a1a', color: '#fff', border: 'none', borderRadius: 6, padding: '8px 16px', fontWeight: 700, cursor: 'pointer' }}
              >
                {signBusy ? '簽署中…' : '確認簽署'}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

function AgentCheckRow({ check }: { check: AgentCheckResult }) {
  const color = check.ok === true ? '#0a7a2f' : check.ok === false ? '#c0392b' : '#999';
  const bg = check.ok === true ? '#f2fbf4' : check.ok === false ? '#fff5f5' : '#f5f5f5';
  const icon = check.ok === true ? '✓' : check.ok === false ? '✗' : '—';
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'space-between',
        gap: 12,
        padding: '6px 10px',
        borderRadius: 6,
        background: bg,
        marginBottom: 4,
        border: `1px solid ${color}`,
        fontSize: 13,
      }}
    >
      <span style={{ color, fontWeight: 700 }}>
        {icon} {check.label}
      </span>
      {check.reason_code && (
        <span style={{ fontSize: 12, color: '#666', textAlign: 'right' }}>
          <code>{check.reason_code}</code>
          {REASON_LABELS_P3[check.reason_code] ? ` — ${REASON_LABELS_P3[check.reason_code]}` : ''}
        </span>
      )}
    </div>
  );
}

function PolicyBlock({ id, text, highlighted }: { id: string; text: string; highlighted: boolean }) {
  return (
    <div
      style={{
        flex: '1 1 260px',
        border: `2px solid ${highlighted ? (id === 'P2' ? '#c0392b' : '#0a7a2f') : '#ccc'}`,
        borderRadius: 6,
        padding: 8,
        background: highlighted ? (id === 'P2' ? '#fff5f5' : '#f2fbf4') : '#fafafa',
        opacity: highlighted ? 1 : 0.55,
      }}
    >
      <div style={{ fontSize: 12, fontWeight: 700, marginBottom: 4 }}>
        policies/{id.toLowerCase()}.cedar {highlighted && '◀ 命中'}
      </div>
      <pre style={{ margin: 0, fontSize: 11, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{text}</pre>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '4px 0', borderBottom: '1px solid #eee', fontSize: 13 }}>
      <span>{label}</span>
      <code style={{ fontSize: 12, textAlign: 'right', wordBreak: 'break-all', maxWidth: 380 }}>{value}</code>
    </div>
  );
}
