import { useEffect, useState } from 'react';
import type { Manifest, DiscloseEvent } from '../App';
import type { PrecursorRef } from '../../../shared/types';
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
  product: string;
  hs6: string;
  origin: string;
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

/** Tab 2 · 誠紡閘道(幕 2:聚合;架構決策 §4 POST /api/aggregate)。 */
export function Gateway({ manifest, lastDisclose }: { manifest: Manifest | null; lastDisclose?: DiscloseEvent | null }) {
  const [caseId, setCaseId] = useState<CaseId>('A');
  const [result, setResult] = useState<AggregateResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [policies, setPolicies] = useState<PoliciesResponse | null>(null);

  useEffect(() => {
    let alive = true;
    fetch('/api/policies')
      .then((r) => (r.ok ? (r.json() as Promise<PoliciesResponse>) : null))
      .then((data) => {
        if (alive) setPolicies(data);
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

  return (
    <section>
      <LeiBadge role={manifest?.fab} fallback="誠紡實業股份有限公司" />
      <h2>誠紡閘道 · 聚合簽發(幕 2)</h2>
      <p style={{ color: '#666' }}>
        誠紡以持有者身分讀上游 tc_carbon_upstream(紗,Sợi Xanh Việt)與外包 pcf_dyeing(染整,彩合染整)、驗過簽章之後,程式計算自身產品(胚布)的三段聚合碳足跡並簽發
        pcf_aggregate——<strong>下游拿到的憑證裡沒有紗廠是誰、沒有染整廠帳單,只有兩個參照指紋</strong>。
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
            <Row label="🟢 HS6" value={result.hs6} />
            <Row label="🟢 產地" value={result.origin} />
            <Row label="🟡 出貨重量 quantity_kg" value={`${result.quantity_kg} kg`} />
            <Row label="🟡 聚合總值 pcf_total(品牌合約層)" value={`${result.breakdown.pcf_total} kgCO₂e/kg`} />
            {result.precursor_refs.map((ref, i) => (
              <div key={ref.id}>
                <Row label={`🟢 參照指紋 #${i + 1} · id`} value={ref.id} />
                <Row label={`🟢 參照指紋 #${i + 1} · hash`} value={ref.hash} />
              </div>
            ))}
            <p style={{ fontSize: 12, marginTop: 10, marginBottom: 0, color: '#666' }}>
              precursor_refs 僅為兩張外部憑證(紗、染整)的 id + hash——不含上游任何明細(direct/indirect/生產路線等)。
            </p>
            <p style={{ fontSize: 12, marginTop: 10, marginBottom: 0, color: '#888' }}>
              pcf_aggregate 完整簽章 token 是誠紡內部簽發物,不由本端點對外交付——跨組織揭露一律走 Nordlicht 品牌
              Agent 的 <code>/api/disclose</code>(mandate + Cedar 逐 claim + 閘道 receipt)。
            </p>
          </div>
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
    </section>
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
