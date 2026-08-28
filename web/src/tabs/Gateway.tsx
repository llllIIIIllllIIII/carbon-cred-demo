import { useState } from 'react';
import type { Manifest } from '../App';
import { LeiBadge } from './badge';
import { StackChart } from '../components/StackChart';

type CaseId = 'A' | 'B';

interface AggregateBreakdown {
  precursor_contribution_tco2e_per_t: number;
  self_direct_tco2e_per_t: number;
  self_indirect_tco2e_per_t: number;
  carbon_total_tco2e_per_t: number;
}

interface PrecursorRef {
  id: string;
  hash: string;
}

interface AggregateResponse {
  id: string;
  case_id: CaseId;
  sd_jwt: string;
  claims: Record<string, unknown>;
  breakdown: AggregateBreakdown;
  precursor_ref: PrecursorRef;
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

const CASE_LABELS: Record<CaseId, string> = {
  A: '案 A · 上游 EAF 電弧爐(較低碳)',
  B: '案 B · 上游 BF-BOF 高爐轉爐(較高碳)',
};

/** Tab 2 · 鴻鋼閘道(幕 2:聚合;架構決策 §4 POST /api/aggregate)。 */
export function Gateway({ manifest }: { manifest: Manifest | null }) {
  const [caseId, setCaseId] = useState<CaseId>('A');
  const [result, setResult] = useState<AggregateResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
      <LeiBadge role={manifest?.hunggang} fallback="鴻鋼精密扣件" />
      <h2>鴻鋼閘道 · 聚合簽發(幕 2)</h2>
      <p style={{ color: '#666' }}>
        鴻鋼以持有者身分讀上游 pcf_upstream 的完整客戶層(它是買方,拿得到)、驗過簽章之後,程式計算自身產品(六角螺栓 M12)的聚合碳足跡並簽發
        pcf_aggregate——<strong>新憑證裡沒有上游明細,只有一個參照指紋</strong>。
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
          <h3>疊層熱點圖(前驅物 / 自身 direct / 自身 indirect)</h3>
          <StackChart
            precursor={result.breakdown.precursor_contribution_tco2e_per_t}
            selfDirect={result.breakdown.self_direct_tco2e_per_t}
            selfIndirect={result.breakdown.self_indirect_tco2e_per_t}
            total={result.breakdown.carbon_total_tco2e_per_t}
            thresholdMax={result.contract_carbon_max}
          />

          <div style={{ border: '1px solid #1a3c6e', borderRadius: 8, padding: 16, marginTop: 16, background: '#fff', maxWidth: 640 }}>
            <h3 style={{ marginTop: 0 }}>pcf_aggregate 憑證卡</h3>
            <p style={{ fontSize: 12, color: '#666' }}>🟢 公開層(非 SD 明文) · 🟡 SD 可撕欄(買方合約層 + 客戶層)</p>
            <Row label="🟢 下游 CN Code" value={String(result.claims.cn_code)} />
            <Row label="🟡 聚合總值(買方合約層)" value={`${result.breakdown.carbon_total_tco2e_per_t} tCO2e/t`} />
            <Row label="🟡 台灣碳費(客戶層)" value={String(result.claims.carbon_price_paid_origin ?? '')} />
            <Row label="🟢 precursor_ref.id" value={result.precursor_ref.id} />
            <Row label="🟢 precursor_ref.hash" value={result.precursor_ref.hash} />
            <p style={{ fontSize: 12, marginTop: 10, marginBottom: 0, color: '#666' }}>
              precursor_ref 僅為上游憑證的 id + hash 兩個欄位——不含上游任何明細(direct/indirect/生產路線等)。
            </p>
            <details style={{ marginTop: 12 }}>
              <summary style={{ cursor: 'pointer' }}>原始 token(一個簽章、N 張可撕欄位)</summary>
              <textarea readOnly value={result.sd_jwt} style={{ width: '100%', height: 100, fontFamily: 'monospace', fontSize: 11, marginTop: 6 }} />
            </details>
          </div>
        </>
      )}
    </section>
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
