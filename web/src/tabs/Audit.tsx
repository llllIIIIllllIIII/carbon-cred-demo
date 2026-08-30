import { useEffect, useState } from 'react';
import type { Manifest } from '../App';

type StatusListName = 'credentials' | 'mandates';
const LISTS: StatusListName[] = ['credentials', 'mandates'];
const LIST_LABELS: Record<StatusListName, string> = { credentials: '憑證(credentials)', mandates: '委任狀(mandates)' };

interface StatusBitsResponse {
  name: StatusListName;
  sub?: string;
  iat?: number;
  bits: number[];
  labels: string[];
}

interface DossierRow {
  id: string;
  case_id: string;
  mandate_id: string;
  status: string;
  effective_status: string;
  created_at: string;
  released_at: string | null;
}

const DOSSIER_STATUS_LABELS: Record<string, string> = {
  PENDING_HUMAN: '待人工放行',
  RELEASED: '已放行',
  DEPENDS_REVOKED: '依據已撤銷,需重驗',
};

/**
 * P2-6(Codex 審查)修法:切換 credentials/mandates 兩份清單時,先前選定的 idx 若不重置,
 * 會停在對另一份清單而言無意義的值(例如從 credentials 切到 mandates,idx 仍是 4,但
 * mandates 只有 idx0=M1/idx1=M2)——使用者以為在撤銷 M1,實際送出的卻是未指派的 mandates
 * idx4,M1 仍未撤銷卻誤以為已處理。切換時一律重置為新清單「第一個有標籤的 idx」
 * (無標籤清單則退回 0)。抽成純函式供 scripts/test.ts 直接單元測試(碼層驗證,無需瀏覽器)。
 */
export function defaultIdxForLabels(labels: string[]): number {
  const firstLabeled = labels.findIndex((label) => !!label);
  return firstLabeled >= 0 ? firstLabeled : 0;
}

/** Status List bit 條:64 格小方塊,非零(撤銷)標紅,有 idx→id 標籤者加外框並顯示標籤。 */
function BitStrip({ data }: { data: StatusBitsResponse }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontWeight: 600, marginBottom: 4 }}>
        {LIST_LABELS[data.name]}(sub={data.sub ? `${data.sub.split('/').pop()}` : '?'}{data.iat ? `,iat=${new Date(data.iat * 1000).toISOString()}` : ''})
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
        {data.bits.map((bit, idx) => {
          const label = data.labels[idx];
          return (
            <div
              key={idx}
              title={`idx ${idx}${label ? ` · ${label}` : ''} · ${bit ? '已撤銷' : '有效'}`}
              style={{
                width: 22,
                height: 22,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 9,
                borderRadius: 3,
                border: label ? '2px solid #1a3c6e' : '1px solid #ccc',
                background: bit ? '#c0392b' : '#dff5df',
                color: bit ? '#fff' : '#245c24',
              }}
            >
              {idx}
            </div>
          );
        })}
      </div>
      <div style={{ marginTop: 4, fontSize: 12, color: '#555' }}>
        {data.labels
          .map((label, idx) => ({ label, idx }))
          .filter((x) => x.label)
          .map((x) => (
            <span key={x.idx} style={{ marginRight: 12 }}>
              idx {x.idx} · {x.label}
              {data.bits[x.idx] ? '(已撤銷)' : ''}
            </span>
          ))}
      </div>
    </div>
  );
}

function DossierBadge({ status }: { status: string }) {
  const isRevoked = status === 'DEPENDS_REVOKED';
  const isReleased = status === 'RELEASED';
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: 4,
        fontSize: 12,
        fontWeight: 600,
        background: isRevoked ? '#fff3cd' : isReleased ? '#dff5df' : '#eef4ff',
        color: isRevoked ? '#8a6d00' : isReleased ? '#245c24' : '#1a3c6e',
        border: `1px solid ${isRevoked ? '#e0b400' : isReleased ? '#3a8f3a' : '#1a3c6e'}`,
      }}
    >
      {DOSSIER_STATUS_LABELS[status] ?? status}
    </span>
  );
}

/** Tab 4 · 稽核與撤銷(全域視角;幕 5、6 在這裡演)。 */
export function Audit({ manifest: _manifest }: { manifest: Manifest | null }) {
  const [bits, setBits] = useState<Partial<Record<StatusListName, StatusBitsResponse>>>({});
  const [dossiers, setDossiers] = useState<DossierRow[]>([]);
  const [revokeList, setRevokeList] = useState<StatusListName>('credentials');
  const [revokeIdx, setRevokeIdx] = useState<number>(4);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    try {
      const results = await Promise.all(
        LISTS.map((name) => fetch(`/api/status/${name}/bits`).then((r) => (r.ok ? (r.json() as Promise<StatusBitsResponse>) : null))),
      );
      const next: Partial<Record<StatusListName, StatusBitsResponse>> = {};
      LISTS.forEach((name, i) => {
        if (results[i]) next[name] = results[i]!;
      });
      setBits(next);
    } catch {
      // 展示端點;讀不到不影響其餘分頁功能。
    }
    try {
      const r = await fetch('/api/dossiers');
      if (r.ok) setDossiers((await r.json()) as DossierRow[]);
    } catch {
      // 同上。
    }
  }

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 4000);
    return () => clearInterval(t);
  }, []);

  async function handleRevoke() {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const r = await fetch('/api/audit/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ list: revokeList, idx: revokeIdx }),
      });
      const data = (await r.json()) as { ok?: boolean; error?: string };
      if (!r.ok || !data.ok) throw new Error(data.error ?? '撤銷失敗');
      setMessage(`已撤銷 ${LIST_LABELS[revokeList]} idx=${revokeIdx}(已重簽對應 Status List Token)`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const currentLabels = (bits[revokeList]?.labels ?? [])
    .map((label, idx) => ({ label, idx }))
    .filter((x) => x.label);

  return (
    <section>
      <div
        style={{
          display: 'inline-block',
          padding: '4px 10px',
          border: '1px solid #6e1a1a',
          borderRadius: 6,
          background: '#fff0f0',
          fontSize: 13,
          marginBottom: 8,
        }}
      >
        全域視角(稽核員)
      </div>
      <h2>稽核與撤銷</h2>
      <p style={{ color: '#666' }}>
        Token Status List(draft-ietf-oauth-status-list-21)之 bit 條與撤銷開關;Dossier(幕 5)依據被撤銷後於此標示「需重驗」。
      </p>

      <h3>Status List bit 條</h3>
      {LISTS.map((name) => (bits[name] ? <BitStrip key={name} data={bits[name]!} /> : <p key={name}>{LIST_LABELS[name]} 讀取中…</p>))}

      <h3>撤銷開關</h3>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
        <select
          value={revokeList}
          onChange={(e) => {
            const next = e.target.value as StatusListName;
            setRevokeList(next);
            // P2-6:切清單一律重置 idx 為新清單之合法預設,不沿用另一份清單的舊選值。
            setRevokeIdx(defaultIdxForLabels(bits[next]?.labels ?? []));
          }}
        >
          {LISTS.map((name) => (
            <option key={name} value={name}>
              {LIST_LABELS[name]}
            </option>
          ))}
        </select>
        <select value={revokeIdx} onChange={(e) => setRevokeIdx(Number(e.target.value))}>
          {currentLabels.length === 0 && <option value={revokeIdx}>idx {revokeIdx}</option>}
          {currentLabels.map((x) => (
            <option key={x.idx} value={x.idx}>
              idx {x.idx} · {x.label}
            </option>
          ))}
        </select>
        <button onClick={handleRevoke} disabled={busy}>
          {busy ? '撤銷中…' : '撤銷'}
        </button>
      </div>
      {message && <p style={{ color: '#245c24' }}>{message}</p>}
      {error && <p style={{ color: '#8a1c1c' }}>錯誤:{error}</p>}
      <p style={{ color: '#888', fontSize: 12 }}>
        亦可於終端執行:<code>make revoke LIST={revokeList} IDX={revokeIdx}</code>(不重啟 make dev 即生效)。
      </p>

      <h3>Dossier 列表(幕 5 · 門檻與付款閘道)</h3>
      {dossiers.length === 0 ? (
        <p style={{ color: '#666' }}>尚無 Dossier(先於誠紡閘道分頁跑 P3 五要件)。</p>
      ) : (
        <table style={{ borderCollapse: 'collapse', width: '100%', fontSize: 13 }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid #ccc' }}>
              <th style={{ padding: '4px 8px' }}>Dossier</th>
              <th style={{ padding: '4px 8px' }}>案件</th>
              <th style={{ padding: '4px 8px' }}>狀態</th>
              <th style={{ padding: '4px 8px' }}>建立時間</th>
              <th style={{ padding: '4px 8px' }}>放行時間</th>
            </tr>
          </thead>
          <tbody>
            {dossiers.map((d) => (
              <tr key={d.id} style={{ borderBottom: '1px solid #eee' }}>
                <td style={{ padding: '4px 8px', fontFamily: 'monospace' }}>{d.id.slice(0, 8)}…</td>
                <td style={{ padding: '4px 8px' }}>{d.case_id}</td>
                <td style={{ padding: '4px 8px' }}>
                  <DossierBadge status={d.effective_status} />
                </td>
                <td style={{ padding: '4px 8px' }}>{d.created_at}</td>
                <td style={{ padding: '4px 8px' }}>{d.released_at ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
