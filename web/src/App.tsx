import { useEffect, useState } from 'react';
import { Yarn } from './tabs/Yarn';
import { Gateway } from './tabs/Gateway';
import { BrandAgent } from './tabs/BrandAgent';
import { Audit } from './tabs/Audit';
import { AuditStrip } from './components/AuditStrip';

export interface ManifestRole {
  alias: string;
  aid: string;
  lei: string;
  credential_said: string;
  presentation_file: string;
  public_key: string;
}
export type Manifest = Record<string, ManifestRole>;

/**
 * 幕 3/4 最近一次 disclose 結果(App 層狀態提升)——Tab2/Tab3 於本 SPA 以條件渲染切換,
 * 切分頁時前一個分頁會卸載、本地 state 隨之歸零,故 Tab2 的 Cedar 決策面板/請求收件匣/
 * DenyStamp 需要的資訊由 Tab3 呼叫 /api/disclose 後主動寫入此處(純前端狀態提升,
 * 未新增/更動任何伺服端 route)。
 */
export interface DiscloseEvent {
  /** /api/audit 最新 seq(呼叫完成後讀取,供「#req-NN」顯示;讀不到時為 null)。 */
  auditSeq: number | null;
  requestedClaims: string[];
  caseId: 'A' | 'B';
  nonce: string;
  decision: 'PERMIT' | 'DENY' | 'REPLAY_DETECTED';
  policyId?: 'P1' | 'P2';
  reasonCode: string;
  presentation?: string;
  at: string;
}

const TABS = [
  { id: 'yarn', label: '越南廠' },
  { id: 'gateway', label: '鴻鋼閘道' },
  { id: 'brand', label: 'Brand Agent' },
  { id: 'audit', label: '稽核與撤銷' },
] as const;

type TabId = (typeof TABS)[number]['id'];

export function App() {
  const [tab, setTab] = useState<TabId>('yarn');
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [lastDisclose, setLastDisclose] = useState<DiscloseEvent | null>(null);

  useEffect(() => {
    fetch('/api/manifest')
      .then((r) => (r.ok ? r.json() : null))
      .then(setManifest)
      .catch(() => setManifest(null));
  }, []);

  return (
    <div style={{ fontFamily: 'system-ui, sans-serif', display: 'flex', flexDirection: 'column', minHeight: '100vh', margin: 0 }}>
      <nav style={{ display: 'flex', gap: 4, padding: '8px 12px', borderBottom: '1px solid #ccc', background: '#f7f7f7' }}>
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              padding: '6px 14px',
              border: '1px solid #bbb',
              borderRadius: 6,
              background: tab === t.id ? '#1a3c6e' : '#fff',
              color: tab === t.id ? '#fff' : '#222',
              cursor: 'pointer',
            }}
          >
            {t.label}
          </button>
        ))}
      </nav>
      <main style={{ flex: 1, padding: 16 }}>
        {tab === 'yarn' && <Yarn manifest={manifest} />}
        {tab === 'gateway' && <Gateway manifest={manifest} lastDisclose={lastDisclose} />}
        {tab === 'brand' && <BrandAgent manifest={manifest} onDisclose={setLastDisclose} />}
        {tab === 'audit' && <Audit manifest={manifest} />}
      </main>
      <AuditStrip />
    </div>
  );
}
