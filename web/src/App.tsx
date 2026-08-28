import { useEffect, useState } from 'react';
import { ThepViet } from './tabs/ThepViet';
import { Gateway } from './tabs/Gateway';
import { BruckAgent } from './tabs/BruckAgent';
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

const TABS = [
  { id: 'thepviet', label: '越南廠' },
  { id: 'gateway', label: '鴻鋼閘道' },
  { id: 'bruck', label: 'Bruck Agent' },
  { id: 'audit', label: '稽核與撤銷' },
] as const;

type TabId = (typeof TABS)[number]['id'];

export function App() {
  const [tab, setTab] = useState<TabId>('thepviet');
  const [manifest, setManifest] = useState<Manifest | null>(null);

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
        {tab === 'thepviet' && <ThepViet manifest={manifest} />}
        {tab === 'gateway' && <Gateway manifest={manifest} />}
        {tab === 'bruck' && <BruckAgent manifest={manifest} />}
        {tab === 'audit' && <Audit manifest={manifest} />}
      </main>
      <AuditStrip />
    </div>
  );
}
