import type { Manifest } from '../App';

/** Tab 4 · 稽核與撤銷(全域視角;幕 5、6 在這裡演;Phase 0 為空殼) */
export function Audit({ manifest: _manifest }: { manifest: Manifest | null }) {
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
      <p style={{ color: '#666' }}>Phase 0 空分頁 — audit_chain 表格、Status List bit 條與撤銷開關將於 Phase 3 實作。</p>
    </section>
  );
}
