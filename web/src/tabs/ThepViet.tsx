import type { Manifest } from '../App';
import { LeiBadge } from './badge';

/** Tab 1 · 越南廠簽發端主控台(幕 1 在這裡演;Phase 0 為空殼) */
export function ThepViet({ manifest }: { manifest: Manifest | null }) {
  return (
    <section>
      <LeiBadge role={manifest?.thepviet} fallback="Thép Việt Wire Co." />
      <h2>越南廠 · 簽發端主控台</h2>
      <p style={{ color: '#666' }}>Phase 0 空分頁 — 幕 1(簽發 pcf_upstream)將於 Phase 1 實作。</p>
    </section>
  );
}
