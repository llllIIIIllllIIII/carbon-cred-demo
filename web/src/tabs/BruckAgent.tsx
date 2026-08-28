import type { Manifest } from '../App';
import { LeiBadge } from './badge';

/** Tab 3 · Bruck Agent(mandate + 查驗 + 驗證;幕 3 在這裡演;Phase 0 為空殼) */
export function BruckAgent({ manifest }: { manifest: Manifest | null }) {
  return (
    <section>
      <LeiBadge role={manifest?.bruck} fallback="Bruck & Söhne GmbH" />
      <h2>Bruck Agent · 委任查驗</h2>
      <p style={{ color: '#666' }}>Phase 0 空分頁 — 幕 3(M2 委任查驗與離線驗證)將於 Phase 2 實作。</p>
    </section>
  );
}
