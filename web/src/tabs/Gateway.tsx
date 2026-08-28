import type { Manifest } from '../App';
import { LeiBadge } from './badge';

/** Tab 2 · 鴻鋼閘道(Cedar 決策 + 聚合;幕 2、4 在這裡演;Phase 0 為空殼) */
export function Gateway({ manifest }: { manifest: Manifest | null }) {
  return (
    <section>
      <LeiBadge role={manifest?.hunggang} fallback="鴻鋼精密扣件" />
      <h2>鴻鋼閘道 · 請求收件匣與 Cedar 決策</h2>
      <p style={{ color: '#666' }}>Phase 0 空分頁 — 幕 2(聚合)與幕 4(越界攔截)將於後續 Phase 實作。</p>
    </section>
  );
}
