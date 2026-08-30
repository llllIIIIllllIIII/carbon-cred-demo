import { useEffect, useRef, useState } from 'react';
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
  { id: 'yarn', label: '紗廠 Sợi Xanh Việt(簽發)' },
  { id: 'gateway', label: '誠紡閘道(聚合 · Cedar)' },
  { id: 'brand', label: 'Nordlicht 品牌 Agent(M2 · 查驗)' },
  { id: 'audit', label: '稽核與撤銷' },
] as const;

export type TabId = (typeof TABS)[number]['id'];

/** deep-link `case` 參數之合法值(四案;各分頁按自身支援範圍再夾限,詳各 Tab 元件)。 */
export type DeepLinkCaseId = 'A' | 'B' | 'C' | 'Cp';

const TAB_IDS: readonly TabId[] = TABS.map((t) => t.id);
const DEEP_LINK_CASE_IDS: readonly DeepLinkCaseId[] = ['A', 'B', 'C', 'Cp'];

function isTabId(value: string | null): value is TabId {
  return value !== null && (TAB_IDS as readonly string[]).includes(value);
}

function isDeepLinkCaseId(value: string | null): value is DeepLinkCaseId {
  return value !== null && (DEEP_LINK_CASE_IDS as readonly string[]).includes(value);
}

export interface DeepLink {
  /** 合法分頁 key(不在四分頁內 → null,呼叫端 fallback 現有預設分頁)。 */
  tab: TabId | null;
  /** 合法案件(A/B/C/Cp;不合法 → null,呼叫端 fallback 各分頁自身預設案件)。 */
  caseId: DeepLinkCaseId | null;
}

/**
 * 純函式(Phase 4 brief §1.1):解析 `?tab=…&case=…` 深連參數。
 * 接受帶或不帶開頭 `?` 的 query string(含完整 `location.search`);未知/缺值一律回 null,
 * 不得讓深連結把畫面帶進不存在的分頁或案件——呼叫端一律 `?? 現有預設值`。
 * 無 DOM 依賴,scripts/test.ts 直接匯入做單元測試(同 web/src/tabs/Audit.tsx 之
 * defaultIdxForLabels 前例)。
 */
export function parseDeepLink(search: string): DeepLink {
  const qs = search.startsWith('?') ? search.slice(1) : search;
  const params = new URLSearchParams(qs);
  const tabRaw = params.get('tab');
  const caseRaw = params.get('case');
  return {
    tab: isTabId(tabRaw) ? tabRaw : null,
    caseId: isDeepLinkCaseId(caseRaw) ? caseRaw : null,
  };
}

/** 依目前分頁/案件組回 `?tab=…&case=…`(案件未定則只留 tab)。 */
function buildDeepLinkSearch(tab: TabId, caseId: DeepLinkCaseId | null): string {
  const params = new URLSearchParams();
  params.set('tab', tab);
  if (caseId) params.set('case', caseId);
  return `?${params.toString()}`;
}

export interface NavState {
  tab: TabId;
  caseId: DeepLinkCaseId | null;
}

/**
 * 純函式(Codex 審查 P2-1 回歸鎖):套用預設值後的畫面導覽狀態——掛載初始化與
 * `popstate`(瀏覽器上一頁/下一頁)重新同步共用同一套 fallback 邏輯,避免兩處分別
 * fallback 出現落差(例如掛載時 tab 不合法回退 'yarn',popstate 卻忘記套用同一預設值)。
 */
export function resolveNavState(search: string): NavState {
  const parsed = parseDeepLink(search);
  return { tab: parsed.tab ?? 'yarn', caseId: parsed.caseId };
}

export function App() {
  // 只在掛載時解析一次(之後的分頁/案件切換一律靠 setTab/setUrlCaseId,不重讀 location;
  // popstate 事件另由下方監聽器處理)。
  const initialNav = useRef<NavState | null>(null);
  if (initialNav.current === null) {
    initialNav.current = resolveNavState(window.location.search);
  }

  const [tab, setTab] = useState<TabId>(initialNav.current.tab);
  const [urlCaseId, setUrlCaseId] = useState<DeepLinkCaseId | null>(initialNav.current.caseId);
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [lastDisclose, setLastDisclose] = useState<DiscloseEvent | null>(null);
  // Codex 審查 P2-1:瀏覽器上一頁/下一頁只會改 window.location,不會觸發我們自己的
  // pushState effect,也不會讓子分頁(Yarn/Gateway/BrandAgent)重新讀取 initialCase——
  // 子分頁的案件選單狀態只在「掛載當下」讀一次 initialCase。若 popstate 前後 tab 不變
  // (例如同在 gateway 分頁內,案 A → 案 B → 上一頁回案 A),子分頁不會自然卸載重掛,
  // 案件選單會停在使用者最後手動選的值,與網址列不符。以 navEpoch 在 popstate 時遞增,
  // 當作子分頁的 React key 一部分,強制該分頁完整重掛、重新以新網址的案件初始化
  // (tab 改變時本就會因條件渲染卸載/掛載,navEpoch 遞增對其無害)。
  const [navEpoch, setNavEpoch] = useState(0);

  useEffect(() => {
    fetch('/api/manifest')
      .then((r) => (r.ok ? r.json() : null))
      .then(setManifest)
      .catch(() => setManifest(null));
  }, []);

  // deep-link 一覽(README 附完整清單):切分頁或分頁內切案件都以 pushState 更新 URL,
  // 不觸發整頁重載——瀏覽器上一頁/下一頁鍵可在錄影時快速回退到前一個畫面。
  useEffect(() => {
    const next = buildDeepLinkSearch(tab, urlCaseId);
    if (window.location.search !== next) {
      window.history.pushState(null, '', next);
    }
  }, [tab, urlCaseId]);

  // Codex 審查 P2-1:popstate 監聽——瀏覽器上一頁/下一頁時以 parseDeepLink(現有單元測試
  // 覆蓋之純函式)重新同步 tab 與案件狀態,並遞增 navEpoch 強制同分頁內的子元件重掛。
  useEffect(() => {
    function onPopState() {
      const next = resolveNavState(window.location.search);
      setTab(next.tab);
      setUrlCaseId(next.caseId);
      setNavEpoch((n) => n + 1);
    }
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
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
        {tab === 'yarn' && <Yarn key={navEpoch} manifest={manifest} initialCase={urlCaseId} onCaseChange={setUrlCaseId} />}
        {tab === 'gateway' && (
          <Gateway key={navEpoch} manifest={manifest} lastDisclose={lastDisclose} initialCase={urlCaseId} onCaseChange={setUrlCaseId} />
        )}
        {tab === 'brand' && (
          <BrandAgent key={navEpoch} manifest={manifest} onDisclose={setLastDisclose} initialCase={urlCaseId} onCaseChange={setUrlCaseId} />
        )}
        {tab === 'audit' && <Audit manifest={manifest} />}
      </main>
      <AuditStrip />
    </div>
  );
}
