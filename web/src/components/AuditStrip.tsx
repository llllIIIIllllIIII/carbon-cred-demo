import { useEffect, useRef, useState } from 'react';

interface AuditEntry {
  seq: number;
  event_type: string;
  entry_hash: string;
  created_at: string;
}

/**
 * 底部常駐稽核帶(Phase 0 殼):以「最後收到的 seq」為游標輪詢 /api/audit,
 * 只抓新事件並附加(避免固定 after=0 在超過分頁上限後永遠看不到新事件——Codex 審查定案)。
 * 畫面僅保留最近 50 筆;make demo-reset 會重建 DB(seq 歸零),重新整理頁面即可重置游標。
 */
export function AuditStrip() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const lastSeqRef = useRef(0);

  useEffect(() => {
    let alive = true;
    const poll = () =>
      fetch(`/api/audit?after=${lastSeqRef.current}`)
        .then((r) => (r.ok ? r.json() : []))
        .then((rows: AuditEntry[]) => {
          if (!alive || !Array.isArray(rows) || rows.length === 0) return;
          lastSeqRef.current = rows[rows.length - 1].seq;
          setEntries((prev) => [...prev, ...rows].slice(-50));
        })
        .catch(() => {});
    poll();
    const t = setInterval(poll, 3000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  return (
    <footer
      style={{
        borderTop: '2px solid #1a3c6e',
        background: '#0d1b2a',
        color: '#cde3ff',
        padding: '6px 12px',
        fontSize: 13,
        whiteSpace: 'nowrap',
        overflowX: 'auto',
      }}
    >
      <span style={{ fontWeight: 700, marginRight: 12 }}>稽核帶 ▸</span>
      {entries.length === 0 ? (
        <span style={{ opacity: 0.7 }}>尚無稽核事件(Phase 0 殼)</span>
      ) : (
        entries.map((e) => (
          <span key={e.seq} style={{ marginRight: 16 }}>
            #{e.seq} {e.event_type} {e.entry_hash.slice(0, 8)}…
          </span>
        ))
      )}
    </footer>
  );
}
