/**
 * 幕 4 越界攔截視覺焦點(藍圖:205)——旋轉紅章 DENY 效果,蓋在 Tab2 決策面板上。
 * 純 CSS,無外部依賴;父層需設 position: relative 供本元件絕對定位覆蓋。
 */
export function DenyStamp({ active }: { active: boolean }) {
  if (!active) return null;
  return (
    <div
      aria-label="DENY"
      style={{
        position: 'absolute',
        top: '50%',
        left: '50%',
        transform: 'translate(-50%, -50%) rotate(-16deg)',
        border: '6px solid #c0392b',
        color: '#c0392b',
        fontSize: 40,
        fontWeight: 900,
        letterSpacing: 6,
        padding: '6px 26px',
        borderRadius: 12,
        background: 'rgba(255,255,255,0.72)',
        opacity: 0.92,
        pointerEvents: 'none',
        textTransform: 'uppercase',
        boxShadow: '0 0 0 2px rgba(192,57,43,0.15)',
        zIndex: 5,
      }}
    >
      DENY
    </div>
  );
}
