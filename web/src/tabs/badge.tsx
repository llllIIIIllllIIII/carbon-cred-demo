import type { ManifestRole } from '../App';

/** 分頁左上角的 LEI 徽章:評審一眼知道現在是誰的視角。資料一律來自 manifest,不寫死。 */
export function LeiBadge({ role, fallback }: { role?: ManifestRole; fallback: string }) {
  return (
    <div
      style={{
        display: 'inline-block',
        padding: '4px 10px',
        border: '1px solid #1a3c6e',
        borderRadius: 6,
        background: '#eef4ff',
        fontSize: 13,
        marginBottom: 8,
      }}
    >
      <strong>LEI</strong> {role ? `${role.lei} · ${fallback}` : `(尚未 presign)· ${fallback}`}
    </div>
  );
}
