import {
  PCF_UPSTREAM_PUBLIC_FIELDS,
  PCF_UPSTREAM_CUSTOMS_SD_FIELDS,
  PCF_UPSTREAM_CUSTOMER_SD_FIELDS,
  PCF_UPSTREAM_CONFIDENTIAL_FIELDS,
} from '../../../shared/types';

const FIELD_LABELS: Record<string, string> = {
  cn_code: '海關碼(CN Code)',
  quantity_t: '數量(t)',
  country_of_origin: '原產地',
  machine_energy_hash: '機台能耗 commitment hash',
  ppa_contract_hash: '電力採購合約(PPA)commitment hash',
  recipe_hash: '配方 commitment hash',
  customer_list_hash: '客戶名單 commitment hash',
  emission_factor_table_hash: '排放係數表 hash(含產能利用率)',
  specific_direct_embedded_emissions: '直接排放 direct(tCO2e/t)',
  production_route: '生產路線',
  carbon_price_paid_origin: '原產地碳定價',
  specific_indirect_embedded_emissions: '間接排放 indirect(tCO2e/t)',
  electricity_mix_ref: '電力排放係數來源',
  installation_unlocode: '產地代碼(UN/LOCODE)',
  dqr: '資料品質評級(DQR)',
  primary_data_share: '原始資料佔比',
};

function formatValue(value: unknown): string {
  if (value === undefined || value === null) return '(無)';
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

function Row({ label, value, badge }: { label: string; value: unknown; badge: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '4px 0', borderBottom: '1px solid #eee', fontSize: 13 }}>
      <span>
        <span style={{ marginRight: 6 }}>{badge}</span>
        {label}
      </span>
      <code style={{ fontSize: 12, textAlign: 'right' }}>{formatValue(value)}</code>
    </div>
  );
}

export interface CredCardProps {
  claims: Record<string, unknown>;
  sdJwt: string;
}

/** 幕 1 憑證卡:欄位以 🟢(公開層)/🟡(SD 可撕欄)/🔴(機密,僅 hash)三色標示(藍圖:129)。 */
export function CredCard({ claims, sdJwt }: CredCardProps) {
  return (
    <div style={{ border: '1px solid #1a3c6e', borderRadius: 8, padding: 16, marginTop: 12, background: '#fff', maxWidth: 640 }}>
      <h3 style={{ marginTop: 0 }}>pcf_upstream 憑證卡</h3>
      <p style={{ fontSize: 12, color: '#666' }}>
        🟢 公開層(非 SD 明文) · 🟡 SD 可撕欄(海關層 + 客戶層) · 🔴 機密(永不進憑證,僅留 commitment hash)
      </p>
      {PCF_UPSTREAM_PUBLIC_FIELDS.map((k) => (
        <Row key={k} label={FIELD_LABELS[k] ?? k} value={claims[k]} badge="🟢" />
      ))}
      {PCF_UPSTREAM_CUSTOMS_SD_FIELDS.map((k) => (
        <Row key={k} label={FIELD_LABELS[k] ?? k} value={claims[k]} badge="🟡" />
      ))}
      {PCF_UPSTREAM_CUSTOMER_SD_FIELDS.map((k) => (
        <Row key={k} label={FIELD_LABELS[k] ?? k} value={claims[k]} badge="🟡" />
      ))}
      <p style={{ fontSize: 12, marginTop: 10, marginBottom: 0 }}>
        🔴 永不揭露(以上 commitment hash 代表):{PCF_UPSTREAM_CONFIDENTIAL_FIELDS.join('、')}
      </p>
      <details style={{ marginTop: 12 }}>
        <summary style={{ cursor: 'pointer' }}>原始 token(一個簽章、N 張可撕欄位:{'<JWT>~<d1>~<d2>…'})</summary>
        <textarea readOnly value={sdJwt} style={{ width: '100%', height: 100, fontFamily: 'monospace', fontSize: 11, marginTop: 6 }} />
      </details>
    </div>
  );
}
