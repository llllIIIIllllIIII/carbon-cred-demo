import {
  TC_UPSTREAM_PUBLIC_FIELDS,
  TC_UPSTREAM_BRAND_SD_FIELDS,
  TC_UPSTREAM_AUDIT_SD_FIELDS,
  TC_UPSTREAM_CONFIDENTIAL_FIELDS,
} from '../../../shared/types';

const FIELD_LABELS: Record<string, string> = {
  tcNo: 'TC 編號(tcNo)',
  tcStandard: 'TC 標準(tcStandard)',
  tcProductStandardLabelGrade: '產品標準/標籤等級',
  tcProductCategoryCode: '產品類別代碼',
  tcProductDetailCode: '產品細項代碼',
  tcCertifiedRawMaterialCountryOrArea: '認證原料產地國/地區',
  sellerTeId: '賣方 TE ID(sellerTeId)',
  buyerTeId: '買方 TE ID(buyerTeId)',
  tcShipmentInvoiceReferences_hash: '出貨發票參照 commitment hash',
  unit_price_hash: '單價 commitment hash',
  energy_invoice_hash: '能源帳單 commitment hash',
  recycler_name_hash: '回收粒供應商名 commitment hash',
  emission_factor_table_hash: '排放係數表 hash',
  tcProductRawMaterialCode: '原料代碼(tcProductRawMaterialCode)',
  tcProductRawMaterialPercentage: '原料成分比例(%)',
  tcProductCertifiedWeight: '認證重量(kg)',
  tcShipmentDate: '出貨日期',
  tcShipmentNo: '出貨編號',
  inputTcNo: '投入批次 TC 編號(inputTcNo)',
  tcProductLastProcessorName: '最後加工廠名稱',
  tcProductLastProcessorCountry: '最後加工廠所在國',
  pcf_total: '碳足跡總值 pcf_total(kgCO₂e/kg)',
  pcf_period: '碳足跡計算期間 pcf_period',
  pcf_method: '碳足跡計算方法 pcf_method',
  pcf_direct: '直接排放 pcf_direct(kgCO₂e/kg)',
  pcf_indirect: '間接排放 pcf_indirect(kgCO₂e/kg)',
  electricity_kwh_per_kg: '單位用電量(kWh/kg)',
  pcf_factor_source: '排放係數來源 pcf_factor_source',
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

/** 幕 1 憑證卡:揭露層以 🟢 公開 / 🟡 品牌 / 🔵 稽核 / 🔴 僅指紋 四色標示(spec v3 §0.2 #7)。 */
export function CredCard({ claims, sdJwt }: CredCardProps) {
  return (
    <div style={{ border: '1px solid #1a3c6e', borderRadius: 8, padding: 16, marginTop: 12, background: '#fff', maxWidth: 640 }}>
      <h3 style={{ marginTop: 0 }}>tc_carbon_upstream 憑證卡</h3>
      <p style={{ fontSize: 12, color: '#666' }}>
        🟢 公開(非 SD 明文) · 🟡 品牌(SD 可撕欄) · 🔵 稽核(SD 可撕欄) · 🔴 僅指紋(永不進憑證明文,僅 commitment hash)
      </p>
      {TC_UPSTREAM_PUBLIC_FIELDS.map((k) => (
        <Row key={k} label={FIELD_LABELS[k] ?? k} value={claims[k]} badge="🟢" />
      ))}
      {TC_UPSTREAM_BRAND_SD_FIELDS.map((k) => (
        <Row key={k} label={FIELD_LABELS[k] ?? k} value={claims[k]} badge="🟡" />
      ))}
      {TC_UPSTREAM_AUDIT_SD_FIELDS.map((k) => (
        <Row key={k} label={FIELD_LABELS[k] ?? k} value={claims[k]} badge="🔵" />
      ))}
      <p style={{ fontSize: 12, marginTop: 10, marginBottom: 0 }}>
        🔴 僅指紋(以上 commitment hash 代表):{TC_UPSTREAM_CONFIDENTIAL_FIELDS.join('、')}
      </p>
      <details style={{ marginTop: 12 }}>
        <summary style={{ cursor: 'pointer' }}>原始 token(一個簽章、N 張可撕欄位:{'<JWT>~<d1>~<d2>…'})</summary>
        <textarea readOnly value={sdJwt} style={{ width: '100%', height: 100, fontFamily: 'monospace', fontSize: 11, marginTop: 6 }} />
      </details>
    </div>
  );
}
