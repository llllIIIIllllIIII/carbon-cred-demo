import {
  TC_RCS_PUBLIC_FIELDS,
  TC_RCS_BRAND_SD_FIELDS,
  PCF_UPSTREAM_PUBLIC_FIELDS,
  PCF_UPSTREAM_BRAND_SD_FIELDS,
  PCF_UPSTREAM_AUDIT_SD_FIELDS,
  PCF_UPSTREAM_CONFIDENTIAL_FIELDS,
} from '../../../shared/types';

const FIELD_LABELS: Record<string, string> = {
  // tc_rcs(卡 1 · 認證機構簽發)
  tcNo: 'TC 編號(tcNo)',
  tcStandard: 'TC 標準(tcStandard)',
  tcProductStandardLabelGrade: '產品標準/標籤等級',
  tcProductCategoryCode: '產品類別代碼',
  tcProductDetailCode: '產品細項代碼',
  tcCertifiedRawMaterialCountryOrArea: '認證原料產地國/地區',
  sellerTeId: '賣方 TE ID(sellerTeId)',
  buyerTeId: '買方 TE ID(buyerTeId)',
  seller_lei: '賣方 LEI(紗廠)',
  buyer_lei: '買方 LEI(布廠)',
  volume_reconciled: '數量勾稽(volume_reconciled)',
  tcShipmentInvoiceReferences_hash: '出貨發票參照 commitment hash',
  tcProductRawMaterialCode: '原料代碼(tcProductRawMaterialCode)',
  tcProductRawMaterialPercentage: '原料成分比例(%)',
  tcProductCertifiedWeight: '認證重量(kg)',
  tcShipmentDate: '出貨日期',
  tcShipmentNo: '出貨編號',
  inputTcNo: '投入批次 TC 編號(inputTcNo)',
  tcProductLastProcessorName: '最後加工廠名稱',
  tcProductLastProcessorCountry: '最後加工廠所在國',
  // pcf_upstream(卡 2 · 紗廠簽發)
  tc_ref: '🔗 tc_ref(綁定卡 1 之 TC)',
  product_code: '產品代碼(product_code)',
  country_of_origin: '產地(country_of_origin)',
  unit_price_hash: '單價 commitment hash',
  energy_invoice_hash: '能源帳單 commitment hash',
  recycler_name_hash: '回收粒供應商名 commitment hash',
  emission_factor_table_hash: '排放係數表 hash',
  pcf_total: '碳足跡總值 pcf_total(kgCO₂e/kg)',
  pcf_period: '碳足跡計算期間 pcf_period',
  pcf_method: '碳足跡計算方法 pcf_method',
  quantity_kg: '批次重量 quantity_kg(kg)',
  pcf_direct: '直接排放 pcf_direct(kgCO₂e/kg)',
  pcf_indirect: '間接排放 pcf_indirect(kgCO₂e/kg)',
  electricity_kwh_per_kg: '單位用電量(kWh/kg)',
  pcf_factor_source: '排放係數來源 pcf_factor_source',
};

function formatValue(key: string, value: unknown): string {
  if (value === undefined || value === null) return '(無)';
  if (key === 'tc_ref' && typeof value === 'object') {
    const ref = value as { id?: string; tcNo?: string; hash?: string };
    return `${ref.tcNo ?? ref.id ?? '?'} · hash ${String(ref.hash ?? '').slice(0, 12)}…`;
  }
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

/** LOW #4 修法:fieldKey 必須傳入並轉交 formatValue,否則 tc_ref 美化分支(line 52)永不觸發。 */
function Row({ fieldKey, label, value, badge }: { fieldKey: string; label: string; value: unknown; badge: string }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '4px 0', borderBottom: '1px solid #eee', fontSize: 13 }}>
      <span>
        <span style={{ marginRight: 6 }}>{badge}</span>
        {label}
      </span>
      <code style={{ fontSize: 12, textAlign: 'right' }}>{formatValue(fieldKey, value)}</code>
    </div>
  );
}

export interface CredCardProps {
  claims: Record<string, unknown>;
  sdJwt: string;
  /** 幕 1 兩張卡(v3.1;spec §4.2a/§4.2b):'tc_rcs' = 卡 1(認證機構簽發,TE 欄位);
   * 'pcf_upstream'(預設)= 卡 2(紗廠簽發,含 tc_ref 綁定卡 1)。 */
  variant?: 'tc_rcs' | 'pcf_upstream';
}

const VARIANTS = {
  tc_rcs: {
    title: 'tc_rcs 憑證卡 — Transaction Certificate(認證機構 Lowland 簽發)',
    publicFields: TC_RCS_PUBLIC_FIELDS as readonly string[],
    brandFields: TC_RCS_BRAND_SD_FIELDS as readonly string[],
    confidentialFields: [] as readonly string[],
    confidentialNote: null as string | null,
  },
  pcf_upstream: {
    title: 'pcf_upstream 憑證卡 — 碳足跡憑證(紗廠 Sợi Xanh Việt 簽發)',
    publicFields: PCF_UPSTREAM_PUBLIC_FIELDS as readonly string[],
    brandFields: [...PCF_UPSTREAM_BRAND_SD_FIELDS, ...PCF_UPSTREAM_AUDIT_SD_FIELDS] as readonly string[],
    confidentialFields: PCF_UPSTREAM_CONFIDENTIAL_FIELDS as readonly string[],
    confidentialNote: '🔴 僅指紋(以上 commitment hash 代表)',
  },
} as const;

/** 幕 1 憑證卡:揭露層以 🟢 公開 / 🟡 品牌+稽核(SD 可撕欄) / 🔴 僅指紋 三色標示(spec v3.1 §0.2 #7)。 */
export function CredCard({ claims, sdJwt, variant = 'pcf_upstream' }: CredCardProps) {
  const v = VARIANTS[variant];
  return (
    <div style={{ border: '1px solid #1a3c6e', borderRadius: 8, padding: 16, marginTop: 12, background: '#fff', maxWidth: 640 }}>
      <h3 style={{ marginTop: 0 }}>{v.title}</h3>
      <p style={{ fontSize: 12, color: '#666' }}>🟢 公開(非 SD 明文) · 🟡 品牌/稽核(SD 可撕欄) · 🔴 僅指紋(永不進憑證明文,僅 commitment hash)</p>
      {v.publicFields.map((k) => (
        <Row key={k} fieldKey={k} label={FIELD_LABELS[k] ?? k} value={claims[k]} badge="🟢" />
      ))}
      {v.brandFields.map((k) => (
        <Row key={k} fieldKey={k} label={FIELD_LABELS[k] ?? k} value={claims[k]} badge="🟡" />
      ))}
      {v.confidentialNote && (
        <p style={{ fontSize: 12, marginTop: 10, marginBottom: 0 }}>
          {v.confidentialNote}:{v.confidentialFields.join('、')}
        </p>
      )}
      <details style={{ marginTop: 12 }}>
        <summary style={{ cursor: 'pointer' }}>原始 token(一個簽章、N 張可撕欄位:{'<JWT>~<d1>~<d2>…'})</summary>
        <textarea readOnly value={sdJwt} style={{ width: '100%', height: 100, fontFamily: 'monospace', fontSize: 11, marginTop: 6 }} />
      </details>
    </div>
  );
}
