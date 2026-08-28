/** L3 修正:僅作 /api/aggregate 未回傳 contract_carbon_max 時的 fallback,正式值一律由後端(data/seed.json)提供。 */
const CONTRACT_THRESHOLD_DEFAULT = 2.0;
const CHART_WIDTH = 480;
const BAR_HEIGHT = 36;
const TOP_MARGIN = 20;

export interface StackChartProps {
  /** 前驅物內含排放 × 投入係數(規格v2:100)。 */
  precursor: number;
  /** 自身 direct(tCO2e/t)。 */
  selfDirect: number;
  /** 自身 indirect(tCO2e/t)。 */
  selfIndirect: number;
  /** 聚合總值(= precursor + selfDirect + selfIndirect)。 */
  total: number;
  /** 合約碳排門檻(規格v2 §3:≤2.00 tCO2e/t,買方合約條款)。 */
  thresholdMax?: number;
}

/**
 * 幕 2 疊層熱點圖(架構決策 §2:web/src/components/StackChart)——
 * 三段寬度全部綁 /api/aggregate 回傳之真值,不寫死(藍圖:151、DoD:159)。
 * 超過合約門檻時前驅物段變紅,呼應藍圖:155「案 B 時上游段變紅,一眼看出超標」——
 * 憑證本身仍不含上游明細(僅以鴻鋼自己算出的聚合總值判色)。
 */
export function StackChart({ precursor, selfDirect, selfIndirect, total, thresholdMax = CONTRACT_THRESHOLD_DEFAULT }: StackChartProps) {
  const domainMax = Math.max(total, thresholdMax) * 1.15;
  const scale = (v: number) => (CHART_WIDTH * v) / domainMax;
  const overThreshold = total > thresholdMax;

  const precursorColor = overThreshold ? '#c0392b' : '#2f6fed';
  const selfDirectColor = '#e8871e';
  const selfIndirectColor = '#8e44ad';

  const precursorW = scale(precursor);
  const selfDirectW = scale(selfDirect);
  const selfIndirectW = scale(selfIndirect);
  const thresholdX = scale(thresholdMax);
  const barY = TOP_MARGIN;

  return (
    <div style={{ marginTop: 12 }}>
      <svg width={CHART_WIDTH + 40} height={TOP_MARGIN + BAR_HEIGHT + 10} role="img" aria-label="疊層熱點圖:前驅物/自身 direct/自身 indirect">
        <line x1={thresholdX} y1={0} x2={thresholdX} y2={barY + BAR_HEIGHT} stroke="#999" strokeDasharray="4 3" />
        <text x={thresholdX + 4} y={12} fontSize={11} fill="#666">
          合約門檻 {thresholdMax.toFixed(2)}
        </text>
        <rect x={0} y={barY} width={precursorW} height={BAR_HEIGHT} fill={precursorColor} />
        <rect x={precursorW} y={barY} width={selfDirectW} height={BAR_HEIGHT} fill={selfDirectColor} />
        <rect x={precursorW + selfDirectW} y={barY} width={selfIndirectW} height={BAR_HEIGHT} fill={selfIndirectColor} />
      </svg>
      <div style={{ display: 'flex', gap: 16, fontSize: 12, marginTop: 4, flexWrap: 'wrap' }}>
        <Legend color={precursorColor} label={`前驅物內含排放 × 投入係數:${precursor.toFixed(4)} tCO2e/t`} />
        <Legend color={selfDirectColor} label={`自身 direct:${selfDirect.toFixed(2)} tCO2e/t`} />
        <Legend color={selfIndirectColor} label={`自身 indirect:${selfIndirect.toFixed(2)} tCO2e/t`} />
      </div>
      <p style={{ fontWeight: 700, marginTop: 6, color: overThreshold ? '#c0392b' : '#0a7a2f' }}>
        合計:{total.toFixed(4)} tCO2e/t 扣件 {overThreshold ? `— 超過合約門檻 ${thresholdMax.toFixed(2)}` : `— 符合合約門檻 ${thresholdMax.toFixed(2)}`}
      </p>
    </div>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
      <span style={{ width: 10, height: 10, background: color, display: 'inline-block', borderRadius: 2 }} />
      {label}
    </span>
  );
}
