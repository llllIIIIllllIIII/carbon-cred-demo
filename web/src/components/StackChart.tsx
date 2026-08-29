/** L3 修正:僅作 /api/aggregate 未回傳 contract_carbon_max 時的 fallback,正式值一律由後端(data/seed.json)提供。 */
const CONTRACT_THRESHOLD_DEFAULT = 9.5;
const CHART_WIDTH = 480;
const BAR_HEIGHT = 36;
const TOP_MARGIN = 20;

export interface StackChartProps {
  /** 紗(外部 tc_carbon_upstream × 損耗加成;kgCO₂e/kg)。 */
  yarn: number;
  /** 自家織布用電(kgCO₂e/kg)。 */
  knitting: number;
  /** 外包染整(外部 pcf_dyeing;kgCO₂e/kg)——A/B 差異的唯一來源。 */
  dyeing: number;
  /** 聚合總值(= yarn + knitting + dyeing)。 */
  total: number;
  /** 品牌合約碳排門檻(kgCO₂e/kg;spec v3:9.5,一律讀 /api/aggregate 的 contract_carbon_max,不寫死)。 */
  thresholdMax?: number;
}

/**
 * 幕 2 疊層熱點圖(架構決策 §2:web/src/components/StackChart)——
 * 三段寬度全部綁 /api/aggregate 回傳之真值,不寫死(藍圖:151、DoD:159)。
 * 案 B 染整燃料改用煤、無綠電,總值越過合約門檻時染整段變紅,一眼看出超標——
 * 憑證本身仍不含上游明細(僅以誠紡自己算出的聚合總值判色)。
 */
export function StackChart({ yarn, knitting, dyeing, total, thresholdMax = CONTRACT_THRESHOLD_DEFAULT }: StackChartProps) {
  const domainMax = Math.max(total, thresholdMax) * 1.15;
  const scale = (v: number) => (CHART_WIDTH * v) / domainMax;
  const overThreshold = total > thresholdMax;

  const yarnColor = '#2f6fed';
  const knittingColor = '#e8871e';
  const dyeingColor = overThreshold ? '#c0392b' : '#8e44ad';

  const yarnW = scale(yarn);
  const knittingW = scale(knitting);
  const dyeingW = scale(dyeing);
  const thresholdX = scale(thresholdMax);
  const barY = TOP_MARGIN;

  return (
    <div style={{ marginTop: 12 }}>
      <svg width={CHART_WIDTH + 40} height={TOP_MARGIN + BAR_HEIGHT + 10} role="img" aria-label="疊層熱點圖:紗/織布/染整">
        <line x1={thresholdX} y1={0} x2={thresholdX} y2={barY + BAR_HEIGHT} stroke="#999" strokeDasharray="4 3" />
        <text x={thresholdX + 4} y={12} fontSize={11} fill="#666">
          合約門檻 {thresholdMax.toFixed(2)}
        </text>
        <rect x={0} y={barY} width={yarnW} height={BAR_HEIGHT} fill={yarnColor} />
        <rect x={yarnW} y={barY} width={knittingW} height={BAR_HEIGHT} fill={knittingColor} />
        <rect x={yarnW + knittingW} y={barY} width={dyeingW} height={BAR_HEIGHT} fill={dyeingColor} />
      </svg>
      <div style={{ display: 'flex', gap: 16, fontSize: 12, marginTop: 4, flexWrap: 'wrap' }}>
        <Legend color={yarnColor} label={`紗:${yarn.toFixed(4)} kgCO₂e/kg`} />
        <Legend color={knittingColor} label={`織布:${knitting.toFixed(2)} kgCO₂e/kg`} />
        <Legend color={dyeingColor} label={`染整:${dyeing.toFixed(2)} kgCO₂e/kg(A/B 差異來源)`} />
      </div>
      <p style={{ fontWeight: 700, marginTop: 6, color: overThreshold ? '#c0392b' : '#0a7a2f' }}>
        合計:{total.toFixed(4)} kgCO₂e/kg {overThreshold ? `— 超過合約門檻 ${thresholdMax.toFixed(2)}` : `— 符合合約門檻 ${thresholdMax.toFixed(2)}`}
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
