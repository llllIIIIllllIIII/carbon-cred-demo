import { useState } from 'react';
import type { Manifest } from '../App';
import { LeiBadge } from './badge';
import { CredCard } from '../components/CredCard';

type CaseId = 'A' | 'B';

interface IssueResponse {
  id: string;
  case_id: CaseId;
  sd_jwt: string;
  claims: Record<string, unknown>;
  issued_at: string;
  valid_from: string;
  valid_until: string;
  /** M2 修正:該案已簽發過時直接回既有憑證,未重簽。 */
  reused?: boolean;
}

interface VerifyResponse {
  valid: boolean;
  error?: string;
  reason_code?: string;
}

/** A/B 兩案紗憑證內容相同(差異只在下游 pcf_dyeing 的燃料/綠電比)——此處僅切換要簽發的批次記錄。 */
const CASE_LABELS: Record<CaseId, string> = {
  A: '案 A · rPET DTY 長絲紗(RCS 100)· 3,000 kg · VN',
  B: '案 B · rPET DTY 長絲紗(RCS 100)· 3,000 kg · VN(與 A 同批;差異僅見於下游染整)',
};

/** L1 修正:理由碼對應之繁中說明,竄改示範失敗時明確顯示「簽章不符」而非含糊訊息。 */
const REASON_LABELS: Record<string, string> = {
  CREDENTIAL_SIG_INVALID: '簽章不符(payload 內容與簽章不一致)',
  CREDENTIAL_PARSE_ERROR: '格式解析錯誤(不是合法的 compact SD-JWT)',
  ISSUER_UNKNOWN: '簽發者未登錄於 manifest',
};

function describeVerifyFailure(reasonCode: string | undefined, error: string | undefined): string {
  const label = reasonCode ? (REASON_LABELS[reasonCode] ?? reasonCode) : '未知原因';
  return `✗ 驗證失敗——${label}${error ? `(${error})` : ''}`;
}

/** Tab 1 · 越南紗廠簽發端主控台(幕 1:簽發 tc_carbon_upstream)。 */
export function Yarn({ manifest }: { manifest: Manifest | null }) {
  const [caseId, setCaseId] = useState<CaseId>('A');
  const [issuance, setIssuance] = useState<IssueResponse | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerifyResponse | null>(null);
  const [tamperedToken, setTamperedToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleIssue() {
    setBusy(true);
    setError(null);
    setVerifyResult(null);
    setTamperedToken(null);
    try {
      const r = await fetch('/api/issue/upstream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ case_id: caseId }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error ?? '簽發失敗');
      setIssuance(data as IssueResponse);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function callVerify(token: string) {
    const r = await fetch('/api/creds/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sd_jwt: token }),
    });
    const data = (await r.json()) as VerifyResponse;
    setVerifyResult(data);
  }

  async function handleTamperDemo() {
    if (!issuance) return;
    const r = await fetch('/api/creds/tamper-demo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sd_jwt: issuance.sd_jwt }),
    });
    const data = await r.json();
    if (!r.ok) {
      setError(data.error ?? '竄改示範失敗');
      return;
    }
    setTamperedToken(data.sd_jwt as string);
    await callVerify(data.sd_jwt as string);
  }

  return (
    <section>
      <LeiBadge role={manifest?.yarn} fallback="Sợi Xanh Việt Co., Ltd.(越藍紗業)" />
      <h2>越南紗廠 · 簽發端主控台</h2>
      <p style={{ color: '#666' }}>
        幕 1:以 Sợi Xanh Việt sandbox LE AID 鑰簽發 tc_carbon_upstream(SD-JWT VC)。一個簽章、N 張可撕欄位——欄位三分法見下方憑證卡。
      </p>
      <p style={{ color: '#888', fontSize: 13 }}>Textile Exchange TC 欄位;pcf_* 為我方延伸——TC 本身無碳數據。</p>

      <label style={{ marginRight: 12 }}>
        案件:
        <select value={caseId} onChange={(e) => setCaseId(e.target.value as CaseId)} disabled={busy} style={{ marginLeft: 6 }}>
          <option value="A">{CASE_LABELS.A}</option>
          <option value="B">{CASE_LABELS.B}</option>
        </select>
      </label>
      <button onClick={handleIssue} disabled={busy}>
        {busy ? '簽發中…' : '簽發'}
      </button>

      {error && <p style={{ color: 'crimson' }}>{error}</p>}

      {issuance && (
        <>
          {issuance.reused && (
            <p style={{ color: '#1a5fb4', fontWeight: 600 }}>ℹ️ 已簽發——載入既有憑證(該案先前已簽發過,冪等未重簽)</p>
          )}
          <CredCard claims={issuance.claims} sdJwt={issuance.sd_jwt} />
          <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
            <button onClick={() => callVerify(issuance.sd_jwt)}>verify()</button>
            <button onClick={handleTamperDemo}>竄改 1 byte → 驗證失敗示範</button>
          </div>
          {verifyResult && (
            <p style={{ color: verifyResult.valid ? '#0a7a2f' : '#c0392b', fontWeight: 700 }}>
              {verifyResult.valid
                ? '✓ 簽章與揭露完整性驗證通過(撤銷狀態查驗屬幕 3)'
                : describeVerifyFailure(verifyResult.reason_code, verifyResult.error)}
            </p>
          )}
          {tamperedToken && (
            <details>
              <summary style={{ cursor: 'pointer' }}>竄改後 token(payload 內一個 commitment hash/數值欄位已被改動 1 個字元)</summary>
              <textarea readOnly value={tamperedToken} style={{ width: '100%', maxWidth: 640, height: 80, fontFamily: 'monospace', fontSize: 11 }} />
            </details>
          )}
        </>
      )}
    </section>
  );
}
