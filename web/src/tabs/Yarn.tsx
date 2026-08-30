import { useState } from 'react';
import type { DeepLinkCaseId, Manifest } from '../App';
import { LeiBadge } from './badge';
import { CredCard } from '../components/CredCard';

type CaseId = 'A' | 'B';

/** deep-link `case` 只支援 A/B 時才採用,C/Cp(幕 5 輔線案件)在本分頁一律 fallback 'A'。 */
function clampCaseId(value: DeepLinkCaseId | null | undefined): CaseId {
  return value === 'A' || value === 'B' ? value : 'A';
}

interface IssueResponse {
  id: string;
  case_id?: CaseId;
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

/**
 * Tab 1 · 越南紗廠簽發端主控台(幕 1,v3.1 兩張卡;spec §4.2a/§4.2b)。
 * 卡 1:CB(Lowland Certification)簽發之 tc_rcs(Transaction Certificate)——TC 本身沒有碳數據。
 * 卡 2:紗廠簽發之 pcf_upstream——公開層 tc_ref 綁定卡 1(hash 指紋),碳只有紗廠有帳單能證明。
 */
export function Yarn({
  manifest,
  initialCase,
  onCaseChange,
}: {
  manifest: Manifest | null;
  /** deep-link(?tab=yarn&case=…)帶入之初始案件;僅掛載時採用一次,之後由分頁內選單接手。 */
  initialCase?: DeepLinkCaseId | null;
  /** 使用者於本分頁切換案件時回呼(App 層據此更新網址列)。 */
  onCaseChange?: (caseId: DeepLinkCaseId) => void;
}) {
  const [caseId, setCaseId] = useState<CaseId>(() => clampCaseId(initialCase));

  function handleCaseChange(next: CaseId) {
    setCaseId(next);
    onCaseChange?.(next);
  }

  const [tcIssuance, setTcIssuance] = useState<IssueResponse | null>(null);
  const [tcBusy, setTcBusy] = useState(false);
  const [tcError, setTcError] = useState<string | null>(null);

  const [issuance, setIssuance] = useState<IssueResponse | null>(null);
  const [verifyResult, setVerifyResult] = useState<VerifyResponse | null>(null);
  const [tamperedToken, setTamperedToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleLoadTc() {
    setTcBusy(true);
    setTcError(null);
    try {
      const r = await fetch('/api/issue/tc', { method: 'POST' });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error ?? '載入 TC 失敗');
      setTcIssuance(data as IssueResponse);
    } catch (e) {
      setTcError(e instanceof Error ? e.message : String(e));
    } finally {
      setTcBusy(false);
    }
  }

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
        幕 1(v3.1)兩張卡:卡 1 是認證機構(Lowland Certification)簽發的 Transaction Certificate;卡 2 是紗廠以 sandbox LE AID
        鑰簽發的 pcf_upstream(SD-JWT VC)——一個簽章、N 張可撕欄位。
      </p>

      <h3>卡 1 · Transaction Certificate — 認證機構簽發</h3>
      <p style={{ color: '#888', fontSize: 13 }}>
        Textile Exchange TC 欄位(camelCase,ASR-104);TC 由賣方(紗廠)的認證機構簽發,<strong>本身沒有碳數據</strong>——碳在卡 2。
      </p>
      <button onClick={handleLoadTc} disabled={tcBusy}>
        {tcBusy ? '載入中…' : '載入 CB 簽發的 TC'}
      </button>
      {tcError && <p style={{ color: 'crimson' }}>{tcError}</p>}
      {tcIssuance && (
        <>
          {tcIssuance.reused && <p style={{ color: '#1a5fb4', fontWeight: 600 }}>ℹ️ 已簽發——載入既有 tc_rcs(CB 於 seed 時已簽發過)</p>}
          <CredCard variant="tc_rcs" claims={tcIssuance.claims} sdJwt={tcIssuance.sd_jwt} />
        </>
      )}

      <h3 style={{ marginTop: 32 }}>卡 2 · 碳足跡憑證 — 紗廠簽發</h3>
      <p style={{ color: '#888', fontSize: 13 }}>
        pcf_* 為我方延伸;公開層 <code>tc_ref</code> 以 hash 指紋鏈結卡 1 之 TC——
        <em>TC 是認證機構開的但沒有碳;碳只有紗廠有帳單能證明,我們把兩條信任鏈綁在一起。</em>
      </p>
      <p style={{ fontSize: 12, color: '#666' }}>
        三色:🟢 tc_ref / 產品代碼 / 產地 · 🟡 pcf_total / pcf_period / 稽核層(pcf_direct、pcf_indirect 等) · 🔴 單價 / 帳單 / 回收粒供應商名
      </p>

      <label style={{ marginRight: 12 }}>
        案件:
        <select value={caseId} onChange={(e) => handleCaseChange(e.target.value as CaseId)} disabled={busy} style={{ marginLeft: 6 }}>
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
          <CredCard variant="pcf_upstream" claims={issuance.claims} sdJwt={issuance.sd_jwt} />
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
