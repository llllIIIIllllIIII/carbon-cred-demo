/**
 * invoice — DYE 染整廠簽發之發票 VC(幕 5 P3 ④ invoice_ok 核對對象;spec v3.1 §4.6)。
 * 全部公開層(非 SD)——發票內容不做選擇性揭露,不跨組織查驗(不進 M1/M2 allowed_claims、
 * 不經 /api/disclose),只供 FAB 內部 P3 管線核對;因此不掛 Token Status List(spec §4.6
 * 未定義撤銷位,status_idx/status_uri 於 credentials 表留 NULL)。
 *
 * amount/quantity_kg/currency/rail 讀 seed.transaction.dyeing_service,不寫死;
 * payee_wallet(合成帳戶識別碼)依全案件(A/B/C/Cp)讀 seed.cases[case].payee_wallet——
 * C/Cp 與 A 之染整輸入相同,差異只在此收款帳戶(供幕 5 風險雙來源測項)。
 * payer_lei/payee_lei 為延伸欄位(比照 tc_rcs.seller_lei/buyer_lei 之「延伸,對映 LEI」
 * 慣例),簽發時自 manifest 取,供 P3 payee ∈ mandate.allowed_counterparties 核對。
 */
import fs from 'node:fs';
import path from 'node:path';
import type Database from 'better-sqlite3';
import type { DisclosureFrame } from '@sd-jwt/core';
import type { SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc';
import { ROOT } from '../db';
import { loadSandboxKey } from '../keys';
import { buildIssuerInstance } from './issuer';
import { verifyCompactSdJwt } from './verifier';
import { readManifest, resolvePublicKeyFromManifest } from '../manifest';
import { getCredential, type CredentialRow } from './store';
import { CODES, type ReasonCode } from '../../shared/codes';

export const INVOICE_VCT = 'https://carbon-cred-demo.local/vct/invoice';

/** 幕 5 案件鍵——A/B 為主線(染整熱源差異),C/Cp 為風險雙來源輔線(碳排同 A,收款帳戶不同)。 */
export type AgentCaseId = 'A' | 'B' | 'C' | 'Cp';

export interface InvoicePayload {
  vct: string;
  iss: string;
  iat: number;
  invoice_no: string;
  amount: number;
  currency: string;
  quantity_kg: number;
  payee_wallet: string;
  payer_lei: string;
  payee_lei: string;
  issued_at: string;
}

interface DyeingServiceSeed {
  quantity_kg: number;
  amount: number;
  currency: string;
  payer: string;
  payee: string;
  rail: string;
}

interface SeedData {
  transaction: { dyeing_service: DyeingServiceSeed };
  dyeing_defaults: { issued_at: string; pcf_period: string };
  cases: Record<string, { payee_wallet: string }>;
}

function readSeed(): SeedData {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8'));
}

export interface InvoiceIssuance {
  id: string;
  caseId: AgentCaseId;
  sdJwt: string;
  payload: InvoicePayload;
  issuedAt: string;
  issuerParty: 'dye';
  holderParty: 'fab';
}

/** 簽出 invoice(DYE sandbox LE AID 鑰;payee_wallet 依案件讀 seed.cases[case])。純函式,不落庫。 */
export async function issueInvoice(caseId: AgentCaseId): Promise<InvoiceIssuance> {
  const seed = readSeed();
  const svc = seed.transaction.dyeing_service;
  const caseData = seed.cases[caseId];
  if (!caseData?.payee_wallet) throw new Error(`seed.cases 缺 ${caseId}.payee_wallet(invoice 收款帳戶)`);
  const manifest = readManifest();
  if (!manifest?.fab?.lei || !manifest?.dye?.lei) {
    throw new Error('manifest 缺 fab/dye 角色(先跑 make setup)——invoice payer_lei/payee_lei 需要之');
  }
  const key = loadSandboxKey('dye');
  const issuedAtSec = Math.floor(new Date(`${seed.dyeing_defaults.issued_at}T00:00:00Z`).getTime() / 1000);

  const payload: InvoicePayload = {
    vct: INVOICE_VCT,
    iss: key.kid,
    iat: issuedAtSec,
    invoice_no: `INV-${seed.dyeing_defaults.pcf_period}-DYE-${caseId}`,
    amount: svc.amount,
    currency: svc.currency,
    quantity_kg: svc.quantity_kg,
    payee_wallet: caseData.payee_wallet,
    payer_lei: manifest.fab.lei,
    payee_lei: manifest.dye.lei,
    issued_at: seed.dyeing_defaults.issued_at,
  };

  // 全部公開層(非 SD)——發票不做選擇性揭露(不跨組織查驗)。
  const disclosureFrame = { _sd: [] } as unknown as DisclosureFrame<SdJwtVcPayload>;
  const instance = buildIssuerInstance(key);
  const sdJwt = await instance.issue(payload as unknown as SdJwtVcPayload, disclosureFrame, { header: { kid: key.kid } });

  return {
    id: `invoice-${caseId}`,
    caseId,
    sdJwt,
    payload,
    issuedAt: seed.dyeing_defaults.issued_at,
    issuerParty: 'dye',
    holderParty: 'fab',
  };
}

/**
 * 冪等取得(必要時先簽發並入庫)invoice——比照 tcRcs.ts ensureTcRcs()/ccsScopeCert.ts
 * ensureCcsScopeCert() 之原子 get-or-create 模式;invoice 不掛 Token Status List,
 * 故不經 server/creds/store.ts 之 insertCredentialIfAbsent(該函式要求 statusIdx/statusUri
 * 為必填數值),改在本檔以相同的 INSERT OR IGNORE + 重讀落庫勝者手法直接操作 credentials 表。
 */
export async function ensureInvoice(db: Database.Database, caseId: AgentCaseId): Promise<{ row: CredentialRow; reused: boolean }> {
  const id = `invoice-${caseId}`;
  const existing = getCredential(db, id);
  if (existing) return { row: existing, reused: true };

  const issuance = await issueInvoice(caseId);
  const info = db
    .prepare(
      `INSERT OR IGNORE INTO credentials
         (id, type, case_id, issuer_party, holder_party, sd_jwt, payload_json, status_idx, status_uri, issued_at, valid_from, valid_until)
       VALUES
         (@id, 'invoice', @case_id, @issuer_party, @holder_party, @sd_jwt, @payload_json, NULL, NULL, @issued_at, @issued_at, @issued_at)`,
    )
    .run({
      id: issuance.id,
      case_id: caseId,
      issuer_party: issuance.issuerParty,
      holder_party: issuance.holderParty,
      sd_jwt: issuance.sdJwt,
      payload_json: JSON.stringify(issuance.payload),
      issued_at: issuance.issuedAt,
    });
  const row = getCredential(db, id);
  if (!row) throw new Error(`原子插入後讀不到該筆 invoice(id=${id})——不應發生`);
  return { row, reused: info.changes === 0 };
}

export interface VerifyInvoiceResult {
  ok: boolean;
  payload?: InvoicePayload;
  reasonCode?: ReasonCode;
  error?: string;
}

/**
 * 驗 invoice:簽章(manifest 公鑰)+ 釘住簽發者角色 dye(manifest 內任一角色都能簽出「驗章
 * 通過」的 token 不夠,實際驗章鑰 header.kid 必須等於 manifest.dye.aid)+ 型別綁定(payload.vct
 * 必須等於 INVOICE_VCT 且 payload.iss 必須等於實際驗章鑰,不符即 INVOICE_INVALID——比照
 * ccsScopeCert.ts verifyScopeCert() 之角色/型別雙釘住模式)。不驗 Token Status List(spec 未定義)。
 */
export async function verifyInvoice(sdJwt: string): Promise<VerifyInvoiceResult> {
  const manifest = readManifest();
  if (!manifest) return { ok: false, reasonCode: CODES.INVOICE_INVALID, error: 'manifest 尚未產生(先跑 make setup)' };

  const verifyResult = await verifyCompactSdJwt(sdJwt, resolvePublicKeyFromManifest(manifest));
  if (!verifyResult.ok || !verifyResult.payload) {
    return { ok: false, reasonCode: CODES.INVOICE_INVALID, error: verifyResult.error ?? 'invoice 簽章驗證失敗' };
  }
  if (verifyResult.kid !== manifest.dye.aid) {
    return {
      ok: false,
      reasonCode: CODES.INVOICE_INVALID,
      error: `invoice 簽發者(kid=${verifyResult.kid ?? '(無)'})不是唯一被授權角色 dye(AID=${manifest.dye.aid})`,
    };
  }
  const untypedPayload = verifyResult.payload as unknown as { vct?: string; iss?: string };
  if (untypedPayload.vct !== INVOICE_VCT || untypedPayload.iss !== verifyResult.kid) {
    return {
      ok: false,
      reasonCode: CODES.INVOICE_INVALID,
      error: `型別不符:vct=${untypedPayload.vct ?? '(無)'}(期望 ${INVOICE_VCT})或 iss≠實際驗章鑰`,
    };
  }
  return { ok: true, payload: verifyResult.payload as unknown as InvoicePayload };
}
