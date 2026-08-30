/**
 * tc_rcs — 認證機構(CB)簽發之 Transaction Certificate SD-JWT VC(幕 1;架構決策 §4:
 * POST /api/issue/tc)。spec v3.1 §4.2a(Yulia 審查修正,CCS-102 V3.1 E2.1):TC 由賣方
 * (紗廠)的認證機構簽發,本身沒有碳數據——碳在 pcf_upstream(見 ./pcfUpstream.ts,以
 * tc_ref 綁定本憑證)。欄位用 Textile Exchange 官方 camelCase 鍵名原樣(ASR-104);
 * 不宣稱 TE 認證,只做欄位對照。seller_lei/buyer_lei 於簽發時自 manifest 取,不寫死。
 * A/B 兩案同一張(id 固定為 tc_rcs;idx 依 seed.status_list_idx.credentials.tc_rcs)。
 * 由 scripts/seed.ts 於灌案件前呼叫一次;server/creds/pcfAggregate.ts ensureInputs()
 * 亦透過本檔之 ensureTcRcs() 冪等取得同一筆入庫紀錄。
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import type Database from 'better-sqlite3';
import type { DisclosureFrame } from '@sd-jwt/core';
import type { SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc';
import { ROOT } from '../db';
import { loadSandboxKey } from '../keys';
import { buildIssuerInstance } from './issuer';
import { statusListUri } from '../statuslist';
import { readManifest } from '../manifest';
import { getCredential, insertCredentialIfAbsent, type CredentialRow } from './store';
import { TC_RCS_BRAND_SD_FIELDS, type TcRcsPayload } from '../../shared/types';

export const TC_RCS_VCT = 'https://carbon-cred-demo.local/vct/tc_rcs';

/** id 固定(A/B 兩案同一張 TC)。 */
export const TC_RCS_ID = 'tc_rcs';

interface TcRcsSeedData {
  issued_at: string;
  valid_from: string;
  valid_until: string;
  tcNo: string;
  inputTcNo: string;
  tcStandard: string;
  tcProductStandardLabelGrade: string;
  tcProductCategoryCode: string;
  tcProductDetailCode: string;
  tcProductRawMaterialCode: string;
  tcProductRawMaterialPercentage: number;
  tcProductCertifiedWeight: number;
  tcCertifiedRawMaterialCountryOrArea: string;
  sellerTeId: string;
  buyerTeId: string;
  tcShipmentDate: string;
  tcShipmentNo: string;
  tcProductLastProcessorName: string;
  tcProductLastProcessorCountry: string;
  volume_reconciled: boolean;
  confidential: { tcShipmentInvoiceReferences: string };
}

interface SeedData {
  tc_rcs: TcRcsSeedData;
  status_list_idx: { credentials: Record<string, number> };
}

function readSeed(): SeedData {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8'));
}

function sha256HexOfJson(value: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

export interface TcRcsIssuance {
  id: string;
  caseId: null;
  sdJwt: string;
  payload: TcRcsPayload;
  issuedAt: string;
  validFrom: string;
  validUntil: string;
  issuerParty: 'cb';
  holderParty: 'fab';
  statusIdx: number;
  statusUri: string;
}

/** 簽出 tc_rcs(CB sandbox LE AID 鑰;seller_lei/buyer_lei 自 manifest 取,不寫死)。純函式,不落庫。 */
export async function issueTcRcs(): Promise<TcRcsIssuance> {
  const seed = readSeed();
  const d = seed.tc_rcs;
  const key = loadSandboxKey('cb');
  const manifest = readManifest();
  if (!manifest?.yarn?.lei || !manifest?.fab?.lei) {
    throw new Error('manifest 缺 yarn/fab 角色(先跑 make setup)——tc_rcs 的 seller_lei/buyer_lei 需要兩者 LEI');
  }

  const statusIdx = seed.status_list_idx.credentials[TC_RCS_ID];
  if (typeof statusIdx !== 'number') throw new Error(`seed.status_list_idx.credentials 缺 ${TC_RCS_ID}`);
  const statusUri = statusListUri('credentials');

  const issuedAtSec = Math.floor(new Date(`${d.issued_at}T00:00:00Z`).getTime() / 1000);
  const validFromSec = Math.floor(new Date(`${d.valid_from}T00:00:00Z`).getTime() / 1000);
  const validUntilSec = Math.floor(new Date(`${d.valid_until}T00:00:00Z`).getTime() / 1000);

  const payload: TcRcsPayload = {
    vct: TC_RCS_VCT,
    iss: key.kid,
    iat: issuedAtSec,
    nbf: validFromSec,
    exp: validUntilSec,
    status: { status_list: { idx: statusIdx, uri: statusUri } },
    tcNo: d.tcNo,
    tcStandard: d.tcStandard,
    tcProductStandardLabelGrade: d.tcProductStandardLabelGrade,
    tcProductCategoryCode: d.tcProductCategoryCode,
    tcProductDetailCode: d.tcProductDetailCode,
    tcCertifiedRawMaterialCountryOrArea: d.tcCertifiedRawMaterialCountryOrArea,
    sellerTeId: d.sellerTeId,
    buyerTeId: d.buyerTeId,
    seller_lei: manifest.yarn.lei,
    buyer_lei: manifest.fab.lei,
    volume_reconciled: d.volume_reconciled,
    tcShipmentInvoiceReferences_hash: sha256HexOfJson(d.confidential.tcShipmentInvoiceReferences),
    tcProductRawMaterialCode: d.tcProductRawMaterialCode,
    tcProductRawMaterialPercentage: d.tcProductRawMaterialPercentage,
    tcProductCertifiedWeight: d.tcProductCertifiedWeight,
    tcShipmentDate: d.tcShipmentDate,
    tcShipmentNo: d.tcShipmentNo,
    inputTcNo: d.inputTcNo,
    tcProductLastProcessorName: d.tcProductLastProcessorName,
    tcProductLastProcessorCountry: d.tcProductLastProcessorCountry,
  };

  // 型別限制註記同 pcfUpstream.ts:_sd 為固定欄位名稱字串,執行期原樣傳入 pack()。
  const disclosureFrame = {
    _sd: [...TC_RCS_BRAND_SD_FIELDS],
  } as unknown as DisclosureFrame<SdJwtVcPayload>;

  const instance = buildIssuerInstance(key);
  const sdJwt = await instance.issue(payload as unknown as SdJwtVcPayload, disclosureFrame, { header: { kid: key.kid } });

  return {
    id: TC_RCS_ID,
    caseId: null,
    sdJwt,
    payload,
    issuedAt: d.issued_at,
    validFrom: d.valid_from,
    validUntil: d.valid_until,
    issuerParty: 'cb',
    holderParty: 'fab',
    statusIdx,
    statusUri,
  };
}

/**
 * 冪等取得(必要時先簽發並入庫)tc_rcs——與 server/creds/pcfAggregate.ts 既有的
 * ensureInput() 相同模式(先讀,未入庫才簽,insertCredentialIfAbsent 原子防併發競態)。
 * 供 scripts/seed.ts(灌案件前)、server/routes/issue.ts(POST /api/issue/tc)、
 * server/creds/pcfAggregate.ts ensureInputs() 共用同一入口,避免各自重複實作。
 */
export async function ensureTcRcs(db: Database.Database): Promise<{ row: CredentialRow; reused: boolean }> {
  const existing = getCredential(db, TC_RCS_ID);
  if (existing) return { row: existing, reused: true };

  const issuance = await issueTcRcs();
  return insertCredentialIfAbsent(db, {
    id: issuance.id,
    type: 'tc_rcs',
    caseId: issuance.caseId,
    issuerParty: issuance.issuerParty,
    holderParty: issuance.holderParty,
    sdJwt: issuance.sdJwt,
    payload: issuance.payload,
    statusIdx: issuance.statusIdx,
    statusUri: issuance.statusUri,
    issuedAt: issuance.issuedAt,
    validFrom: issuance.validFrom,
    validUntil: issuance.validUntil,
  });
}
