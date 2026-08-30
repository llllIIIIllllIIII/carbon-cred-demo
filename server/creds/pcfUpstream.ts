/**
 * pcf_upstream — YARN 紗廠碳足跡 SD-JWT VC(幕 1 核心;架構決策 §4:POST /api/issue/upstream)。
 * v3.1(Yulia 審查修正):TC 改由 CB 簽發(tc_rcs,見 ./tcRcs.ts);本憑證公開層帶
 * tc_ref = { id, tcNo, issuer_lei, hash } 綁定入庫之 tc_rcs——簽發前必先取得該筆入庫紀錄,
 * 不存在則拒簽(TcRefMissingError → CODES.TC_REF_MISMATCH;紗廠不得自簽 TC 欄位)。
 * 以 data/seed.json 之 upstream_defaults 預填簽發;A/B 兩案紗憑證相同(差異在染整段),
 * 但仍各簽一張(status idx 依 seed.status_list_idx)。issued_at/valid_from/valid_until 直接
 * 取自 seed(回填約三個月前,非簽發當日臨時產生)。
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
import { verifyCompactSdJwt } from './verifier';
import { statusListUri } from '../statuslist';
import { readManifest, resolvePublicKeyFromManifest } from '../manifest';
import { getCredential } from './store';
import { CODES, type ReasonCode } from '../../shared/codes';
import { PCF_UPSTREAM_BRAND_SD_FIELDS, PCF_UPSTREAM_AUDIT_SD_FIELDS, type PcfCaseId, type PcfUpstreamPayload, type TcRef } from '../../shared/types';

export const PCF_UPSTREAM_VCT = 'https://carbon-cred-demo.local/vct/pcf_upstream';

/**
 * 簽發前必先取入庫 tc_rcs 且驗章通過、簽發者確為 cb——不存在/驗章失敗/簽發者不符即拒簽
 * (v3.1;範圍鐵則:紗廠不得自簽 TC 欄位;LOW #5 修法:tc_ref 不得盲信未驗證之入庫紀錄)。
 */
export class TcRefMissingError extends Error {
  reasonCode: ReasonCode = CODES.TC_REF_MISMATCH;
}

interface EmissionFactorTable {
  grid_tw_kg_per_kwh: number;
  grid_vn_kg_per_kwh: number;
  natural_gas_kg_per_mj: number;
  coal_kg_per_mj: number;
  boiler_efficiency: { natural_gas: number; coal: number };
}

interface UpstreamDefaults {
  issued_at: string;
  valid_from: string;
  valid_until: string;
  pcf_period: string;
  product_code: string;
  country_of_origin: string;
  quantity_kg: number;
  pcf_direct: number;
  electricity_kwh_per_kg: number;
  pcf_method: string;
  pcf_factor_source: string;
  confidential: { unit_price: string; energy_invoice: string; recycler_name: string };
}

interface SeedData {
  upstream_defaults: UpstreamDefaults;
  emission_factor_table: EmissionFactorTable;
  status_list_idx: { credentials: Record<string, number> };
}

function readSeed(): SeedData {
  return JSON.parse(fs.readFileSync(path.join(ROOT, 'data', 'seed.json'), 'utf-8'));
}

/** raw string 之 SHA-256 hex——用於 tc_ref.hash = sha256(tc_rcs 之 compact SD-JWT 字串)。 */
function sha256HexOfString(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/** JSON 序列化後之 SHA-256 hex commitment——機密原始資料永不進憑證,只留此雜湊。 */
function sha256HexOfJson(value: unknown): string {
  return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

/** 去除浮點乘加誤差(計算保留 4 位小數即為精確值;顯示 2 位由前端處理)。 */
export function round4(n: number): number {
  return Math.round(n * 10000) / 10000;
}

export interface PcfUpstreamIssuance {
  id: string;
  caseId: PcfCaseId;
  sdJwt: string;
  payload: PcfUpstreamPayload;
  issuedAt: string;
  validFrom: string;
  validUntil: string;
  issuerParty: 'yarn';
  holderParty: 'fab';
  statusIdx: number;
  statusUri: string;
}

/**
 * 簽出 pcf_upstream(YARN sandbox LE AID 鑰;A/B 內容相同、idx 依 seed.status_list_idx)。
 * db 僅用於讀入庫之 tc_rcs(v3.1 tc_ref 綁定;不存在則拒簽)——本函式本身不落庫,落庫由
 * 呼叫端(server/routes/issue.ts、server/creds/pcfAggregate.ts ensureInputs)負責,與既有
 * insertCredentialIfAbsent 併發防護模式一致。
 */
export async function issuePcfUpstream(db: Database.Database, caseId: PcfCaseId): Promise<PcfUpstreamIssuance> {
  const seed = readSeed();
  if (caseId !== 'A' && caseId !== 'B') throw new Error(`未知案件 case_id=${caseId}(pcf_upstream 僅支援 A/B)`);
  const d = seed.upstream_defaults;
  const key = loadSandboxKey('yarn');

  // v3.1:簽發前必先取入庫 tc_rcs(CB 簽發)——不存在即拒簽,紗廠不得自簽 TC 欄位。
  const tcRcsRow = getCredential(db, 'tc_rcs');
  if (!tcRcsRow) {
    throw new TcRefMissingError('入庫查無 tc_rcs——CB 尚未簽發 Transaction Certificate,紗廠不得自簽 TC 欄位(先跑 make setup / seed 流程簽發 tc_rcs)');
  }
  const manifest = readManifest();
  if (!manifest?.cb?.lei) throw new Error('manifest 缺 cb 角色(先跑 make setup)——tc_ref.issuer_lei 需要 CB LEI');

  // LOW #5(與 HIGH #1 連動):tcNo/hash/issuer_lei 必須來自「已驗章且簽發者確為 cb」的 tc_rcs,
  // 不得盲信入庫 payload_json(可能與 sd_jwt 不同步)或無條件假設 issuer_lei=cb。
  const tcRcsVerify = await verifyCompactSdJwt(tcRcsRow.sd_jwt, resolvePublicKeyFromManifest(manifest));
  if (!tcRcsVerify.ok || !tcRcsVerify.payload) {
    throw new TcRefMissingError(`入庫 tc_rcs 驗章失敗,拒絕簽發 pcf_upstream:${tcRcsVerify.error ?? '未知錯誤'}`);
  }
  if (tcRcsVerify.kid !== manifest.cb.aid) {
    throw new TcRefMissingError(
      `入庫 tc_rcs 簽發者(kid=${tcRcsVerify.kid ?? '(無)'})不是唯一被授權角色 cb(AID=${manifest.cb.aid})——紗廠不得引用非 CB 簽發之 TC`,
    );
  }
  const verifiedTcRcsPayload = tcRcsVerify.payload as unknown as { tcNo: string };
  const tcRef: TcRef = {
    id: 'tc_rcs',
    tcNo: verifiedTcRcsPayload.tcNo,
    issuer_lei: manifest.cb.lei,
    hash: sha256HexOfString(tcRcsRow.sd_jwt),
  };

  const id = `pcf_upstream-${caseId}`;
  const statusIdx = seed.status_list_idx.credentials[id];
  if (typeof statusIdx !== 'number') throw new Error(`seed.status_list_idx.credentials 缺 ${id}`);
  const statusUri = statusListUri('credentials');

  const issuedAtSec = Math.floor(new Date(`${d.issued_at}T00:00:00Z`).getTime() / 1000);
  const validFromSec = Math.floor(new Date(`${d.valid_from}T00:00:00Z`).getTime() / 1000);
  const validUntilSec = Math.floor(new Date(`${d.valid_until}T00:00:00Z`).getTime() / 1000);

  // pcf_indirect = 用電強度 × 越南電網係數;pcf_total = direct + indirect(程式計算,不寫死)。
  const pcfIndirect = round4(d.electricity_kwh_per_kg * seed.emission_factor_table.grid_vn_kg_per_kwh);
  const pcfTotal = round4(d.pcf_direct + pcfIndirect);

  const payload: PcfUpstreamPayload = {
    vct: PCF_UPSTREAM_VCT,
    iss: key.kid,
    iat: issuedAtSec,
    nbf: validFromSec,
    exp: validUntilSec,
    status: { status_list: { idx: statusIdx, uri: statusUri } },
    tc_ref: tcRef,
    product_code: d.product_code,
    country_of_origin: d.country_of_origin,
    unit_price_hash: sha256HexOfJson(d.confidential.unit_price),
    energy_invoice_hash: sha256HexOfJson(d.confidential.energy_invoice),
    recycler_name_hash: sha256HexOfJson(d.confidential.recycler_name),
    emission_factor_table_hash: sha256HexOfJson(seed.emission_factor_table),
    pcf_total: pcfTotal,
    pcf_period: d.pcf_period,
    pcf_method: d.pcf_method,
    quantity_kg: d.quantity_kg,
    pcf_direct: d.pcf_direct,
    pcf_indirect: pcfIndirect,
    electricity_kwh_per_kg: d.electricity_kwh_per_kg,
    pcf_factor_source: d.pcf_factor_source,
  };

  // @sd-jwt/sd-jwt-vc 的 SdJwtVcPayload 帶隱含索引簽章(經 SdJwtPayload = Record<string, unknown>),
  // 導致其 Frame<> 條件型別與具名 payload 型別互斥(套件本身的已知型別限制,純型別層面,
  // 不影響執行期行為)——_sd 陣列內容為固定欄位名稱字串,執行期原樣傳入 pack(),故以型別斷言繞過。
  const disclosureFrame = {
    _sd: [...PCF_UPSTREAM_BRAND_SD_FIELDS, ...PCF_UPSTREAM_AUDIT_SD_FIELDS],
  } as unknown as DisclosureFrame<SdJwtVcPayload>;

  const instance = buildIssuerInstance(key);
  const sdJwt = await instance.issue(payload as unknown as SdJwtVcPayload, disclosureFrame, { header: { kid: key.kid } });

  return {
    id,
    caseId,
    sdJwt,
    payload,
    issuedAt: d.issued_at,
    validFrom: d.valid_from,
    validUntil: d.valid_until,
    issuerParty: 'yarn',
    holderParty: 'fab',
    statusIdx,
    statusUri,
  };
}
