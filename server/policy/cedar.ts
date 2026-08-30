/**
 * Cedar 授權引擎包裝(幕 3 P1 permit / 幕 4 P2 forbid;cedar-wasm isAuthorized)——
 * 逐 claim 呼叫(impl-spec §2 步驟 9);principal/resource 皆以純資料 entity 表達,
 * Cedar 只判定 mandate 資料欄位(allowed_claims/max_granularity_rank)與三個可信布林,
 * 不碰任何密碼學(CLAUDE.md:後端先驗完簽章/狀態/防重放,才把布林餵給 Cedar)。
 *
 * policies/*.cedar 語意不得修改(CLAUDE.md Codex 審查定案);字串集合成員判斷已在
 * p1.cedar 原文採 .contains(),此處僅負責組出 isAuthorized() 所需的 principal/resource
 * entity 與 context。
 */
import fs from 'node:fs';
import path from 'node:path';
import { isAuthorized } from '@cedar-policy/cedar-wasm/nodejs';
import type { AuthorizationCall, Entities } from '@cedar-policy/cedar-wasm/nodejs';
import { ROOT } from '../db';
import type { ClaimTag } from './claims';
import type { TrustedContext } from '../../shared/types';

const POLICIES_DIR = path.join(ROOT, 'policies');

function readPolicyText(id: 'p1' | 'p2' | 'p3'): string {
  return fs.readFileSync(path.join(POLICIES_DIR, `${id}.cedar`), 'utf-8');
}

const PRINCIPAL_UID = { type: 'Agent', id: 'brand-agent-2' };
const ACTION_UID = { type: 'Action', id: 'DiscloseClaim' };

export interface ClaimAuthzInput {
  claim: string;
  tag: ClaimTag;
  granularityRank: number;
  mandateAllowedClaims: readonly string[];
  mandateMaxGranularityRank: number;
  trustedContext: TrustedContext;
}

export interface ClaimAuthzResult {
  allow: boolean;
  /** 構成該決策之政策 id(如 ['P1']、['P2']);供路由對應理由碼。 */
  matchedPolicies: string[];
}

/** 逐 claim 呼叫 isAuthorized(P1 permit + P2 forbid 同時載入;forbid 優先於 permit 為 Cedar 內建語意)。 */
export function authorizeDiscloseClaim(input: ClaimAuthzInput): ClaimAuthzResult {
  const resourceUid = { type: 'Claim', id: input.claim };
  const entities: Entities = [
    {
      uid: PRINCIPAL_UID,
      attrs: {
        mandate: {
          allowed_claims: [...input.mandateAllowedClaims],
          max_granularity_rank: input.mandateMaxGranularityRank,
        },
      },
      parents: [],
    },
    {
      uid: resourceUid,
      attrs: {
        claim: input.claim,
        tag: input.tag,
        granularity_rank: input.granularityRank,
      },
      parents: [],
    },
  ];

  const call: AuthorizationCall = {
    principal: PRINCIPAL_UID,
    action: ACTION_UID,
    resource: resourceUid,
    context: {
      mandate_status_ok: input.trustedContext.mandate_status_ok,
      delegate_key_ok: input.trustedContext.delegate_key_ok,
      replay_ok: input.trustedContext.replay_ok,
    },
    policies: { staticPolicies: { P1: readPolicyText('p1'), P2: readPolicyText('p2') } },
    entities,
  };

  const answer = isAuthorized(call);
  if (answer.type === 'failure') {
    throw new Error(`cedar-wasm isAuthorized 失敗:${JSON.stringify(answer.errors)}`);
  }
  return { allow: answer.response.decision === 'allow', matchedPolicies: answer.response.diagnostics.reason };
}

const P3_PRINCIPAL_UID = { type: 'Agent', id: 'fab-agent-1' };
const P3_ACTION_UID = { type: 'Action', id: 'EmitReleaseCredential' };
const P3_RESOURCE_UID = { type: 'ReleaseCredential', id: 'release' };

/** P3 之後端算好可信布林 + mandate 資料欄位(幕 5 放行管線;Phase 3 接上實際 P3 pipeline 時共用本檔)。 */
export interface P3AuthzContext {
  mandate_status_ok: boolean;
  identity_ok: boolean;
  /** v3.1:染整廠 LEI ∈ 布廠 ccs_scope_cert.associated_subcontractors 且 SC 有效、sc_no 一致。 */
  subcontractor_listed: boolean;
  /** 整數 gCO2e/kg(= pcf_aggregate.pcf_total × 1000;Cedar 不支援浮點——Codex 審查定案)。 */
  carbon_total_g: number;
  invoice_ok: boolean;
  wallet_risk: number;
  risk_sources_confirming: number;
  amount: number;
}

export interface P3AuthzInput {
  /** mandate 資料欄位(整數 g;9.5 kgCO2e/kg → 9500)。 */
  carbonMaxG: number;
  maxAmount: number;
  context: P3AuthzContext;
}

/**
 * P3 EmitReleaseCredential 之 isAuthorized 呼叫(幕 5 放行管線;Cedar 只消費布林與 mandate
 * 資料欄位,不直接讀 SC/mandate 狀態)。principal 之 mandate 屬性對應 policies/p3.cedar 之
 * principal.mandate.carbon_max_g / max_amount。
 */
export function authorizeEmitReleaseCredential(input: P3AuthzInput): ClaimAuthzResult {
  const entities: Entities = [
    {
      uid: P3_PRINCIPAL_UID,
      attrs: { mandate: { carbon_max_g: input.carbonMaxG, max_amount: input.maxAmount } },
      parents: [],
    },
    { uid: P3_RESOURCE_UID, attrs: {}, parents: [] },
  ];

  const call: AuthorizationCall = {
    principal: P3_PRINCIPAL_UID,
    action: P3_ACTION_UID,
    resource: P3_RESOURCE_UID,
    context: { ...input.context },
    policies: { staticPolicies: { P3: readPolicyText('p3') } },
    entities,
  };

  const answer = isAuthorized(call);
  if (answer.type === 'failure') {
    throw new Error(`cedar-wasm isAuthorized(P3)失敗:${JSON.stringify(answer.errors)}`);
  }
  return { allow: answer.response.decision === 'allow', matchedPolicies: answer.response.diagnostics.reason };
}
