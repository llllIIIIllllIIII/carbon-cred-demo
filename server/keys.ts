/**
 * Key loader — 全案唯一取鑰入口(信任邊界原則 1:一方一鑰)。
 *
 * 組織/個人鑰(Plan A):自 `.vlei/state.json` 匯出。
 *   state.json 格式(vendor/vlei-sandbox 實測):
 *     state.actors[alias] = { alias, aid, seed, verkey, ... }
 *     seed   = CESR qb64,code "A"(44 字元)→ 內含 32B Ed25519 seed
 *     verkey = CESR qb64,code "D"(44 字元)→ 內含 32B Ed25519 公鑰
 *   CESR 解碼:base64url("A"×cs + qb64[cs:]) 後去掉前 cs 個 byte(cs=1,code 為數字開頭時 2)。
 *
 * workload 鑰:app 產生,存 `data/keys/<name>.json`(JWK,gitignored)。
 *
 * 除本模組外,任何 route/script 不得直接讀 `.vlei/state.json` 或 `data/keys/`。
 * Plan B(state.json 解析失敗時):以 app 鑰代替 sandbox 鑰 + manifest 綁定聲明——
 * 由呼叫端捕捉 KeyLoaderError 後決定;本 session 實測 Plan A 可行,未啟用 Plan B。
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { ROOT, VLEI_PUBLIC_STATE_DIR } from './db';

const VLEI_STATE = path.join(ROOT, '.vlei', 'state.json');
const KEYS_DIR = path.join(ROOT, 'data', 'keys');

/** 公開狀態檔實體路徑(vendor/vlei-sandbox WORKSPACE=".vlei"、STATE_FILE="state.json",vendor 唯讀)。 */
export const PUBLIC_VLEI_STATE_FILE = path.join(VLEI_PUBLIC_STATE_DIR, '.vlei', 'state.json');

/** actor 內屬於私鑰材料、絕不得離開 .vlei/ 的欄位(H3:公開子集匯出時一律剔除)。 */
const ACTOR_PRIVATE_FIELDS = ['seed', 'next_seed'] as const;

/** 允許取用的 sandbox 角色 → actor alias(presign-vlei.sh 同步維護)。 */
export const SANDBOX_ROLES = {
  yarn: 'yarn', // YARN 紗廠 LE 鑰:幕 1 簽 tc_carbon_upstream
  fab: 'fab', // FAB 布廠 LE 鑰:幕 2 簽 pcf_aggregate;Status List Token 簽章(閘道為清單發布方)
  dye: 'dye', // DYE 染整廠 LE 鑰:簽 pcf_dyeing 與 invoice;幕 6 撤銷主線簽發者
  brand: 'brand', // BRAND 品牌 LE(驗證側身分錨定)
  cb: 'cb', // CB 認證機構 LE 鑰:slcp_dcc 與(選配)查證聲明 VC
  fab_cfo: 'fab-cfo', // FAB 財務主管 ECR 鑰:簽 M1、幕 5 人工放行
  brand_cso: 'brand-cso', // BRAND 永續長 ECR 鑰:簽 M2
} as const;

export type SandboxRole = keyof typeof SANDBOX_ROLES;
export type WorkloadName = 'fab-workload' | 'brand-workload';

export class KeyLoaderError extends Error {}

export interface SigningKey {
  /** kid:sandbox 鑰用 AID;workload 鑰用 JWK thumbprint(RFC 7638)。 */
  kid: string;
  alias: string;
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
  publicJwk: { kty: 'OKP'; crv: 'Ed25519'; x: string };
}

/** CESR qb64 → raw bytes(演算法照 vendor/vlei-sandbox/scripts/cesr.py decode)。 */
export function cesrDecode(qb64: string): Buffer {
  const cs = '01234'.includes(qb64[0]) ? 2 : 1;
  const b64 = 'A'.repeat(cs) + qb64.slice(cs);
  return Buffer.from(b64, 'base64url').subarray(cs);
}

/** raw bytes → CESR qb64。 */
export function cesrEncode(code: string, raw: Buffer): string {
  const ps = (3 - (raw.length % 3)) % 3;
  const b64 = Buffer.concat([Buffer.alloc(ps), raw]).toString('base64url');
  return code + b64.slice(code.length);
}

function keyFromSeed(seed: Buffer, verkey: Buffer): { priv: crypto.KeyObject; pub: crypto.KeyObject; x: string } {
  const jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    d: seed.toString('base64url'),
    x: verkey.toString('base64url'),
  };
  const priv = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  return { priv, pub: crypto.createPublicKey(priv), x: jwk.x };
}

function readState(): Record<string, any> {
  if (!fs.existsSync(VLEI_STATE)) {
    throw new KeyLoaderError(
      `.vlei/state.json 不存在——先跑 make setup(scripts/presign-vlei.sh)。若 presign 已跑仍失敗,啟動全域 Plan B。`,
    );
  }
  try {
    return JSON.parse(fs.readFileSync(VLEI_STATE, 'utf-8'));
  } catch (e) {
    throw new KeyLoaderError(`.vlei/state.json 解析失敗(${e})——啟動全域 Plan B(app 鑰 + 綁定聲明)。`);
  }
}

/** 載入 sandbox 匯出鑰(2 LE + 2 ECR + 台驗/Brand)。 */
export function loadSandboxKey(role: SandboxRole): SigningKey {
  const alias = SANDBOX_ROLES[role];
  const state = readState();
  const actor = state?.actors?.[alias];
  if (!actor?.seed || !actor?.verkey || !actor?.aid) {
    throw new KeyLoaderError(`state.json 內找不到 actor ${alias} 的 seed/verkey/aid——presign 未完成或格式不符(Plan B 判定點)。`);
  }
  const seed = cesrDecode(actor.seed);
  const verkey = cesrDecode(actor.verkey);
  if (seed.length !== 32 || verkey.length !== 32) {
    throw new KeyLoaderError(`actor ${alias} 金鑰長度異常(seed=${seed.length}B, verkey=${verkey.length}B)——Plan B 判定點。`);
  }
  const { priv, pub, x } = keyFromSeed(seed, verkey);
  return { kid: actor.aid, alias, privateKey: priv, publicKey: pub, publicJwk: { kty: 'OKP', crv: 'Ed25519', x } };
}

/**
 * H3 修法:把 `.vlei/state.json` 的**公開子集**匯出到 data/vlei/public-state/.vlei/state.json,
 * 供 Brand 端 sandbox verify(child_process)查驗 vLEI 信任鏈時使用。
 *
 * 為何需要:sandbox `verify` 只吃 workspace 狀態檔,但原始狀態檔含每個 actor 的私鑰種子
 * (seed/next_seed);CLAUDE.md:25 限定 Brand 端只讀 token、manifest 公鑰、data/vlei/、
 * data/status/。本函式剔除 ACTOR_PRIVATE_FIELDS 後另存一份——查驗所需材料(aid/verkey/kel/
 * registries(TEL)/credentials/root_aid)全屬公開材料,驗證強度不變(SAID 重算、簽章驗證、
 * TEL 撤銷狀態一項不少),但 Brand 端從此不再碰 `.vlei/`。
 *
 * 本函式為 `.vlei/state.json` 的唯一讀取點所在模組(一方一鑰鐵則),由 scripts/seed.ts
 * (make setup / make demo-reset 皆會執行)呼叫;回傳寫出的檔案路徑。
 */
export function writePublicVleiState(): string {
  const state = readState();
  const actors: Record<string, unknown> = {};
  for (const [alias, actor] of Object.entries((state.actors ?? {}) as Record<string, Record<string, unknown>>)) {
    const publicActor: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(actor)) {
      if ((ACTOR_PRIVATE_FIELDS as readonly string[]).includes(k)) continue;
      publicActor[k] = v;
    }
    actors[alias] = publicActor;
  }
  const publicState = { ...state, actors };

  const dir = path.dirname(PUBLIC_VLEI_STATE_FILE);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(PUBLIC_VLEI_STATE_FILE, JSON.stringify(publicState, null, 2));
  // presign 以 umask 077 執行,seed 亦可能繼承收緊的 umask;公開材料一律放寬回可讀(比照 data/vlei/*.json)。
  fs.chmodSync(dir, 0o755);
  fs.chmodSync(PUBLIC_VLEI_STATE_FILE, 0o644);
  return PUBLIC_VLEI_STATE_FILE;
}

/** 以 manifest 內的公鑰(CESR qb64 verkey)建立驗章用 KeyObject——驗證方不接觸 state.json。 */
export function publicKeyFromQb64(verkeyQb64: string): crypto.KeyObject {
  const raw = cesrDecode(verkeyQb64);
  if (raw.length !== 32) throw new KeyLoaderError(`verkey 長度異常:${raw.length}B`);
  return crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') }, format: 'jwk' });
}

/** RFC 7638 JWK thumbprint(OKP)。 */
function jwkThumbprint(x: string): string {
  const canonical = JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x });
  return crypto.createHash('sha256').update(canonical).digest('base64url');
}

/** 確保兩把 workload 鑰存在(app 產生;冪等)。回傳兩把鑰的 kid。 */
export function ensureWorkloadKeys(): Record<WorkloadName, string> {
  fs.mkdirSync(KEYS_DIR, { recursive: true });
  const kids = {} as Record<WorkloadName, string>;
  for (const name of ['fab-workload', 'brand-workload'] as WorkloadName[]) {
    const file = path.join(KEYS_DIR, `${name}.json`);
    if (!fs.existsSync(file)) {
      const { privateKey } = crypto.generateKeyPairSync('ed25519');
      const jwk = privateKey.export({ format: 'jwk' }) as { x: string; d: string };
      const kid = jwkThumbprint(jwk.x);
      fs.writeFileSync(file, JSON.stringify({ kty: 'OKP', crv: 'Ed25519', kid, x: jwk.x, d: jwk.d }, null, 2), { mode: 0o600 });
    }
    kids[name] = (JSON.parse(fs.readFileSync(file, 'utf-8')) as { kid: string }).kid;
  }
  return kids;
}

/** 載入 workload 鑰(不存在則先產生)。 */
export function loadWorkloadKey(name: WorkloadName): SigningKey {
  ensureWorkloadKeys();
  const jwk = JSON.parse(fs.readFileSync(path.join(KEYS_DIR, `${name}.json`), 'utf-8'));
  const priv = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  return {
    kid: jwk.kid,
    alias: name,
    privateKey: priv,
    publicKey: crypto.createPublicKey(priv),
    publicJwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x },
  };
}

/**
 * 幕 3 disclose 閘道用:依 request_jws header.kid 找出是哪一把 workload 鑰(僅兩把,逐一比對)。
 * 找不到回傳 undefined——呼叫端據此判定 kid 既非 mandate.delegate_kid 綁定之鑰,亦非任何已知
 * workload 鑰,一律以 DELEGATE_KEY_MISMATCH 處理,不另外分類。
 */
export function resolveWorkloadPublicKeyByKid(kid: string): crypto.KeyObject | undefined {
  for (const name of ['fab-workload', 'brand-workload'] as WorkloadName[]) {
    const key = loadWorkloadKey(name);
    if (key.kid === kid) return key.publicKey;
  }
  return undefined;
}
