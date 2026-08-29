/**
 * seed:讀 data/vlei/manifest.json + data/seed.json →
 *   1) 重建 DB(parties / policies / risk_signals / status_lists)
 *   2) 產生兩把 workload 鑰(經 server/keys.ts,冪等)
 *   3) 重簽重寫 data/status/mandates.jwt、credentials.jwt(全 0 = 無撤銷)
 * make demo-reset 重跑本腳本即可還原 seed 狀態(錄影 SOP 第一步)。
 * seed 只有 A/B/C/Cp 四組;E = 撤銷後重跑 A 的狀態轉換,不建 fixture。
 */
import fs from 'node:fs';
import path from 'node:path';
import { ROOT, DB_PATH, openDb } from '../server/db';
import { ensureWorkloadKeys, writePublicVleiState } from '../server/keys';
import {
  buildAndWriteStatusList,
  statusListUri,
  statusListFile,
  STATUS_LIST_NAMES,
  STATUS_LIST_SIZE,
} from '../server/statuslist';
import type { Manifest } from '../shared/types';

const MANIFEST_PATH = path.join(ROOT, 'data', 'vlei', 'manifest.json');
const SEED_PATH = path.join(ROOT, 'data', 'seed.json');

async function main() {
  if (!fs.existsSync(MANIFEST_PATH)) {
    console.error('manifest.json 不存在——先跑 scripts/presign-vlei.sh(make setup)。');
    process.exit(1);
  }
  const manifest: Manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf-8'));
  const seed = JSON.parse(fs.readFileSync(SEED_PATH, 'utf-8'));

  const kids = ensureWorkloadKeys();
  console.log(`workload 鑰:fab-workload kid=${kids['fab-workload'].slice(0, 12)}… / brand-workload kid=${kids['brand-workload'].slice(0, 12)}…`);

  // H3:匯出 .vlei/state.json 的公開子集(去 seed/next_seed)供 Brand 端 sandbox verify 使用,
  // 使驗證端只讀 data/vlei/(CLAUDE.md:25);唯一讀 state.json 的模組仍是 server/keys.ts。
  const publicStateFile = writePublicVleiState();
  console.log(`vLEI 公開狀態(不含私鑰種子):${path.relative(ROOT, publicStateFile)}`);

  // 重建 DB
  for (const suffix of ['', '-wal', '-shm']) {
    const f = DB_PATH + suffix;
    if (fs.existsSync(f)) fs.rmSync(f);
  }
  const db = openDb();

  // parties(6 角色,一律讀 manifest,不寫死 SAID)
  const insParty = db.prepare(
    'INSERT INTO parties (id, kind, alias, legal_name, lei, aid, public_key, credential_said) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  );
  for (const [id, r] of Object.entries(manifest)) {
    insParty.run(id, r.kind, r.alias, r.legal_name, r.lei, r.aid, r.public_key, r.credential_said);
  }

  // policies(Cedar 原文;前端顯示同一份)
  const insPolicy = db.prepare('INSERT INTO policies (id, version, name, cedar_text, active) VALUES (?, ?, ?, ?, 1)');
  const policyNames: Record<string, string> = {
    P1: 'mandate 範圍內的欄位揭露',
    P2: '機密標籤欄位絕對禁止',
    P3: '放行憑證四要件',
  };
  for (const pid of ['P1', 'P2', 'P3']) {
    const text = fs.readFileSync(path.join(ROOT, 'policies', `${pid.toLowerCase()}.cedar`), 'utf-8');
    insPolicy.run(pid, 'pol-2026-08-v2', policyNames[pid], text);
  }

  // risk_signals(收款帳戶識別碼為合成字串)
  const insRisk = db.prepare(
    'INSERT INTO risk_signals (account_ref, case_id, provider, score, labels, observed_at) VALUES (?, ?, ?, ?, ?, ?)',
  );
  for (const r of seed.risk_signals) {
    insRisk.run(r.payee_wallet, r.case_id, r.provider, r.score, JSON.stringify(r.labels), seed.risk_observed_at);
  }

  // Token Status List:全 0(無撤銷)重簽重寫 + 登錄表
  const insList = db.prepare('INSERT INTO status_lists (name, uri, bits, size, file, updated_at) VALUES (?, ?, 1, ?, ?, ?)');
  for (const name of STATUS_LIST_NAMES) {
    await buildAndWriteStatusList(name);
    insList.run(name, statusListUri(name), STATUS_LIST_SIZE, path.relative(ROOT, statusListFile(name)), new Date().toISOString());
  }

  const counts = {
    parties: (db.prepare('SELECT COUNT(*) c FROM parties').get() as { c: number }).c,
    policies: (db.prepare('SELECT COUNT(*) c FROM policies').get() as { c: number }).c,
    risk_signals: (db.prepare('SELECT COUNT(*) c FROM risk_signals').get() as { c: number }).c,
    status_lists: (db.prepare('SELECT COUNT(*) c FROM status_lists').get() as { c: number }).c,
  };
  db.close();
  console.log(
    `seed 完成:parties=${counts.parties} policies=${counts.policies} risk_signals=${counts.risk_signals} status_lists=${counts.status_lists}(案件 A/B/C/Cp 定義存 data/seed.json)`,
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
