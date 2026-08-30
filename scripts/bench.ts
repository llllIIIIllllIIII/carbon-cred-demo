/**
 * scripts/bench.ts — Phase 4 brief B-9:實測成本側數字(presign 張數、簽發/驗證耗時、
 * 一輪秒數之量測輔助)。`make bench` 執行。
 *
 * 原則(brief §2/§4):不得杜撰數字——全部由本機真實呼叫既有簽發/驗證程式碼路徑量測;
 * 不新增依賴、不碰 vendor/。量測完以 scripts/seed.ts 歸位,不留污染態,不影響
 * `make demo-reset` SOP。「跑完一輪秒數」請另以 `time make test` 量測(見 README)。
 */
import { performance } from 'node:perf_hooks';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildServer } from '../server/index';
import { ROOT, openDb } from '../server/db';
import { issuePcfUpstream } from '../server/creds/pcfUpstream';
import { verifyCompactSdJwt } from '../server/creds/verifier';
import { readManifest, resolvePublicKeyFromManifest } from '../server/manifest';

const TSX_BIN = path.join(ROOT, 'node_modules', '.bin', 'tsx');

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

function stats(samplesMs: number[]): { avg: number; min: number; max: number; n: number } {
  const avg = samplesMs.reduce((a, b) => a + b, 0) / samplesMs.length;
  return { avg: round2(avg), min: round2(Math.min(...samplesMs)), max: round2(Math.max(...samplesMs)), n: samplesMs.length };
}

function fmt(s: { avg: number; min: number; max: number; n: number }): string {
  return `avg ${s.avg}ms · min ${s.min}ms · max ${s.max}ms(n=${s.n})`;
}

function runSeed(label: string): void {
  const r = spawnSync(TSX_BIN, ['scripts/seed.ts'], { cwd: ROOT, encoding: 'utf-8' });
  if (r.status !== 0) throw new Error(`${label} 失敗:${r.stdout.slice(-400)}${r.stderr.slice(-400)}`);
}

async function main() {
  console.log('== make bench(Phase 4 B-9 實測)==');
  console.log(`環境:node ${process.version} · ${os.platform()}/${os.arch()} · ${new Date().toISOString()}`);

  // 0) 乾淨狀態起跑,不倚賴呼叫前殘留 db(與 make demo-reset 同一腳本)。
  runSeed('bench 前置 scripts/seed.ts');

  // Codex 審查 P2-2:量測本體(1~4)包進 try/finally——任一步驟(簽發/驗證/聚合/
  // presentation 驗證)拋錯都必須先跑完收尾 reset 才把錯誤往外拋,不得讓 credentials/
  // mandates/audit/status 停在半量測狀態。finally 內的 reset 本身若也失敗,只記警告、
  // 不覆蓋/吞掉原始錯誤(finally 不再向外 throw,交由 main().catch 印出原始錯誤)。
  try {
    // 1) presign 呈現包張數(brief §2:ls data/vlei/*.presentation.json | wc -l,應為 7)。
    const vleiDir = path.join(ROOT, 'data', 'vlei');
    const presignCount = fs.readdirSync(vleiDir).filter((f) => f.endsWith('.presentation.json')).length;
    console.log(`\n[1] presign 呈現包張數:${presignCount}(ls data/vlei/*.presentation.json | wc -l)`);

    // 2) 簽發耗時——issuePcfUpstream(YARN sandbox LE 鑰,真實 SD-JWT + Ed25519 簽章)。
    //    此函式本身不落庫(落庫由呼叫端負責,見 server/creds/pcfUpstream.ts 檔頭註記),
    //    可安全重覆呼叫量測純簽章成本,不受「該案已簽發」冪等快取影響。
    const db = openDb();
    const N_SIGN = 30;
    const signSamples: number[] = [];
    let lastSample: Awaited<ReturnType<typeof issuePcfUpstream>> | undefined;
    for (let i = 0; i < N_SIGN; i++) {
      const t0 = performance.now();
      lastSample = await issuePcfUpstream(db, 'A');
      signSamples.push(performance.now() - t0);
    }
    console.log(`[2] 簽發耗時(issuePcfUpstream × ${N_SIGN};pcf_upstream,SD-JWT 簽章運算,不含 HTTP/DB 落庫):${fmt(stats(signSamples))}`);

    // 3) 單張憑證驗證耗時——verifyCompactSdJwt(單一 SD-JWT 簽章 + 揭露完整性驗證)。
    const manifest = readManifest();
    if (!manifest) throw new Error('manifest 尚未產生(先跑 make setup)');
    if (!lastSample) throw new Error('bench 內部錯誤:未取得 pcf_upstream 樣本');
    const N_VERIFY = 30;
    const verifySamples: number[] = [];
    for (let i = 0; i < N_VERIFY; i++) {
      const t0 = performance.now();
      const r = await verifyCompactSdJwt(lastSample.sdJwt, resolvePublicKeyFromManifest(manifest));
      verifySamples.push(performance.now() - t0);
      if (!r.ok) throw new Error('bench:驗證未通過,無法採信量測值');
    }
    console.log(`[3] 單張憑證驗證耗時(verifyCompactSdJwt × ${N_VERIFY}):${fmt(stats(verifySamples))}`);
    db.close();

    // 4) 跨組織 presentation 驗證耗時——完整幕 1→3 管線(HTTP route 層,同 POST /api/verify),
    //    含 vLEI sandbox 鏈驗證(真跑 child_process,非 mock)。樣本數較少(subprocess 較慢)。
    const app = buildServer();
    try {
      await app.inject({ method: 'POST', url: '/api/issue/tc' });
      await app.inject({ method: 'POST', url: '/api/issue/upstream', payload: { case_id: 'A' } });
      await app.inject({ method: 'POST', url: '/api/issue/dyeing?case=A' });
      const aggRes = await app.inject({ method: 'POST', url: '/api/aggregate', payload: { case_id: 'A' } });
      if (aggRes.statusCode !== 200) throw new Error(`bench:/api/aggregate 失敗(${aggRes.statusCode}):${aggRes.body}`);

      const mandateRes = await app.inject({ method: 'POST', url: '/api/mandates', payload: { mandate: 'M2' } });
      if (mandateRes.statusCode !== 200) throw new Error(`bench:/api/mandates 失敗(${mandateRes.statusCode}):${mandateRes.body}`);
      const mandateData = mandateRes.json() as { mandate_jwt: string; summary: { jti: string; allowed_claims: string[] } };

      const signRes = await app.inject({
        method: 'POST',
        url: '/api/demo/sign-disclose-request',
        payload: { mandate_id: mandateData.summary.jti, case_id: 'A', requested_claims: mandateData.summary.allowed_claims },
      });
      if (signRes.statusCode !== 200) throw new Error(`bench:/api/demo/sign-disclose-request 失敗(${signRes.statusCode}):${signRes.body}`);
      const { request_jws } = signRes.json() as { request_jws: string };

      const discloseRes = await app.inject({ method: 'POST', url: '/api/disclose', payload: { request_jws } });
      if (discloseRes.statusCode !== 200) throw new Error(`bench:/api/disclose 失敗(${discloseRes.statusCode}):${discloseRes.body}`);
      const disclose = discloseRes.json() as { presentation: string; receipt: string };

      const N_PRESENT = 10;
      const presentSamples: number[] = [];
      for (let i = 0; i < N_PRESENT; i++) {
        const t0 = performance.now();
        const r = await app.inject({
          method: 'POST',
          url: '/api/verify',
          payload: { presentation: disclose.presentation, mandate_jwt: mandateData.mandate_jwt, receipt: disclose.receipt },
        });
        presentSamples.push(performance.now() - t0);
        if (!(r.json() as { valid: boolean }).valid) throw new Error('bench:presentation 驗證未通過,無法採信量測值');
      }
      console.log(
        `[4] 跨組織 presentation 驗證耗時(POST /api/verify × ${N_PRESENT};含簽章 + vLEI sandbox 鏈驗證 child_process + Status List):${fmt(stats(presentSamples))}`,
      );
    } finally {
      await app.close();
    }
  } finally {
    // 5) 收尾歸位——不論上面是否拋錯都執行,不留污染態,demo-reset SOP 不受影響。
    try {
      runSeed('bench 收尾 scripts/seed.ts');
      console.log('\n== bench 收尾:已以 scripts/seed.ts 歸位(乾淨 demo 狀態)==');
    } catch (resetError) {
      console.error('bench 收尾 reset 失敗——請手動執行 `make demo-reset`(原始錯誤〔若有〕仍會照常拋出):', resetError);
    }
  }

  console.log('「跑完一輪秒數」另以 `time make test` 量測(見 README B-9 節);上列數字請一併複製進 README,標明機器/node 版本/日期。');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
