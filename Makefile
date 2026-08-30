# carbon-cred-demo — 統一 npm 與 make(不使用 pnpm)
.PHONY: setup dev demo-reset test presign seed revoke tamper untamper verify-chain

setup: ## 乾淨環境一鍵:venv + pip + npm i + presign + workload 鑰 + seed
	python3 -m venv .venv
	.venv/bin/pip install -q blake3 cryptography
	npm install
	bash scripts/presign-vlei.sh
	npx tsx scripts/seed.ts

presign:
	bash scripts/presign-vlei.sh

seed:
	npx tsx scripts/seed.ts

dev: ## fastify(:3000)+ vite(:5173)並行
	@sh -c 'npx tsx watch server/index.ts & S=$$!; npx vite; kill $$S 2>/dev/null || true'

demo-reset: ## 還原 DB 與 status 檔到 seed 狀態(錄影 SOP 第一步)
	npx tsx scripts/seed.ts

test:
	npx tsx scripts/test.ts

revoke: ## 幕 6:make revoke LIST=credentials|mandates IDX=<n>——翻 bit 並以 FAB LE 鑰重簽該清單 JWT
	npx tsx scripts/revoke.ts --list $(LIST) --idx $(IDX)

tamper: ## 幕 6:make tamper N=<seq>——先備份 db,竄改 audit_chain 第 N 筆 payload_json
	npx tsx scripts/tamper.ts --n $(N)

untamper: ## 幕 6:還原 make tamper 建立的 db 備份
	npx tsx scripts/untamper.ts

verify-chain: ## 幕 4/6:逐列重驗稽核鏈雜湊 + 簽章(竄改示範對照組)
	npx tsx scripts/verify-chain.ts
