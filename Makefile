# carbon-cred-demo — 統一 npm 與 make(不使用 pnpm)
.PHONY: setup dev demo-reset test presign seed

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
