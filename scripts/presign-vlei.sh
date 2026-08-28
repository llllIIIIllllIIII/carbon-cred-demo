#!/usr/bin/env bash
# 賽前預簽:GLEIF(root)→ QVI(delegated)→ 4 家法人 LE → 2 張 ECR
# 產出:.vlei/(私鑰,gitignored)+ data/vlei/(公開呈現包 + manifest.json)
# 全案任何程式不得寫死 SAID,一律讀 manifest。
set -euo pipefail
cd "$(dirname "$0")/.."
# .vlei/state.json 含全部 actor 私鑰 seed:以 umask 077 產生,避免共用主機上他人可讀
umask 077

PY=.venv/bin/python
SB=vendor/vlei-sandbox/scripts/vlei_sandbox.py
run() { "$PY" "$SB" "$@"; }
said_of() { sed -n 's/^ *SAID *: *//p' | head -1; }

echo "== [1/6] init sandbox workspace (.vlei/) =="
run init --force
# 既存目錄/檔案不受 umask 影響,明確收緊(dir 700 / state.json 600)
chmod 700 .vlei
chmod 600 .vlei/state.json

echo "== [2/6] LEI(20 碼,ISO 17442-1 檢核碼由 sandbox lei make 產生)=="
LEI_QVI=$(run lei make 984500QVISANDBOX00)
LEI_HUNGGANG=$(run lei make 984500HUNGGANG0001)
LEI_THEPVIET=$(run lei make 984500THEPVIET0001)
LEI_BRUCK=$(run lei make 984500BRUCKDEU0001)
LEI_TWVERIFY=$(run lei make 984500TWVERIFY0001)
echo "  hunggang=$LEI_HUNGGANG thepviet=$LEI_THEPVIET bruck=$LEI_BRUCK taiwanverify=$LEI_TWVERIFY"

echo "== [3/6] actors =="
run actor add --alias gleif --registry gleifRegistry --root
run actor add --alias qvi --registry qviRegistry --delegator gleif
run actor add --alias thepviet --registry thepvietRegistry
run actor add --alias hunggang --registry hunggangRegistry
run actor add --alias bruck --registry bruckRegistry
run actor add --alias taiwanverify --registry taiwanverifyRegistry
# person actor 正確建法(vendor SKILL.md/demo 實測):不掛 registry、不設 delegator
run actor add --alias hunggang-cfo
run actor add --alias bruck-cso

echo "== [4/6] issue(QVI → 4 LE → 2 ECR;ECR 由 LE 以 --auth 直發)=="
QVI_SAID=$(run issue --type qvi --issuer gleif --holder qvi --lei "$LEI_QVI" | said_of)
THEPVIET_SAID=$(run issue --type le --issuer qvi --holder thepviet --lei "$LEI_THEPVIET" --auth "$QVI_SAID" | said_of)
HUNGGANG_SAID=$(run issue --type le --issuer qvi --holder hunggang --lei "$LEI_HUNGGANG" --auth "$QVI_SAID" | said_of)
BRUCK_SAID=$(run issue --type le --issuer qvi --holder bruck --lei "$LEI_BRUCK" --auth "$QVI_SAID" | said_of)
TWVERIFY_SAID=$(run issue --type le --issuer qvi --holder taiwanverify --lei "$LEI_TWVERIFY" --auth "$QVI_SAID" | said_of)
HG_CFO_SAID=$(run issue --type ecr --issuer hunggang --holder hunggang-cfo --lei "$LEI_HUNGGANG" \
  --person "Lin Hsiu-Feng" --context-role "Finance Director" --auth "$HUNGGANG_SAID" | said_of)
BR_CSO_SAID=$(run issue --type ecr --issuer bruck --holder bruck-cso --lei "$LEI_BRUCK" \
  --person "Anna Schäfer" --context-role "Chief Sustainability Officer" --auth "$BRUCK_SAID" | said_of)

echo "== [5/6] present(每張被驗憑證匯出自足呈現包)+ verify fail-fast =="
mkdir -p data/vlei
run present --said "$THEPVIET_SAID" --out data/vlei/thepviet.presentation.json
run present --said "$HUNGGANG_SAID" --out data/vlei/hunggang.presentation.json
run present --said "$BRUCK_SAID" --out data/vlei/bruck.presentation.json
run present --said "$TWVERIFY_SAID" --out data/vlei/taiwanverify.presentation.json
run present --said "$HG_CFO_SAID" --out data/vlei/hunggang_cfo.presentation.json
run present --said "$BR_CSO_SAID" --out data/vlei/bruck_cso.presentation.json
run verify --said "$HG_CFO_SAID" >/dev/null
run verify --said "$BR_CSO_SAID" >/dev/null
echo "  ECR × 2 verify: chain verified"

echo "== [6/6] manifest.json(公開材料:公鑰自 sandbox 匯出)=="
"$PY" - <<'PYEOF'
import json

state = json.load(open('.vlei/state.json', encoding='utf-8'))
roles = {
    'thepviet':     dict(alias='thepviet',     kind='le',  legal_name='Thép Việt Wire Co.'),
    'hunggang':     dict(alias='hunggang',     kind='le',  legal_name='鴻鋼精密扣件股份有限公司'),
    'bruck':        dict(alias='bruck',        kind='le',  legal_name='Bruck & Söhne GmbH'),
    'taiwanverify': dict(alias='taiwanverify', kind='le',  legal_name='台驗國際股份有限公司'),
    'hunggang_cfo': dict(alias='hunggang-cfo', kind='ecr', legal_name='鴻鋼財務主管 Lin Hsiu-Feng'),
    'bruck_cso':    dict(alias='bruck-cso',    kind='ecr', legal_name='Bruck 永續長 Anna Schäfer'),
}
creds = state['credentials']

def find_cred(ctype, holder_alias):
    for said, e in creds.items():
        if e['type'] == ctype and e['holder'] == holder_alias:
            return said, e
    raise SystemExit(f'credential not found: type={ctype} holder={holder_alias}')

manifest = {}
for key, meta in roles.items():
    actor = state['actors'][meta['alias']]
    said, entry = find_cred(meta['kind'], meta['alias'])
    manifest[key] = {
        'alias': meta['alias'],
        'kind': meta['kind'],
        'legal_name': meta['legal_name'],
        'aid': actor['aid'],
        'public_key': actor['verkey'],  # CESR qb64(公開材料;私鑰只存 .vlei/)
        'lei': entry['acdc']['a']['LEI'],
        'credential_said': said,
        'presentation_file': f'data/vlei/{key}.presentation.json',
    }

with open('data/vlei/manifest.json', 'w', encoding='utf-8') as f:
    json.dump(manifest, f, indent=2, ensure_ascii=False)
print('  manifest.json:', ', '.join(manifest))
PYEOF

# data/vlei/ 為公開材料(呈現包 + manifest),放寬回一般可讀(umask 077 會產出 600)
chmod 644 data/vlei/*.json

echo "presign 完成:data/vlei/manifest.json + 6 份呈現包"
