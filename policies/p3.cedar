// P3 放行憑證要件(Agent-1)
// sign_transaction 永遠不在任何 agent scope → 由財務主管以其 ECR 金鑰簽署放行
// 單位約定(Codex 審查定案):Cedar 不支援浮點、decimal 擴充無 <=——
// 碳排一律以整數 kgCO2e/t 傳入(mandate 的 2.00 tCO2e/t → carbon_max_kg = 2000)。
permit (
  principal,
  action == Action::"EmitReleaseCredential",
  resource
)
when {
  context.mandate_status_ok &&
  context.identity_ok &&
  context.carbon_total_kg <= principal.mandate.carbon_max_kg &&
  context.invoice_ok &&
  (context.wallet_risk <= 40 || context.risk_sources_confirming < 2) &&
  context.amount <= principal.mandate.max_amount
};
