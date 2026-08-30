// P3 放行憑證要件(Agent-1,付染整費前)
// sign_transaction 永遠不在任何 agent scope → 由財務主管以其 ECR 金鑰簽署放行
// 單位約定(Codex 審查定案):Cedar 不支援浮點、decimal 擴充無 <=——
// 碳排一律以整數 gCO2e/kg 布傳入(mandate 的 9.5 kgCO2e/kg → carbon_max_g = 9500)。
// v3.1:subcontractor_listed 為後端算好的可信布林(染整廠 LEI ∈ 布廠 ccs_scope_cert 之
// associated_subcontractors 且 SC 有效、sc_no 與 pcf_dyeing.ccs_scope_ref 一致)——
// Cedar 不得直接讀 SC 狀態,只消費此布林。
permit (
  principal,
  action == Action::"EmitReleaseCredential",
  resource
)
when {
  context.mandate_status_ok &&
  context.identity_ok &&
  context.subcontractor_listed &&
  context.carbon_total_g <= principal.mandate.carbon_max_g &&
  context.invoice_ok &&
  (context.wallet_risk <= 40 || context.risk_sources_confirming < 2) &&
  context.amount <= principal.mandate.max_amount
};
