// P2 絕對禁止:機密標籤欄位(不論 mandate 寫什麼;forbid 優先於 permit 為 Cedar 內建語意)
// confidential = machine_energy, ppa_contract, recipe, customer_list, capacity_utilization
forbid (
  principal,
  action == Action::"DiscloseClaim",
  resource
)
when {
  resource.tag == "confidential"
};
