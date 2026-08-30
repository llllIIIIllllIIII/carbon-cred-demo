// P2 絕對禁止:機密標籤欄位(不論 mandate 寫什麼;forbid 優先於 permit 為 Cedar 內建語意)
// confidential = plant_total_output, capacity_utilization, other_customers,
//                brand_allocation_share, utility_invoice_ref, monthly_utility_commitments,
//                chemical_inventory, fuel_contract, boiler_model, ppa_price, recycler_name, unit_price
forbid (
  principal,
  action == Action::"DiscloseClaim",
  resource
)
when {
  resource.tag == "confidential"
};
