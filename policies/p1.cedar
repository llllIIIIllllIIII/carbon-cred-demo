// ⚠ 硬性關卡優先:Cedar 不做密碼學。後端先完成——
//   mandate 簽章、iss/aud/exp/jti、delegate_kid 對 request 簽章、
//   Token Status List、request_nonce UNIQUE——
//   再以三個可信布林餵入 context。
//   政策只讀布林與 mandate 的資料欄位,絕不直接信任 mandate.status。

// P1 允許:mandate 範圍內的欄位揭露
permit (
  principal,
  action == Action::"DiscloseClaim",
  resource
)
when {
  // 字串集合成員判斷用 .contains();Cedar 的 in 僅限 entity 階層(Codex 審查定案)
  principal.mandate.allowed_claims.contains(resource.claim) &&
  resource.granularity_rank <= principal.mandate.max_granularity_rank &&
  context.mandate_status_ok &&   // 簽章 + iss/aud/exp/jti + Token Status List 皆通過
  context.delegate_key_ok &&     // request 確由 mandate.delegate_kid 簽章
  context.replay_ok              // request_nonce 未重複
};
