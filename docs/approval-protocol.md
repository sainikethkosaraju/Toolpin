# Approval protocol
1. Agent calls a tool; policy returns `require_approval`.
2. (Modern client, MCP 2026-07-28) Toolpin returns `InputRequiredResult` with an elicitation asking the human to confirm and `request_state` = `b64(payload).b64(HMAC-SHA256(secret, "toolpin-approval-v1." + payload))`, payload = `{principal, tool, sha256(canonical args), nonce, exp}`. (The SDK additionally seals `requestState` with its own AEAD; Toolpin's HMAC does not rely on that.)
3. The client retries the same call with `input_responses` and the echoed `request_state`.
4. Toolpin recomputes the argument hash, verifies signature, expiry, principal and tool, checks the human answered `accept`, and consumes the nonce (single use). A *declined* answer also spends the token. Only then is the call forwarded.
5. Legacy clients (no MRTR): denied by default, or `no_mrtr: out_of_band`: the call fails with a reference; an operator runs `toolpin approve-call REF`; the identical retry succeeds once (one-shot, bound to principal+tool+args hash).

A forged `confirm=true` has nothing to attach to: without a valid token it only earns a new challenge.
