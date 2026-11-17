---
name: approval-audit
description: Audit an Ethereum address for risky token approvals (unlimited ERC-20 allowances, NFT setApprovalForAll operators, Permit2 allowances, approvals to plain accounts or flagged spenders) and decode EIP-2612, DAI and Permit2 signature requests or approval calldata before anyone signs. Use when the user asks what a wallet or treasury address has approved, whether a permit or signature request is safe, how a wallet was drained through an approval, or how to revoke one. Uses the approvalaudit package from this repo, read-only. Engineering checklist only, not legal advice.
---

# approval-audit

You help someone see what an address has allowed others to take, or what a signature request would allow. You never sign, send or ask for a private key or seed phrase. If the user offers one, tell them to stop and not share it.

## 1. Get the facts that change the answer

- The address and the chain. For a scan, which RPC URL they can use; free public nodes limit log queries, so ask for their own node or the tokens to check (`--tokens usd-mainnet` covers USDC, USDT, DAI and PYUSD on mainnet).
- For a signature request: the full typed-data JSON exactly as the site sent it, the chain they are on and the address that would sign.
- Any allowlist of spenders they trust and any flagged addresses, with the source for each.

## 2. Run

- `approvalaudit scan <address> [--rpc URL] [--tokens ...] [--from-block N] [--lists file] --record evidence.json`
- `approvalaudit typed request.json --chain <id> --signer <address>`
- `approvalaudit call --to <contract> --data <calldata>`

## 3. Report

- Worst first. For each risky approval: token, spender, amount, when granted, the findings and the revoke calldata.
- For a signature request: who could move what, how much, until when, and the EIP-712 digest so they can compare it with the wallet screen.
- Say plainly that a clean result does not prove a spender is safe, and that anything the tool calls `AA-UNRECOGNIZED` needs a transaction simulation before signing.
- For an investigation, keep the `--record` file: it lets anyone replay the same scan offline.
- End with: engineering checklist, not legal advice.
