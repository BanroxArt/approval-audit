# approval-audit

`approvalaudit` answers two questions about an Ethereum address, without ever signing or sending anything:

1. **What can other people still take from this wallet?** It finds every ERC-20 allowance, ERC-721 token approval, `setApprovalForAll` operator and Permit2 allowance the address has granted, reads the current state from the chain, and flags the dangerous ones: unlimited amounts, spenders that are plain accounts rather than contracts, spenders on your flagged list or missing from your allowlist, approvals that have sat live for months, Permit2 allowances that never expire. For each it prints the calldata that would revoke it.
2. **What does this signature request actually grant?** It decodes the JSON a site passes to `eth_signTypedData_v4` (EIP-2612 `permit`, DAI's `permit`, and Permit2's `PermitSingle`, `PermitBatch`, `PermitTransferFrom`, batch and witness variants) and raw approval calldata, says who could move which tokens, how much and until when, and computes the EIP-712 digest so you can check it is the message your wallet will sign.

Standard library only. Python 3.11+. Read-only by construction: the RPC client refuses every method except `eth_blockNumber`, `eth_call`, `eth_chainId`, `eth_getBlockByNumber`, `eth_getCode` and `eth_getLogs`.

Built and maintained by Art Akopian, CEO of [Banrox](https://banrox.com). Banrox builds consumer credit and fraud-prevention software and publishes the general-purpose pieces.

> **Engineering checklist, not legal advice.** A finding says an approval or a signature request has a risky shape. It does not say the spender is malicious, and a clean report does not say a spender is safe. Tested on synthetic data only: the test suite runs against an in-memory chain and made-up addresses. The live RPC path was exercised once, read-only, against a public node to confirm the round trip works; it has not been validated against real victim wallets.

## Why

The idea that tokenized money is "push-only, like cash, so nobody can pull it from your account" is wrong on public chains. ERC-20 has `approve` and `transferFrom` from the start, EIP-2612 lets an approval be granted with an off-chain signature, and Permit2 adds signature-based allowances and one-shot transfers. Each of these lets a third party pull tokens later, and drainers depend on them.

- Chainalysis estimated about $1.0 billion lost to approval phishing between May 2021 and November 2023, $374.6 million of it in 2023, and described the on-chain pattern: the victim approves a second address, and that approved spender, not the victim, initiates the transfer out ([Chainalysis, December 14, 2023](https://www.chainalysis.com/blog/approval-phishing-cryptocurrency-scams-2023/)).
- ScamSniffer counted $494 million in wallet-drainer losses across 332,000 addresses in 2024; in its 30 cases over $1 million, `Permit` signatures accounted for 56.7% of losses and `increaseAllowance` for 3.5% ([ScamSniffer 2024 report](https://drops.scamsniffer.io/scam-sniffer-2024-web3-phishing-attacks-wallet-drainers-drain-494-million/)).
- In 2025 the total fell to $83.85 million across 106,106 victims, but the largest single theft, $6.5 million in stETH and aEthWBTC in September, was again a `Permit` signature, and Permit or Permit2 signatures made up $8.72 million of the eleven cases over $1 million ([ScamSniffer 2025 report](https://drops.scamsniffer.io/scam-sniffer-2025-crypto-phishing-losses-fall-83-to-84-million/)).

For banks the question is getting closer to home. Payment stablecoins under the GENIUS Act (Pub. L. 119-27) are ERC-20-style tokens on public chains, and the Act takes effect on January 18, 2027 (the earlier of 18 months after enactment or 120 days after the primary regulators' final rules; the OCC's final rule came on October 23, 2026, so the 18-month date governs). A treasury desk, an exchange or a bank that holds customer stablecoins in on-chain addresses inherits every approval those addresses ever granted.

## Install

```sh
pip install git+https://github.com/BanroxArt/approval-audit
```

## Scan an address

```sh
approvalaudit scan 0xYourAddress --rpc https://your-node.example --lists my-lists.json
approvalaudit scan 0xYourAddress --tokens usd-mainnet --from-block 26000000 --record evidence.json
approvalaudit scan 0xYourAddress --fixture evidence.json      # replay offline, same answer
```

```
HIGH   erc20        token 0xc1c1...c1c1
       spender 0xe1e1...e1e1 (example drainer)  amount unlimited  granted 2024-08-18
       high   AA-UNLIMITED: unlimited allowance
       high   AA-SPENDER-FLAGGED: spender 0xe1e1...e1e1 is flagged: example drainer (made-up entry for the examples)
       high   AA-SPENDER-EOA: spender is a plain account, not a contract; legitimate apps rarely ask for that
       revoke: to 0xc1c1...c1c1 data 0x095ea7b3...
```

How it works: `eth_getLogs` for `Approval` and `ApprovalForAll` with the owner as the first indexed topic, and for Permit2's `Approval` and `Permit` events; the latest event per (token, spender, token id); then `allowance`, `getApproved`, `isApprovedForAll` or Permit2's `allowance` through `eth_call` for the current state, because `transferFrom` spends allowances down without emitting `Approval` and Permit2 allowances expire on their own. ERC-20 and ERC-721 `Approval` share a signature; the ERC-721 one has the token id as a fourth topic, which is how they are told apart.

Free public nodes limit `eth_getLogs`. Some refuse a query without a contract address, others refuse archive ranges or anything over a few thousand blocks. The scanner halves the range when a node refuses and tries again, `--tokens` restricts the search to named contracts (`usd-mainnet` is USDC, USDT, DAI and PYUSD on Ethereum mainnet), and for a full history you need your own node or a provider URL. `--record` saves every RPC answer so a scan can be replayed offline as evidence.

Exit codes: 0 nothing above low, 2 medium, 3 high, 1 bad input or RPC failure. The `revoke` line is calldata for you to send from the wallet yourself; this tool has no key and cannot send it.

## Read a signature request before signing

```sh
approvalaudit typed request.json --chain 1 --signer 0xYourAddress --lists my-lists.json
approvalaudit call --to 0xToken --data 0x095ea7b3...
```

```
HIGH   permit2-permitSingle
       chain 1  contract 0x000000000022d473030f116ddee9f6b43ac78ba3
       spender 0xe1e1...e1e1
       token 0xc1c1...c1c1  amount unlimited  allowance expires never
       EIP-712 digest 0x...
       high   AA-NO-EXPIRY: allowance on 0xc1c1...c1c1 never expires
       high   AA-UNLIMITED: unlimited amount of token 0xc1c1...c1c1
```

## Findings

| Code | Severity | Meaning |
| --- | --- | --- |
| `AA-UNLIMITED` | high | Amount is the maximum, or so large it has no practical limit (top bit set: 2^255 for uint256, 2^159 for Permit2's uint160). |
| `AA-APPROVAL-FOR-ALL` | high | An operator may move every NFT in the collection, including ones bought later. |
| `AA-SPENDER-EOA` | high | The spender has no code. Apps spend through contracts; an approval to a plain account matches the drain pattern Chainalysis describes. |
| `AA-SPENDER-FLAGGED` | high | The spender is on your flagged list. The source you gave is shown. |
| `AA-NO-EXPIRY` | high | A permit deadline or Permit2 expiration at the maximum, or a DAI permit with expiry 0. |
| `AA-PERMIT2-IMPOSTOR` | high | A Permit2-shaped message or call whose domain or target is not the Permit2 contract. |
| `AA-CHAIN-MISMATCH` | high | The domain's chain id is not the chain you said you are on. |
| `AA-MALFORMED` | high | The typed data does not hash; a value does not fit its declared type. |
| `AA-SPENDER-UNKNOWN` | medium | You gave an allowlist and the spender is not on it. |
| `AA-STALE` | medium | Live and granted more than `--stale-days` (180) ago. |
| `AA-LONG-EXPIRY` | medium | Deadline or expiration more than `--max-days` (30) away for a request, or more than a year for a live Permit2 allowance. |
| `AA-MULTI-TOKEN` | medium | One signature covers several tokens. |
| `AA-OWNER-MISMATCH` | medium | The message's owner is not the address you said would sign. |
| `AA-UNRECOGNIZED` | medium | Not a permit or approval this tool decodes. Read every field. |
| `AA-STATE-UNKNOWN` | low | The token did not answer the standard read; the row shows the last event. |
| `AA-ALLOWANCE-PERSISTS`, `AA-WITNESS`, `AA-EXPIRED`, `AA-EXPIRATION-ZERO`, `AA-PERMIT2-ROUTER`, `AA-AMBIGUOUS-721`, `AA-INACTIVE` | info | Context. An unlimited approval to Permit2 itself is the normal Permit2 setup and is shown as info; the risk sits in the Permit2 allowances. |

Nothing is bundled in the flagged list. Build it from sources you can cite, such as digital currency addresses on OFAC's SDN list, published incident postmortems or your own cases, and keep the source in the `source` field so it appears in reports. See [examples/lists.json](examples/lists.json) for the format (JSON or CSV).

## What is real and what is not

- **"Tokenized payments are push-only."** Refuted for public-chain tokens, as above. A tokenized deposit on a permissioned bank ledger may be push-only by design; that is a property of that ledger, not of tokens.
- **"Tokens carry a UETR through mint and burn."** We found no standard that does this. ERC-20 `Transfer` events carry sender, receiver and amount only. ISO 20022 UETRs live in bank payment messages.
- **"The GENIUS Act mandates velocity limits or cooling-off periods."** Not in the Act. The text of Pub. L. 119-27 has no velocity or cooling-off requirement. Section 4(a)(5)(A)(iv) does require an issuer to have "technical capabilities, policies, and procedures to block, freeze, and reject specific or impermissible transactions that violate Federal or State laws", and the Act's lawful-order provisions require orders that specify the coins or accounts "with reasonable particularity". That is a freeze capability at the issuer, not a hold on every new receipt.

## Limits

- EVM chains only. Solana and other token programs have different approval models.
- It does not simulate transactions, so an approval hidden inside a multicall, a `setOwner` on a proxy (the mechanism behind the $55 million DAI theft in August 2024 that ScamSniffer reports) or an EIP-7702 delegation is reported as `AA-UNRECOGNIZED` at best. Simulate those with a node before signing.
- Spender labels come only from your lists. The tool does not query block explorers or vendor risk APIs.
- `AA-SPENDER-EOA` reads code at the latest block. Since EIP-7702 an account can carry delegated code; treat such a spender as a contract you have not reviewed.
- A token that misreports `allowance` will be misreported here.

## Development

```sh
pip install -e '.[dev]'
ruff check . && ruff format --check . && python scripts/check.py && mypy && pytest -q
python tests/make_fixture.py     # rebuild the recorded fixture from the in-memory chain
python bench/run.py
```

## License

MIT, copyright 2026 Banrox Inc.
