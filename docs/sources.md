# Sources

Checked 2026-11-16.

| Topic | Source | What we use |
| --- | --- | --- |
| Approval phishing losses and pattern | [Chainalysis, Targeted approval phishing scams, December 14, 2023](https://www.chainalysis.com/blog/approval-phishing-cryptocurrency-scams-2023/) | About $1.0 billion since May 2021, $374.6 million in 2023 through November, $516.8 million in 2022; the approved spender, not the victim, initiates the drain. |
| Drainer losses, 2024 | [ScamSniffer 2024 report, January 3, 2025](https://drops.scamsniffer.io/scam-sniffer-2024-web3-phishing-attacks-wallet-drainers-drain-494-million/) | $494 million, 332,000 addresses, 30 cases over $1 million; Permit 56.7%, setOwner 31.9%, increaseAllowance 3.5% of large-case losses; the $55 million DAI case was a setOwner signature. |
| Drainer losses, 2025 | [ScamSniffer 2025 report, January 3, 2026](https://drops.scamsniffer.io/scam-sniffer-2025-crypto-phishing-losses-fall-83-to-84-million/) | $83.85 million, 106,106 victims; largest theft $6.5 million via Permit; Permit or Permit2 $8.72 million of large cases; EIP-7702 batch signatures appeared. |
| ERC-20 | [EIP-20](https://eips.ethereum.org/EIPS/eip-20) | `approve`, `allowance`, `transferFrom`, the `Approval` event. |
| ERC-721 | [EIP-721](https://eips.ethereum.org/EIPS/eip-721) | `approve`, `getApproved`, `setApprovalForAll`, `isApprovedForAll`, the indexed token id in `Approval`. |
| Permit | [EIP-2612](https://eips.ethereum.org/EIPS/eip-2612) | The `Permit` typed-data shape. |
| Typed data | [EIP-712](https://eips.ethereum.org/EIPS/eip-712) | Type encoding and hashing; the Mail example is a test vector. |
| Permit2 | [Uniswap Permit2 docs, signature transfer](https://docs.uniswap.org/contracts/permit2/reference/signature-transfer) and [allowance transfer](https://docs.uniswap.org/contracts/permit2/reference/allowance-transfer) | Struct shapes, witness type strings, canonical address. |
| GENIUS Act | [Pub. L. 119-27](https://www.congress.gov/119/plaws/publ27/PLAW-119publ27.htm) | Section 20 effective date; section 4(a)(5)(A)(iv) block, freeze and reject capability; lawful orders must specify coins or accounts with reasonable particularity; no velocity or cooling-off requirement in the text. |
| OCC implementing rule | [OCC final rule, 2026-21706, October 23, 2026](https://www.federalregister.gov/documents/2026/10/23/2026-21706/implementing-the-guiding-and-establishing-national-innovation-for-us-stablecoins-act-for-the) | First primary-regulator final rule; 120 days later falls after January 18, 2027. |
