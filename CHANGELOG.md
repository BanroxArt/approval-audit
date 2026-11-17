# Changelog

## 0.1.0 (2026-11-16)

- `scan`: live ERC-20, ERC-721, setApprovalForAll and Permit2 approvals for an address, current state through eth_call, findings and revoke calldata. Range splitting when a node refuses, `--tokens` for nodes that need an address, record and replay of RPC answers.
- `typed`: decoding of EIP-2612, DAI and Permit2 typed data (single, batch, transfer, witness) with the EIP-712 digest.
- `call`: decoding of approve, increaseAllowance, setApprovalForAll, permit and Permit2 approve calldata.
- Read-only RPC client that refuses any method outside a fixed read list.
