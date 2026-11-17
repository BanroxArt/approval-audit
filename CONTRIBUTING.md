# Contributing

Useful contributions:

- A drain technique the decoder misses, with a primary source (an on-chain postmortem, a research report, the EIP) and a synthetic typed-data or calldata sample.
- Tokens whose approval events or reads are non-standard, with the contract source.

Code changes:

- `ruff check .`, `ruff format --check .`, `python scripts/check.py`, `mypy` and `pytest -q` must pass.
- Tests run offline against `tests/chain.py`. Use made-up addresses (repeated hex bytes) except for well-known public contracts the code itself checks for, such as Permit2.
- Never commit a private key, a seed phrase or a real victim's address.
