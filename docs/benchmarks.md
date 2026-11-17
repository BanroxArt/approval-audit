# Benchmarks

`python bench/run.py` on a shared 2-vCPU Linux box with CPython 3.13:

- About 275 typed-data decodes per second for a two-token Permit2 batch. Keccak-256 is pure Python here; a decode takes a few milliseconds, which is fine for a person reading one request.
- A scan of 500 approval events on the in-memory chain finishes in milliseconds. Real scans are bound by the node: one `eth_getLogs` per block range plus one `eth_call`, one `eth_getCode` and one `eth_getBlockByNumber` per live approval.
