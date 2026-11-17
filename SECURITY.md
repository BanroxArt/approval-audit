# Security

Report a vulnerability privately through GitHub's "Report a vulnerability" button on this repository (Security tab). Please do not open a public issue for it.

The package makes JSON-RPC read calls to the URL you give it and reads local files. It holds no keys and cannot sign.

Things worth a private report:

- A signature request or calldata that grants a spender access but decodes as harmless.
- A way to make the RPC client send a method outside its read list.
- A live approval the scanner misses on a standard token.
