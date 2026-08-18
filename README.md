# EnzoCrypt

**Encrypt any file. Send it anywhere. No cloud required.**

EnzoCrypt is a local file encryption tool built on AES-256-GCM + RSA-2048-OAEP. No accounts, no servers, no internet connection needed. Your files never leave your machine unencrypted.

---

## Features

- **AES-256-GCM** streaming encryption — handles files of any size with configurable chunk sizes (1 MB to 64 MB)
- **RSA-2048-OAEP** key system — encrypt for a recipient using only their public key
- **Two-pass decryption** — full cryptographic verification before writing a single byte
- **Per-chunk authentication** — each chunk is bound to the file header, preventing tampering or reordering
- **Backward compatible** — reads both V1 (single-pass) and V2 (streaming) `.enzocrypt` files
- **No cloud, no telemetry** — entirely local, works offline

## How it works

```
Your file  →  AES-256-GCM (random key)  →  .enzocrypt container
                      ↑
              RSA-2048-OAEP (recipient's public key encrypts the AES key)
```

To decrypt, the recipient uses their private key (password-protected) to recover the AES key, then verifies and decrypts all chunks.

## Requirements

- Python 3.9+
- `tkinter` (included with standard Python on Windows)

## Installation

```bash
git clone https://github.com/Enzopro777/enzocrypt.git
cd enzocrypt
pip install -r requirements.txt
python app1.0.6.py
```

## Usage

1. **Identity tab** — generate your RSA key pair once. Share only the public key.
2. **Encrypt tab** — select a file and the recipient's public key → saves a `.enzocrypt` file.
3. **Decrypt tab** — open a `.enzocrypt` file with your private key and password.

## File format

| Field | Size | Description |
|---|---|---|
| Magic | 4 bytes | `ENZO` |
| Version | 2 bytes | `2` (V2 streaming) |
| Extension length | 1 byte | Length of original extension |
| Extension | variable | Original file extension |
| RSA blob length | 2 bytes | Length of encrypted AES key |
| RSA blob | variable | AES key encrypted with recipient's public key |
| Chunk size | 4 bytes | Chunk size used for this file |
| Chunks | variable | `[length][nonce][tag][ciphertext]` × N |

Each chunk's nonce is unique and its AAD binds it cryptographically to the header and its index, preventing reordering or substitution attacks.

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) for full text.

You are free to use, study, and redistribute this software. Any derivative work must also be released under GPL v3.

## Support the project

EnzoCrypt is developed independently on modest hardware. If this tool is useful to you, consider supporting its development:

[![Ko-fi](https://img.shields.io/badge/Ko--fi-Support-ff5e5b?logo=ko-fi&logoColor=white)](https://ko-fi.com/enzopro777)

🇦🇷 Since I'm based in Argentina, you can also donate directly via **Mercado Pago**: https://link.mercadopago.com.ar/patatascalientes

🪙 **Crypto (USDT TRC20):** `TUZ6xXYoES78JPrUA6ZcBqxpaUoXGRjtXc`

Donations help fund a new development machine and the Microsoft Store release.

---

*Built by [Enzo](https://github.com/Enzopro777) · Rosario, Argentina*