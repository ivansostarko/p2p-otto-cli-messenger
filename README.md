# OTTO P2P Chat (CLI)

A simple **peer‑to‑peer direct chat** over TCP where **all text and files** are encrypted with the **OTTO algorithm**.

- Handshake: **X25519 ephemeral** exchange to derive a **32‑byte session key** (HKDF, label: `OTTO-P2P-SESSION`).  
- Data encryption: OTTO **raw‑key mode** (session key) with **AES‑256‑GCM**, header bound as AAD, **deterministic HKDF nonces**.
- Files: streamed to a temporary `.otto` container on the sender, transmitted, then decrypted on the receiver.

## Install

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run

On one machine (host):
```bash
python chat.py
# choose: host, pick a port (default 5000)
```

On the other machine (client):
```bash
python chat.py
# choose: connect, enter host IP and port
```

## Usage

- First screen: enter **nickname** and then **host/connect**.
- After the secure session is established, type text messages or:
  - `/file <path>` to send any file (photo, pdf, mp3/mp4, etc.).
  - `/quit` to exit.

Received files are saved under your **Downloads** folder.

## Security notes

- The session key is derived from the X25519 shared secret using **HKDF(SHA‑256)** with both ephemeral public keys as salt (order‑independent).
- Message/file encryption uses OTTO **raw‑key mode** (header format compatible with the OTTO spec). Each object carries its own `file_salt`, ensuring fresh keys per object while keeping the same session key.
- Nonces are derived per chunk via HKDF with the `"OTTO-CHUNK-NONCE"||counter64be` label, preventing GCM nonce reuse.
- This is a minimal demo; add identity authentication (e.g., Ed25519 signatures over the handshake) if you need to verify who is on the other end.

MIT © 2025 Ivan Sostarko
