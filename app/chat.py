# chat.py - P2P direct chat over TCP with OTTO-encrypted messages and files.
from __future__ import annotations
import base64, os, socket, struct, threading, json, sys, tempfile, pathlib
from typing import Tuple

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from nacl.public import PrivateKey
from nacl.bindings import crypto_scalarmult

from otto import Otto

FRAME_MAGIC = b"P2P0"
F_HANDSHAKE   = 0x01
F_TEXT        = 0x02
F_FILE_META   = 0x03
F_FILE_BYTES  = 0x04

def read_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return bytes(buf)

def send_frame(sock: socket.socket, ftype: int, payload: bytes):
    hdr = FRAME_MAGIC + bytes([ftype]) + struct.pack(">Q", len(payload))
    sock.sendall(hdr + payload)

def recv_frame(sock: socket.socket) -> Tuple[int, bytes]:
    hdr = read_exact(sock, 4+1+8)
    if hdr[:4] != FRAME_MAGIC:
        raise ValueError("bad frame magic")
    ftype = hdr[4]
    length = struct.unpack(">Q", hdr[5:13])[0]
    payload = read_exact(sock, length)
    return ftype, payload

def hkdf(ikm: bytes, length: int, info: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, info=info, salt=salt).derive(ikm)

class Session:
    def __init__(self, nickname:str):
        self.nickname = nickname
        self.priv = PrivateKey.generate()
        self.pub = bytes(self.priv.public_key)
        self.peer_nick = None
        self.peer_pub = None
        self.session_key = None
        self.otto = Otto()

    def derive_after_peer(self, peer_pub: bytes):
        self.peer_pub = peer_pub
        shared = crypto_scalarmult(bytes(self.priv), peer_pub)
        s = b"".join(sorted([self.pub, self.peer_pub]))
        self.session_key = hkdf(shared, 32, b"OTTO-P2P-SESSION", s)

def run_host(nickname:str, listen_port:int):
    print(f"[i] Hosting on 0.0.0.0:{listen_port} ...")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", listen_port))
    srv.listen(1)
    conn, addr = srv.accept()
    print(f"[+] Connected from {addr[0]}:{addr[1]}")
    sess = Session(nickname)
    ftype, payload = recv_frame(conn)
    assert ftype == F_HANDSHAKE
    hp = json.loads(payload.decode("utf-8"))
    sess.peer_nick = hp["nickname"]
    peer_pub = base64.b64decode(hp["pub_b64"])
    sess.derive_after_peer(peer_pub)
    send_frame(conn, F_HANDSHAKE, json.dumps({
        "nickname": nickname,
        "pub_b64": base64.b64encode(sess.pub).decode("ascii")
    }).encode("utf-8"))
    print(f"[i] Handshake OK with {sess.peer_nick}. Secure session established.")
    chat_loop(conn, sess)

def run_client(nickname:str, host:str, port:int):
    print(f"[i] Connecting to {host}:{port} ...")
    conn = socket.create_connection((host, port))
    sess = Session(nickname)
    send_frame(conn, F_HANDSHAKE, json.dumps({
        "nickname": nickname,
        "pub_b64": base64.b64encode(sess.pub).decode("ascii")
    }).encode("utf-8"))
    ftype, payload = recv_frame(conn)
    assert ftype == F_HANDSHAKE
    hp = json.loads(payload.decode("utf-8"))
    sess.peer_nick = hp["nickname"]
    peer_pub = base64.b64decode(hp["pub_b64"])
    sess.derive_after_peer(peer_pub)
    print(f"[i] Handshake OK with {sess.peer_nick}. Secure session established.")
    chat_loop(conn, sess)

def reader_thread(sock: socket.socket, sess: Session, download_dir: str):
    while True:
        try:
            ftype, payload = recv_frame(sock)
        except Exception as e:
            print(f"\n[!] Connection closed: {e}")
            os._exit(0)
        if ftype == F_TEXT:
            obj = json.loads(payload.decode("utf-8"))
            header = base64.b64decode(obj["header_b64"])
            cipher = base64.b64decode(obj["cipher_b64"])
            pt = sess.otto.decrypt_string(cipher, header, sess.session_key)
            msg = pt.decode("utf-8", errors="replace")
            print(f"\n<{sess.peer_nick}> {msg}")
            print("> ", end="", flush=True)
        elif ftype == F_FILE_META:
            meta = json.loads(payload.decode("utf-8"))
            fname = meta["filename"]
            size = int(meta["otto_size"])
            print(f"\n[i] Receiving file '{fname}' ({size} bytes encrypted) ...")
            ftype2, data = recv_frame(sock)
            if ftype2 != F_FILE_BYTES or len(data) != size:
                print("[!] Bad file frame"); continue
            tmp_otto = os.path.join(download_dir, fname + ".otto")
            with open(tmp_otto, "wb") as f:
                f.write(data)
            out_path = os.path.join(download_dir, fname)
            try:
                sess.otto.decrypt_file(tmp_otto, out_path, sess.session_key)
                print(f"[+] File saved: {out_path}")
            except Exception as e:
                print(f"[!] Decrypt error: {e}")
            finally:
                try: os.remove(tmp_otto)
                except: pass
            print("> ", end="", flush=True)
        else:
            print(f"\n[?] Unknown frame type {ftype}")
            print("> ", end="", flush=True)

def chat_loop(conn: socket.socket, sess: Session):
    downloads = os.path.join(str(pathlib.Path.home()), "Downloads")
    os.makedirs(downloads, exist_ok=True)
    rt = threading.Thread(target=reader_thread, args=(conn, sess, downloads), daemon=True)
    rt.start()

    print("\nCommands:")
    print("  /file <path>     send a file")
    print("  /quit            exit")
    print("Type your message and press Enter.\n")
    while True:
        try:
            msg = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[i] Bye"); os._exit(0)
        if not msg: continue
        if msg.startswith("/quit"):
            os._exit(0)
        if msg.startswith("/file "):
            path = msg[6:].strip().strip('"')
            if not os.path.isfile(path):
                print("[!] File not found"); continue
            fname = os.path.basename(path)
            with tempfile.TemporaryDirectory() as td:
                tmp_out = os.path.join(td, fname + ".otto")
                try:
                    sess.otto.encrypt_file(path, tmp_out, sess.session_key)
                    data = open(tmp_out, "rb").read()
                except Exception as e:
                    print(f"[!] Encrypt error: {e}"); continue
            meta = json.dumps({"filename": fname, "otto_size": len(data)}).encode("utf-8")
            send_frame(conn, F_FILE_META, meta)
            send_frame(conn, F_FILE_BYTES, data)
            print(f"[i] Sent file '{fname}' ({len(data)} bytes encrypted)"); continue
        enc = sess.otto.encrypt_string(msg.encode("utf-8"), sess.session_key)
        obj = {
            "nickname": sess.nickname,
            "header_b64": base64.b64encode(enc.header).decode("ascii"),
            "cipher_b64": base64.b64encode(enc.cipher_and_tag).decode("ascii"),
        }
        send_frame(conn, F_TEXT, json.dumps(obj).encode("utf-8"))

def main():
    print("=== OTTO P2P Chat ===")
    nickname = input("Enter your nickname: ").strip() or "me"
    mode = input("Mode: [h]ost or [c]onnect? ").strip().lower()
    if mode.startswith("h"):
        port = input("Listen port [5000]: ").strip() or "5000"
        run_host(nickname, int(port))
    else:
        host = input("Peer IP (or host): ").strip()
        if not host:
            print("Peer IP required"); return
        port = input("Peer port [5000]: ").strip() or "5000"
        run_client(nickname, host, int(port))

if __name__ == "__main__":
    main()
