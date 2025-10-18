# otto.py - Minimal OTTO encryption (raw-key mode) for strings & streaming files.
from __future__ import annotations
import os, struct
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

MAGIC = b"OTTO1"
ALGO_ID = 0xA1
KDF_PASSWORD = 0x01
KDF_RAW = 0x02
KDF_X25519 = 0x03
FLAG_CHUNKED = 0x01

def _be16(x:int)->bytes: return struct.pack(">H", x)
def _be32(x:int)->bytes: return struct.pack(">I", x)
def _be64(x:int)->bytes: return struct.pack(">Q", x)
def _u32(b:bytes,off:int)->int: return struct.unpack(">I", b[off:off+4])[0]

def hkdf_derive(ikm:bytes, length:int, info:bytes, salt:bytes)->bytes:
    hk = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return hk.derive(ikm)

def chunk_nonce(nonce_key:bytes, counter:int)->bytes:
    info = b"OTTO-CHUNK-NONCE"+_be64(counter)
    return hkdf_derive(nonce_key, 12, info, b"")

@dataclass
class OttoEncResult:
    cipher_and_tag: bytes
    header: bytes

class Otto:
    def __init__(self, chunk_size:int=1<<20):
        self.chunk_size = chunk_size

    def _init_context(self, raw_key:bytes, chunked:bool)->Tuple[bytes, bytes, bytes, bytes]:
        if len(raw_key) != 32:
            raise ValueError("raw_key must be 32 bytes")
        file_salt = os.urandom(16)
        header = bytearray()
        header += MAGIC
        header.append(ALGO_ID)
        header.append(KDF_RAW)
        header.append(FLAG_CHUNKED if chunked else 0x00)
        header.append(0x00)
        var_part = file_salt
        header += _be16(len(var_part))
        header += var_part
        header = bytes(header)
        enc_key   = hkdf_derive(raw_key, 32, b"OTTO-ENC-KEY",  file_salt)
        nonce_key = hkdf_derive(raw_key, 32, b"OTTO-NONCE-KEY", file_salt)
        return header, header, enc_key, nonce_key

    def _init_context_from_header(self, header:bytes, raw_key:bytes)->Tuple[bytes, bytes, bytes, bytes]:
        if len(header) < 11: raise ValueError("header too short")
        if header[:5] != MAGIC: raise ValueError("bad magic")
        if header[5] != ALGO_ID: raise ValueError("algo mismatch")
        kdf_id = header[6]
        if kdf_id != KDF_RAW: raise ValueError("expected RAW key mode header")
        hlen = struct.unpack(">H", header[9:11])[0]
        if len(header) < 11+hlen: raise ValueError("truncated header")
        var_part = header[11:11+hlen]
        file_salt = var_part[:16]
        enc_key   = hkdf_derive(raw_key, 32, b"OTTO-ENC-KEY",  file_salt)
        nonce_key = hkdf_derive(raw_key, 32, b"OTTO-NONCE-KEY", file_salt)
        full_header = header[:11+hlen]
        return full_header, full_header, enc_key, nonce_key

    def encrypt_string(self, plaintext:bytes, raw_key:bytes)->OttoEncResult:
        header, aad, enc_key, nonce_key = self._init_context(raw_key, chunked=False)
        nonce = chunk_nonce(nonce_key, 0)
        aes = AESGCM(enc_key)
        ct_and_tag = aes.encrypt(nonce, plaintext, aad)
        return OttoEncResult(ct_and_tag, header)

    def decrypt_string(self, cipher_and_tag:bytes, header:bytes, raw_key:bytes)->bytes:
        header, aad, enc_key, nonce_key = self._init_context_from_header(header, raw_key)
        nonce = chunk_nonce(nonce_key, 0)
        aes = AESGCM(enc_key)
        pt = aes.decrypt(nonce, cipher_and_tag, aad)
        return pt

    def encrypt_file(self, in_path:str, out_path:str, raw_key:bytes):
        header, aad, enc_key, nonce_key = self._init_context(raw_key, chunked=True)
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            fout.write(header)
            counter = 0
            aes = AESGCM(enc_key)
            while True:
                chunk = fin.read(self.chunk_size)
                if not chunk: break
                nonce = chunk_nonce(nonce_key, counter)
                ct_tag = aes.encrypt(nonce, chunk, aad)
                ct, tag = ct_tag[:-16], ct_tag[-16:]
                fout.write(_be32(len(ct)))
                fout.write(ct)
                fout.write(tag)
                counter += 1

    def decrypt_file(self, in_path:str, out_path:str, raw_key:bytes):
        with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
            fixed = fin.read(11)
            if len(fixed) != 11: raise ValueError("bad header")
            hlen = struct.unpack(">H", fixed[9:11])[0]
            var_part = fin.read(hlen)
            if len(var_part) != hlen: raise ValueError("truncated header")
            header = fixed + var_part
            header, aad, enc_key, nonce_key = self._init_context_from_header(header, raw_key)
            aes = AESGCM(enc_key)
            counter = 0
            while True:
                len_bytes = fin.read(4)
                if not len_bytes: break
                if len(len_bytes) < 4: raise ValueError("truncated chunk length")
                clen = _u32(len_bytes, 0)
                if clen <= 0: break
                cipher = fin.read(clen)
                if len(cipher) < clen: raise ValueError("truncated cipher")
                tag = fin.read(16)
                if len(tag) < 16: raise ValueError("missing tag")
                nonce = chunk_nonce(nonce_key, counter)
                pt = aes.decrypt(nonce, cipher+tag, aad)
                fout.write(pt)
                counter += 1
