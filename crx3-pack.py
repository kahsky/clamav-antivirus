#!/usr/bin/env python3
"""
Empaquetage CRX3 (format Chrome) sans Chrome : crx3-pack.py <dossier-extension> <clé RSA privée .pem> <sortie.crx>
En-tête : "Cr24", version 3, longueur, CrxFileHeader (protobuf : AsymmetricKeyProof sha256_with_rsa = 2,
signed_header_data = 10000 contenant SignedData.crx_id = 1), puis l'archive ZIP. Signature RSA PKCS#1 v1.5 SHA-256 sur
"CRX3 SignedData\\0" + longueur (uint32 LE) + signed_header_data + ZIP. L'identifiant Chrome = sha256(clé publique DER)
[:16 octets] en lettres a–p. Imprime l'identifiant.
(c) 2026 Dukiwi SA - Estavayer-le-Lac
"""

import hashlib
import io
import os
import struct
import sys
import zipfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def field_bytes(number, data):
    return varint((number << 3) | 2) + varint(len(data)) + data


def zip_dir(folder):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(folder):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(root, name)
                z.write(full, os.path.relpath(full, folder))
    return buf.getvalue()


def main():
    folder, key_path, out = sys.argv[1:4]
    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    pub_der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    crx_id = hashlib.sha256(pub_der).digest()[:16]
    signed_data = field_bytes(1, crx_id)                     # SignedData { crx_id = 1 }
    payload = zip_dir(folder)
    to_sign = b"CRX3 SignedData\x00" + struct.pack("<I", len(signed_data)) + signed_data + payload
    signature = key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
    proof = field_bytes(1, pub_der) + field_bytes(2, signature)   # AsymmetricKeyProof { public_key = 1, signature = 2 }
    header = field_bytes(2, proof) + field_bytes(10000, signed_data)
    with open(out, "wb") as f:
        f.write(b"Cr24" + struct.pack("<II", 3, len(header)) + header + payload)
    print("".join(chr(ord("a") + c) for c in bytes.fromhex(crx_id.hex()) for c in [c >> 4, c & 15]))


if __name__ == "__main__":
    main()
