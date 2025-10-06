#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chữ ký số RSA-PSS + SHA-256: Sinh khóa, tính hash, ký hash (Prehashed), xác minh chữ ký.
Yêu cầu: pip install cryptography

Các lệnh ví dụ:
- Sinh khóa:        python src/signature_demo.py gen-keys --out-dir keys --bits 3072
- Tính hash:        python src/signature_demo.py hash DATA.TXT
- Ký hash:          python src/signature_demo.py sign DATA.TXT --private-key keys/private_key.pem
- Xác minh chữ ký:  python src/signature_demo.py verify DATA.TXT --public-key keys/public_key.pem --signature DATA.TXT.sig
"""

import argparse
import base64
import pathlib
import sys
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.backends import default_backend


def write_bytes(path: pathlib.Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def read_bytes(path: pathlib.Path) -> bytes:
    return pathlib.Path(path).read_bytes()


def sha256_bytes(data: bytes) -> Tuple[bytes, str]:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    h = digest.finalize()
    return h, h.hex()


def cmd_gen_keys(args: argparse.Namespace) -> None:
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=args.bits,
        backend=default_backend(),
    )
    public_key = private_key.public_key()

    # Lưu private key (PKCS#8)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # Gợi ý: dùng BestAvailableEncryption(b"passphrase") nếu cần
    )
    write_bytes(out_dir / "private_key.pem", private_pem)

    # Lưu public key (SubjectPublicKeyInfo)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    write_bytes(out_dir / "public_key.pem", public_pem)

    print(f"Đã sinh khóa RSA {args.bits} bit:")
    print(f"- Private key: {out_dir / 'private_key.pem'}")
    print(f"- Public key : {out_dir / 'public_key.pem'}")


def cmd_hash(args: argparse.Namespace) -> None:
    file_path = pathlib.Path(args.file)
    data = read_bytes(file_path)
    h, h_hex = sha256_bytes(data)

    out_hex = file_path.with_suffix(file_path.suffix + ".sha256.txt")
    out_bin = file_path.with_suffix(file_path.suffix + ".sha256.bin")

    write_bytes(out_bin, h)
    out_hex.write_text(h_hex + "\n", encoding="utf-8")

    print(f"SHA-256({file_path.name}) = {h_hex}")
    print(f"- Lưu hash nhị phân: {out_bin}")
    print(f"- Lưu hash hex     : {out_hex}")


def load_private_key(pem_path: pathlib.Path):
    return serialization.load_pem_private_key(
        read_bytes(pem_path),
        password=None,  # Đổi thành password=b"passphrase" nếu private key có password
        backend=default_backend(),
    )


def load_public_key(pem_path: pathlib.Path):
    return serialization.load_pem_public_key(
        read_bytes(pem_path),
        backend=default_backend(),
    )


def cmd_sign(args: argparse.Namespace) -> None:
    file_path = pathlib.Path(args.file)
    priv_path = pathlib.Path(args.private_key)

    data = read_bytes(file_path)
    h, h_hex = sha256_bytes(data)

    private_key = load_private_key(priv_path)

    # Ký CHÍNH hash (Prehashed) với RSA-PSS + SHA-256
    signature = private_key.sign(
        h,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        utils.Prehashed(hashes.SHA256()),
    )

    sig_path = file_path.with_suffix(file_path.suffix + ".sig")
    sig_b64_path = file_path.with_suffix(file_path.suffix + ".sig.b64")

    write_bytes(sig_path, signature)
    sig_b64 = base64.b64encode(signature)
    write_bytes(sig_b64_path, sig_b64)

    # Lưu lại hash để tiện đối chiếu trong báo cáo
    (file_path.with_suffix(file_path.suffix + ".sha256.txt")).write_text(h_hex + "\n", encoding="utf-8")

    print(f"Đã ký hash của {file_path.name}")
    print(f"- Hash (hex): {h_hex}")
    print(f"- Chữ ký     : {sig_path} (nhị phân), {sig_b64_path} (Base64)")


def cmd_verify(args: argparse.Namespace) -> None:
    file_path = pathlib.Path(args.file)
    pub_path = pathlib.Path(args.public_key)
    sig_path = pathlib.Path(args.signature)

    data = read_bytes(file_path)
    signature = read_bytes(sig_path)
    public_key = load_public_key(pub_path)

    # Tính lại hash rồi xác minh chữ ký trên hash (Prehashed)
    h, _ = sha256_bytes(data)

    try:
        public_key.verify(
            signature,
            h,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            utils.Prehashed(hashes.SHA256()),
        )
        print("XÁC MINH: HỢP LỆ (file chưa bị thay đổi, chữ ký đúng).")
        sys.exit(0)
    except Exception as e:
        print("XÁC MINH: KHÔNG HỢP LỆ (file bị thay đổi hoặc chữ ký/khóa sai).")
        # print(f"Chi tiết: {e}")  # bật nếu cần debug
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Demo Chữ ký số RSA-PSS + SHA-256 (ký hash).")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p1 = sub.add_parser("gen-keys", help="Sinh cặp khóa RSA")
    p1.add_argument("--out-dir", default="keys", help="Thư mục lưu khóa (mặc định: keys)")
    p1.add_argument("--bits", type=int, default=3072, help="Độ dài khóa (mặc định: 3072)")
    p1.set_defaults(func=cmd_gen_keys)

    p2 = sub.add_parser("hash", help="Tính SHA-256 cho file")
    p2.add_argument("file", help="Đường dẫn file cần tính hash (ví dụ: DATA.TXT)")
    p2.set_defaults(func=cmd_hash)

    p3 = sub.add_parser("sign", help="Ký chữ ký số trên HASH của file")
    p3.add_argument("file", help="Đường dẫn file cần ký (ví dụ: DATA.TXT)")
    p3.add_argument("--private-key", required=True, help="Đường dẫn private_key.pem")
    p3.set_defaults(func=cmd_sign)

    p4 = sub.add_parser("verify", help="Xác minh chữ ký số")
    p4.add_argument("file", help="Đường dẫn file gốc cần xác minh (ví dụ: DATA.TXT)")
    p4.add_argument("--public-key", required=True, help="Đường dẫn public_key.pem")
    p4.add_argument("--signature", required=True, help="Đường dẫn file chữ ký (.sig)")
    p4.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()