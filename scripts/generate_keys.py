"""
Generate RS256 key pair for secured-mode JWT signing.

Output: secrets/private.pem + secrets/public.pem
Usage:  python scripts/generate_keys.py
"""
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rs256_keypair(key_size: int = 2048, output_dir: str = "secrets") -> None:
    Path(output_dir).mkdir(exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path = Path(output_dir) / "private.pem"
    public_path = Path(output_dir) / "public.pem"

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    os.chmod(private_path, 0o600)

    print(f"[+] RS256 {key_size}-bit key pair generated:")
    print(f"    Private key: {private_path}")
    print(f"    Public key:  {public_path}")
    print()
    print("Add to .env.secured:")
    print(f"    JWT_PRIVATE_KEY_PATH={private_path}")
    print(f"    JWT_PUBLIC_KEY_PATH={public_path}")
    print()
    print("[!] secrets/ is in .gitignore — never commit private keys.")


if __name__ == "__main__":
    generate_rs256_keypair()
