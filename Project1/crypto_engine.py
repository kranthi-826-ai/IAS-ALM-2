"""
AegisCrypt :: Cryptographic Primitives Engine
Implements Asymmetric Cryptography (RSA-OAEP, RSA-PSS, X.509 PKI),
Diffie-Hellman Key Exchange Arithmetic, and Elgamal Digital Signatures with SHA-512.
"""

import base64
import datetime
import hashlib
import random
from typing import Tuple, Dict, Any, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class AsymmetricEngine:
    """Manages RSA-2048 keypair operations, OAEP ciphers, PSS signatures, and X.509 PKI certificates."""

    @staticmethod
    def generate_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey, str, str]:
        """Generates an RSA keypair and exports both keys in PEM format."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        public_key = private_key.public_key()

        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        return private_key, public_key, priv_pem, pub_pem

    @staticmethod
    def issue_x509_certificate(
        private_key: rsa.RSAPrivateKey,
        public_key: rsa.RSAPublicKey,
        subject_name: str,
        ca_authority: str = "AegisOps Root Certificate Authority"
    ) -> str:
        """Issues an X.509 certificate binding identity to the public key."""
        distinguished_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Telangana"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Hyderabad"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca_authority),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ])

        valid_from = datetime.datetime.now(datetime.timezone.utc)
        valid_until = valid_from + datetime.timedelta(days=365)

        cert = (
            x509.CertificateBuilder()
            .subject_name(distinguished_name)
            .issuer_name(distinguished_name)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(valid_from)
            .not_valid_after(valid_until)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(private_key, hashes.SHA256())
        )

        return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    @staticmethod
    def encrypt_oaep(pub_pem: str, plaintext: str) -> Dict[str, Any]:
        """Performs RSA-OAEP encryption with SHA-256 digest and MGF1."""
        public_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
        cipher_bytes = public_key.encrypt(
            plaintext.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {
            "ciphertext_base64": base64.b64encode(cipher_bytes).decode("utf-8"),
            "ciphertext_hex": cipher_bytes.hex(),
            "byte_length": len(cipher_bytes),
            "algorithm": "RSA-OAEP-SHA256",
            "security_profile": "Optimal Asymmetric Encryption Padding (Prevents Coppersmith/Bleichenbacher attacks)"
        }

    @staticmethod
    def decrypt_oaep(priv_pem: str, ciphertext_base64: str) -> Dict[str, Any]:
        """Performs RSA-OAEP decryption with SHA-256 digest and MGF1."""
        private_key = serialization.load_pem_private_key(priv_pem.encode("utf-8"), password=None)
        raw_cipher = base64.b64decode(ciphertext_base64)
        decrypted_bytes = private_key.decrypt(
            raw_cipher,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {
            "plaintext": decrypted_bytes.decode("utf-8"),
            "algorithm": "RSA-OAEP-SHA256",
            "status": "DECRYPTED_SUCCESSFULLY"
        }

    @staticmethod
    def sign_pss(priv_pem: str, message: str) -> Dict[str, Any]:
        """Generates digital signature via RSA-PSS (Probabilistic Signature Scheme) with SHA-256."""
        private_key = serialization.load_pem_private_key(priv_pem.encode("utf-8"), password=None)
        signature = private_key.sign(
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {
            "signature_base64": base64.b64encode(signature).decode("utf-8"),
            "signature_hex": signature.hex(),
            "message": message,
            "algorithm": "RSA-PSS-SHA256",
            "standard": "PKCS #1 v2.1 (PSS with randomized salt)"
        }

    @staticmethod
    def verify_pss(pub_pem: str, message: str, signature_b64: str) -> Dict[str, Any]:
        """Verifies RSA-PSS digital signature against the message digest."""
        try:
            public_key = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
            signature_bytes = base64.b64decode(signature_b64)
            public_key.verify(
                signature_bytes,
                message.encode("utf-8"),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return {
                "is_valid": True,
                "status": "VALID",
                "message": "Signature verified authentic. Origin authenticity and data integrity guaranteed."
            }
        except Exception as err:
            return {
                "is_valid": False,
                "status": "INVALID",
                "error": f"Verification failed: {str(err)}"
            }


class DiffieHellmanProtocol:
    """Simulates multi-step Diffie-Hellman Key Agreement over insecure channels."""

    PROFILES = {
        "small": {"p": 353, "g": 3, "description": "Educational Small Prime"},
        "medium": {"p": 7919, "g": 7, "description": "13-bit Prime"},
        "rfc3526": {
            "p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF,
            "g": 2,
            "description": "RFC 3526 MODP 1536-bit Group"
        }
    }

    @classmethod
    def initialize_parameters(cls, profile: str = "small", custom_p: Optional[int] = None, custom_g: Optional[int] = None) -> Dict[str, Any]:
        if profile == "custom" and custom_p and custom_g:
            p, g = int(custom_p), int(custom_g)
        elif profile in cls.PROFILES:
            p = cls.PROFILES[profile]["p"]
            g = cls.PROFILES[profile]["g"]
        else:
            p, g = 353, 3

        upper_bound = min(p - 2, 200) if p > 1000 else p - 2
        alice_priv = random.randint(2, max(3, upper_bound))
        bob_priv = random.randint(2, max(3, upper_bound))

        return {
            "p": str(p),
            "g": str(g),
            "alice_private_suggested": alice_priv,
            "bob_private_suggested": bob_priv
        }

    @staticmethod
    def execute_exchange_step(step: int, p: int, g: int, a: int, b: int) -> Dict[str, Any]:
        if step == 1:
            return {
                "step": 1,
                "title": "Private Secret Generation",
                "alice": {"private_key": a, "note": f"Alice chooses private exponent a = {a}"},
                "bob": {"private_key": b, "note": f"Bob chooses private exponent b = {b}"},
                "public_params": {"p": p, "g": g},
                "description": "Each party selects a private secret scalar that is never revealed to anyone."
            }

        A = pow(g, a, p)
        B = pow(g, b, p)

        if step == 2:
            return {
                "step": 2,
                "title": "Public Key Computation",
                "alice": {
                    "private_key": a,
                    "public_key": A,
                    "formula": f"A = {g}^{a} mod {p} = {A}"
                },
                "bob": {
                    "private_key": b,
                    "public_key": B,
                    "formula": f"B = {g}^{b} mod {p} = {B}"
                },
                "description": "Both parties evaluate modular exponentiation to produce public keys."
            }

        if step == 3:
            return {
                "step": 3,
                "title": "Public Keys Exchanged Across Untrusted Network",
                "channel_transmission": {
                    "alice_to_bob": f"Alice transmits Public Key A = {A} across network",
                    "bob_to_alice": f"Bob transmits Public Key B = {B} across network",
                    "eavesdropper_sees": {"prime_p": p, "generator_g": g, "alice_pub_A": A, "bob_pub_B": B},
                    "eavesdropper_does_not_see": [f"Alice's secret '{a}'", f"Bob's secret '{b}'"]
                },
                "description": "Even if Eve captures A, B, p, and g, computing a from A requires solving the Discrete Logarithm Problem (DLP)."
            }

        # Step 4: Shared Secret
        alice_s = pow(B, a, p)
        bob_s = pow(A, b, p)
        matches = (alice_s == bob_s)

        return {
            "step": 4,
            "title": "Shared Symmetric Secret Derivation",
            "alice_computation": {
                "formula": f"s = B^a mod p = ({B})^{a} mod {p}",
                "shared_secret": alice_s
            },
            "bob_computation": {
                "formula": f"s = A^b mod p = ({A})^{b} mod {p}",
                "shared_secret": bob_s
            },
            "match": matches,
            "explanation": "Alice and Bob independently arrived at the identical symmetric master secret key without sending it over the network!"
        }


class ElgamalSignatureSystem:
    """Implements Elgamal Digital Signature Scheme with SHA-512 cryptographic hashing."""

    P_DEFAULT = 1000000007  # Safe prime
    G_DEFAULT = 5           # Primitive generator

    @staticmethod
    def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, y1, x1 = ElgamalSignatureSystem._extended_gcd(b % a, a)
        return gcd, x1 - (b // a) * y1, y1

    @staticmethod
    def _mod_inverse(a: int, m: int) -> int:
        gcd, x, _ = ElgamalSignatureSystem._extended_gcd(a, m)
        if gcd != 1:
            raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
        return x % m

    @classmethod
    def generate_keypair(cls, p: int = P_DEFAULT, g: int = G_DEFAULT) -> Dict[str, Any]:
        x = random.randint(2, p - 2)
        y = pow(g, x, p)
        return {
            "p": p,
            "g": g,
            "private_key_x": x,
            "public_key_y": y,
            "domain_info": f"Finite Field GF({p}), Generator {g}"
        }

    @staticmethod
    def compute_sha512_digest(message: str, p: int = P_DEFAULT) -> Dict[str, Any]:
        raw_hash = hashlib.sha512(message.encode("utf-8")).hexdigest()
        digest_int = int(raw_hash, 16) % (p - 1)
        if digest_int == 0:
            digest_int = 1
        return {
            "message": message,
            "sha512_hex": raw_hash,
            "sha512_bits": 512,
            "hash_reduced_mod_p_minus_1": digest_int
        }

    @classmethod
    def sign_message(cls, message: str, private_x: int, p: int = P_DEFAULT, g: int = G_DEFAULT) -> Dict[str, Any]:
        digest_data = cls.compute_sha512_digest(message, p)
        m_val = digest_data["hash_reduced_mod_p_minus_1"]

        # Choose ephemeral secret k such that gcd(k, p - 1) == 1
        while True:
            k = random.randint(2, p - 2)
            gcd_val, _, _ = cls._extended_gcd(k, p - 1)
            if gcd_val == 1:
                break

        r = pow(g, k, p)
        k_inv = cls._mod_inverse(k, p - 1)
        s = ((m_val - private_x * r) * k_inv) % (p - 1)

        return {
            "message": message,
            "sha512_hex": digest_data["sha512_hex"],
            "hash_value_m": m_val,
            "ephemeral_k": k,
            "signature_r": r,
            "signature_s": s,
            "explanation": f"r = g^k mod p = {r}, s = (H(m) - x*r)*k^-1 mod (p-1) = {s}"
        }

    @classmethod
    def verify_signature(cls, message: str, r: int, s: int, public_y: int, p: int = P_DEFAULT, g: int = G_DEFAULT) -> Dict[str, Any]:
        if not (0 < r < p) or not (0 < s < p - 1):
            return {
                "is_valid": False,
                "status": "INVALID",
                "reason": "Bounds verification failure: require 0 < r < p and 0 < s < p-1"
            }

        digest_data = cls.compute_sha512_digest(message, p)
        m_val = digest_data["hash_reduced_mod_p_minus_1"]

        v1 = pow(g, m_val, p)
        v2 = (pow(public_y, r, p) * pow(r, s, p)) % p

        valid = (v1 == v2)
        return {
            "is_valid": valid,
            "status": "VALID" if valid else "INVALID",
            "sha512_hex": digest_data["sha512_hex"],
            "v1_left_hand_side": f"g^H(m) mod p = {v1}",
            "v2_right_hand_side": f"(y^r * r^s) mod p = {v2}",
            "comparison": f"{v1} == {v2}"
        }
