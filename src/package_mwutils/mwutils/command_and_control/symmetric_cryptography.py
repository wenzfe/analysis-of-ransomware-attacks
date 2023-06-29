"""Encrypted Channel: Symmetric Cryptography

Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic 
rather than relying on any inherent protections provided by a communication protocol. 
Symmetric encryption algorithms use the same key for plaintext encryption and ciphertext decryption. 
Common symmetric encryption algorithms include AES, DES, 3DES, Blowfish, and RC4.

Mitre: `T1573.001 <https://attack.mitre.org/techniques/T1573/001/>`_

This moduel is a wrapper of 
`PyCryptodome <https://pycryptodome.readthedocs.io/en/latest/index.html>`_
That is intendet to simplify its use.
"""
import logging
from typing import Tuple

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)


def gen_aes256_key() -> bytes:
    """Generate 32 random bytes for AES256.

    Returns:
        bytes: Random bytes.
    """
    return get_random_bytes(32)


def aes256_encrypt(key: bytes, data: bytes) -> Tuple[bytes, bytes, bytes]:
    """Encrypt the data via AES256.

    Args:
        key (bytes): The key to use for encryption.
        data (bytes): The data to encrypt.

    Returns:
        Tuple[bytes, bytes, bytes]: nonce, ciphertext, tag
    """
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce, ciphertext, tag


def aes256_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Decrypt AES 256 encrypted data.

    Args:
        key (bytes): key (32 bytes).
        nonce (bytes): nonce.
        ciphertext (bytes): ciphertext.
        tag (bytes): tag.

    Returns:
        bytes: decrypted data.
    """
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        logger.info("The message is authentic: %s", plaintext)
    except ValueError:
        logger.warning("Key incorrect or message corrupted")
    return plaintext
