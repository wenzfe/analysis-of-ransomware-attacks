"""Encrypted Channel: Asymmetric Cryptography

Adversaries may employ a known asymmetric encryption algorithm to conceal command and 
control traffic rather than relying on any inherent protections provided 
by a communication protocol. 
Asymmetric cryptography, also known as public key cryptography, uses a keypair per party: 
one public that can be freely distributed, and one private. 
Due to how the keys are generated, the sender encrypts data with the receiver's public key 
and the receiver decrypts the data with their private key. 
This ensures that only the intended recipient can read the encrypted data. 
Common public key encryption algorithms include RSA and ElGamal.

For efficiency, many protocols (including SSL/TLS) use symmetric cryptography once 
a connection is established, but use asymmetric cryptography to establish or transmit a key. 
As such, these protocols are classified as Asymmetric Cryptography.

Mitre: `T1573.002 <https://attack.mitre.org/versions/v12/techniques/T1573/002/>`_

This moduel is a wrapper of 
`PyCryptodome <https://pycryptodome.readthedocs.io/en/latest/index.html>`_
That is intendet to simplify its use.
"""
import logging
from typing import Tuple

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)


def gen_rsa(key_size: int = 4096) -> Tuple[bytes, bytes]:
    """Generate a RSA key pair.

    Args:
        key_size (int, optional): The key size in bits for the RSA. Defaults to 4096.

    Returns:
        Tuple[bytes, bytes]: public key, private key
    """
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return public_key, private_key


def rsa_enc(
    data: bytes, public_key: bytes, session_key_size=32
) -> Tuple[bytes, bytes, bytes, bytes]:
    """Encrypt data via an hybrid encryption scheme.

    The hybrid scheme uses RSA PKCS#1 OAEP for asymmetric encryption of an AES session key.
    The session key is used to encrypt the actual data with AES using the EAX mode.

    Args:
        data (bytes): The data thats to be encrypted.
        public_key (bytes): The public key used for encryption.
        session_key_size (int, optional): The key size in bytes for the symmetric encryption.
            Defaults to 32.

    Returns:
        Tuple[bytes, bytes, bytes, bytes]: encrypted session key, nonce, tag, ciphertext
    """
    recipient_key = RSA.import_key(public_key)
    session_key = get_random_bytes(session_key_size)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    return enc_session_key, cipher_aes.nonce, tag, ciphertext


def rsa_dec(
    private_key: bytes,
    enc_session_key: bytes,
    nonce: bytes,
    tag: bytes,
    ciphertext: bytes,
) -> bytes:
    """Decrypting data via an hybrid decryption scheme.

    The hybrid scheme uses RSA PKCS#1 OAEP for asymmetric decryption of an AES session key.
    The session key is used to decrypt the actual data with AES using the EAX mode.

    Args:
        private_key (bytes): The private key.
        enc_session_key (bytes): The encrypted session key.
        nonce (bytes): The nonce.
        tag (bytes): The tag.
        ciphertext (bytes): The ciphertext.

    Returns:
        bytes: The unencrypted data.
    """
    private_key = RSA.import_key(private_key)

    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return data
