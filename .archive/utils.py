import os
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import padding
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from binascii import hexlify, unhexlify

def aes_encrypt(message, key):
    """AES encryption with CBC mode"""
    iv = os.urandom(16)  # 16 bytes for AES block size
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    # Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext
def aes_decrypt(iv, ciphertext, key):
    """AES decryption"""
    cipher = Cipher(algorithms.AES(key), modes.ECB(iv))
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(padded_data) + unpadder.finalize()
    return message.decode()

def des_encrypt(message, key):
    """DES encryption with random IV"""
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv, ciphertext

def des_decrypt(iv, ciphertext, key):
    """DES decryption"""
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(iv))
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(64).unpadder()
    message = unpadder.update(padded_data) + unpadder.finalize()
    return message.decode()

def rsa_key_pair():
    """Generate RSA key pair"""
    key = RSA.generate(1024)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def rsa_encrypt(message, public_key):
    """RSA encryption"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted = cipher_rsa.encrypt(message)
    return encrypted

def rsa_decrypt(ciphertext, private_key):
    """RSA decryption"""
    private_key_bytes = private_key.export_key()
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key_bytes))
    decrypted = cipher_rsa.decrypt(ciphertext)
    return decrypted.decode('utf-8')