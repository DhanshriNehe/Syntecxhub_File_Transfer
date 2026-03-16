from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hmac
import hashlib

BLOCK_SIZE = 16

def pad(data: bytes) -> bytes:
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_len]) * padding_len

def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    if padding_len < 1 or padding_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    return data[:-padding_len]

def generate_key(key_size=32) -> bytes:
    return get_random_bytes(key_size)

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))
    return iv + ciphertext

def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    iv = ciphertext[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_padded = cipher.decrypt(ciphertext[BLOCK_SIZE:])
    return unpad(plaintext_padded)

def compute_hmac(data: bytes, key: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def verify_hmac(data: bytes, key: bytes, mac: bytes) -> bool:
    expected = compute_hmac(data, key)
    return hmac.compare_digest(expected, mac)
