# Date: 06/23/2018
# Author: Pure-L0G1C
# Description: Encryption & Decryption

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP 
from Crypto.Random import get_random_bytes


class CryptoRSA:

    @staticmethod
    def gen_key():
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return public_key, private_key

    @staticmethod
    def encrypt(data, rec_publ_key):
        recipient_key = RSA.import_key(rec_publ_key)
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        return cipher_rsa.encrypt(data)

    @staticmethod
    def decrypt(data, priv_key):
        key = RSA.import_key(priv_key)
        cipher_rsa = PKCS1_OAEP.new(key)
        return cipher_rsa.decrypt(data)
    
    @staticmethod
    def sign(data, priv_key):
        key = RSA.import_key(priv_key)
        _hash = SHA256.new(data)
        return pkcs1_15.new(key).sign(_hash)
    
    @staticmethod
    def verify(data, signature, publ_key):
        key = RSA.import_key(publ_key)
        _hash = SHA256.new(data)
  
        try:
            pkcs1_15.new(key).verify(_hash, signature)
            return True 
        except ValueError:
            return False


class CryptoAES:

    @staticmethod
    def gen_key():
        return b64encode(get_random_bytes(16))

    @classmethod
    def gen_nonce(cls):
        return b64encode(get_random_bytes(12))

    @staticmethod
    def encrypt(data, key, nonce, is_file=False):
        key, nonce = [b64decode(_) for _ in [key, nonce]]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext = cipher.encrypt(data)
        return b64encode(ciphertext) if not is_file else ciphertext

    @staticmethod
    def decrypt(ciphertext, key, nonce, is_file=False):
        key, nonce = [b64decode(_) for _ in [key, nonce]]
        ciphertext = b64decode(ciphertext) if not is_file else ciphertext
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext
