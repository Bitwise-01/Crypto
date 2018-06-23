# Date: 06/23/2018
# Author: Pure-L0G1C
# Description: Encryption & Decryption

from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class CryptoRSA(object):

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

class CryptoAES(object):

 @staticmethod
 def gen_key():
  return b64encode(get_random_bytes(16))

 @classmethod
 def gen_iv(cls):
  return cls.gen_key()

 @staticmethod
 def encrypt(data, key, iv, is_file=False):
  key, iv = [b64decode(_) for _ in [key, iv]]
  cipher = AES.new(key, AES.MODE_CBC, iv=iv)
  ciphertext = cipher.encrypt(pad(data, AES.block_size))
  return b64encode(ciphertext) if not is_file else ciphertext

 @staticmethod
 def decrypt(ciphertext, key, iv, is_file=False):
  key, iv = [b64decode(_) for _ in [key, iv]]
  ciphertext = b64decode(ciphertext) if not is_file else ciphertext
  cipher = AES.new(key, AES.MODE_CBC, iv=iv)
  plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
  return plaintext