# Crypto
A wrapper for pycryptodome

# AES
### Encrypt a text
```python
from crypto import CryptoAES

secret = b'This is a secret'

key = CryptoAES.gen_key()
iv = CryptoAES.gen_iv()

ciphertext = CryptoAES.encrypt(secret, key, iv)
print(ciphertext)

plaintext = CryptoAES.decrypt(ciphertext, key, iv)
print(plaintext)
```

### Encrypt a text from password input
```python
from hashlib import sha256
from base64 import b64encode
from crypto import CryptoAES

secret = b'This is a secret'
key = b64encode(sha256(input('Enter a secure key: ').encode('utf8')).digest())
iv = CryptoAES.gen_iv()

ciphertext = CryptoAES.encrypt(secret, key, iv)
print(ciphertext)

plaintext = CryptoAES.decrypt(ciphertext, key, iv)
print(plaintext)
```

### Encrypt a file
```python
from crypto import CryptoAES

# file to encrypt & decrypt
my_file = 'notes.pptx'

# generate a secure key and iv
key = CryptoAES.gen_key()
iv = CryptoAES.gen_iv()

# read and encrypt data
encrypted_data = []
with open(my_file, 'rb') as f:
	while True:
		data = f.read(64 * 1024)
		if not data:break
		_data = CryptoAES.encrypt(data, key, iv, is_file=True)
		encrypted_data.append(_data)

# write out encrypted data
encrypted_file = 'encrypted_{}'.format(my_file)
with open(encrypted_file, 'wb') as f:
	for data in encrypted_data:
		f.write(data)

# read and decrypt data
decrypted_data = []
with open(encrypted_file, 'rb') as f:
	while True:
		data = f.read(64 * 1024)
		if not data:break
		_data = CryptoAES.decrypt(data, key, iv, is_file=True)
		decrypted_data.append(_data)

# write out decrypted data 
decrypted_file = 'decrypted_{}'.format(my_file)
with open(decrypted_file, 'wb') as f:
	for byte in decrypted_data:
		f.write(byte)
```

# RSA
### Encrypt a text
```python
from crypto import CryptoRSA

secret = b'This Is The Password'

# generate key pair
public_key, private_key = CryptoRSA.gen_key()

# encrypt data
ciphertext = CryptoRSA.encrypt(secret, public_key)
print(ciphertext)

# decrypt data
plaintext = CryptoRSA.decrypt(ciphertext, private_key)
print(plaintext)
```

### Encrypt session key
```python
from crypto import CryptoAES, CryptoRSA

secret = b'This Is The Password'

# generate key pair
public_key, private_key = CryptoRSA.gen_key()

# generate AES keys
session_key = CryptoAES.gen_key()
session_iv = CryptoAES.gen_iv()

# encrypt text
ciphertext = CryptoAES.encrypt(secret, session_key, session_iv)
print(ciphertext)

# encrypt session key
encrypted_session_key = CryptoRSA.encrypt(session_key, public_key)
print(encrypted_session_key)

# decrypt session key
decrypted_session_key = CryptoRSA.decrypt(encrypted_session_key, private_key)
print(decrypted_session_key)

# decrypt text
plaintext = CryptoAES.decrypt(ciphertext, decrypted_session_key, session_iv)
print(plaintext) 
```