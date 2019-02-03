# Crypto
A wrapper for pycryptodome

# AES
### Encrypt a text
```python
from crypto import CryptoAES

secret = b'Get to attack by 12'
key = b'Winning is our goal'

ciphertext = CryptoAES.encrypt(secret, key)
print(ciphertext)
```

### Decrypt
```python
from crypto import CryptoAES

key = b'Winning is our goal'
plaintext = CryptoAES.decrypt(ciphertext, key)
print(plaintext)
```

### Encrypt & Decrypt
```python
from crypto import CryptoAES

secret = b'No one but you should see this'
key = CryptoAES.generate_key()

ciphertext = CryptoAES.encrypt(secret, key)
plaintext = CryptoAES.decrypt(ciphertext, key)

print('Ciphertext: {}\nPlaintext: {}'.format(ciphertext, plaintext))
```

# RSA

### Encrypt & Decrypt a session key

```python
from crypto import CryptoRSA, CryptoAES

# generate session key
session_key = CryptoAES.generate_key()

# generate key pair
public_key, private_key = CryptoRSA.gen_key()

# encrypt session key
ciphertext = CryptoRSA.encrypt(session_key, public_key)
print(ciphertext)

# decrypt session key
plaintext = CryptoRSA.decrypt(ciphertext, private_key)
print(plaintext)
```
