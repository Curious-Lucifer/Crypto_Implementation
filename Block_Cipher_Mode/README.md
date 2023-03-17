# Block Cipher Mode
> use AES for example

## GCM Mode

usage : 
```python
from GCM_Mode import *
import os

# key's length can be 16, 24, 32 bytes
key = os.urandom(16)

plain = os.urandom(37)
nonce = os.urandom(11)
AAD = os.urandom(53)

cipher, auth_tag = AES_GCM_encrypt_digest(key, plain, nonce, AAD)
new_plain, auth = AES_GCM_decrypt_auth(key, cipher, nonce, auth_tag, AAD)

assert (new_plain == plain) and auth
```

same functionality with `pycryptodome` : 
```python
from Crypto.Cipher import AES
import os

# key's length can be 16, 24, 32 bytes
key = os.urandom(16)

plain = os.urandom(37)
nonce = os.urandom(11)
AAD = os.urandom(53)

aes = AES.new(key, AES.MODE_GCM, nonce = nonce)
aes.update(AAD)
cipher = aes.encrypt(plain)
auth_tag = aes.digest()

aes = AES.new(key, AES.MODE_GCM, nonce = nonce)
aes.update(AAD)
new_plain = aes.decrypt(cipher)
aes.verify(auth_tag)

assert (new_plain == plain)
```
