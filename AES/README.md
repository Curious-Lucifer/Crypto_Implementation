# AES

usage : 
```python
from AES import *
import os

# key's length can be 16, 24, 32 bytes
key = os.urandom(16)

# plain's length can only be 16 bytes
plain = os.urandom(16)

aes = AES_Block(key)

cipher = aes.encrypt(plain)
new_plain = aes.decrypt(cipher)

assert new_plain == plain
```

same functionality with `pycryptodome` : 
```python
from Crypto.Cipher import AES
import os

# key's length can be 16, 24, 32 bytes
key = os.urandom(16)

plain = os.urandom(16)

aes = AES.new(key, AES.MODE_ECB)

cipher = aes.encrypt(plain)
new_plain = aes.decrypt(cipher)

assert new_plain == plain
```
