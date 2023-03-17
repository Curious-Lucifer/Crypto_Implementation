# DES

usage : 
```python
from DES import *
import os

# key's length can only be 8 bytes
key = os.urandom(8)

# plain's length can only be 8 bytes
plain = os.urandom(8)

des = DES_Block(key)

cipher = des.encrypt(plain)
new_plain = des.decrypt(cipher)

assert new_plain == plain
```

same functionality with `pycrytodome` : 
```python
from Crypto.Cipher import DES
import os

# key's length can only be 8 bytes
key = os.urandom(8)

plain = os.urandom(8)

des = DES.new(key, DES.MODE_ECB)

cipher = des.encrypt(plain)
new_plain = des.decrypt(cipher)

assert new_plain == plain
```
