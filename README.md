# Crypto Implementation

## AES

### AES basic

usage : 
```python
from AES_basic import *
import os

# key's length can be 16, 24, 32 bytes
key = os.urandom(16)

# plain's length can only be 16 bytes
plain = os.urandom(16)

aes = AES_Block(key)

cipher = aes.encrypt_block(plain)
new_plain = aes.decrypt_block(cipher)

assert new_plain == plain
```

same functionality with : 
```python
from Crypto.Cipher import AES
import os

# key's length can be 16, 24, 32 bytes
key = os.urandom(16)

# plain's length can only be 16 bytes
plain = os.urandom(16)

aes = AES.new(key, AES.MODE_ECB)

cipher = aes.encrypt(plain)
new_plain = aes.decrypt(cipher)

assert new_plain == plain
```

---

### AES ECB Mode

usage : 
```python
from AES_ECB_Mode import *
import os

# key's length can be 16, 24, 32 bytes
key = os.urandom(16)

# plain's length can only be 16's multiple bytes
plain = os.urandom(32)

cipher = AES_ECB_encrypt(key, plain)
new_plain = AES_ECB_decrypt(key, cipher)

assert new_plain == plain
```

same functionality with : 
```python
from Crypto.Cipher import AES
import os

# key's length can be 16, 24, 32 bytes
key = os.urandom(16)

# plain's length can only be 16's multiple bytes
plain = os.urandom(32)

aes = AES.new(key, AES.MODE_ECB)

cipher = aes.encrypt(plain)
new_plain = aes.decrypt(cipher)

assert new_plain == plain
```

---

### AES CBC Mode

usage : 
```python
from AES_CBC_Mode import *
import os

# key's length can be 16, 24, 32 bytes
key = os.urandom(16)

# plain's length can only be 16's multiple bytes
plain = os.urandom(32)

# iv's length can only be 16 bytes
iv = os.urandom(16)

cipher = AES_CBC_encrypt(key, plain, iv)
new_plain = AES_CBC_decrypt(key, cipher, iv)

assert new_plain == plain
```

same functionality with : 
```python
from Crypto.Cipher import AES
import os

# key's length can be 16, 24, 32 bytes
key = os.urandom(16)

# plain's length can only be 16's multiple bytes
plain = os.urandom(32)

# iv's length can only be 16 bytes
iv = os.urandom(16)

aes = AES.new(key, AES.MODE_CBC, iv = iv)
cipher = aes.encrypt(plain)

aes = AES.new(key, AES.MODE_CBC, iv = iv)
new_plain = aes.decrypt(cipher)

assert new_plain == plain
```

---

### AES CTR Mode

usage : 
```python
from AES_CTR_Mode import *
import os

# key's length can be 16, 24, 32 bytes
key = os.urandom(16)

plain = os.urandom(37)

# iv's length can only be 16 bytes
iv = os.urandom(16)

# prefix's length + nbits = 128 bits
prefix = os.urandom(12)
nbits = 128 - len(prefix) * 8

cipher = AES_CTR_encrypt(key, plain, prefix, initial_value = 5)
new_plain = AES_CTR_decrypt(key, cipher, prefix, initial_value = 5)

assert new_plain == plain
```

same functionality with : 
```python
from Crypto.Cipher import AES
from Crypto.Util import Counter
import os

# key's length can be 16, 24, 32 bytes
key = os.urandom(16)

plain = os.urandom(37)

# iv's length can only be 16 bytes
iv = os.urandom(16)

# prefix's length + nbits = 128 bits
prefix = os.urandom(12)
nbits = 128 - len(prefix) * 8

counter = Counter.new(nbits, prefix = prefix, initial_value = 5)
aes = AES.new(key, AES.MODE_CTR, counter = counter)
cipher = aes.encrypt(plain)

aes = AES.new(key, AES.MODE_CTR, counter = counter)
new_plain = aes.decrypt(cipher)

assert new_plain == plain
```

---

### AES GCM Mode

usage : 
```python
from AES_GCM_Mode import *
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

same functionality with : 
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

---

## DES
### DES basic

usage : 
```python
from DES_basic import *
import os

# key's length can only be 8 bytes
key = os.urandom(8)

# plain's length can only be 8 bytes
plain = os.urandom(8)

des = DES_Block(key)

cipher = des.encrypt_block(plain)
new_plain = des.decrypt_block(cipher)

assert new_plain == plain
```

same functionality with : 
```python
from Crypto.Cipher import DES
import os

# key's length can only be 8 bytes
key = os.urandom(8)

# plain's length can only be 8 bytes
plain = os.urandom(8)

des = DES.new(key, DES.MODE_ECB)

cipher = des.encrypt(plain)
new_plain = des.decrypt(cipher)

assert new_plain == plain
```
