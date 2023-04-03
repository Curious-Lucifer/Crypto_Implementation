# Hash

## MD5

usage : 
```python
from MD5 import *
import os

msg = os.urandom(456)

md5(msg)
```

same functionality with `hashlib` : 
```python
from hashlib import md5
import os

msg = os.urandom(456)

md5(msg).digest()
```

---

## SHA1

usage : 
```python
from SHA1 import *
import os

msg = os.urandom(456)

sha1(msg)
```

same functionality with `hashlib` : 
```python
from hashlib import sha1
import os

msg = os.urandom(456)

sha1(msg).digest()
```

---

## SHA256

usage : 
```python
from SHA256 import *
import os

msg = os.urandom(456)

sha256(msg)
```

same functionality with `hashlib` : 
```python
from hashlib import sha256
import os

msg = os.urandom(456)

sha256(msg).digest()
```

---

## SHA512

usage : 
```python
from SHA512 import *
import os

msg = os.urandom(456)

sha512(msg)
```

same functionality with `hashlib` : 
```python
from hashlib import sha512
import os

msg = os.urandom(456)

sha512(msg).digest()
```
