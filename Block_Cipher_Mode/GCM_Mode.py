from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long

class GCM_Galois_Field:
    MODULO = (1 << 128) + (1 << 7) + (1 << 2) + (1 << 1) + 1

    def __init__(self, n: int):
        assert n.bit_length() <= 128
        
        self.n = n

    def __add__(self, other):
        return GCM_Galois_Field(self.n ^ other.n)

    def __mul__(self, other):
        other_bin = list(reversed([int(b) for b in bin(other.n)[2:]]))
        result = 0
        for i in range(len(other_bin)):
            result ^= ((self.n << i) * other_bin[i])

        while (result.bit_length() > 128):
            result ^= (GCM_Galois_Field.MODULO << (result.bit_length() - 129))

        return GCM_Galois_Field(result)


def bytes2GF_num(string: bytes):
    assert len(string) == 16

    return GCM_Galois_Field(int(''.join(reversed(list(bin(bytes_to_long(string))[2:].rjust(128, '0')))), base=2))


def GF_num2bytes(GF_num: GCM_Galois_Field):
    return long_to_bytes(int(''.join(reversed(list(bin(GF_num.n)[2:].rjust(128, '0')))), base=2), 16)


def GCM_Hash(string: bytes, H: bytes):
    assert (len(string) % 16) == 0

    H = bytes2GF_num(H)
    ans = bytes2GF_num(string[:16])

    for i in range(16, len(string), 16):
        sub_str = bytes2GF_num(string[i: i + 16])
        ans = ans * H + sub_str

    return GF_num2bytes(ans * H)


def AES_GCM_encrypt_digest(key: bytes, plain: bytes, nonce: bytes, AAD: bytes = b''):
    aes = AES.new(key, AES.MODE_ECB)
    xor = lambda x, y: bytes([i ^ j for i, j in zip(x, y)])

    H = aes.encrypt(b'\x00' * 16)

    if len(nonce) == 12:
        J0 = nonce + b'\x00\x00\x00\x01'
    else:
        nonce += b'\x00' * (16 - (len(nonce) % 16)) + b'\x00' * 8 + long_to_bytes(len(nonce) * 8, 8)
        J0 = GCM_Hash(nonce, H)

    initial_value = bytes_to_long(J0[-4:]) + 1
    plain_block_list = [plain[i * 16: (i + 1) * 16] for i in range(len(plain) // 16)]
    cipher = b''

    for i in range(len(plain_block_list)):
        count_cipher = aes.encrypt(J0[:12] + long_to_bytes(initial_value + i, 4))
        cipher += xor(count_cipher, plain_block_list[i])

    count_cipher = aes.encrypt(J0[:12] + long_to_bytes(initial_value + i + 1, 4))
    cipher += xor(plain[-(len(plain) % 16):], count_cipher[:len(plain) % 16])

    auth_string = AAD
    if (len(auth_string) % 16) != 0:
        auth_string += b'\x00' * (16 - (len(auth_string) % 16))
    auth_string += cipher
    if (len(auth_string) % 16) != 0:
        auth_string += b'\x00' * (16 - (len(auth_string) % 16))
    auth_string += long_to_bytes(len(AAD) * 8, 8) + long_to_bytes(len(cipher) * 8, 8)
    
    auth_tag = xor(GCM_Hash(auth_string, H), aes.encrypt(J0))

    return cipher, auth_tag


def AES_GCM_decrypt_auth(key: bytes, cipher: bytes, nonce: bytes, auth_tag: bytes, AAD: bytes = b''):
    aes = AES.new(key, AES.MODE_ECB)
    xor = lambda x, y: bytes([i ^ j for i, j in zip(x, y)])

    H = aes.encrypt(b'\x00' * 16)

    if len(nonce) == 12:
        J0 = nonce + b'\x00\x00\x00\x01'
    else:
        nonce += b'\x00' * (16 - (len(nonce) % 16) + 8) + long_to_bytes(len(nonce) * 8, 8)
        J0 = GCM_Hash(nonce, H)

    initial_value = bytes_to_long(J0[-4:]) + 1
    cipher_block_list = [cipher[i * 16: (i + 1) * 16] for i in range(len(cipher) // 16)]
    plain = b''

    for i in range(len(cipher_block_list)):
        count_cipher = aes.encrypt(J0[:12] + long_to_bytes(initial_value + i, 4))
        plain += xor(count_cipher, cipher_block_list[i])

    count_cipher = aes.encrypt(J0[:12] + long_to_bytes(initial_value + i + 1, 4))
    plain += xor(cipher[- (len(cipher) % 16):], count_cipher[:len(cipher) % 16])

    auth_string = AAD
    if (len(auth_string) % 16) != 0:
        auth_string += b'\x00' * (16 - (len(auth_string) % 16))
    auth_string += cipher
    if (len(auth_string) % 16) != 0:
        auth_string += b'\x00' * (16 - (len(auth_string) % 16))
    auth_string += long_to_bytes(len(AAD) * 8, 8) + long_to_bytes(len(cipher) * 8, 8)
    
    new_auth_tag = xor(GCM_Hash(auth_string, H), aes.encrypt(J0))

    if new_auth_tag != auth_tag:
        return b'',False

    return plain, True
