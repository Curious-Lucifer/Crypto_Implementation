from AES_basic import AES_Block, xor_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes
from sage.all import PolynomialRing, GF

def GCM_Mul(Target: bytes, H: bytes):
    assert (len(Target) <= 16) and (len(H) <= 16)

    Target = bin(bytes_to_long(Target))[2:].rjust(128,'0')
    H = bin(bytes_to_long(H))[2:].rjust(128,'0')

    Z = PolynomialRing(GF(2), names=('x',)); (x,) = Z._first_ngens(1)
    Target = sum([int(Target[i]) * (x ** i) for i in range(128)])
    H = sum([int(H[i]) * (x ** i) for i in range(128)])

    ans = Target * H
    modulus_polynomial = x ** 128 + x ** 7 + x ** 2 + x + 1
    while ans.degree() >= modulus_polynomial.degree():
        ans = ans - modulus_polynomial * (x ** (ans.degree() - modulus_polynomial.degree()))

    return long_to_bytes(int(''.join([str(a) for a in list(ans)]).ljust(128,'0'), base=2), 16)


def GCM_HASH(string: bytes, H: bytes):
    assert (len(string) % 16) == 0

    string_block = [string[i:i + 16] for i in range(0, len(string), 16)]
    ans = b'\x00' * 16

    for i in range(len(string_block)):
        ans = GCM_Mul(xor_bytes(ans, string_block[i]), H)

    return ans


def AES_GCM_encrypt_digest(key: bytes, plain: bytes, nonce: bytes, AAD: bytes = b''):
    aes = AES_Block(key)

    H = aes.encrypt_block(b'\x00' * 16)

    if len(nonce) == 12:
        J0 = nonce + b'\x00\x00\x00\x01'
    else:
        nonce += b'\x00' * (16 - (len(nonce) % 16) + 8) + long_to_bytes(len(nonce) * 8, 8)
        J0 = GCM_HASH(nonce, H)

    initial_value = bytes_to_long(J0[-4:]) + 1
    plain_block_list = [plain[i * 16:(i + 1) * 16] for i in range(len(plain) // 16)]
    cipher = b''

    for i in range(len(plain_block_list)):
        count_cipher = aes.encrypt_block(J0[:12] + long_to_bytes(initial_value + i, 4))
        cipher += xor_bytes(count_cipher, plain_block_list[i])

    count_cipher = aes.encrypt_block(J0[:12] + long_to_bytes(initial_value + i + 1, 4))
    cipher += xor_bytes(plain[- (len(plain) % 16):], count_cipher[:len(plain) % 16])

    auth_string = AAD
    if (len(auth_string) % 16) != 0:
        auth_string += b'\x00' * (16 - (len(auth_string) % 16))
    auth_string += cipher
    if (len(auth_string) % 16) != 0:
        auth_string += b'\x00' * (16 - (len(auth_string) % 16))
    auth_string += long_to_bytes(len(AAD) * 8, 8) + long_to_bytes(len(cipher) * 8, 8)
    
    auth_tag = xor_bytes(GCM_HASH(auth_string, H), aes.encrypt_block(J0))

    return cipher, auth_tag


def AES_GCM_decrypt_auth(key: bytes, cipher: bytes, nonce: bytes, auth_tag: bytes, AAD: bytes = b''):
    aes = AES_Block(key)

    H = aes.encrypt_block(b'\x00' * 16)

    if len(nonce) == 12:
        J0 = nonce + b'\x00\x00\x00\x01'
    else:
        nonce += b'\x00' * (16 - (len(nonce) % 16) + 8) + long_to_bytes(len(nonce) * 8, 8)
        J0 = GCM_HASH(nonce, H)

    initial_value = bytes_to_long(J0[-4:]) + 1
    cipher_block_list = [cipher[i * 16:(i + 1) * 16] for i in range(len(cipher) // 16)]
    plain = b''

    for i in range(len(cipher_block_list)):
        count_cipher = aes.encrypt_block(J0[:12] + long_to_bytes(initial_value + i, 4))
        plain += xor_bytes(count_cipher, cipher_block_list[i])

    count_cipher = aes.encrypt_block(J0[:12] + long_to_bytes(initial_value + i + 1, 4))
    plain += xor_bytes(cipher[- (len(cipher) % 16):], count_cipher[:len(cipher) % 16])

    auth_string = AAD
    if (len(auth_string) % 16) != 0:
        auth_string += b'\x00' * (16 - (len(auth_string) % 16))
    auth_string += cipher
    if (len(auth_string) % 16) != 0:
        auth_string += b'\x00' * (16 - (len(auth_string) % 16))
    auth_string += long_to_bytes(len(AAD) * 8, 8) + long_to_bytes(len(cipher) * 8, 8)
    
    new_auth_tag = xor_bytes(GCM_HASH(auth_string, H), aes.encrypt_block(J0))

    if new_auth_tag != auth_tag:
        return b'',False
    return plain, True
