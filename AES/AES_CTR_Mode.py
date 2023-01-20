from AES_basic import AES_Block, xor_bytes
from Crypto.Util.number import long_to_bytes

def AES_CTR_encrypt(key: bytes, plain: bytes, prefix: bytes = b'', initial_value: int = 1):
    assert len(prefix) < 16

    aes = AES_Block(key)
    plain_block_list = [plain[i * 16:(i + 1) * 16] for i in range(len(plain) // 16)]
    cipher = b''

    for i in range(len(plain_block_list)):
        count_cipher = aes.encrypt_block(prefix + long_to_bytes(initial_value + i, 16 - len(prefix)))
        cipher += xor_bytes(count_cipher, plain_block_list[i])

    count_cipher = aes.encrypt_block(prefix + long_to_bytes(initial_value + i + 1, 16 - len(prefix)))
    cipher += xor_bytes(plain[- (len(plain) % 16):], count_cipher[:len(plain) % 16])

    return cipher


def AES_CTR_decrypt(key: bytes, cipher: bytes, prefix: bytes = b'', initial_value: int = 1):
    assert len(prefix) < 16

    aes = AES_Block(key)
    cipher_block_list = [cipher[i * 16:(i + 1) * 16] for i in range(len(cipher) // 16)]
    plain = b''

    for i in range(len(cipher_block_list)):
        count_cipher = aes.encrypt_block(prefix + long_to_bytes(initial_value + i, 16 - len(prefix)))
        plain += xor_bytes(count_cipher, cipher_block_list[i])

    count_cipher = aes.encrypt_block(prefix + long_to_bytes(initial_value + i + 1, 16 - len(prefix)))
    plain += xor_bytes(cipher[- (len(cipher) % 16):], count_cipher[:len(cipher) % 16])

    return plain

