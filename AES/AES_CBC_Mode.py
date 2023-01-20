from AES_basic import AES_Block, xor_bytes

def AES_CBC_encrypt(key: bytes, plain: bytes, iv: bytes):
    assert (len(iv) == 16) and ((len(plain) % 16) == 0)

    aes = AES_Block(key)
    plain_block_list = [plain[i:i + 16] for i in range(0, len(plain), 16)]
    cipher = b''
    for i in range(len(plain_block_list)):
        cipher += aes.encrypt_block(xor_bytes(iv, plain_block_list[i]))
        iv = cipher[-16:]

    return cipher


def AES_CBC_decrypt(key: bytes, cipher: bytes, iv: bytes):
    assert (len(iv) == 16) and ((len(cipher) % 16) == 0)

    aes = AES_Block(key)
    cipher_block_list = [cipher[i:i + 16] for i in range(0, len(cipher), 16)]
    plain = b''
    for i in range(len(cipher_block_list)):
        plain += xor_bytes(aes.decrypt_block(cipher_block_list[i]), iv)
        iv = cipher_block_list[i]

    return plain

