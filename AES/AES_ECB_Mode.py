from AES_basic import AES_Block

def AES_ECB_encrypt(key: bytes, plain: bytes):
    assert (len(plain) % 16) == 0

    plain_block_list = [plain[i:i + 16] for i in range(0, len(plain), 16)]
    aes = AES_Block(key)
    cipher = b''.join([aes.encrypt_block(plain_block) for plain_block in plain_block_list])

    return cipher

def AES_ECB_decrypt(key: bytes, cipher: bytes):
    assert (len(cipher) % 16) == 0

    cipher_block_list = [cipher[i:i + 16] for i in range(0, len(cipher), 16)]
    aes = AES_Block(key)
    plain = b''.join([aes.decrypt_block(cipher_block) for cipher_block in cipher_block_list])

    return plain
