def sha1(message: bytes):
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0

    left_rotate = lambda x, n: (x << n | x >> (32 - n)) & 0xFFFFFFFF
    modular_add = lambda *args : sum(args) & 0xFFFFFFFF
    
    message_length = len(message) * 8
    message += b'\x80'
    message += b'\x00' * ((56 - len(message)) % 64) + message_length.to_bytes(8, byteorder='big')

    chunks = [message[i: i + 64] for i in range(0, len(message), 64)]
    for chunk in chunks:
        w = [int.from_bytes(chunk[i: i + 4], byteorder='big') for i in range(0, len(chunk), 4)]
        for i in range(16, 80):
            w.append(left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

        a, b, c, d, e = h0, h1, h2, h3, h4
        for i in range(80):
            if 0 <= i < 20:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif 20 <= i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = modular_add(left_rotate(a, 5), f, e, k, w[i]), a, left_rotate(b, 30), c, d

        h0 = modular_add(h0, a)
        h1 = modular_add(h1, b)
        h2 = modular_add(h2, c)
        h3 = modular_add(h3, d)
        h4 = modular_add(h4, e)

    return b''.join(int.to_bytes(h, 4, byteorder='big') for h in (h0, h1, h2, h3, h4))
