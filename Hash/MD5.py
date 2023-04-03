from math import sin


def md5(message: bytes):
    R = [
        7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
        5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
        4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
        6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    ]
    K = [int(abs(sin(i + 1)) * (1 << 32)) for i in range(64)]
    h0, h1, h2, h3 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    left_rotate = lambda x, n: (x << n | x >> (32 - n)) & 0xFFFFFFFF
    modular_add = lambda *args : sum(args) & 0xFFFFFFFF

    message_length = len(message) * 8
    message += b'\x80'
    message += b'\x00' * ((56 - len(message)) % 64) + message_length.to_bytes(8, byteorder='little')

    chunks = [message[i: i + 64] for i in range(0, len(message), 64)]
    for chunk in chunks:
        w = [int.from_bytes(chunk[i: i + 4], byteorder='little') for i in range(0, len(chunk), 4)]
        a, b, c, d = h0, h1, h2, h3

        for i in range(64):
            if 0 <= i < 16:
                f = (b & c) | (~b & d)
                g = i
            elif 16 <= i < 32:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif 32 <= i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | ~d)
                g = (7 * i) % 16

            a, b, c, d = d, modular_add(left_rotate(modular_add(a, f, K[i], w[g]), R[i]), b), b, c

        h0 = modular_add(h0, a)
        h1 = modular_add(h1, b)
        h2 = modular_add(h2, c)
        h3 = modular_add(h3, d)

    return b''.join(int.to_bytes(h, 4, byteorder='little') for h in (h0, h1, h2, h3))

