def sha256(message: bytes):
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    right_rotate = lambda x, n: (x << (32 - n) | x >> n) & 0xFFFFFFFF
    modular_add = lambda *args : sum(args) & 0xFFFFFFFF

    message_length = len(message) * 8
    message += b'\x80'
    message += b'\x00' * ((56 - len(message)) % 64) + message_length.to_bytes(8, byteorder='big')

    chunks = [message[i: i + 64] for i in range(0, len(message), 64)]
    for chunk in chunks:
        w = [int.from_bytes(chunk[i: i + 4], byteorder='big') for i in range(0, len(chunk), 4)]
        for i in range(16, 64):
            s0 = right_rotate(w[i - 15], 7) ^ right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = right_rotate(w[i - 2], 17) ^ right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append(modular_add(w[i - 16], w[i - 7], s0, s1))

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7
        for i in range(64):
            s1 = right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = modular_add(h, s1, ch, k[i], w[i])
            s0 = right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = modular_add(s0, maj)

            h = g
            g = f
            f = e
            e = modular_add(d, temp1)
            d = c
            c = b
            b = a
            a = modular_add(temp1, temp2)

        h0 = modular_add(h0, a)
        h1 = modular_add(h1, b)
        h2 = modular_add(h2, c)
        h3 = modular_add(h3, d)
        h4 = modular_add(h4, e)
        h5 = modular_add(h5, f)
        h6 = modular_add(h6, g)
        h7 = modular_add(h7, h)

    return b''.join(int.to_bytes(h, 4, byteorder='big') for h in (h0, h1, h2, h3, h4, h5, h6, h7))
