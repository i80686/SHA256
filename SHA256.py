def ROTR(x, n):
    x = (x >> n) | (x << 32 - n)
    return x

def sha256(binaries):
    H = [
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19]

    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    remainder = len(binaries) % 64
    quotient = len(binaries) // 64
    bit_n = (len(binaries) * 8).to_bytes(8, byteorder='big')

    Mn = []
    Mn_i = 0
    while Mn_i < quotient:
        Mn.append(binaries[Mn_i * 64:Mn_i * 64 + 64])
        Mn_i = Mn_i + 1

    if remainder == 0:
        # binaries % 64 = 0 时：补位，附加M = binaries[n+1] = 1+0+len(M)
        Mn.append(b'\x80' + b'\x00' * (64-8-1) + bit_n)
    else:
        if remainder < 55:
            # M < 55，补位 M = M+1+0+len(binaries)
            Mn.append(binaries[-remainder:]+b'\x80'+b'\x00'*(64-8-1-remainder)+bit_n)
        elif remainder < 56:
            # 55 < M <56时:补位 M = M+1+len(M)
            Mn.append(binaries[-remainder:]+b'\x80'+bit_n)
        else:
            # 56 < M <64时：补位 M = M+1，再附加M = binaries[n+1] = 0+len(M)
            Mn.append(binaries[-remainder:]+b'\x80'+b'\x00'*(64-1-remainder))
            Mn.append(b'\x00' * (64-8) + bit_n)
    for M in Mn:

        W = [0] * 64
        for t in range(0, 16):
            W[t] = M[t * 4:t * 4 + 4]
            W[t] = int(W[t].hex(), 16)
        #print(W[0:16])

        for t in range(16, 64):
            S1 = ROTR(W[t - 2], 17) ^ ROTR(W[t - 2], 19) ^ (W[t - 2]>>10)
            S0 = ROTR(W[t - 15], 7) ^ ROTR(W[t - 15], 18) ^ (W[t - 15] >> 3)
            W[t] = (S1+W[t-7]+S0+W[t-16]) & 0xFFFFFFFF
            # 压缩为8位 & 0xFFFFFFFF
            # 为什么要进行压缩？因为运算的时候超过8位16进制数字了
            # 压缩的目的是去掉8位前多余的数值
            # >>> hex(0xa54ff53a + 0xb85e2ce9)
            # '0x15dae2223'
            # >>> hex((0xa54ff53a + 0xb85e2ce9) & 0xFFFFFFFF)
            # '0x5dae2223'
        #print(W)
        a = H[0]
        b = H[1]
        c = H[2]
        d = H[3]
        e = H[4]
        f = H[5]
        g = H[6]
        h = H[7]

        for t in range(0, 64):
            S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25)
            Ch = (e & f) ^ ((~e) & g)
            S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22)
            Maj = (a & b) ^ (a & c) ^ (b & c)
            T1 = h + S1 + Ch + K[t] + W[t]
            T2 = S0 + Maj
            h = g
            g = f
            f = e
            e = (d + T1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xFFFFFFFF
            #hashs = (a, b, c, d, e, f, g, h)
            #for hash in hashs:
                #print(hex(hash))
            #input('按enter继续……')

        H[0] = a + H[0] & 0xFFFFFFFF
        H[1] = b + H[1] & 0xFFFFFFFF
        H[2] = c + H[2] & 0xFFFFFFFF
        H[3] = d + H[3] & 0xFFFFFFFF
        H[4] = e + H[4] & 0xFFFFFFFF
        H[5] = f + H[5] & 0xFFFFFFFF
        H[6] = g + H[6] & 0xFFFFFFFF
        H[7] = h + H[7] & 0xFFFFFFFF

    sha256_result = ''
    for sha in H:
        #print(hex(sha))
        sha256_result = sha256_result + sha.to_bytes(4, byteorder='big').hex()
    return sha256_result

tests_list = {
'abc':'abc'.encode('utf8'),
"('x'*54)":('x'*54).encode('utf8'),
"('x'*55)":('x'*55).encode('utf8'),
"('x'*56)":('x'*56).encode('utf8'),
"('x'*57)":('x'*57).encode('utf8'),
"('x'*64)":('x'*64).encode('utf8'),
"('x'*512)":('x'*512).encode('utf8'),
}
#file = sys.argv[1]
#with open(file, 'rb') as f:
    #binaries = f.read()
#binaries
for tests, binaries in tests_list.items():
    sha256_result = sha256(binaries)
    print(tests, sha256_result)
    import hashlib
    print(tests, hashlib.sha256(binaries).hexdigest(), 'hashlib')
    if sha256_result == hashlib.sha256(binaries).hexdigest():
        print('结果一致')
