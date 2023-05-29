import struct


class MD4:
   

    width = 32
    mask = 0xFFFFFFFF

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def __init__(self, wiadomosc):
        if len(wiadomosc)<2**61 and type(wiadomosc)==bytes:
            self.wiadomosc=wiadomosc
            self.hash = None
       
        

    @classmethod
    def from_string(cls, string):
        
        return cls(string.encode())

    @classmethod
    def from_file(cls, filename):
        
        with open(filename, "rb") as file:
            return cls(file.read())

    def get_hash(self):
        """hashuje, jesli nie jest zhashowane"""
        if self.hash is None:
            #dlugosc calkowita - wielokrotnosc 512 bitow.
            wiadomosc = self.wiadomosc
            wdl = len(wiadomosc) * 8
            wiadomosc += b"\x80"
            wiadomosc += b"\x00" * (-(len(wiadomosc) + 8) % 64)
            wiadomosc += struct.pack("<Q", wdl)

            #przetwarza wiadomosc na 512-bitowe kawalki.
            h = self.h.copy()
            kawalki = [wiadomosc[i : i + 64] for i in range(0, len(wiadomosc), 64)]
            for kawalek in kawalki:
                X = list(struct.unpack("<16I", kawalek))

                # runda 1.
                Xi = [3, 7, 11, 19]
                for n in range(16):
                    i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                    K, S = n, Xi[n % 4]
                    hn = h[i] + MD4.F(h[j], h[k], h[l]) + X[K]
                    h[i] = MD4.rotacja(hn & MD4.mask, S)

                # runda 2.
                Xi = [3, 5, 9, 13]
                for n in range(16):
                    i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                    K, S = n % 4 * 4 + n // 4, Xi[n % 4]
                    hn = h[i] + MD4.G(h[j], h[k], h[l]) + X[K] + 0x5A827999
                    h[i] = MD4.rotacja(hn & MD4.mask, S)

                # runda 3.
                Xi = [3, 9, 11, 15]
                Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
                for n in range(16):
                    i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                    K, S = Ki[n], Xi[n % 4]
                    hn = h[i] + MD4.H(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
                    h[i] = MD4.rotacja(hn & MD4.mask, S)

                self.h = [((v + n) & MD4.mask) for v, n in zip(self.h, h)]

            self.hash = struct.pack("<4I", *self.h)
        return (int.from_bytes(self.hash, byteorder="big"))

    def __str__(self):
        """zwraca w szesnastkowym."""
        if self.hash is None:
            self.get_hash()

        return self.hash.hex()


    @staticmethod
    def F(x, y, z):
        return (x & y) | (~x & z)

    @staticmethod
    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def H(x, y, z):
        return x ^ y ^ z

    @staticmethod
    def rotacja(value, n):
        nalewo, naprawo = (value << n) & MD4.mask, value >> (MD4.width - n)
        return nalewo | naprawo



wiadomosc = b"Ala ma kota"
md4 = MD4(wiadomosc)
print(md4.get_hash())
print(md4)
