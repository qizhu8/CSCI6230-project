#!/usr/bin/env python3

import sys
import numpy as np
import PythonClasses.Number_Package as npkg

np.warnings.filterwarnings('ignore')


class SHA1(object):

    def __init__(self):
        super(SHA1, self).__init__()

    """
      functions as defined by FIPS 180-1 standard
    """
    def f0_19(self, B, C, D):
        return (B & C) | ((~ B) & D)

    def f20_39(self, B, C, D):
        return B ^ C ^ D

    def f40_59(self, B, C, D):
        return (B & C) | (B & D) | (C & D)

    def f60_79(self, B, C, D):
        return B ^ C ^ D

    def f(self, t, B, C, D):
        if t >= 0 and t <= 19:
            v = self.f0_19(B, C, D)
        elif t >= 20 and t <= 39:
            v = self.f20_39(B, C, D)
        elif t >= 40 and t <= 59:
            v = self.f40_59(B, C, D)
        elif t >= 60 and t <= 79:
            v = self.f60_79(B, C, D)
        else:
            return None

        return np.uint32(v)

    """
      constants Kt for 0 <= t <= 79 as defined by FIPS 180-1 standard.
    """
    def K(self, t):
        if t >= 0 and t <= 19:
            return np.uint32(int("0x5A827999", 16))
        elif t >= 20 and t <= 39:
            return np.uint32(int("0x6ED9EBA1", 16))
        elif t >= 40 and t <= 59:
            return np.uint32(int("0x8F1BBCDC", 16))
        elif t >= 60 and t <= 79:
            return np.uint32(int("0xCA62C1D6", 16))
        else:
            return None

    """
      circular left shift
    """
    def S(self, n, X):
        A = X
        a = A << n
        b = A >> (32 - n)

        return np.uint32(a | b)

    """
      pads a bit string based on the FIPS 180-1 standard:
        suppose a message has length l < 2^64. Before it is input
        to the SHA-1, the message is padded on the right as follows:
          a. "1" is appended. EXAMPLE: if the original message is
             "01010000", this is padded to "010100001".
          b. "0"'s are appended. The number of "0"'s will depend on
             the original length of the message. The last 64 bits of
             the last 512-bit block are reserved for the length l of
             the original message.
    """
    def padding(self, M):
        l = len(M)
        ret_M = M
        ret_M += "1"
        ret_M += "0" * (511 - 64 - (l % 512))
        ret_M += format(l, "064b")
        return ret_M

    """
      message computed with final padded message.
    """
    def message_digest(self, M):
        H = [
            np.uint32(int("0x67452301", 16)),
            np.uint32(int("0xEFCDAB89", 16)),
            np.uint32(int("0x98BADCFE", 16)),
            np.uint32(int("0x10325476", 16)),
            np.uint32(int("0xC3D2E1F0", 16))
        ]

        i = 1
        while i * 16 <= len(M):
            W = [np.uint32(m) for m in M[16 * (i - 1):16 * i] ]
            for t in range(16, 80):
                W.append(self.S(1, np.uint32(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16])))

            A = H[0]
            B = H[1]
            C = H[2]
            D = H[3]
            E = H[4]

            for t in range(80):
                tmp = np.uint32(self.S(5, A) + self.f(t, B, C, D) + \
                        E + W[t] + self.K(t))

                E = D
                D = C
                C = self.S(30, B)
                B = A
                A = tmp

                """
                print(t, format(A, '08x'), format(B, '08x'), format(C, '08x'), \
                    format(D, '08x'), format(E, '08x'))
                """

            H[0] = np.uint32(H[0] + A)
            H[1] = np.uint32(H[1] + B)
            H[2] = np.uint32(H[2] + C)
            H[3] = np.uint32(H[3] + D)
            H[4] = np.uint32(H[4] + E)

            i += 1

        ret = ""
        for h in H:
            # print(h.hex)
            ret += format(h, '08x')

        return ret

    """
      finally, we are able to hash a message!
    """
    def hash(self, M):
        m = ""
        for c in M:
            m += format(ord(c), '08b')

        padded_m = self.padding(m)

        m_list = []
        i = 0
        while i * 32 < len(padded_m):
            m_list.append(int(padded_m[i * 32 : (i + 1) * 32], 2))
            i += 1

        return self.message_digest(m_list)
