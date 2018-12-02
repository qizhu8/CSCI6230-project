#!/usr/bin/env python3

import numpy as np
import PythonClasses.Number_Package as npkg

class RSA(object):
    """docstring for RSA."""
    def __init__(self, e=-1, N=-1):
        super(RSA, self).__init__()
        self.q = -1
        self.p = -1
        self.N = -1
        self.e = -1
        self.d = -1

        if N > 5 and e > 0 and e < N:
            self.N = N
            self.e = e
        if self.N == -1 or self.e == -1:
            self.random_private_key()

    def update_N(self):
        if self.p != -1 and self.q != -1:
            self.N = self.p * self.q

    def update_e_and_d(self):
        phi = (self.p-1) * (self.q-1)
        e = np.random.randint(phi//2, phi, dtype=np.int64)
        while np.gcd(e, phi) != 1:
            e = np.random.randint(phi//2, phi, dtype=np.int64)

        self.e = e
        self.d = npkg.mult_inv_mod_N(e, phi)

    def set_p(self, p):
        if npkg.is_prime(p):
            self.p = p
            self.update_N()
            self.update_e_and_d()
        else:
            print("p should be prime")

    def set_q(self, q):
        if npkg.is_prime(q):
            self.q = q
            self.update_N()
            self.update_e_and_d()
        else:
            print("q should be prime")

    def get_public_key(self):
        return [self.N, self.e]

    def encrypt(self, m):
        if m > self.N:
            print("message is greater than N")
            m %= self.N
        return npkg.exp_mod(m, self.e, self.N)

    def decrypt(self, c):
        return npkg.exp_mod(c, self.d, self.N)

    def sign(self, m): # sign the message
        if m > self.N:
            # print("message is greater than N")
            m %= self.N
        return npkg.exp_mod(m, self.d, self.N)

    def de_sign(self, c): # use public key to decrypt the message
        return npkg.exp_mod(c, self.e, self.N)

    def check_sign(self, m, s):
        if self.de_sign(m) == s:
            return True
        else:
            return False

    def random_private_key(self):
        base = np.random.randint(2**10)
        self.p = npkg.find_prime_smaller_than_k(2**31 - base)
        self.q = npkg.find_prime_greater_than_k(2**31 + base)

        self.N = self.p*self.q
        self.update_e_and_d()
