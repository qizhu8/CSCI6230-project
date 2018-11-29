#!/usr/bin/env python3

import numpy as np
import Number_Package as npkg

class RSA(object):
    """docstring for RSA."""
    def __init__(self, q=-1, alpha=-1, k=1000):
        super(RSA, self).__init__()
        self.q = -1
        self.alpha = -1
        self.set_q(q)
        self.set_alpha(alpha)
        self.pv_key = np.random.randint(k)

    def set_q(self, q):
        if npkg.is_prime(q):
            self.q = q
        else:
            print('q:', q, ' is not prime. Failed')

    def set_alpha(self, alpha):
        if npkg.is_prime(alpha):
            self.alpha = alpha
        else:
            print('alpha:', alpha, ' is not prime. Failed')

    def set_pv_key(self, pv_key):
        self.pv_key = pv_key

    def change_pv_key(self, k=1000):
        self.pv_key = np.random.randint(k)

    def is_prime(self, t):
        return npkg.is_prime(t)

    def find_prime_smaller_than_k(self, k):
        return npkg.find_prime_smaller_than_k(k)

    def exp_mod(self, m, alpha, q):
        m = int(m)

        if npkg.is_prime(q):
            m %= q - 1
        return npkg.exp_mod(alpha, m, q)
        # return alpha**m % q

    def gen_pv_key(self):
        if self.q == -1:
            print('q is not initialized')
            return
        if self.alpha == -1:
            print('alpha is not initialized')
            return
        self.change_pv_key(1000)
        return self.exp_mod(self.pv_key, self.alpha, self.q)

    def gen_shared_key(self, cipher_key):
        cipher_key = int(cipher_key)
        return self.exp_mod(self.pv_key, cipher_key, self.q)
