#!/usr/bin/env python3
import numpy as np
import PythonClasses.Number_Package as npkg

class BG(object):
    """docstring for BG."""
    def __init__(self, p=-1, q=-1):
        self.p = -1
        self.q = -1
        self.n = -1
        self.h = -1
        self.h_mask = -1
        if p != -1:
            self.set_p(p)
        if q != -1:
            self.set_q(q)

    def __str__(self):
        str_format="Blum-Goldwessar Probabilistic Encryption\np:{p}\nq:{q}\nn:{n}".format(p=self.p, q=self.q, n=self.n)
        return str_format

    def set_p(self, p):
        p = int(p)
        if p > 0 and p % 4 == 3:
            self.p = p
            if self.p != -1:
                self.update_n()
        else:
            print("p should be a positive integer and p % 4 = 3")

    def set_q(self, q):
        q = int(q)
        if q > 0 and q % 4 ==3:
            self.q = q
            if self.q != -1:
                self.update_n()
        else:
            print("q should be a positive integer and q % 4 = 3")

    def set_n(self, n):
        n = int(n)
        if n > 21:
            self.n = n
            self.update_h()
        else:
            raise Exception("n should be a blum integer")

    def update_n(self):
        if self.p != -1 and self.q != -1:
            self.n = self.p * self.q
            self.update_h()

    def update_h(self):
        if self.n > 21:
            k = int(np.floor(np.log2(self.n)))
            self.h = int(np.floor(np.log2(k)))
            self.h_mask = (2 << (self.h+1))-1
        else:
            raise Exception("please use set_n() to initialize n with a blum integer")

    def encrypt(self, m, x0=-1):
        if isinstance(m, int):
            m = bin(m)

        if self.n == -1:
            raise Exception("Please use set_n() to set n first")

        if x0 == -1:
            x0_sqrt = np.random.randint(self.n)
            x0 = x0_sqrt*x0_sqrt % self.n
            # print("BG chooses x0:", x0)
        t = np.ceil(len(m)/self.h)

        m_group, ciphertext = [], []
        for i in range(0, len(m), self.h):
            m_group.append(m[i:i+self.h])
        if len(m_group[-1]) < self.h:
            m_group[-1] += "0" * (self.h - len(m_group[-1]))

        xi = x0
        for i, mi in enumerate(m_group):
            xi = pow(int(xi), 2, int(self.n))
            # xi = xi * xi % self.n
            pi = xi & self.h_mask
            ci = int(mi, 2) ^ pi
            ciphertext.append(ci)
        ciphertext.append(xi)
        ciphertext = '|'.join([str(num) for num in ciphertext])
        return ciphertext

    def decrypt(self, c, bin_on=True):
        if isinstance(c, str):
            c = [int(item) for item in c.split('|')]

        if self.p == -1 or self.q == -1:
            raise Exception("Please use set_p() or set_q() to initialize p and q")

        x_end = c[-1]
        t = len(c) - 1
        d1 = npkg.exp_mod((self.p+1)/4, t, self.p-1)
        d2 = npkg.exp_mod((self.q+1)/4, t, self.q-1)
        rp = npkg.exp_mod(x_end, d1, self.p)
        rq = npkg.exp_mod(x_end, d2, self.q)

        p_inv = npkg.mult_inv_mod_N(self.p, self.q)
        q_inv = npkg.mult_inv_mod_N(self.q, self.p)

        xi = (((self.p * p_inv)% self.n) * rq) % self.n + (((self.q * q_inv) %self.n) * rp) % self.n
        xi %= self.n

        m_dec = ""
        for i, ci in enumerate(c[:-1]):
            # xi = xi * xi % self.n
            xi = pow(int(xi), 2, int(self.n))
            pi = xi & self.h_mask
            mi = ci ^ pi
            mi_bin = bin(mi)[2:]
            mi_bin = "0"*(self.h - len(mi_bin)) + mi_bin
            m_dec += mi_bin

        if bin_on:
            # print("BG dec rst:", m_dec)
            if m_dec[-1] != '0':
                return m_dec
            for i in range(1, len(m_dec)):
                if m_dec[-i] != '0':
                    break
            i -= 1
            return m_dec[:-i]
        else:
            return int(m_dec, 2)


    def get_public_key(self):
        return [self.n]

    def get_public_key_str(self):
        self.update_n()
        return str(self.n)

    def random_private_key(self):
        p, q, n = npkg.blum_interger_generator(2**21, 2**19)
        # r = np.random.randint(n)
        # x0 = r * r % n
        self.set_p(p)
        self.set_q(q)
        return p, q
