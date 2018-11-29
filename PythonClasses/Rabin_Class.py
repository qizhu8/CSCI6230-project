#!/usr/bin/env python3
import Number_Package as npkg

class Rabin(object):
    """docstring for Rabin."""
    def __init__(self, p=-1, q=-1):
        self.p = -1
        self.q = -1
        self.n = -1
        self.b = -1
        if p != -1:
            self.set_p(p)
        if p != -1:
            self.set_q(q)

    def __str__(self):
        str_format="Rabin Encryption\np:{p}\nq:{q}\nb:{b}\nn:{n}".format(p=self.p, q=self.q, b=self.b, n=self.n)
        return str_format

    def set_p(self, p):
        if npkg.is_prime(p):
            if p % 4 == 3:
                self.p = p
                if self.q != -1:
                    self.update_n()
            else:
                raise Exception("p should satisfy p mod 4 = 3")
        else:
            raise Exception("p should be a prime number")

    def set_q(self, q):
        if npkg.is_prime(q):
            if q % 4 == 3:
                self.q = q
                if self.p != -1:
                    self.update_n()
            else:
                raise Exception("q should satisfy q mod 4 = 3")
        else:
            raise Exception("q should be a prime number")

    def update_n(self):
        if self.p != -1 and self.q != -1:
            self.n = self.p * self.q
        else:
            raise Exception("p and q should both be prime numbers")

    def set_n(self, n, check=True):
        is_blum_flag = True
        if check:
            is_blum_flag = npkg.is_blum(n)
        if is_blum_flag and n > 21:
            self.n = n
        else:
            raise Exception("n should be a blum integer")

    def choose_b(self):
        if self.n != -1:
            self.b = np.random.randint(1, self.n)
            return self.b
        else:
            raise Exception("Use set_n() or set_p and set_q() to set a blum value to n")

    def set_b(self, b):
        if self.n == -1:
            raise Exception("Use set_n() or set_p and set_q() to set a blum value to n")
        if b >= 0 and b < self.n:
            self.b = b
        else:
            raise Exception("b should be in [0, n)")

    def encrypt_m(self, m):
        if self.b == -1:
            b = self.choose_b()
            print("choose b to be", b)
        m = int(m) % self.n
        c = (m * (m + self.b)) % self.n
        return c

    def decrypt_c(self, c):
        if self.b == -1: # b != 0 implies n != 0
            raise Exception("Please specify b using set_b()")
        if self.p == -1 or self.q == -1:
            raise Exception("Please use set_p() and set_q() to set numbers to p and q")
        delta_c = (self.b * self.b + 4 * c) % self.n
        # r = npkg.exp_mod(c, (self.p+1)/4, self.p)
        # s = npkg.exp_mod(c, (self.q+1)/4, self.q)
        r = npkg.exp_mod(delta_c, (self.p+1)/4, self.p)
        s = npkg.exp_mod(delta_c, (self.q+1)/4, self.q)
        p_inv = npkg.mult_inv_mod_N(self.p, self.q)
        q_inv = npkg.mult_inv_mod_N(self.q, self.p)

        t = (p_inv * self.p * s + q_inv * self.q * r) % self.n
        u = (p_inv * self.p * s - q_inv * self.q * r) % self.n

        two_inv = npkg.mult_inv_mod_N(2, self.n)

        four_sqrt_delta_c = [t, -t % self.n, u, -u % self.n]
        candidates = [0] * 4
        for idx in range(4):
            rt = four_sqrt_delta_c[idx]
            candidates[idx] = ((rt - self.b) * two_inv) % self.n

        return candidates
