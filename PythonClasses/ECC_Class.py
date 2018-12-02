#!/usr/bin/env python3

import numpy as np
import PythonClasses.Number_Package as npkg

class ECC(object):
    """docstring for ECC."""
    def __init__(self, poly_coeff=None, N=-1):
        self.poly_coeff = None
        self.N = -1
        self.set_poly_coeff(poly_coeff)
        self.set_modulo(N)

    def __str__(self):
        if self.poly_coeff is None or self.N == -1:
            str_format = "Elliptic Curve not specified. Please input the coefficients and the modulo using set_poly_coeff() and set_modulo()"
        else:
            str_format="""The Elliptic Curve is:\n y^2 = x^3 + {a}x + {b} mod {N}""".format(a=self.poly_coeff[0], b=self.poly_coeff[-1], N=self.N)
        return str_format

    def set_poly_coeff(self, poly_coeff):
        if isinstance(poly_coeff, list) or isinstance(poly_coeff, tuple):
            try:
                poly_coeff = np.asarray(poly_coeff)
            except Exception as e:
                print(e, "polynomial coefficients should be an 1-d array with two integers")
                raise
        if isinstance(poly_coeff, np.ndarray):
            if poly_coeff.shape != (2, ):
                print("polynomial coefficients should be an 1-d array with two integers")
                return None
        else:
            print("not support input for polynomial coefficients")
            return None

        self.poly_coeff = poly_coeff

    def set_modulo(self, N):
        if N > 1:
            self.N = int(N)
        else:
            print("modulo should be an integer greater than 2.")

    def is_on_EC(self, point):
        if self.N < 0:
            print("please use set_modulo() to set a valid modulo")
            return None
        if isinstance(point, list) or isinstance(point, tuple):
            point = np.asarray(point)
        if isinstance(point, np.ndarray):
            if point.shape != (2,):
                print("input point should be an 1-d array containing two integers")
                return None
        else:
            print("unsupport data type")
            return None

        LHS = (point[1] * point[1]) % self.N
        RHS = (point[0] * point[0] * point[0] + self.poly_coeff[0] * point[0] + self.poly_coeff[1]) % self.N
        return LHS == RHS

    def mult_inv_mod_N(self, t, N=None):
        if N is None:
            N = self.N
        return npkg.mult_inv_mod_N(t, N)

    def add(self, p1, p2):
        if isinstance(p1, list) or isinstance(p1, tuple):
            p1 = np.asarray(p1)
        if isinstance(p2, list) or isinstance(p2, tuple):
            p2 = np.asarray(p2)

        if isinstance(p1, np.ndarray) and p1.shape != (2,):
            print("point 1 should be an 1-d array with two integers")
            return None
        if isinstance(p2, np.ndarray) and p2.shape != (2,):
            print("point 2 should be an 1-d array with two integers")
            return None

        x1, y1, x2, y2 = p1[0], p1[1], p2[0], p2[1]

        if np.isnan(x1) or np.isnan(y1):
            return p2
        if np.isnan(x2) or np.isnan(y2):
            return p1

        if x1 == x2 and y1 == y2:
            denumerator = 2 * y1
            numerator = 3 * x1 * x1 + self.poly_coeff[0]
        else:
            denumerator = x2 - x1
            numerator = y2 - y1
        if denumerator != 0:
            denumerator_inv = npkg.mult_inv_mod_N(denumerator, self.N)
            if denumerator_inv is None:
                print("inverse of ", denumerator, " modulos ", self.N, " doesnt exist.")
                return None
            m = (numerator * denumerator_inv) % self.N

            x3 = (m * m - x1 - x2) % self.N
            y3 = (m * (x1 - x3) - y1) % self.N
            p3 = np.array([x3, y3])

            # print("m={m}, x3={x}, y3={y}".format(m=m, x=(m * m - x1 - x2), y=(m * (x1 - x2) - y1)))
        else:
            p3 = np.array([np.NAN, np.NAN])
        return p3

    def multiply(self, p, k):
        k = int(k)
        if k == 0:
            return np.array([np.NAN, np.NAN])
        if k == 1:
            return p

        k_bin = bin(k)[2:]
        q = np.array([np.NAN, np.NAN])
        for s in k_bin[::-1]:
            if s == '1':
                q = self.add(q, p)
            p = self.add(p, p)
        return q

    def minus(self, p1, p2):
        return self.add(p1, [p2[0], -p2[1]])

    def random_private_key(self):
        self.N = np.random.randint(2**9, 2**10)
        a = np.random.randint(self.N)
        b = np.random.randint(self.N)
        self.set_poly_coeff((a, b))
