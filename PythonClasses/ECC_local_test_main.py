#!/usr/bin/env python3

from ECC_Class import ECC
import Number_Package as npkg

ecc = ECC([9, 17], 23)

print(ecc.mult_inv_mod_N(6))

P = (16, 5)

Q = P

for i in range(8):
    Q = ecc.add(Q, P)
    print(i+2, Q)

for i in range(8):
    Q = ecc.minus(Q, P)
    print(i+2, Q)

print(npkg.jacobi(2, 3))
