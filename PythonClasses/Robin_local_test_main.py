#!/usr/bin/env python3

import numpy as np
from Rabin_Class import Rabin
# p = 7
# q = 11
# n = p*q
# b = 0
# m = 20

p = 11
q = 19
n = p*q
b = 183
m = 31


Alice = Rabin(p, q)
Alice.set_b(b)
print(Alice)

Bob = Rabin()
Bob.set_n(n)
Bob.set_b(b)

ciphertext = Bob.encrypt_m(m)
print("ciphertext:", ciphertext)

decryption_candidates = Alice.decrypt_c(ciphertext)
print("Decryption Result Set:", decryption_candidates)
