#!/usr/bin/env python3

import numpy as np
import Number_Package as npkg
from Blum_Goldwessar_Class import BG

p = 499
q = 547
a = -57
b = 52
X0 = 159201
m="10011100000100001100"


Bob = BG()
Bob.set_n(p * q)
Alice = BG(p, q)

ciphertext = Bob.encrypt(m, X0)
m_dec = Alice.decrypt(ciphertext)

print("Ciphertext is")
print(ciphertext)
print("Decryption result")
print(m_dec)
if m == m_dec:
    print("Decryption success")
else:
    print("Decryption failed")
