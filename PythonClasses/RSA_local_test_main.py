#!/usr/bin/env python3

from PythonClasses.RSA_Class import RSA

rsa1 = RSA()
rsa2 = RSA()

q = rsa1.find_prime_smaller_than_k(10000)
alpha = rsa1.find_prime_smaller_than_k(100)

print(q, alpha)

rsa1.set_q(q)
rsa1.set_alpha(alpha)
rsa2.set_q(q)
rsa2.set_alpha(alpha)

cipher_key_1 = rsa1.gen_pv_key()
cipher_key_2 = rsa2.gen_pv_key()
shared_key_1 = rsa1.gen_shared_key(cipher_key_2)
shared_key_2 = rsa2.gen_shared_key(cipher_key_1)
print(shared_key_1, shared_key_2)
