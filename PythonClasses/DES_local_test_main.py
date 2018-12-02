# -*- coding: utf-8 -*-
#!/usr/bin/env python3

import numpy as np
from PythonClasses.DES_Class import DES

import sys
if sys.version_info[0] < 3:
    raise Exception("Must be using Python 3")

# # initial permutation table
# tab_init_P = np.array([2, 6, 3, 1, 4, 8, 5, 7]) - 1
# # Inverse initial permutation table
# tab_inv_P = np.array([4, 1, 3, 5, 7, 2, 8, 6]) - 1
#
# ## F function
# # expansion table of the F function
# tab_F_E = np.array([[4, 1, 2, 3], [2, 3, 4, 1]]) - 1
# # substitution tables of the F function's
# tab_F_S_0 = np.array([[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]])
# tab_F_S_1 = np.array([[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]])
# # permutation table of the F function
# tab_F_P = np.array([2, 4, 3, 1])- 1
#
# # permutation table for key generation block
# tab_key_P10 = np.array([3, 5, 2, 7, 4, 10, 1, 9, 8, 6]) - 1
# tab_key_P8 = np.array([6, 3, 7, 4, 8, 5, 10, 9]) - 1
#
#
# # test input
plaintext = np.array([1, 1, 0, 1, 0, 0, 1, 0], dtype=bool)
# init_key_10bits = np.array([0, 1, 1, 0, 1, 0, 1, 0, 1, 1], dtype=bool)
init_key_10bits = np.random.randint(0, 2, 10, dtype=bool)
# rounds=2

des = DES()
# des.set_rounds(rounds)
# des.set_init_P_table(tab_init_P)
# des.set_inv_P_table(tab_inv_P)
# des.set_F_E_table(tab_F_E)
# des.set_F_SBoxs_tables(np.array([tab_F_S_0, tab_F_S_1]))
# des.set_F_P_table(tab_F_P)
# des.set_key_init_P_table(tab_key_P10)
# des.set_key_sub_P_table(tab_key_P8)

cipher, _ = des.encrypt_one_byte(plaintext, init_key_10bits)
plaintext_rec, _ = des.decrypt_one_byte(cipher, init_key_10bits)
print("Test on local machine")
print("plaintext    :", plaintext+0)
print("ciphertext   :", cipher+0)
print("plaintext rec:", plaintext_rec+0)

# deal with files
# with open('tx_file.txt', 'rb') as f:
#     bytes = f.read()
#     # for byte in bytes:
#     #     print(type(byte))
#     cipher = des.encrypt(bytes, init_key_10bits)
#     bytes_rec = des.decrypt(cipher, init_key_10bits)
#     print(bytes)
#     print(cipher)
#     print(bytes_rec)
