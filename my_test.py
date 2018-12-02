#!/usr/bin/env python3
from PythonClasses.User_Info_DB_Class import User_Info_DB
import PythonClasses.Constants as Constants
import time
import numpy as np
import PythonClasses.Number_Package as npkg
from PythonClasses.RSA_Class import RSA
from PythonClasses.SHA1_Class import SHA1
import hashlib
from PythonClasses.HMAC_Class import HMAC
import hmac
from User_Class import User

user_info_db = User_Info_DB()
user_info_db.add_user(user_id=135, ip="192.168.31.31")
print("add a user twice")
user_info_db.add_user(user_id=135, ip="192.168.31.32")
print("check: number of users:", len(user_info_db.user_behave_db))

user_info_db.add_user(user_id=133, ip="192.168.31.128")
user_info_db.add_record(user_id=133, behavior="DoS_ATK")
print(user_info_db.check_user(user_id=133))

user_info_db.add_user(user_id=999, ip="192.168.31.128")

print(user_info_db.check_ip("192.168.31.128"))
print(user_info_db.check_ip("192.168.31.31"))
print(user_info_db.check_ip("192.168.31.131")) # new ip


#
#
# m = "abc"
# S = SHA1()
# hashed = S.hash(m.encode())
# print(hashed)
#
#
# hashlib_rst = hashlib.sha1(m.encode()).hexdigest()
# print(hashed)
#
#
#
#
# m, k = "123", "oqwiejrhaskdf"
#
# print(HMAC(m=m, k=k))
#
# print(hmac.new(k.encode('utf-8'), m.encode('utf-8'), hashlib.sha1).hexdigest())
#
# print(m)
#
#
#
# rsa = RSA()
# print(rsa.get_public_key())
#
# c = rsa.sign(123123123123123123)
# p = rsa.de_sign(c)
# print(c, p)
#
# alice = User()
#
# print(alice.cert)
# print(alice.public_key)
# cert = "4563|1543692210.0468721|451628423787981108"
# SRC_ID =4563
# N, e = 4611686044196354491, 3152956804623902679
# print(alice.cert_check(cert=cert, SRC_ID=SRC_ID, N=N, e=e))
#
# N, e = alice.public_key
# print(alice.cert_check(cert=alice.cert, SRC_ID=alice.user_id, N=N, e=e))
#
# print(alice.SRC_ID_check("123asd"))
#

p, q, n = npkg.blum_interger_generator(2**32, 2**10)
print(p, q, n)
