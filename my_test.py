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

def print_pkg_info(pkg_info):
    for key in Constants.PKG_INFO_ITEMS:
        if pkg_info[key]:
            print(key, ":", pkg_info[key])

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

alice = User(user_id=1234)
bob = User(user_id=4321)

nego_choices = ['RSA', 'DES', 'SHA1']
alice_pkg_info = alice.ACK_CERT_gen(nego_choices)
print(alice_pkg_info)
