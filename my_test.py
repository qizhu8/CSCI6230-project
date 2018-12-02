#!/usr/bin/env python3
from PythonClasses.User_Info_DB_Class import User_Info_DB
import PythonClasses.Constants as Constants
import time
import numpy as np
import PythonClasses.Number_Package as npkg
from PythonClasses.RSA_Class import RSA
from PythonClasses.DES_Class import DES

from PythonClasses.Blum_Goldwessar_Class import BG
from PythonClasses.SHA1_Class import SHA1
import hashlib
from PythonClasses.HMAC_Class import HMAC
import hmac
from User_Class import User

def print_pkg_info(pkg_info):
    for key in Constants.PKG_INFO_ITEMS:
        if pkg_info[key]:
            print(key, ":", pkg_info[key])

# user_info_db = User_Info_DB()
# user_info_db.add_user(user_id=135, ip="192.168.31.31")
# print("add a user twice")
# user_info_db.add_user(user_id=135, ip="192.168.31.32")
# print("check: number of users:", len(user_info_db.user_behave_db))
#
# user_info_db.add_user(user_id=133, ip="192.168.31.128")
# user_info_db.add_record(user_id=133, behavior="DoS_ATK")
# print(user_info_db.check_user(user_id=133))
#
# user_info_db.add_user(user_id=999, ip="192.168.31.128")
#
# print(user_info_db.check_ip("192.168.31.128"))
# print(user_info_db.check_ip("192.168.31.31"))
# print(user_info_db.check_ip("192.168.31.131")) # new ip

alice = User(user_id=1234)
bob = User(user_id=4321)

print("="*40)
nego_choices = ['RSA', 'DES', 'SHA1']
alice_HELLO_MSG_pkg_info = alice.HELLO_MSG_gen(nego_choices)
alice_HELLO_MSG_pkg_info_interp = bob.pkg_interp(alice.pkg_gen(alice_HELLO_MSG_pkg_info))
print_pkg_info(alice_HELLO_MSG_pkg_info_interp)
bob.cur_dst_user_info['public_key_str']=alice.public_key_str


print("="*40)
alice_ACK_CERT_pkg_info = alice.ACK_CERT_gen()
alice_ACK_CERT_pkg_info_interp = bob.pkg_interp(alice.pkg_gen(alice_ACK_CERT_pkg_info))
print_pkg_info(alice_ACK_CERT_pkg_info_interp)
alice.cur_dst_user_info['public_key_str']=bob.public_key_str

print("="*40)
alice_DNY_MSG_pkg_info = alice.DNY_MSG_gen(1)
alice_DNY_MSG_pkg_info_interp = bob.pkg_interp(alice.pkg_gen(alice_DNY_MSG_pkg_info))
print_pkg_info(alice_DNY_MSG_pkg_info_interp)

# print("="*40)
# alice_CERT_REQ_pkg_info = alice.CERT_REQ_gen()
# alice_CERT_REQ_pkg_info_interp = bob.pkg_interp(alice.pkg_gen(alice_CERT_REQ_pkg_info))
# print_pkg_info(alice_CERT_REQ_pkg_info_interp)

print("="*40, "CERT_RPY")
alice_CERT_RPY_pkg_info = alice.CERT_RPY_gen()
alice_CERT_RPY_pkg_info_interp = bob.pkg_interp(alice.pkg_gen(alice_CERT_RPY_pkg_info))
print_pkg_info(alice_CERT_RPY_pkg_info_interp)

print("="*40)
alice_CERT_ERR_pkg_info = alice.CERT_ERR_gen(3)
alice_CERT_ERR_pkg_info_interp = bob.pkg_interp(alice.pkg_gen(alice_CERT_ERR_pkg_info))
print_pkg_info(alice_CERT_ERR_pkg_info_interp)

print("="*40)
alice.PKC_obj = BG()
# alice.PKC_obj = RSA()

alice.PKC_obj.random_private_key()
alice_KEY_REQ_pkg_info = alice.KEY_REQ_gen()
alice_KEY_REQ_pkg_info_interp = bob.pkg_interp(alice.pkg_gen(alice_KEY_REQ_pkg_info))
print_pkg_info(alice_KEY_REQ_pkg_info_interp)

print("="*40)
bob.PKC_obj = BG()
bob.PKC_obj.set_n(int(alice_KEY_REQ_pkg_info_interp['KEY_INFO']))
# bob.PKC_obj.set_p(alice.PKC_obj.p)
# bob.PKC_obj.set_q(alice.PKC_obj.q)

# bob.PKC_obj = RSA()
# bob.PKC_obj.set_e_N(alice.PKC_obj.e, alice.PKC_obj.N)

bob.SymmEnc_obj = DES()
bob.SymmEnc_obj.random_key()
bob_KEY_RPY_info = bob.KEY_RPY_gen()
bob_KEY_RPY_info_interp = alice.pkg_interp(bob.pkg_gen(bob_KEY_RPY_info))
print_pkg_info(bob_KEY_RPY_info_interp)

print("="*40)
alice.SymmEnc_obj = DES()
key_with_padding = alice.PKC_obj.decrypt(bob_KEY_RPY_info_interp['KEY_INFO'], bin_on=True)
print(key_with_padding, "@@@@", len(key_with_padding))
print("str 2 change:", key_with_padding[:-19])
alice.SymmEnc_obj.init_key=int(key_with_padding[:-19], 2)
print("bob send:", bob.SymmEnc_obj.init_key)
print("alice get:", alice.SymmEnc_obj.init_key)

bob_KEY_ERR_info = bob.KEY_ERR_gen()
bob_KEY_ERR_info_interp = alice.pkg_interp(bob.pkg_gen(bob_KEY_ERR_info))
print_pkg_info(bob_KEY_ERR_info_interp)

print("="*40 + "MSG")
bob_COM_MSG_info = bob.COM_MSG_gen("hello")
print_pkg_info(bob_COM_MSG_info)
print("="*40 + "MSG")
bob_COM_MSG_info_interp = alice.pkg_interp(bob.pkg_gen(bob_COM_MSG_info))
print_pkg_info(bob_COM_MSG_info_interp)
print(alice.SymmEnc_obj.decrypt(bob_COM_MSG_info_interp['PAYLOAD']))


print("="*40 + "MSG")
bob_COM_ERR_info = bob.COM_ERR_gen(1)
bob_COM_ERR_info_interp = alice.pkg_interp(bob.pkg_gen(bob_COM_ERR_info))
print_pkg_info(bob_COM_ERR_info_interp)

print("="*40)
bob_DISCON_REQ_info = bob.DISCON_REQ_gen()
bob_DISCON_REQ_info_interp = alice.pkg_interp(bob.pkg_gen(bob_DISCON_REQ_info))
print_pkg_info(bob_DISCON_REQ_info_interp)

print("="*40)
bob_DISCON_CLG_info = bob.DISCON_CLG_gen()
bob_DISCON_CLG_info_interp = alice.pkg_interp(bob.pkg_gen(bob_DISCON_CLG_info))
print_pkg_info(bob_DISCON_CLG_info_interp)

print("="*40)
bob_DISCON_RPY_info = alice.DISCON_RPY_gen(bob_DISCON_CLG_info_interp["CHALLG"])
bob_DISCON_RPY_info_interp = bob.pkg_interp(alice.pkg_gen(bob_DISCON_RPY_info))
print_pkg_info(bob_DISCON_RPY_info_interp)

bob.cur_dst_user_info['public_key'] = alice.sign_obj.get_public_key()
print(bob.CHALLG_check(bob_DISCON_RPY_info_interp['CHALLG_RPY']))

print("="*40)
bob_DISCON_ERR_info = bob.DISCON_ERR_gen(1)
bob_DISCON_ERR_info_interp = alice.pkg_interp(bob.pkg_gen(bob_DISCON_ERR_info))
print_pkg_info(bob_DISCON_ERR_info_interp)
