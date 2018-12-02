#!/usr/bin/env python3

from User_Class import User
import PythonClasses.Constants as Constants

def print_pkg_info(pkg_info):
    for key in Constants.PKG_INFO_ITEMS:
        if pkg_info[key]:
            print(key, ":", pkg_info[key])

alice = User(user_id=1234)
bob = User(user_id=4321)

#%% HELLO_MSG
pkg_info = alice.pkg_info_init_gen()
pkg_info["PKG_TYPE_ID"] = Constants.PKG_TYPE_ID_DICT["HELLO_MSG"]
pkg_info["NONCE"] = alice.nonce_gen()
pkg_info["SRC_ID"] = 13
pkg_info["PUBLIC_KEY"] = 123
pkg_info["NEGO_PARAMS"] = "hahaha||hahahah"  # "||" should be correctly interpreted

pkg_msg = alice.pkg_gen(pkg_info)
print(pkg_msg)

print("="*60)
pkg_info_inter = alice.pkg_interp(pkg_msg)
print_pkg_info(pkg_info_inter)

#%% ACK_CERT
pkg_info["PKG_TYPE_ID"] = Constants.PKG_TYPE_ID_DICT["ACK_CERT"]
pkg_info["NONCE"] = alice.nonce_gen()
pkg_info["HMAC"] = "HMAC"
pkg_info["DST_ID"] = 998
pkg_info["CERT"] = "hahaha||hahahah"  # "||" should be correctly interpreted

pkg_msg = alice.pkg_gen(pkg_info)
print(pkg_msg)

print("="*60)
print(alice.public_key_str)
bob.cur_dst_user_info["public_key_str"]=alice.public_key_str
bob.cur_dst_user_info["user_id"] = alice.user_id
pkg_info_inter = bob.pkg_interp(pkg_msg)
print_pkg_info(pkg_info_inter)


HMAC = alice.HMAC_gen(pkg_msg, [12, 13])

print(HMAC)

print(alice.HMAC_check(HMAC, [pkg_msg], [12, 13]))
