#!/usr/bin/env python3

from User_Class import User
import PythonClasses.Constants as Constants
from PythonClasses.RSA_Class import RSA
import numpy as np

def print_pkg_info(pkg_info):
    for key in Constants.PKG_INFO_ITEMS:
        if pkg_info[key]:
            print(key, ":", pkg_info[key])

alice = User(user_id=1234)
bob = User(user_id=4321)
alice_ip = '192.168.31.1'
bob_ip = '192.168.31.2'

print("="*50)
alice_HELLO_MSG_pkg_info = alice.HELLO_MSG_gen(nego_choices=['RSA', 'DES', 'SHA1'])
pkg_msg = alice.pkg_gen(alice_HELLO_MSG_pkg_info)
print_pkg_info(alice_HELLO_MSG_pkg_info)

print("-"*50)
print("bob -> ACK CERT")

_, bob_resp = bob.respond_state_machine(pkg_msg, alice_ip)
print_pkg_info(alice.pkg_interp(bob_resp))

print("-"*50)
print("alice -> CERT RPY")
_, alice_resp = alice.respond_state_machine(bob_resp, bob_ip)
print_pkg_info(bob.pkg_interp(alice_resp))

print("-"*50)
print("bob -> KEY REQ")
_, bob_resp = bob.respond_state_machine(alice_resp, alice_ip)
print_pkg_info(alice.pkg_interp(bob_resp))

print("-"*50)
print("alice -> KEY RPY")
_, alice_resp = alice.respond_state_machine(bob_resp, bob_ip)
print_pkg_info(bob.pkg_interp(alice_resp))

print("-"*50)
print("bob digests KEY RPY and send back ACK message")
_, bob_resp = bob.respond_state_machine(alice_resp, alice_ip)
print_pkg_info(alice.pkg_interp(bob_resp))

print("-"*50)
print("alice starts communication")
_, alice_resp = alice.respond_state_machine(bob_resp, bob_ip)

print("-"*50)
print("alice talks once")
alice_msg = alice.send_message("Hi Bob, how are you doing?")
_, bob_resp = bob.respond_state_machine(alice_msg, alice_ip)
_, alice_resp = alice.respond_state_machine(bob_resp, bob_ip)

print("-"*50)
print("alice talks twice")
alice_msg = alice.send_message("Hi Bob, how are you doing? Can you hear me?")
_, bob_resp = bob.respond_state_machine(alice_msg, alice_ip)
_, alice_resp = alice.respond_state_machine(bob_resp, bob_ip)

print("-"*50)
print("alice talks thrice")
alice_msg = alice.send_message("What?")
_, bob_resp = bob.respond_state_machine(alice_msg, alice_ip)
_, alice_resp = alice.respond_state_machine(bob_resp, bob_ip)

print("-"*50)
print("alice talks frice")
alice_msg = alice.send_message("What?")
_, bob_resp = bob.respond_state_machine(alice_msg, alice_ip)
_, alice_resp = alice.respond_state_machine(bob_resp, bob_ip)

print("-"*50)
print("alice -> DISCON REQ")
alice_msg = alice.disconnect()
print_pkg_info(bob.pkg_interp(alice_msg))

print("-"*50)
print("bob -> DISCON CLG")
_, bob_resp = bob.respond_state_machine(alice_msg, alice_ip)
print_pkg_info(alice.pkg_interp(bob_resp))

print("-"*50)
print("alice -> DISCON RPY")
_, alice_resp = alice.respond_state_machine(bob_resp, bob_ip)
print_pkg_info(bob.pkg_interp(alice_resp))

print("-"*50)
print("bob -> disconnects")
_, bob_resp = bob.respond_state_machine(alice_resp, alice_ip)
