#!/usr/bin/env python3

"""
Alice is the starter of the conversation. Alice wants to talk to Bob.

Alice should know:
    Bob's ip

Alice should run the program after Bob
"""
from User_Class import User

import socket
import os
import sys
import time

# Choice_of_protocol = ["RSA", "DES", "SHA1"]
Choice_of_protocol = ["BG", "DES", "SHA1"]
messages_to_send = ["Hi Bob, this is Alice, how are you doing?", "Hi Bob, how are you doing? Can you hear me?", "What?", "What?"]


bob_host, bob_port = '127.0.0.1', 9200

Alice = User()

# Alice starts the handshake
try:
    sock_self = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_self.connect((bob_host, bob_port))
    print('connecting to bob')
    # talk to bob
    alice_HELLO_MSG_pkg_info = Alice.HELLO_MSG_gen(nego_choices=['RSA', 'DES', 'SHA1'])
    sock_self.send(Alice.pkg_gen(alice_HELLO_MSG_pkg_info).encode())

    for rounds in range(3):
        bob_resp = sock_self.recv(1024).decode()
        need_response, alice_resp, terminal_signal = Alice.respond_state_machine(bob_resp, bob_host)
        if need_response or terminal_signal:
            sock_self.send(alice_resp.encode())
        else:
            break;
except socket.error as msg:
    if msg.args[0] == 61:
        print("Bob is not online, maybe tomorrow.")
    else:
        print(msg);
    sys.exit(1)

print(Alice.cur_comm_state)
for message in messages_to_send:
    Alice_message = Alice.send_message(message)
    sock_self.send(Alice_message.encode())
    bob_resp = sock_self.recv(1024).decode()
    need_response, alice_resp, terminal_signal = Alice.respond_state_machine(bob_resp, bob_host)
    if terminal_signal:
        break

try:
    Alice_msg = Alice.disconnect()
    sock_self.send(Alice_msg.encode())
    for rounds in range(3):
        bob_resp = sock_self.recv(1024).decode()
        need_response, Alice_msg, terminal_signal = Alice.respond_state_machine(bob_resp, bob_host)
        if need_response or not terminal_signal:
            sock_self.send(Alice_msg.encode())
        else:
            break;
    sock_self.close()
except BrokenPipeError as e:
    print("Bob left")
