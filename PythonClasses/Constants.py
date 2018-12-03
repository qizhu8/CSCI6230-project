#!/usr/bin/env python3
from PythonClasses.bidict_Class import bidict

PKG_TYPE_ID_DICT=bidict({
"HELLO_MSG": 0x00,
"ACK_CERT": 0x01,
"DNY_MSG": 0x0f,
"CERT_REQ": 0x10,
"CERT_RPY": 0x11,
"CERT_ERR": 0x1f,
"KEY_REQ": 0x20,
"KEY_RPY": 0x21,
"KEY_ERR": 0x2f,
"COM_MSG": 0x30,
"COM_ERR": 0x3f,
"DISCON_REQ": 0x40,
"DISCON_CLG": 0x41,
"DISCON_RPY": 0x42,
"DISCON_ERR": 0x4f
})

ENCRYPT_ID_DICT=bidict({
"RSA": 0x01,
# "ECC": 0x02, # map message to a point on ECC has not been resolved yet
"BG": 0x03,
"DES": 0x11,
"SHA1":0x21
})

ERROR_CODE_DICT=bidict({
"WRONG_NEGO_PARAMS": 0x01,
"EXPIRED_PKG": 0x02,
"EXPIRED_CERT": 0x03,
"INVALID_CERT": 0x04,
"WRONG_KEY_INFO": 0x05,
"INVALID_PAYLOAD": 0x06,
"INVALID_PKG": 0x07,
"INVALID_USER_ID": 0x10,
"INVALID_IP": 0x11,
"FAIL_CLG": 0x30,
"BEHAVIOR_UNKNOWN": 0x40,    # no punishment
"DoS_ATK": 0x99
})

BAD_BEHAVIOR=bidict({
"WRONG_NEGO_PARAMS": 1,
"EXPIRED_PKG": 1,
"EXPIRED_CERT": 1,
"INVALID_CERT": 10,
"WRONG_KEY_INFO": 1,
"INVALID_PAYLOAD": 1,
"INVALID_USER_ID": 1,
"INVALID_IP": 1,
"FAIL_CLG": 3,
"DoS_ATK": 10
})


PKG_STRUCT_DICT={
"HELLO_MSG": "{PKG_TYPE_ID}||{NONCE}||{SRC_ID}||{PUBLIC_KEY}||{NEGO_PARAMS}",  # add public key here
"ACK_CERT": "{PKG_TYPE_ID}||{NONCE}||{HMAC}||{DST_ID}||{PUBLIC_KEY}||{CERT}", # add public key here
"DNY_MSG": "{PKG_TYPE_ID}||{NONCE}||{HMAC}||{DST_ID}||{PUBLIC_KEY}||{ERR_CODE}", # add public key here
"CERT_REQ": "{PKG_TYPE_ID}||{NONCE}||{HMAC}",  # subject to changes
"CERT_RPY": "{PKG_TYPE_ID}||{NONCE}||{HMAC}||{CERT}",
"CERT_ERR": "{PKG_TYPE_ID}||{NONCE}||{HMAC}||{ERR_CODE}",
"KEY_REQ": "{PKG_TYPE_ID}||{NONCE}||{HMAC}||{KEY_INFO}",
"KEY_RPY": "{PKG_TYPE_ID}||{NONCE}||{HMAC}||{KEY_INFO}",
"KEY_ERR": "{PKG_TYPE_ID}||{NONCE}||{HMAC}||{ERR_CODE}",
"COM_MSG": "{PKG_TYPE_ID}||{NONCE}||{HMAC}||{PAYLOAD}",
"COM_ERR": "{PKG_TYPE_ID}||{NONCE}||{HMAC}||{ERR_CODE}",
"DISCON_REQ": "{PKG_TYPE_ID}||{NONCE}||{HMAC}",
"DISCON_CLG": "{PKG_TYPE_ID}||{NONCE}||{HMAC}||{CHALLG}",
"DISCON_RPY": "{PKG_TYPE_ID}||{NONCE}||{HMAC}||{CHALLG_RPY}",
"DISCON_ERR": "{PKG_TYPE_ID}||{NONCE}||{HMAC}||{ERR_CODE}",
"Nonce": "{time}" # subject to changes
}

PKG_INFO_ITEMS = ['PKG_TYPE_ID', 'PKG_DESC', 'SRC_ID', 'DST_ID', 'PUBLIC_KEY',
'NEGO_PARAMS', 'HMAC', 'CERT', 'NONCE', 'ERR_CODE', 'KEY_INFO', 'PAYLOAD', 'CHALLG', 'CHALLG_RPY']

USER_STATES = {
    "START": 0,
    "PUNISH": 3,
    "SEND": 1,
    "DISCONNECT": 2,
    "ACCEPT": 4,
}


PAYLOAD_MAX_LENGTH = 1025  # maximum length of the payload
CTRL_INFO_MAX_LENGTH = 256 # maximum length of the control information (including PKG_TYPE_ID, src_id, etc)
MSG_MAX_LENGTH = CTRL_INFO_MAX_LENGTH+PAYLOAD_MAX_LENGTH  # maximum length of the received message
PUNISH_COOLDOWN_TIME = 6   # time to block the ip (sec)
SCORE_TO_PUNISH = 10       # when a user reaches 10 points, punish him

USER_ID_MAX = 10000        # user id is in range 1 to 9999
PKG_TOL = 30               # time of life for a package
CERT_TOL = 600             # validation period for certification
CHALLG_NUMS = 2
DELIMITER="||"

# regularization express quick reference
# "^.{3}$ " : length is exactly 3
# "[0-9]{1,6}" : digits of length 1~6
#


if __name__ == "__main__":
    bd = bidict(PKG_TYPE_ID_DICT)
    print(bd)                     # {'a': 1, 'b': 2}
    print(bd.inverse)             # {1: ['a'], 2: ['b']}
