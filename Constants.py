#!/usr/bin/env python3
from PythonClasses.bidict_Class import bidict

PKG_TYPE_ID_DICT={
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
}

ENCRYPT_ID_DICT={
"RSA": 0x01,
"ECC": 0x02,
"BG": 0x03,
"DES": 0x01,
"SHA1":0x01
}

ERROR_CODE_DICT={
"WRONG_NEGO_PARAMS": 0x01,
"EXPIRED_PKG": 0x02,
"EXPIRED_CERT": 0x03,
"INVALID_CERT": 0x04,
"WRONG_KEY_INFO": 0x05,
"INVALID_PAYLOAD": 0x06,
"DoS_ATK": 0x09
}



PKG_STRUCT_DICT={
"HELLO_MSG": "{PKG_TYPE_ID}||{NONCE}||{SRC_ID}||{NEGO_PARAMS}",
"ACK_CERT": "{PKG_TYPE_ID}||{NONCE}||{HMAC}||{CERT}",
"DNY_MSG": "{PKG_TYPE_ID}||{NONCE}||{HMAC}||{CERT}||{ERR_CODE}",
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
"DISCON_ERR": "{PKG_TYPE_ID}||{NONCE}||{HMAC}",
"Nonce": "{time}" # subject to changes
}

PKG_INFO_ITEMS = ['PKG_TYPE_ID', 'PKG_DESC', 'SRC_ID', 'DST_ID',
'NEGO_PARAMS', 'HMAC', 'CERT', 'NONCE', 'ERR_CODE', 'KEY_INFO', 'PAYLOAD', 'CHALLG']


PAYLOAD_MAX_LENGTH = 1025  # maximum length of the payload
CTRL_INFO_MAX_LENGTH = 256 # maximum length of the control information (including PKG_TYPE_ID, src_id, etc)
MSG_MAX_LENGTH = CTRL_INFO_MAX_LENGTH+PAYLOAD_MAX_LENGTH  # maximum length of the received message
PUNISH_COOLDOWN_TIME = 10  # time to block the ip (sec)
CHALLENGE_ERROR_TIME= 2    # number of times that the receiver can fail the challenge

if __name__ == "__main__":
    bd = bidict(PKG_TYPE_ID_DICT)
    print(bd)                     # {'a': 1, 'b': 2}
    print(bd.inverse)             # {1: ['a'], 2: ['b']}
