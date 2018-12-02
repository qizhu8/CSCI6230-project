#!/usr/bin/env python3
from PythonClasses.SHA1_Class import SHA1



def HMAC(m, k):

    trans_5C = "".join ([chr (x ^ 0x5C) for x in range(256)])
    trans_36 = "".join ([chr (x ^ 0x36) for x in range(256)])

    k = k + chr(0) * (64 - len(k))

    inner_msg = k.translate(trans_36) + m
    inner_hash = SHA1().hash(inner_msg.encode())
    inner_digest = bytes.fromhex(inner_hash)

    outer_msg_2 = k.translate(trans_5C).encode() + inner_digest # different from line 29
    result = SHA1().hash(outer_msg_2)
    return result

# # for test
# import hmac
# result = hmac.new(KEY.encode('utf-8'), MESSAGE.encode('utf-8'), hashlib.sha1).hexdigest()
# print(result) # prints 2d93cbc1be167bcb1637a4a23cbff01a7878f0c50ee833954ea5221bb1b8c628
