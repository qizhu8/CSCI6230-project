#!/usr/bin/env python3

import sys
import numpy as np
# import Nonce_Class as Nonce

class Package(object):
    def __init__(self, PKG_TYPE_ID):
        super(Package, self).__init__()
        self.PKG_TYPE_ID_ = PKG_TYPE_ID

    # generate a message:
    def gen(self):
        ret = {
            "PKG_TYPE_ID": self.PKG_TYPE_ID_,
            "NONCE": "current time"
        }
        return ret

    def interpret(self):
        pass

class HELLO_PKG(Package):
    def __init__(self, SRC_ID, NEGO_PARAMS):
        super(HELLO_PKG, self).__init__("HELLO_MSG")
        self.SRC_ID_ = SRC_ID
        self.NEGO_PARAMS_ = NEGO_PARAMS

    def gen(self):
        ret = super(HELLO_PKG, self).gen()
        ret["SRC_ID"] = self.SRC_ID_
        ret["NEGO_PARAMS"] = self.NEGO_PARAMS_
        return ret

class NORM_PKG(Package):
    def gen(self):
        r = super().gen()
        if not type(self) == type(NORM_PKG):
            H = self.get_HMAC()
            r["HMAC"] = H
        return r

    def get_HMAC(self):
        return "HMAC"


class COM_PKG(NORM_PKG):
    pass

class KEY_PKG(NORM_PKG):
    def set_KEY_INFO(self, KEY_INFO):
        self.KEY_INFO_ = KEY_INFO

class CERT_PKG(NORM_PKG):
    def set_CERT(self, CERT):
        self.CERT_ = CERT

class ERR_PKG(NORM_PKG):
    def set_ERR_CODE(self, ERR_CODE):
        self.ERR_CODE_ = ERR_CODE

class CERT_REQ(NORM_PKG):
    pass

class DISCON_PKG(NORM_PKG):
    pass

class KEY_REQ(KEY_PKG):
    def __init__(self):
        super(KEY_REQ, self).__init__("KEY_REQ")

    def gen(self):
        r = super().gen()
        r["KEY_INFO"] = self.KEY_INFO_
        return r

class KEY_RPY(KEY_PKG):
    def __init__(self):
        super(KEY_RPY, self).__init__("KEY_RPY")

    def gen(self):
        r = super().gen()
        r["KEY_INFO"] = self.KEY_INFO_

class ACK_CERT(CERT_PKG):
    def __init__(self):
        super(ACK_CERT, self).__init__("ACK_CERT")

    def gen(self):
        r = super(ACK_CERT, self).gen()
        r["CERT"] = self.CERT_
        return r

class CERT_RPY(CERT_PKG):
    def __init__(self):
        super(CERT_RPY, self).__init__("CERT_RPY")

    def gen(self, CERT):
        r = super(CERT_RPY, self).gen()
        r["CERT"] = self.CERT_
        return r

class DNY_MSG(CERT_PKG, ERR_PKG):
    def __init__(self):
        super(DNY_MSG, self).__init__("DNY_MSG")

    def gen(self):
        r = super().gen()
        r["CERT"] = self.CERT_
        r["ERR_CODE"] = self.ERR_CODE_
        return r

class COM_ERR(COM_PKG, ERR_PKG):
    def __init__(self):
        super().__init__("COM_ERR")

    def gen(self):
        r = super().gen()
        r["ERR_CODE"] = self.ERR_CODE_
        return r

class COM_MSG(COM_PKG):
    def __init__(self):
        super().__init__("COM_MSG")

    def set_PAYLOAD(self, PAYLOAD):
        self.PAYLOAD_ = PAYLOAD

    def gen(self):
        r = super().gen()
        r["PAYLOAD"] = self.PAYLOAD_

class KEY_ERR(KEY_PKG, ERR_PKG):
    def __init__(self):
        super().__init__("KEY_ERR")

    def gen(self):
        r = super().gen()
        r["ERR_CODE"] = self.ERR_CODE_
        return r

class DISCON_REQ(DISCON_PKG):
    def __init__(self):
        super().__init__("DISCON_REQ")


class DISCON_CLG(DISCON_PKG):
    def __init__(self):
        super().__init__("DISCON_CLG")

    def set_CHALLG(self, CHALLG):
        self.CHALLG_ = CHALLG

    def gen(self):
        r = super().gen()
        r["CHALLG"] = self.CHALLG_
        return r

class DISCON_RPY(DISCON_PKG):
    def __init__(self):
        super().__init__("DISCON_RPY")

    def set_CHALLG_RPY(CHALLG_TPY):
        self.CHALLG_RPY_ = CHALLG_RPY

    def gen(self):
        r = super().gen()
        r["CHALLG_RPY"] = self.CHALLG_RPY_
        return r

class DISCON_ERR(DISCON_PKG, ERR_PKG):
    def __init__(self):
        super().__init__("DISCON_ERR")

    def gen(self):
        r = super().gen()
        r["ERR_CODE"] = self.ERR_CODE_
        return r
