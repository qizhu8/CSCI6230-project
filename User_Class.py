#!/usr/bin/env python3
from PythonClasses.bidict_Class import bidict
import PythonClasses.Number_Package as npkg

from PythonClasses.DES_Class import DES

from PythonClasses.Blum_Goldwessar_Class import BG
# from PythonClasses.ECC_Class import ECC
from PythonClasses.RSA_Class import RSA

from PythonClasses.User_Info_DB_Class import User_Info_DB

from PythonClasses.SHA1_Class import SHA1
import PythonClasses.HMAC_Class as HMAC

import PythonClasses.Constants as Constants
import time
import re

import numpy as np


class User(object):
    """docstring for User."""
    def __init__(self, user_id=-1):
        # super(User, self).__init__()
        if user_id > 1 and user_id < Constants.USER_ID_MAX:
            self.user_id = user_id
        else:
            self.user_id = np.random.randint(1, Constants.USER_ID_MAX)
            print("user_id is set to be ", self.user_id)
        self.PKC_obj = None                     # chosen from RSA, ECC and BG
        self.SymmEnc_obj = None                 # currently, DES only
        self.sign_obj = RSA()
        self.public_key = self.sign_obj.get_public_key()              # public key for check
        if isinstance(self.public_key, list):
            self.public_key_str = str(self.public_key[0])
            for item in self.public_key[1:]:
                self.public_key_str += '|' + str(item)
        self.cert = None
        self.cert_update()
        # self.PKG_TYPE_ID_DICT = Constants.PKG_TYPE_ID_DICT  # Package id - package funcionality
        # self.PKG_INFO_ITEMS = Constants.PKG_STRUCT_DICT             # structure of each type of package
        # self.ERROR_CODES = Constants.ERROR_CODE_DICT        # ErrorCode - description
        # self.ENCRYPT_ID_DICT = Constants.ENCRYPT_ID_DICT    # encryption - id
        # self.PKG_INFO_ITEMS = Constants.PKG_INFO_ITEMS              # list of items in the package
        # self.user_state = -1
        self.User_Info_DB = User_Info_DB()              # an object storing (userid: User_info )
        self.delimiter = Constants.DELIMITER            #

        self.cur_dst_user_info = {'user_id':-1, 'public_key_str':None, 'public_key':None, 'PKC_obj':None}
        self.cur_comm_state = -1

    """
    pkg_gen()
    ==============================================
    A function is to generate the package to send

    inputs:
      pkg_info: a dictionary containing nessary informations say: PKG_TYPE_ID, SRC_ID, MSG, etc

    outputs:
        pkg_msg_lst: a list of strings to be sent (even if usually there is only one object in the list)
    """
    def pkg_gen(self, pkg_info):
        PKG_TYPE_ID = pkg_info["PKG_TYPE_ID"]
        PKG_DESC = Constants.PKG_TYPE_ID_DICT.inverse[PKG_TYPE_ID][0]
        print(PKG_DESC)
        if PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["HELLO_MSG"]:
            # pkg_info["PKG_DESC"] = "HELLO_MSG"
            # pkg_info["SRC_ID"] = pkg_msg_list[2]
            # pkg_info["NEGO_PARAMS"] = Constants.DELIMITER.join(pkg_msg_list[3:])

            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            SRC_ID=pkg_info["SRC_ID"],\
            PUBLIC_KEY=self.public_key_str,\
            NEGO_PARAMS=pkg_info["NEGO_PARAMS"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["ACK_CERT"]:
            # pkg_info["PKG_DESC"] = "ACK_CERT"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["DST_ID"] = pkg_msg_list[3]
            # pkg_info["CERT"] = Constants.DELIMITER.join(pkg_msg_list[4:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["DST_ID"], pkg_info["CERT"]], self.public_key_str),\
            DST_ID=pkg_info["DST_ID"],\
            PUBLIC_KEY=self.public_key_str,\
            CERT=pkg_info["CERT"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DNY_MSG"]:
            # pkg_info["PKG_DESC"] = "DNY_MSG"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["ERR_CODE"]], self.public_key_str),\
            ERR_CODE=pkg_info["ERR_CODE"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["CERT_REQ"]:
            # pkg_info["PKG_DESC"] = "CERT_REQ"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["CERT_REQ"]], self.public_key_str)\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["CERT_RPY"]:
            # pkg_info["PKG_DESC"] = "CERT_RPY"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["CERT"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["CERT"]], self.public_key_str),\
            CERT=pkg_info["CERT"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["CERT_ERR"]:
            # pkg_info["PKG_DESC"] = "CERT_ERR"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["ERR_CODE"]], self.public_key_str),\
            ERR_CODE=pkg_info["ERR_CODE"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["KEY_REQ"]:
            # pkg_info["PKG_DESC"] = "KEY_REQ"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["KEY_INFO"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["KEY_INFO"]], self.public_key_str),\
            KEY_INFO=pkg_info["KEY_INFO"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["KEY_RPY"]:
            # pkg_info["PKG_DESC"] = "KEY_RPY"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["KEY_INFO"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["KEY_INFO"]], self.public_key_str),\
            KEY_INFO=pkg_info["KEY_INFO"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["KEY_ERR"]:
            # pkg_info["PKG_DESC"] = "KEY_ERR"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["ERR_CODE"]], self.public_key_str),\
            ERR_CODE=pkg_info["ERR_CODE"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["COM_MSG"]:
            # pkg_info["PKG_DESC"] = "COM_MSG"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["PAYLOAD"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["PAYLOAD"]], self.public_key_str),\
            PAYLOAD=pkg_info["PAYLOAD"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["COM_ERR"]:
            # pkg_info["PKG_DESC"] = "COM_ERR"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["ERR_CODE"]], self.public_key_str),\
            ERR_CODE=pkg_info["ERR_CODE"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_REQ"]:
            # pkg_info["PKG_DESC"] = "DISCON_REQ"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"]], self.public_key_str)\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_CLG"]:
            # pkg_info["PKG_DESC"] = "DISCON_CLG"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["CHALLG"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["CHALLG"]], self.public_key_str),\
            CHALLG=pkg_info["CHALLG"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_RPY"]:
            # pkg_info["PKG_DESC"] = "DISCON_RPY"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["CHALLG_RPY"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["CHALLG_RPY"]], self.public_key_str),\
            CHALLG_RPY=pkg_info["CHALLG_RPY"]\
            )
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_ERR"]:
            # pkg_info["PKG_DESC"] = "DISCON_ERR"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            # pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["ERR_CODE"]], self.public_key_str),\
            ERR_CODE=pkg_info["ERR_CODE"]\
            )
        else: # package type not support
            raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])


        return msg

    """
    pkg_interp()
    ==============================================
    A function to turn received one received message to a dictionary of parameters

    inputs:
        pkg_msg: a STRING of length at most Constants.MSG_MAX_LENGTH

    outputs:
        pkg_info: a dictionary
    """
    def pkg_interp(self, pkg_msg):
        pkg_info = self.pkg_info_init_gen()

        # check pkg type
        pkg_msg_list = pkg_msg.split(Constants.DELIMITER)
        PKG_TYPE_ID_str = pkg_msg_list[0]
        if re.compile('(\d){1,3}').match(PKG_TYPE_ID_str):
            PKG_TYPE_ID = int(PKG_TYPE_ID_str)
        else:
            raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])

        # check nonce
        pkg_info["NONCE"] = pkg_msg_list[1]
        if not self.nonce_check(pkg_info["NONCE"]):
            raise ValueError(Constants.ERROR_CODE_DICT["EXPIRED_PKG"])

        pkg_info["PKG_TYPE_ID"] = PKG_TYPE_ID
        if PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["HELLO_MSG"]:
            if len(pkg_msg_list) < 5:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "HELLO_MSG"
            pkg_info["SRC_ID"] = pkg_msg_list[2]
            pkg_info["PUBLIC_KEY"] = pkg_msg_list[3]
            pkg_info["NEGO_PARAMS"] = Constants.DELIMITER.join(pkg_msg_list[4:])
            self.SRC_ID_check(pkg_info["SRC_ID"])
            self.NEGO_PARAMS_check(pkg_info["NEGO_PARAMS"])

        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["ACK_CERT"]:
            if len(pkg_msg_list) < 6:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "ACK_CERT"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["DST_ID"] = pkg_msg_list[3]
            pkg_info["PUBLIC_KEY"] = pkg_msg_list[4]
            pkg_info["CERT"] = Constants.DELIMITER.join(pkg_msg_list[5:])
            self.DST_ID_check(pkg_info["DST_ID"])
            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"], pkg_info["DST_ID"], pkg_info["CERT"]], self.cur_dst_user_info['public_key_str'])

        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DNY_MSG"]:
            if len(pkg_msg_list) < 3:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "DNY_MSG"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"],pkg_info["NONCE"], pkg_info["ERR_CODE"]], self.cur_dst_user_info['public_key_str'])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["CERT_REQ"]:
            if len(pkg_msg_list) < 3:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "CERT_REQ"
            pkg_info["HMAC"] = pkg_msg_list[2]
            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"]], self.cur_dst_user_info['public_key_str'])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["CERT_RPY"]:
            if len(pkg_msg_list) < 4:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "CERT_RPY"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["CERT"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["CERT"]], self.cur_dst_user_info['public_key_str'])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["CERT_ERR"]:
            if len(pkg_msg_list) < 4:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "CERT_ERR"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["ERR_CODE"]], self.cur_dst_user_info['public_key_str'])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["KEY_REQ"]:
            if len(pkg_msg_list) < 4:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "KEY_REQ"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["KEY_INFO"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["KEY_INFO"]], self.cur_dst_user_info['public_key_str'])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["KEY_RPY"]:
            if len(pkg_msg_list) < 4:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "KEY_RPY"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["KEY_INFO"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["KEY_INFO"]], self.cur_dst_user_info['public_key_str'])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["KEY_ERR"]:
            if len(pkg_msg_list) < 4:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "KEY_ERR"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["ERR_CODE"]], self.cur_dst_user_info['public_key_str'])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["COM_MSG"]:
            if len(pkg_msg_list) < 4:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "COM_MSG"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["PAYLOAD"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["PAYLOAD"]], self.cur_dst_user_info['public_key_str'])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["COM_ERR"]:
            if len(pkg_msg_list) < 4:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "COM_ERR"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["ERR_CODE"]], self.cur_dst_user_info['public_key_str'])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_REQ"]:
            if len(pkg_msg_list) < 3:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "DISCON_REQ"
            pkg_info["HMAC"] = pkg_msg_list[2]
            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"]], self.cur_dst_user_info['public_key_str'])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_CLG"]:
            if len(pkg_msg_list) < 4:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "DISCON_CLG"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["CHALLG"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["CHALLG"]], self.cur_dst_user_info['public_key_str'])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_RPY"]:
            if len(pkg_msg_list) < 4:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "DISCON_RPY"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["CHALLG_RPY"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["CHALLG_RPY"]], self.cur_dst_user_info['public_key_str'])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DISCON_ERR"]:
            if len(pkg_msg_list) < 4:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "DISCON_ERR"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[3:])
            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["ERR_CODE"]], self.cur_dst_user_info['public_key_str'])
        else: # package type not support
            # reply error code to the sender
            raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])

        # need to add HMAC check

        return pkg_info

    """
    pkg_info_init_gen()
    ==============================================
    A function to generate a pkg_info dictionary.

    outputs:
        pkg_info: the dictionary
    """
    def pkg_info_init_gen(self):
        return {key:None for key in Constants.PKG_INFO_ITEMS}


    """
    Check whether inputs are valid
    """
    def SRC_ID_check(self, SRC_ID):
        try:
            SRC_ID = int(SRC_ID)
            if SRC_ID > 0 and SRC_ID < Constants.USER_ID_MAX:
                return True
            else:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
                return False
        except Exception as e:
            raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            return False

    def HMAC_check(self, HMAC_rst, list_of_parts, key):
        if self.HMAC_gen(list_of_parts, str(key)) != HMAC_rst:
            raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            return False
        else:
            return True

    def HMAC_gen(self, list_of_parts, key):
        if isinstance(list_of_parts, list):
            m = ""
            for item in list_of_parts:
                m += str(item)
        else:
            m = str(list_of_parts)
        return HMAC.HMAC(m, str(key))

    def DST_ID_check(self, DST_ID):
        return self.SRC_ID_check(DST_ID)

    def NEGO_PARAMS_check(self, NEGO_PARAMS): # only check whether it has three parts
        nego_param_parts = NEGO_PARAMS.split("|")
        if len(nego_param_parts) != 3:
            raise ValueError(Constants.ERROR_CODE_DICT["WRONG_NEGO_PARAMS"])
            return False
        else:
            return True

    """
    nonce_gen()
    ===========
    outputs:
        nonce: follow the structure in Constants
    """
    def nonce_gen(self):
        nonce = str(time.time())
        return nonce

    """
    nonce_check()
    ==============
    check whether the nonce is valid

    inputs:
        nonce
        rules: dictionary of rules, say t_wind

    output:
        Rst: True/False
        ErrorCode: None or ErrorCode
    """
    def nonce_check(self, nonce):
        now = time.time()
        if now - float(nonce) > Constants.PKG_TOL:
            return False, Constants.ERROR_CODE_DICT("EXPIRED_PKG")
        else:
            return True, None

    """
    respond_state_machine()
    =======================
    React based on the received pkg and current status.

    inputs:
        pkg_rev: received package (string)

    output:
        pkg_send: package to send
    """
    def respond_state_machine(self, pkg_rev, ip):
        pkg_info = self.pkg_interp(pkg_rev) # has some simply sanitary checks
        try:
            if self.cur_comm_state == -1: # expect a HELLO_MSG
                if pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT['HELLO_MSG']:
                    # check whether in black list
                    user_id = int(pkg_info["SRC_ID"])
                    if self.User_Info_DB.check_user(user_id) and self.User_Info_DB.check_ip(ip): # good
                        self.User_Info_DB.add_user(user_id=user_id, ip=ip)
                        # extract SRC_ID, PUBLIC_KEY, NEGO_PARAMS
                        self.cur_dst_user_info['user_id'] = user_id
                        self.cur_dst_user_info['public_key_str'] = pkg_info["PUBLIC_KEY"]
                        if pkg_info["PUBLIC_KEY"].find('|') >= 0:
                            self.cur_dst_user_info['public_key'] = [int(item) for item in pkg_info["PUBLIC_KEY"].split('|')]
                        nego_param_parts = pkg_info["NEGO_PARAMS"].split('|')
                        # PKC algorithm
                        if int(nego_param_parts[0]) == Constants.ENCRYPT_ID_DICT["RSA"]:
                            if len(self.cur_dst_user_info['public_key']) == 2:
                                self.cur_dst_user_info['PKC_obj'] = RSA(n=self.cur_dst_user_info['public_key'][0], e=self.cur_dst_user_info['public_key'][1])
                                self.cur_comm_state = 1 # jump to next state
                            else: # key not valid
                                raise ValueError(Constants.ERROR_CODE_DICT["WRONG_NEGO_PARAMS"])
                        elif int(nego_param_parts[0]) == Constants.ENCRYPT_ID_DICT["BG"]:
                            if len(self.cur_dst_user_info['public_key']) == 1:
                                self.cur_dst_user_info['PKC_obj'] = BG(self.cur_dst_user_info['public_key'][0])
                                self.cur_comm_state = 1 # jump to next state
                            else:
                                raise ValueError(Constants.ERROR_CODE_DICT["WRONG_NEGO_PARAMS"])

                        else:
                            raise ValueError(Constants.ERROR_CODE_DICT["WRONG_NEGO_PARAMS"])
                    else: # has bad records and is in jail
                        # do nothing, until the cooldown time passes
                        pass
                else:
                    raise ValueError(Constants.ERROR_CODE_DICT['INVALID_PKG'])


            elif self.cur_comm_state == 1:
                pass
        except Exception as e:
            # send error package

    """
    cert_update()
    =====================
    Generate/update the certification.
    Certification is generated using
    {USER_ID}|{cert generation time}|{signed hash value of previous two parts}

    Certification will be updated if 1) expired 2) doesn't exist
    """
    def cert_update(self):
        def cert_gen():
            cur_time = str(time.time())

            message = str(self.user_id) + '|' + cur_time
            msg_hash = SHA1().hash(message.encode())[-8:]
            sign = self.sign_obj.sign(int(msg_hash, 16))
            self.cert = message + '|' + str(sign)
        if self.cert is None:
            cert_gen()
            return
        cert_gen_time = float(self.cert.split('|')[1])
        if (time.time() - cert_gen_time) > Constants.CERT_TOL/2:
            cert_gen()
            return

    def cert_check(self, cert, SRC_ID, N, e):
        cert_check_obj = RSA(e=e, N=N)
        cert_parts = self.cert.split('|')
        if len(cert_parts) == 3:
            try:
                cert_SRC_ID = int(cert_parts[0])
                cert_gen_time = float(cert_parts[1])
                cert_sign = int(cert_parts[2])
            except Exception as e:
                return False

            if cert_SRC_ID != SRC_ID: # user not match
                return False
            if (time.time() - cert_gen_time) > Constants.CERT_TOL: # expire
                return False

            message = cert_parts[0] + '|' + cert_parts[1]
            msg_hash = SHA1().hash(message.encode())[-8:]
            return cert_check_obj.check_sign(cert_sign, int(msg_hash, 16))
        else:
            return False


    ####################################

    """
    generate an ACK_CERT pkg_info
    """
    def gen_ACK_CERT(self):
        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["ACK_CERT"]
        pkg_info['PKG_DESC'] = "ACK_CERT"
        pkg_info['DST_ID'] = self.user_id
        pkg_info["PUBLIC_KEY"] = self.public_key_str
        self.cert_update()
        pkg_info["CERT"] = self.cert
        return pkg_info
