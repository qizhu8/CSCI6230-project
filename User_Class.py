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
            self.user_id = np.random.randint(2, Constants.USER_ID_MAX)
            print("user_id is set to be ", self.user_id)
        self.PKC_obj = None                     # chosen from RSA, ECC and BG
        self.SymmEnc_obj = None                 # currently, DES only
        self.sign_obj = RSA()
        self.public_key = self.sign_obj.get_public_key()              # public key for check
        self.public_key_str = self.sign_obj.get_public_key_str()   # will be appended with PKC_obj.public_key_str

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

        self.cur_dst_user_info = {'user_id':-1, 'public_key_str':None, 'public_key':None, 'PKC_obj':None, 'CHALLG':None}
        self.cur_comm_state = -1

        # if not specified, this is the auto-reply message set
        self.message_set = ["Sorry, I cannot hear you.", "I'm going to take a shower. See you tomorrow!", "Autoreply, I'm taking a shower"]

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
        pkg_info["NONCE"] = self.nonce_gen()
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
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["DST_ID"], pkg_info["PUBLIC_KEY"], pkg_info["CERT"]], self.public_key_str),\
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
            DST_ID=pkg_info["DST_ID"],\
            PUBLIC_KEY=pkg_info["PUBLIC_KEY"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["DST_ID"], pkg_info["PUBLIC_KEY"], pkg_info["ERR_CODE"]], self.public_key_str),\
            ERR_CODE=pkg_info["ERR_CODE"]\
            )
            # print("gen, ", [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["DST_ID"], pkg_info["PUBLIC_KEY"], pkg_info["ERR_CODE"]])
        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["CERT_REQ"]:
            # pkg_info["PKG_DESC"] = "CERT_REQ"
            # pkg_info["HMAC"] = pkg_msg_list[2]
            msg = Constants.PKG_STRUCT_DICT[PKG_DESC].format(\
            PKG_TYPE_ID=PKG_TYPE_ID,\
            NONCE=pkg_info["NONCE"],\
            HMAC=self.HMAC_gen([pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"]], self.public_key_str)\
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
            self.cur_dst_user_info['public_key_str'] = pkg_msg_list[4]
            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"],pkg_info["NONCE"], pkg_info["DST_ID"],pkg_info["PUBLIC_KEY"], pkg_info["CERT"]], self.cur_dst_user_info['public_key_str'])

        elif PKG_TYPE_ID == Constants.PKG_TYPE_ID_DICT["DNY_MSG"]:
            if len(pkg_msg_list) < 3:
                raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            pkg_info["PKG_DESC"] = "DNY_MSG"
            pkg_info["HMAC"] = pkg_msg_list[2]
            pkg_info["DST_ID"] = pkg_msg_list[3]
            pkg_info["PUBLIC_KEY"] = pkg_msg_list[4]
            pkg_info["ERR_CODE"] = Constants.DELIMITER.join(pkg_msg_list[5:])
            # print("rec pk:", [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["DST_ID"], pkg_info["PUBLIC_KEY"], pkg_info["ERR_CODE"]])
            self.cur_dst_user_info['public_key_str'] = pkg_msg_list[4]

            self.HMAC_check(pkg_info["HMAC"], [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["DST_ID"], pkg_info["PUBLIC_KEY"], pkg_info["ERR_CODE"]], self.cur_dst_user_info['public_key_str'])
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
            # print("HMAC check", [pkg_info["PKG_TYPE_ID"], pkg_info["NONCE"], pkg_info["CERT"]], self.cur_dst_user_info['public_key_str'])
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
        try:
            nonce_float = float(nonce)
        except Exception as e:
            return False, Constants.ERROR_CODE_DICT["INVALID_PKG"]

        if now - nonce_float > Constants.PKG_TOL:
            return False, Constants.ERROR_CODE_DICT["EXPIRED_PKG"]
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
        # ignore too long or too sort messages
        if len(pkg_rev) > Constants.MSG_MAX_LENGTH or len(pkg_rev) < 10:
            return False, None, False
        try:
            print("==========================")
            if not self.User_Info_DB.check_ip(ip): # user in jail, disconnect immediately
                print("user in jail")
                return False, None, True
            pkg_info = self.pkg_interp(pkg_rev) # has some simply sanitary checks
            print("--------------------------")

            # raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            print("receive:", pkg_info["PKG_DESC"])

            # receive error message
            if pkg_info['PKG_TYPE_ID'] in [Constants.PKG_TYPE_ID_DICT['DNY_MSG'], Constants.PKG_TYPE_ID_DICT['CERT_ERR'], Constants.PKG_TYPE_ID_DICT['KEY_ERR'], Constants.PKG_TYPE_ID_DICT['COM_ERR']]:
                print("Encounter Error")
                if pkg_info['ERR_CODE'] is not None and pkg_info['ERR_CODE'] in Constants.ERROR_CODE_DICT.inverse:
                    print("ERROR CODE:", Constants.ERROR_CODE_DICT.inverse[pkg_info['ERR_CODE']])
                self.cur_comm_state = -1
                self.sign_obj = RSA()
                self.public_key = self.sign_obj.get_public_key()              # public key for check
                self.public_key_str = self.sign_obj.get_public_key_str()   # will be appended with PKC_obj.public_key_str

                self.cert = None

                return False, None, True


            if self.cur_comm_state == -1: # initial state  expect hello msg
                if pkg_info['PKG_TYPE_ID'] == Constants.PKG_TYPE_ID_DICT['HELLO_MSG']:
                    self.HELLO_MSG_react(pkg_info)
                    resp_pkg_info = self.ACK_CERT_gen()
                    self.cur_comm_state = 1 # expect CERT_RPY
                    self.message_id = 0
                else:
                    raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])

            elif self.cur_comm_state == 0: # user just sent HELLO_MSG,
                if pkg_info['PKG_TYPE_ID'] == Constants.PKG_TYPE_ID_DICT['ACK_CERT']:
                    self.ACK_CERT_react(pkg_info)
                    resp_pkg_info = self.CERT_RPY_gen()
                    self.cur_comm_state = 2 # expect key exchange
                    self.message_id = 0
                else:
                    raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])


            elif self.cur_comm_state == 1: # expect certification CERT_RPY
                if pkg_info['PKG_TYPE_ID'] == Constants.PKG_TYPE_ID_DICT['CERT_RPY']:
                    self.CERT_RPY_react(pkg_info)
                    resp_pkg_info = self.KEY_REQ_gen()
                    self.cur_comm_state = 3 # expect key rpy
                else: # potential DOS ATTACK
                    raise ValueError(Constants.ERROR_CODE_DICT["DoS_ATK"])

            elif self.cur_comm_state == 2: # receive key req:
                if pkg_info['PKG_TYPE_ID'] == Constants.PKG_TYPE_ID_DICT['KEY_REQ']:
                    self.KEY_REQ_react(pkg_info)
                    resp_pkg_info = self.KEY_RPY_gen()
                    self.cur_comm_state = 4 # expect comm message
                else:
                    raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])


            elif self.cur_comm_state == 3: # receive key rpy
                if pkg_info['PKG_TYPE_ID'] == Constants.PKG_TYPE_ID_DICT['KEY_RPY']:
                    self.KEY_RPY_react(pkg_info)
                    resp_pkg_info = self.COM_MSG_gen(message="Good to go")
                    self.cur_comm_state = 5 # talking......
                else:
                    raise ValueError(Constants.ERROR_CODE_DICT["WRONG_KEY_INFO"])

            elif self.cur_comm_state == 4: # start taking
                if pkg_info['PKG_TYPE_ID'] == Constants.PKG_TYPE_ID_DICT['COM_MSG']:
                    self.COM_MSG_react(pkg_info)
                    # print("=====Successfully connects to the remote=====")
                    # resp_pkg_info = self.COM_MSG_gen(message="I'm Ready")
                    self.cur_comm_state = 5 # expect session key
                    return False, None, False
                else:
                    raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])

            elif self.cur_comm_state == 5: # send random messages
                if pkg_info['PKG_TYPE_ID'] == Constants.PKG_TYPE_ID_DICT['COM_MSG']:
                    self.COM_MSG_react(pkg_info)

                    resp_pkg_info = self.COM_MSG_gen(message=self.message_set[self.message_id % len(self.message_set)])
                    self.message_id = min(self.message_id+1, len(self.message_set)-1)

                elif pkg_info['PKG_TYPE_ID'] == Constants.PKG_TYPE_ID_DICT['DISCON_REQ']:
                    resp_pkg_info = self.DISCON_CLG_gen()
                    self.cur_comm_state = 8 # expect challenge reply
                else:
                    raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])

            elif self.cur_comm_state == 7: # sent DISCON_REQ
                if pkg_info['PKG_TYPE_ID'] == Constants.PKG_TYPE_ID_DICT['DISCON_CLG']:
                    # after replying, do nothing
                    resp_pkg_info = self.DISCON_RPY_gen(pkg_info["CHALLG"])
                    self.cur_comm_state = 9 # expect challenge reply
                else:
                    raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])


            elif self.cur_comm_state == 8: # sent DISCON_CLG
                if pkg_info['PKG_TYPE_ID'] == Constants.PKG_TYPE_ID_DICT['DISCON_RPY']:
                    if self.CHALLG_check(pkg_info['CHALLG_RPY']):
                        print("disconnect accept")
                        self.cur_comm_state = -1
                        self.sign_obj = RSA()
                        self.public_key = self.sign_obj.get_public_key()              # public key for check
                        self.public_key_str = self.sign_obj.get_public_key_str()   # will be appended with PKC_obj.public_key_str

                        self.cert = None
                        return False, None, True
                    else:
                        self.cur_comm_state = 5
                else:
                    raise ValueError(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            elif self.cur_comm_state == 9: # do nothing, no reply, just nothing
                return False, None, False

        except Exception as e:
            # send error package

            if int(str(e)) in [Constants.ERROR_CODE_DICT["EXPIRED_CERT"], Constants.ERROR_CODE_DICT["INVALID_CERT"]]:
                resp_pkg_info = self.CERT_ERR_gen()
                self.User_Info_DB.add_record(ip=ip, behavior="INVALID_CERT")
            elif int(str(e)) == Constants.ERROR_CODE_DICT["DoS_ATK"]:
                resp_pkg_info = self.DNY_MSG_gen(str(e))
                self.User_Info_DB.add_record(ip=ip, behavior="DoS_ATK")
            else:
                resp_pkg_info = self.DNY_MSG_gen(str(e))
                self.User_Info_DB.add_record(ip=ip, behavior="INVALID_PKG")
            # encounter any of them, start from scratch
            self.cur_comm_state = -1
            self.sign_obj = RSA()
            self.public_key = self.sign_obj.get_public_key()              # public key for check
            self.public_key_str = self.sign_obj.get_public_key_str()   # will be appended with PKC_obj.public_key_str

            self.cert = None
            return True, self.pkg_gen(resp_pkg_info), True



        return True, self.pkg_gen(resp_pkg_info), False

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
        # print("check:", cert, SRC_ID, N, e)
        print("checking cert")
        cert_check_obj = RSA(e=e, N=N)
        cert_parts = cert.split('|')
        if len(cert_parts) == 3:

            try:
                cert_SRC_ID = int(cert_parts[0])
                cert_gen_time = float(cert_parts[1])
                cert_sign = int(cert_parts[2])
            except Exception as e:
                return False

            if cert_SRC_ID != SRC_ID: # user not match
                print("SRC_ID not match")
                return False
            if (time.time() - cert_gen_time) > Constants.CERT_TOL: # expire
                print("CERT expires")
                return False
            message = cert_parts[0] + '|' + cert_parts[1]
            msg_hash = SHA1().hash(message.encode())[-8:]
            return cert_check_obj.check_sign(cert_sign, int(msg_hash, 16))
            # return True # for debug
        else:
            return False
            # return True # for debug


    def CHALLG_check(self, CHALLG_RPY_str):
        CHALLG_RPY = [int(num) for num in CHALLG_RPY_str.split('|')]
        rsa = RSA(N=self.cur_dst_user_info['public_key'][0], e=self.cur_dst_user_info['public_key'][1])
        check_rst = [rsa.check_sign(CHALLG_RPY[i], self.cur_dst_user_info['CHALLG'][i]) for i in range(len(CHALLG_RPY))]
        if sum(check_rst) > 0:
            return True
        else:
            return False
    ####################################

    """
    generate a HELLO_MSG pkg_info
    """
    def HELLO_MSG_gen(self, nego_choices=['RSA', 'DES', 'SHA1']):
        self.cur_comm_state = 0 #

        if nego_choices[0] == 'RSA':
            self.PKC_obj = RSA()
            self.PKC_obj.random_private_key()
            self.cur_dst_user_info['PKC_obj'] = RSA()
            self.public_key_str += "@" + self.PKC_obj.get_public_key_str()
        elif nego_choices[0] == 'BG':
            self.PKC_obj = BG()
            self.PKC_obj.random_private_key()
            self.cur_dst_user_info['PKC_obj'] = BG()
            self.public_key_str += "@" + self.PKC_obj.get_public_key_str()


        if nego_choices[1] == 'DES':
            self.SymmEnc_obj = DES()
        self.SymmEnc_obj.random_key()


        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["HELLO_MSG"]
        pkg_info['PKG_DESC'] = "HELLO_MSG"
        pkg_info['SRC_ID'] = self.user_id
        pkg_info["PUBLIC_KEY"] = self.public_key_str
        pkg_info['NEGO_PARAMS'] = '|'.join([str(Constants.ENCRYPT_ID_DICT[ID]) for ID in nego_choices])


        return pkg_info

    def HELLO_MSG_react(self, pkg_info):
        nego_choices = pkg_info['NEGO_PARAMS'].split('|')
        public_key_str_parts = pkg_info['PUBLIC_KEY'].split('@')

        try: # extract keys for signature
            self.cur_dst_user_info['public_key_str'] = pkg_info["PUBLIC_KEY"]
            self.cur_dst_user_info['user_id'] = int(pkg_info['SRC_ID'])
            N_e_str = public_key_str_parts[0].split('|')
            self.cur_dst_user_info['public_key'] = [int(N_e_str[0]), int(N_e_str[1])]
            print("public key for sign are, ", self.cur_dst_user_info['public_key'])
        except:
            raise ValueError(Constants.ERROR_CODE_DICT['INVALID_PKG'])

        if int(nego_choices[0]) == Constants.ENCRYPT_ID_DICT['RSA']:
            print("choose RSA")
            try:
                keys = public_key_str_parts[1].split('|')
                print("public key for PKC is", keys)
                self.cur_dst_user_info['PKC_obj'] = RSA(N=int(keys[0]), e=int(keys[1]))

                self.PKC_obj = RSA()
                self.PKC_obj.random_private_key()
            except:
                raise ValueError(Constants.ERROR_CODE_DICT['INVALID_PKG'])
            # self.PKC_obj.random_private_key()
        elif int(nego_choices[0]) == Constants.ENCRYPT_ID_DICT['BG']:
            print("choose BG")
            try:
                keys = public_key_str_parts[1]
                print("public key for PKC is", keys)
                self.cur_dst_user_info['PKC_obj'] = BG()
                self.cur_dst_user_info['PKC_obj'].set_n(int(keys))

                self.PKC_obj = BG()
                self.PKC_obj.random_private_key()

            except:
                raise ValueError(Constants.ERROR_CODE_DICT['INVALID_PKG'])

        else:
            raise ValueError(Constants.ERROR_CODE_DICT['WRONG_NEGO_PARAMS'])

        if int(nego_choices[1]) == Constants.ENCRYPT_ID_DICT['DES']:
            print("choose DES")
            self.SymmEnc_obj = DES()
            self.SymmEnc_obj.random_key()
        else:
            raise ValueError(Constants.ERROR_CODE_DICT['WRONG_NEGO_PARAMS'])

        if int(nego_choices[2]) == Constants.ENCRYPT_ID_DICT['SHA1']:
            print("choose SHA1")
        else:
            raise ValueError(Constants.ERROR_CODE_DICT['WRONG_NEGO_PARAMS'])
        return None

    """
    generate an ACK_CERT pkg_info
    """
    def ACK_CERT_gen(self):
        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["ACK_CERT"]
        pkg_info['PKG_DESC'] = "ACK_CERT"
        pkg_info['DST_ID'] = self.user_id
        pkg_info["PUBLIC_KEY"] = self.public_key_str
        self.cert_update()
        pkg_info["CERT"] = self.cert
        return pkg_info

    def ACK_CERT_react(self, pkg_info):
        # (self, cert, SRC_ID, N, e)
        try:
            self.cur_dst_user_info['user_id'] = int(pkg_info['DST_ID'])
            self.cur_dst_user_info['public_key_str'] = pkg_info["PUBLIC_KEY"]
            N_e_str = pkg_info["PUBLIC_KEY"].split('|')
            self.cur_dst_user_info['public_key'] = [int(N_e_str[0]), int(N_e_str[1])]
        except:
            raise ValueError(Constants.ERROR_CODE_DICT['INVALID_PKG'])

        N = self.cur_dst_user_info['public_key'][0]
        e = self.cur_dst_user_info['public_key'][1]
        if not self.cert_check(cert=pkg_info['CERT'], SRC_ID=self.cur_dst_user_info['user_id'], N=N, e=e):
            print("invalid cert")
            raise ValueError(Constants.ERROR_CODE_DICT['INVALID_CERT'])
        else:
            print("valid cert")

        return None


    def DNY_MSG_gen(self, ERR_CODE=1):
        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["DNY_MSG"]
        pkg_info['DST_ID'] = self.user_id
        pkg_info["PUBLIC_KEY"] = self.public_key_str
        pkg_info['PKG_DESC'] = "DNY_MSG"
        pkg_info['ERR_CODE'] = str(ERR_CODE)
        return pkg_info

    def CERT_REQ_gen(self): # not used, no worry
        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["CERT_REQ"]
        pkg_info['PKG_DESC'] = "CERT_REQ"
        return pkg_info

    def CERT_RPY_gen(self):
        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["CERT_RPY"]
        pkg_info['PKG_DESC'] = "CERT_RPY"
        self.cert_update()
        pkg_info['CERT'] = self.cert
        return pkg_info

    def CERT_RPY_react(self, pkg_info):
        N = self.cur_dst_user_info['public_key'][0]
        e = self.cur_dst_user_info['public_key'][1]
        if not self.cert_check(cert=pkg_info['CERT'], SRC_ID=self.cur_dst_user_info['user_id'], N=N, e=e):
            print("invalid cert")
            raise ValueError(Constants.ERROR_CODE_DICT['INVALID_CERT'])
        else:
            print("valid cert")

        return None

    def CERT_ERR_gen(self, ERR_CODE=3):
        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["CERT_ERR"]
        pkg_info['PKG_DESC'] = "CERT_ERR"
        pkg_info['ERR_CODE'] = ERR_CODE
        return pkg_info

    def KEY_REQ_gen(self): # send public key
        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["KEY_REQ"]
        pkg_info['PKG_DESC'] = "KEY_REQ"
        pkg_info['KEY_INFO'] = self.PKC_obj.get_public_key_str()
        return pkg_info

    def KEY_REQ_react(self, pkg_info):
        print("KEY_info:", pkg_info['KEY_INFO'])
        try:
            if isinstance(self.cur_dst_user_info['PKC_obj'], RSA):
                print("RSA")
                PKC_str_parts = pkg_info['KEY_INFO'].split('|')
                self.cur_dst_user_info['PKC_obj'].set_e_N(e=int(PKC_str_parts[1]), N=int(PKC_str_parts[0]))
            elif isinstance(self.cur_dst_user_info['PKC_obj'], BG):
                print("BG")
                self.cur_dst_user_info['PKC_obj'].set_n(int(pkg_info['KEY_INFO']))
            else:
                raise ValueError(Constants.ERROR_CODE_DICT['INVALID_PKG'])
        except:
            raise ValueError(Constants.ERROR_CODE_DICT['INVALID_PKG'])
        return None



    def KEY_RPY_gen(self):
        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["KEY_RPY"]
        pkg_info['PKG_DESC'] = "KEY_RPY"

        key = self.SymmEnc_obj.init_key
        key_with_padding = (key<<19) + (np.random.randint(2**18)<<1) + 1
        # print("real number", bin(key_with_padding))
        # print("true:", np.binary_repr(key_with_padding, 29))
        pkg_info['KEY_INFO'] = self.cur_dst_user_info['PKC_obj'].encrypt(key_with_padding)
        # print("PKC public key", self.cur_dst_user_info['PKC_obj'].get_public_key_str())
        return pkg_info

    def KEY_RPY_react(self, pkg_info):
        try:
            key_with_padding = self.PKC_obj.decrypt(pkg_info['KEY_INFO'], bin_on=True)
            # print("Decrypt p, q", self.PKC_obj.p, self.PKC_obj.q, self.PKC_obj.n)
            # print(key_with_padding, "@@@@", len(key_with_padding))
            # print("str 2 change:", key_with_padding[:-19])
            self.SymmEnc_obj.init_key=int(key_with_padding[:-19], 2)
        except:
            raise ValueError(Constants.ERROR_CODE_DICT['INVALID_PKG']) # create key error if possible
        return None

    def KEY_ERR_gen(self, ERR_CODE=1):
        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["KEY_ERR"]
        pkg_info['PKG_DESC'] = "KEY_ERR"
        pkg_info['ERR_CODE'] = ERR_CODE
        return pkg_info

    def COM_MSG_gen(self, message):
        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["COM_MSG"]
        pkg_info['PKG_DESC'] = "COM_MSG"
        pkg_info['PAYLOAD'] = self.SymmEnc_obj.encrypt(message.encode())
        return pkg_info

    def COM_MSG_react(self, pkg_info):
        plaintext = self.SymmEnc_obj.decrypt(pkg_info["PAYLOAD"])
        print("receive:", plaintext)

    def COM_ERR_gen(self, ERR_CODE=1):
        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["COM_ERR"]
        pkg_info['PKG_DESC'] = "COM_ERR"
        pkg_info['ERR_CODE'] = ERR_CODE
        return pkg_info

    def DISCON_REQ_gen(self):
        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["DISCON_REQ"]
        pkg_info['PKG_DESC'] = "DISCON_REQ"
        return pkg_info

    def DISCON_CLG_gen(self):
        CHALLG = np.random.randint(self.sign_obj.N//2, self.sign_obj.N, Constants.CHALLG_NUMS, dtype=np.int64)
        CHALLG_str = '|'.join([str(num) for num in CHALLG])
        self.cur_dst_user_info['CHALLG'] = CHALLG

        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["DISCON_CLG"]
        pkg_info['PKG_DESC'] = "DISCON_CLG"
        pkg_info['CHALLG'] = CHALLG_str

        return pkg_info

    def DISCON_RPY_gen(self, CHALLG_str):
        CHALLG = [int(num) for num in CHALLG_str.split('|')] # len(CHALLG) should be Constants.CHALLG_NUMS
        idx = np.random.randint(len(CHALLG))
        CHALLG_RPY = np.random.randint(self.sign_obj.N//2, self.sign_obj.N, len(CHALLG))
        CHALLG_RPY[idx] = self.sign_obj.sign(CHALLG[idx])
        CHALLG_RPY_str = '|'.join([str(num) for num in CHALLG_RPY])

        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["DISCON_RPY"]
        pkg_info['PKG_DESC'] = "DISCON_RPY"
        pkg_info['CHALLG_RPY'] = CHALLG_RPY_str

        return pkg_info

    def DISCON_ERR_gen(self, ERR_CODE=1):
        pkg_info = self.pkg_info_init_gen()
        pkg_info['PKG_TYPE_ID'] = Constants.PKG_TYPE_ID_DICT["DISCON_ERR"]
        pkg_info['PKG_DESC'] = "DISCON_ERR"
        pkg_info['ERR_CODE'] = ERR_CODE

        return pkg_info

    def send_message(self, message):
        print("send:", message)
        pkg_info = self.COM_MSG_gen(message=message)
        self.cur_comm_state = 4
        return self.pkg_gen(pkg_info)

    def disconnect(self):
        pkg_info = self.DISCON_REQ_gen()
        self.cur_comm_state = 7
        return self.pkg_gen(pkg_info)
