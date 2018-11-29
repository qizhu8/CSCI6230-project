#!/usr/bin/env python3
from PythonClasses.bidict_Class import bidict
import PythonClasses.Number_Package as npkg

from PythonClasses.DES_Class import DES

from PythonClasses.Blum_Goldwessar_Class import BG
from PythonClasses.ECC_Class import ECC
from PythonClasses.RSA_Class import RSA

from PythonClasses.User_Info_DB_Class import User_Info_DB

import Constants
import time

import numpy as np


class User(object):
    """docstring for User."""
    def __init__(self, userid=-1):
        # super(User, self).__init__()
        self.user_id = -1
        self.PKC_obj = None                     # chosen from RSA, ECC and BG
        self.SymmEnc_obj = None                 # currently, DES only
        # self.PKG_TYPE_ID_DICT = Constants.PKG_TYPE_ID_DICT  # Package id - package funcionality
        # self.PKG_INFO_ITEMS = Constants.PKG_STRUCT_DICT             # structure of each type of package
        # self.ERROR_CODES = Constants.ERROR_CODE_DICT        # ErrorCode - description
        # self.ENCRYPT_ID_DICT = Constants.ENCRYPT_ID_DICT    # encryption - id
        # self.PKG_INFO_ITEMS = Constants.PKG_INFO_ITEMS              # list of items in the package
        self.user_state = -1
        self.User_Info_DB = User_Info_DB()              # an object storing (userid: User_info )

    """
    pkg_gen()
    ==============================================
    A function is to generate the package to send

    inputs:
      pkg_info: a dictionary containing nessary informations say: PKG_TYPE_ID, SRC_ID, MSG, etc

    outputs:
        pkg_msg_lst: a list of strings to be sent (even if usually there is only one object in the list)
    """
    def pkg_gen(self, packet_info):
        pkg_msg_lst = [""]

        return pkg_msg_lst

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

        return pkg_info

    """
    pkg_info_init_gen()
    ==============================================
    A function to generate a pkg_info dictionary.

    outputs:
        pkg_info: the dictionary
    """
    def pkg_info_init_gen(self):
        pkg_info = {key:None for key in Constants.PKG_INFO_ITEMS}


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
    def nonce_check(self, nonce, rules):

        return True, ErrorCode

    """
    respond_state_machine()
    =======================
    React based on the received pkg and current status.

    inputs:
        pkg_rev: received package (string)

    output:
        pkg_send: package to send
    """
    def respond_state_machine(self, pkg_rev):
        pkg_info = self.pkg_interp(pkg_rev)
        try:
            if pkg_info["PKG_TYPE_ID"] is None:
                raise Exception(Constants.ERROR_CODE_DICT["INVALID_PKG"])
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["HELLO_MSG"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["ACK_CERT"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["DNY_MSG"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["CERT_REQ"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["CERT_RPY"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["CERT_ERR"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["KEY_REQ"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["KEY_RPY"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["KEY_ERR"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["COM_MSG"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["COM_ERR"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["DISCON_REQ"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["DISCON_CLG"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["DISCON_RPY"]:
                pass
            elif pkg_info["PKG_TYPE_ID"] == Constants.PKG_TYPE_ID_DICT["DISCON_ERR"]:
                pass
        except Exception as e:
            raise
