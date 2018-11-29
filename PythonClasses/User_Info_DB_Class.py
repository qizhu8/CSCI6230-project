#!/usr/bin/env python3
import re
import time
import Constants

class User_info(object):
    """docstring for User_info."""
    def __init__(self, user_id, ip="127.0.0.1"):
        super(User_info, self).__init__()
        self.user_id = -1
        self.ip = ""
        self.last_connect_time = time.time()
        self.state = 0      # !=0 means under punishment, =0 means it's ok
        self.score = 0

        self.set_user_id(user_id)
        self.set_ip(ip)


    def set_user_id(self, user_id):
        if user_id >= 0 and user_id < Constants.USER_ID_MAX:
            self.user_id = user_id
        else:
            raise Exception(Constants.ERROR_CODE_DICT["INVALID_USER_ID"])

    def set_ip(self, ip):
        if re.compile("([01]?[0-9]?[0-9][.]){3}([01]?[0-9]?[0-9])").match(ip):
            self.ip = ip
        else:
            raise Exception(Constants.ERROR_CODE_DICT["INVALID_IP"])

    def add_record(self, behavior):
        self.check_user()
        if behavior in Constants.BAD_BEHAVIOR:
            self.score += Constants.BAD_BEHAVIOR[behavior]
        if self.score >= Constants.SCORE_TO_PUNISH:
            # punish the user
            self.state = time.time()
            return False
        return True

    def check_user(self):
        if self.state == 0:
            return True     # clean title
        else:
            if (time.time() - self.state) > Constants.PUNISH_COOLDOWN_TIME:
                self.state = 0
                return True  # time to release
            else:
                return False # in jail

class User_Info_DB(object):
    """docstring for User_Info_DB."""
    def __init__(self):
        super(User_Info_DB, self).__init__()
        self.user_behave_db = {}
        self.ip_2_user_id = {}

    def add_user(self, user_id, ip):

        if ip in self.ip_2_user_id:
            if self.check_ip(ip): # good ip, can overwrite the user
                old_user_id = self.ip_2_user_id[ip]
                self.user_behave_db.pop(old_user_id) # delete the old user info
                try:
                    self.user_behave_db[user_id] = User_info(user_id=user_id, ip=ip)
                    self.ip_2_user_id[ip] = user_id
                except Exception as e:
                    print("Cannot add user because",  Constants.ERROR_CODE_DICT.inverse[int(str(e))][0])
            else:
                print("IP is blocked")

        elif user_id not in self.user_behave_db: # both the user_id and ip are not known
            try:
                self.user_behave_db[user_id] = User_info(user_id=user_id, ip=ip)
                self.ip_2_user_id[ip] = user_id
            except Exception as e:
                print("Cannot add user because",  Constants.ERROR_CODE_DICT.inverse[int(str(e))][0])
        else:
            print("Cannot add user because User Exists")

    def add_record(self, user_id=-1, ip="", behavior=""):
        if user_id in self.user_behave_db: # add record by user_id
            cur_state = self.user_behave_db[user_id].add_record(behavior)
        elif ip in self.ip_2_user_id: # add record by ip
             user_id = self.ip_2_user_id[ip]
             cur_state = self.user_behave_db[user_id].add_record(behavior)
        else:
            try:
                self.user_behave_db[user_id] = User_info(user_id=user_id, ip=ip)
                self.ip_2_user_id[ip] = user_id
                cur_state = self.user_behave_db[user_id].add_record(behavior)
            except Exception as e:
                print("Cannot add user because",  Constants.ERROR_CODE_DICT.inverse[int(str(e))][0])

    def check_user(self, user_id):
        if user_id in self.user_behave_db:
            return self.user_behave_db[user_id].check_user()
        else:
            raise Exception("User not in DB")

    def check_ip(self, ip):
        if ip in self.ip_2_user_id:
            user_id = self.ip_2_user_id[ip]
            return self.check_user(user_id)
        else:
            return True
