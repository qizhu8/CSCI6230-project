#!/usr/bin/env python3

class User_info(object):
    """docstring for User_info."""
    def __init__(self, user_id=-1, ip="", last_login_time=-1, state=0):
        super(User_info, self).__init__()
        self.user_id = user_id
        self.ip = ip
        self.last_login_time = last_login_time
        self.state = state

class UserInfo(object):
    """docstring for UserBehavior."""
    def __init__(self, arg):
        super(UserBehavior, self).__init__()
        self.user_behave_db = {}

    def self.add_user(self, user_id, last_login_time=-1, )
