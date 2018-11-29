#!/usr/bin/env python3
from PythonClasses.User_Info_DB_Class import User_Info_DB
import Constants
import time

user_info_db = User_Info_DB()
user_info_db.add_user(user_id=135, ip="192.168.31.31")
user_info_db.add_user(user_id=133, ip="192.168.31.128")
user_info_db.add_record(user_id=133, behavior="DoS_ATK")
print(user_info_db.check_user(user_id=133))

user_info_db.add_user(user_id=999, ip="192.168.31.128")

print(user_info_db.check_ip("192.168.31.128"))
print(user_info_db.check_ip("192.168.31.31"))
print(user_info_db.check_ip("192.168.31.131")) # new ip
