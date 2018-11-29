from PythonClasses.SHA1_Class import SHA1
import hashlib

m = "abc"
S = SHA1()
hashed = S.hash(m)
print(hashed)

hashlib_rst = hashlib.sha1(m.encode()).hexdigest()
print(hashed)
