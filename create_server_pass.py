import bcrypt

password = b"MyS3cureV!PN"
hashed = bcrypt.hashpw(password, bcrypt.gensalt())

print(hashed.decode())