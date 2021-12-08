# huawei-dg8045-hg630-hg633-Config-file-decryption-and-password-decode

Usage dg8045.py decrypt input_file output_file

It cannot encrypt the config file because the signatures are missing 

It decrypts the encrypted passwords too 

the Userpassword is stored as an encrypted string that when decrypted
outputs a SHA-1 hash

made from the password and the salt from the config file 

To create it 

`import hashlib
t = hashlib.pbkdf2_hmac('sha1', b'thepassword', b'salt', 1000, 16).hex()
print(t)`
