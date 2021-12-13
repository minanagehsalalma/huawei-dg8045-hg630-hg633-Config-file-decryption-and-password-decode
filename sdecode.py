from binascii import hexlify, unhexlify 
from Crypto.Cipher import AES
import base64
from Crypto.Util import number
pwd_enc = base64.b64decode("Encryptedvalues")
decryptor = AES.new(bytes.fromhex('0386DDC2789180D4B9A0CDB52126DEBB'), AES.MODE_CBC, bytes.fromhex('1A5F11D8D619537E23EB9B8FF4A238AF'))
print(decryptor.decrypt(pwd_enc).rstrip(b'\0').decode())
