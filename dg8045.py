#! /usr/bin/env python

# hg658c.wordpress.com
# This is for the Huawei HG633
"""
To decrypt encrypted values in the config, use 
echo 5a4fp5tqtcTWDcjTTR3V4R== | openssl enc -d -base64 -aes-128-cbc -K 65CE89619D8929CDCF998D42D74C59E3 -iv 9D057CC3E05784F158A972B797E90D3F -nopad
"""

import sys
import os
from binascii import hexlify, unhexlify 
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Util import number
import zlib
import re
from zlib import decompress
import base64


#30003/100020
RSA_D = (
    "1A9FCE09FD5B6FAA0CEC5C9841B4105D"
	"0AD9D1DD0324817413EEF77267C56DBE"
	"E76C135B63160F759FD5333B060AFC08"
	"71C813D0FDDFA3AA3CA5DD4C0430940D"
	"B14A9DF8A31B4B38B4690BE84E9A38D0"
	"FBB405244648CED3A8EAFE7F5451752E"
	"F201B94A13C1DF915012302F12C6946B"
	"230474034A665B2CAAD23794BF7B6381")

#30003/40010
RSA_N = (
    "B1AAE240AE798C9051E97745519F737A"
	"4F5E82902CAA630420EC5B0F6FE64926"
	"CA9D766811C354C951E58B4796037159"
	"45F344DEA71A72106E1BA10FF72721DF"
	"C7C5273A808ADF2F8A39BEB2D03370A8"
	"7749E778F2135A1625FFFBBFB17631A3"
	"207C9E129105F3E7DCE0AFA654321597"
	"F9B2026BD197AEABF2F03B1EB8137F1D")

RSA_E = "010001"         

SIG_TEMPLATE = ("0001ffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffff003020"
                "300c06082a864886f70d020505000410")

#30000/10040
AES256CBC_KEY = "65CE89619D8929CDCF998D42D74C59E3B4E11CFCAE5927760A78E18061D2145C"
## AES256CBC_IV  = "9D057CC3E05784F158A972B797E90D3F"
#note the iv is down there it changes for every config file

XML_VERSION_STRING = b'<?xml version="1.0" ?>'
def print_usage():
    print(("Usage : " + sys.argv[0] + " {encrypt | decrypt} input_file output_file"))
    

def load_config(config_file):
    if os.path.isfile(config_file):
        cf = open(config_file, "rb")
        config = cf.read()
        global iv
        iv=config[48:64]
        cf.close()
    else:
        print("Config file not found..exiting")
         
    return config

def repl(blahblah):
   pwd_enc = base64.b64decode(blahblah.group(1))
   data1 = AES.new(bytes.fromhex('0386DDC2789180D4B9A0CDB52126DEBB'), AES.MODE_CBC, iv=pwd_enc[48:64]).decrypt(pwd_enc[64:]).rstrip(b'\0').decode()
   realdata = f'="{data1}"'
   return realdata

def save_to_file(dest_file, data):
    with open(dest_file, "w" ,errors = 'ignore') as f:
     data = re.sub('="([^"]+=)"', repl, data.decode("utf-8", "ignore"))
     f.write(data[data.index('<?xml '):(data.rindex('</InternetGatewayDeviceConfig>') + 30)])
     
def get_md5_hash_from_sig(sig):
    sig_int = int(hexlify(sig),16)
    rsa_n = int(RSA_N,16)
    dec_sig_as_int = pow(sig_int, 0x10001, rsa_n );
    decrypted_sig = number.long_to_bytes(dec_sig_as_int, 128)
    target_md5 = hexlify(decrypted_sig)[-64:]
    return target_md5

def calc_actual_md5_hash(enc_config_body):
    md5 = MD5.new()
    md5.update(enc_config_body)
    actual_md5_sig = md5.hexdigest()
    actual_md5_sig = str.encode(actual_md5_sig)
    return actual_md5_sig

def decrypt_config(input_file, output_file):
    enc_config=load_config(input_file)

    print("Decrypting...")
   ## iv= unhexlify(AES256CBC_IV)
    key= unhexlify(AES256CBC_KEY)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted_data = cipher.decrypt(enc_config[0x50:])
        decompressed_data=""

        decompressed_data = zlib.decompress(decrypted_data)
    except:
        print("Bad config file...exiting")

    config_text = decompressed_data[:-0x80]
    actual_md5_hash = calc_actual_md5_hash(config_text)

    print("Verifying signature...")
    sig = decompressed_data [-0x80:]
    sig_int = int(hexlify(sig),16)
    rsa_n = int(RSA_N,16)
    dec_sig_as_int = pow(sig_int, 0x10001, rsa_n );
    decrypted_sig = number.long_to_bytes(dec_sig_as_int, 128)
    target_md5_hash = hexlify(decrypted_sig)[-32:]

    if (actual_md5_hash == target_md5_hash):
        print("Signature ok...")        
    else:
        print("Signature not ok...exiting")
        

    config_text = config_text[:-1]
    check_config(config_text)

    print(("Saving decrypted config to " + output_file + "..."))
    save_to_file(output_file, config_text)
    

def check_config(new_config_file):
    head = new_config_file[0:len(XML_VERSION_STRING)]
    head2 = new_config_file[0:len(XML_VERSION_TSTRING)]
    if head != XML_VERSION_STRING:
     if head2 != XML_VERSION_TSTRING:         		
        print("Not a valid config file...exiting")
        sys.exit()
        

def encrypt_config(input_file, output_file):
    new_config_data=load_config(input_file)
    check_config(new_config_data)
    new_config_data += '\0'.encode()

    print("Calculating MD5 hash...")
    h = MD5.new()
    h.update(new_config_data)
    actual_md5_sig = h.hexdigest()

    sig = SIG_TEMPLATE + actual_md5_sig;

    print("Adding Signature...")
    sig_int = int(sig,16)
    rsa_d = int(RSA_D,16)
    rsa_n = int(RSA_N,16)
    enc_sig_int = pow(sig_int, rsa_d, rsa_n);
    encrypted_sig = number.long_to_bytes(enc_sig_int, 128)
    new_config_data = new_config_data + encrypted_sig

    print("Compressing config...")
    compressed_data = zlib.compress(new_config_data, 9)

    padding_amount = len(compressed_data) % 16
    print(("" + str(padding_amount) + " bytes padding needed"))
    print("Adding padding...")
    compressed_data=compressed_data + b'\0'*(16-padding_amount)

    print("Encrypting config...")
    #iv = unhexlify(AES256CBC_IV)
    key= unhexlify(AES256CBC_KEY)
    aes = AES.new(key, AES.MODE_CBC, iv)
    enc_new_config = aes.encrypt(compressed_data)

    print(("Saving encrypted config to " + output_file + "..."))
    save_to_file(output_file, enc_new_config)

def main():
    if len(sys.argv) < 4:
        print_usage()

    input_file = sys.argv[2]
    output_file = sys.argv[3]
    command = sys.argv[1]

    if (command == "encrypt"):
        encrypt_config(input_file, output_file)
    elif (command == "decrypt"):
        decrypt_config(input_file, output_file) 
    else: 
        print_usage()


if __name__ == "__main__":
    main()
