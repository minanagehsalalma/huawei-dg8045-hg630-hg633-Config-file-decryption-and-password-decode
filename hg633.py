#! /usr/bin/env python

# hg658c.wordpress.com
# This is for the Huawei HG633
"""
To decrypt encrypted values in the config, use 
echo 5a4fp5tqtcTWDcjTTR3V4R== | openssl enc -d -base64 -aes-128-cbc -K 0386DDC2789180D4B9A0CDB52126DEBB -iv 1A5F11D8D619537E23EB9B8FF4A238AF -nopad
"""

import sys
import os
from binascii import hexlify, unhexlify 
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Util import number
import zlib
import re
import base64


#30003/100020
RSA_D = (
    "3571FA75E1C7E457D6BCE5F97DA537F7"
	"BE4B001329101601E41348AE87BB09EB"
	"B4DDD4DC95DF87FE7FC43FC277D2B9FB"
	"C0BD1088D9AAE9C8A1BF74DEF76785A4"
	"D5658602722376B64907DFCB23399F4E"
	"7823E839D3559230FC1939630DC6C48B"
	"7D36642C2BA3F6B2E077782959006536"
	"6B9933E26065A1FF97338095851ED8E5")

#30003/40010
RSA_N = (
    "9CFDDA6E973A127866386467435998E7"
	"7B92E28C345043372260EB60F90D9DA6"
	"EC7446A9A475E24E22E3D933DEB157A8"
	"17E0298EF579B91B7F894BA18C4117EF"
	"129458E4FDF5EBF959FD9A6B5D3F337A"
	"6EA7F06C03B2CD5F8F7F8BAA6B3605CC"
	"21108A97206BE965BC654389C54A71F4"
	"8C2100D19587F7852E300F8BE0FE09CD")

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
#30000/20040
AES256CBC_IV  = "85AE4578D5A1BD0758E8349AE0335F0A"

XML_VERSION_STRING = b'<?xml version="1.0" ?>'

def print_usage():
    print(("Usage : " + sys.argv[0] + " {encrypt | decrypt} input_file output_file"))
    

def load_config(config_file):
    if os.path.isfile(config_file):
        cf = open(config_file, "rb")
        config = cf.read()
        cf.close()
    else:
        print("Config file not found..exiting")
         
    return config
def repl(blahblah):
   pwd_enc = base64.b64decode(blahblah.group(0))
   decryptor = AES.new(bytes.fromhex('0386DDC2789180D4B9A0CDB52126DEBB'), AES.MODE_CBC, bytes.fromhex('1A5F11D8D619537E23EB9B8FF4A238AF'))
   data1 = decryptor.decrypt(pwd_enc).rstrip(b'\0').decode()
   realdata = f'"{data1}"'
   return realdata

def save_to_file(dest_file, data):
    wfile = open(dest_file,"wb")
    wfile.write(data)
    wfile.close()

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
    iv = unhexlify(AES256CBC_IV)
    key= unhexlify(AES256CBC_KEY)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted_data = cipher.decrypt(enc_config)
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
        sys.exit()

    config_text = config_text[:-1]
    check_config(config_text)

    print(("Saving decrypted config to " + output_file + "..."))
    save_to_file(output_file, config_text)

def check_config(new_config_file):
    head = new_config_file[0:len(XML_VERSION_STRING)]
    if head != XML_VERSION_STRING:
        print("Not a valid config file...exiting")
        

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
    iv = unhexlify(AES256CBC_IV)
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