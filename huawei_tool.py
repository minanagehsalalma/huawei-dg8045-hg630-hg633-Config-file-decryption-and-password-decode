#!/usr/bin/env python3
import base64
import re
import sys
import zlib
from binascii import hexlify, unhexlify

from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.Util import number

# Common Constants
AES256CBC_KEY = unhexlify("65CE89619D8929CDCF998D42D74C59E3B4E11CFCAE5927760A78E18061D2145C")
PWD_KEY = unhexlify("0386DDC2789180D4B9A0CDB52126DEBB")
XML_VERSION_STRING = b'<?xml version="1.0" ?>'

# RSA Constants for DG8045
DG8045_RSA_N = int("B1AAE240AE798C9051E97745519F737A4F5E82902CAA630420EC5B0F6FE64926CA9D766811C354C951E58B479603715945F344DEA71A72106E1BA10FF72721DFC7C5273A808ADF2F8A39BEB2D03370A87749E778F2135A1625FFFBBFB17631A3207C9E129105F3E7DCE0AFA654321597F9B2026BD197AEABF2F03B1EB8137F1D", 16)

# RSA Constants for HG633
HG633_RSA_N = int("9CFDDA6E973A127866386467435998E77B92E28C345043372260EB60F90D9DA6EC7446A9A475E24E22E3D933DEB157A817E0298EF579B91B7F894BA18C4117EF129458E4FDF5EBF959FD9A6B5D3F337A6EA7F06C03B2CD5F8F7F8BAA6B3605CC21108A97206BE965BC654389C54A71F48C2100D19587F7852E300F8BE0FE09CD", 16)
HG633_IV = unhexlify("85AE4578D5A1BD0758E8349AE0335F0A")
HG633_PWD_IV = unhexlify("1A5F11D8D619537E23EB9B8FF4A238AF")
SUPPORTED_MODELS = ("dg8045", "hg633")
ZLIB_HEADERS = (b"\x78\x9c", b"\x78\x01", b"\x78\x5e", b"\x78\xda")
XML_ROOT_CLOSE = "</InternetGatewayDeviceConfig>"

class HuaweiConfigTool:
    def __init__(self, model="dg8045"):
        self.model = model.lower()
        if self.model not in SUPPORTED_MODELS:
            raise ValueError(f"Unsupported model '{model}'. Supported models: {', '.join(SUPPORTED_MODELS)}")

        if self.model == "dg8045":
            self.rsa_n = DG8045_RSA_N
        else:
            self.rsa_n = HG633_RSA_N
            self.fixed_iv = HG633_IV

    def decrypt_password(self, encrypted_b64, iv=None):
        try:
            data = base64.b64decode(encrypted_b64)
            if self.model == "dg8045":
                if len(data) < 64: return encrypted_b64
                pwd_iv = data[48:64]
                pwd_data = data[64:]
            else:
                pwd_iv = HG633_PWD_IV
                pwd_data = data
            
            cipher = AES.new(PWD_KEY, AES.MODE_CBC, pwd_iv)
            decrypted = cipher.decrypt(pwd_data).rstrip(b'\0')
            return decrypted.decode('utf-8', errors='ignore')
        except Exception as e:
            return f"[Decryption Failed: {e}]"

    def process_xml_passwords(self, xml_content, config_iv):
        def repl_dg8045(match):
            val = match.group(1)
            dec = self.decrypt_password(val, config_iv)
            return f'="{dec}"'

        def repl_hg633(match):
            val = match.group(1)
            dec = self.decrypt_password(val)
            return f'"{dec}"'

        if self.model == "dg8045":
            return re.sub(r'="([^"]+==)"', repl_dg8045, xml_content)
        else:
            return re.sub(r'"([^"]+==)"', repl_hg633, xml_content)

    def decompress_payload(self, decrypted_padded):
        try:
            return zlib.decompress(decrypted_padded)
        except zlib.error:
            for header in ZLIB_HEADERS:
                idx = decrypted_padded.find(header)
                if idx == -1:
                    continue
                try:
                    return zlib.decompress(decrypted_padded[idx:])
                except zlib.error:
                    continue

        raise ValueError(
            "Could not locate a valid zlib stream after AES decryption. "
            "This usually means the input is not an exported router config for the selected model "
            "(for example, `DG8045 WE.bin` in this repo is a firmware/reference blob, not a config export)."
        )

    def decrypt(self, input_path, output_path):
        with open(input_path, "rb") as f:
            data = f.read()

        if self.model == "dg8045":
            config_iv = data[48:64]
            encrypted_body = data[0x50:]
        else:
            config_iv = HG633_IV
            encrypted_body = data

        print(f"[*] Decrypting {self.model.upper()} config...")
        cipher = AES.new(AES256CBC_KEY, AES.MODE_CBC, config_iv)
        decrypted_padded = cipher.decrypt(encrypted_body)
        decompressed = self.decompress_payload(decrypted_padded)

        if len(decompressed) <= 0x80:
            raise ValueError("The decrypted payload is too short to contain XML data plus the RSA signature block.")

        config_text = decompressed[:-0x80]
        signature = decompressed[-0x80:]

        print("[*] Verifying signature...")
        sig_int = int(hexlify(signature), 16)
        dec_sig_int = pow(sig_int, 0x10001, self.rsa_n)
        dec_sig_bytes = number.long_to_bytes(dec_sig_int, 128)
        target_md5 = hexlify(dec_sig_bytes)[-32:]
        
        actual_md5 = MD5.new(config_text).hexdigest().encode()
        
        if actual_md5 == target_md5:
            print("[+] Signature verified successfully.")
        else:
            print("[-] Signature verification failed!")

        config_text = config_text.rstrip(b'\0')
        xml_str = config_text.decode('utf-8', errors='ignore')
        xml_start = xml_str.find('<?xml')
        xml_end = xml_str.rfind(XML_ROOT_CLOSE)
        if xml_start == -1 or xml_end == -1:
            raise ValueError("The decrypted payload does not contain a complete Huawei XML configuration document.")
        xml_str = xml_str[xml_start:xml_end + len(XML_ROOT_CLOSE)]
        
        print("[*] Decoding passwords in XML...")
        processed_xml = self.process_xml_passwords(xml_str, config_iv)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(processed_xml)
        print(f"[+] Decrypted config saved to {output_path}")

def print_usage():
    print(f"Usage: {sys.argv[0]} <{'|'.join(SUPPORTED_MODELS)}> <input_file> <output_file>")

def main():
    if len(sys.argv) < 4:
        print_usage()
        sys.exit(1)

    model = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3]

    tool = HuaweiConfigTool(model)
    try:
        tool.decrypt(input_file, output_file)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
