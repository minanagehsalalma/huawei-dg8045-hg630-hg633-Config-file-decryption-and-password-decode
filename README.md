# Huawei Router Config Decryption and Password Decoder

This workspace packages the scripts from the upstream Huawei config repository into a Python 3 friendly layout. The main entrypoint is `huawei_tool.py`, which decrypts exported config files and decodes the encrypted passwords inside the XML for `dg8045` and `hg633`.

## What Matches the Upstream README

- `dg8045` config decryption is supported.
- `hg633` config decryption is supported.
- Password values inside the decrypted XML are decoded automatically.
- The original one-file scripts from the upstream repository are preserved in `archive/`.

## Installation

Install the dependency listed in `requirements.txt`:

```bash
pip install -r requirements.txt
```

## Usage

Decrypt a Huawei router configuration export:

```bash
python3 huawei_tool.py <dg8045|hg633> <input_file> <output_file>
```

Examples:

```bash
python3 huawei_tool.py dg8045 config.bin decrypted.xml
python3 huawei_tool.py hg633 config.bin decrypted.xml
```

## Important Input Note

`DG8045 WE.bin` is kept from the upstream repository as a firmware/reference binary for reverse-engineering. It is not a decryptable router config export, so it should not be passed to `huawei_tool.py`.

Use an actual config backup exported from the router web UI as the input file.

## Project Structure

- `huawei_tool.py`: Unified decrypt-and-decode entrypoint.
- `archive/`: Original legacy scripts from the upstream repo.
- `DG8045 WE.bin`: Upstream firmware/reference blob, retained for analysis.

## Credits

Original research and scripts were published in the upstream repository:

- https://github.com/minanagehsalalma/huawei-dg8045-hg630-hg633-Config-file-decryption-and-password-decode
- https://web.archive.org/web/20200104011630/https://hg658c.wordpress.com/2017/12/04/decrypting-configuration-files-from-other-huawei-home-gateway-routers/
