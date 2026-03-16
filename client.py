import requests
import os
from crypto_utils import encrypt, decrypt, compute_hmac, verify_hmac

# use HTTP by default; set CLIENT_SERVER_URL to override (use https when server has cert)
SERVER_URL = os.environ.get('CLIENT_SERVER_URL', 'http://localhost:5000')
AES_KEY = b'sixteen byte key......1234567890'
HMAC_KEY = b'some hmac key for integrity....'
CHUNK_SIZE = 1024 * 1024


def upload(filepath):
    filename = os.path.basename(filepath)
    try:
        resp = requests.get(f"{SERVER_URL}/upload_status/{filename}", verify=False)
        resp.raise_for_status()
        offset = resp.json().get('offset', 0)
    except Exception:
        offset = 0
    with open(filepath, 'rb') as f:
        f.seek(offset)
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            ciphertext = encrypt(chunk, AES_KEY)
            mac = compute_hmac(ciphertext, HMAC_KEY)
            headers = {
                'X-Offset': str(offset),
                'X-HMAC': mac.hex()
            }
            resp = requests.post(f"{SERVER_URL}/upload/{filename}", data=ciphertext, headers=headers, verify=False)
            resp.raise_for_status()
            offset += len(chunk)
    print('Upload complete')


def download(filename, dest):
    resp = requests.get(f"{SERVER_URL}/download/{filename}", stream=True, verify=False)
    resp.raise_for_status()
    with open(dest, 'wb') as f:
        for piece in resp.iter_content(chunk_size=None):
            if len(piece) < 4 + 32:
                continue
            length = int.from_bytes(piece[:4], 'big')
            mac = piece[4:36]
            ciphertext = piece[36:36+length]
            if not verify_hmac(ciphertext, HMAC_KEY, mac):
                raise ValueError('integrity failure')
            plaintext = decrypt(ciphertext, AES_KEY)
            f.write(plaintext)
    print('Download complete')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest='cmd')
    up = sub.add_parser('upload')
    up.add_argument('file')
    down = sub.add_parser('download')
    down.add_argument('name')
    down.add_argument('dest')
    args = parser.parse_args()
    if args.cmd == 'upload':
        upload(args.file)
    elif args.cmd == 'download':
        download(args.name, args.dest)
    else:
        parser.print_help()
