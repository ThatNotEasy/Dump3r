import os
import sys
import binascii
import argparse
from itertools import product
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import unpad

def xor_decrypt(data, key):
    """Decrypt data using XOR with a given key."""
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

def aes_decrypt(data, key, iv=b'\x00' * 16, mode=AES.MODE_CBC):
    """Decrypt data using AES."""
    cipher = AES.new(key, mode, iv)
    try:
        return unpad(cipher.decrypt(data), AES.block_size)
    except ValueError:
        return None

def des_decrypt(data, key, iv=b'\x00' * 8, mode=DES.MODE_CBC):
    """Decrypt data using DES."""
    cipher = DES.new(key, mode, iv)
    try:
        return unpad(cipher.decrypt(data), DES.block_size)
    except ValueError:
        return None

def bruteforce_xor(data, max_key_length=16, magic_bytes=None):
    """Bruteforce XOR key with given max length."""
    if magic_bytes is None:
        magic_bytes = [b"UBI", b"ELF", b"SQSH"]  # Common firmware magic bytes
    
    for key_length in range(1, max_key_length + 1):
        print(f"[*] Trying XOR key length: {key_length}")
        for key in product(range(256), repeat=key_length):
            key_bytes = bytes(key)
            decrypted = xor_decrypt(data, key_bytes)
            for magic in magic_bytes:
                if magic in decrypted:
                    print(f"[+] Found XOR key: {key_bytes.hex()}")
                    return decrypted, key_bytes
    return None, None

def bruteforce_aes(data, key_length=16, iv=b'\x00' * 16, mode=AES.MODE_CBC, magic_bytes=None):
    """Bruteforce AES key (WARNING: Very slow, use with small keyspace)."""
    if magic_bytes is None:
        magic_bytes = [b"UBI", b"ELF", b"SQSH"]
    
    print(f"[*] Bruteforcing AES-{key_length * 8} (This may take a while)...")
    for key in product(range(256), repeat=key_length):
        key_bytes = bytes(key)
        decrypted = aes_decrypt(data, key_bytes, iv, mode)
        if decrypted:
            for magic in magic_bytes:
                if magic in decrypted:
                    print(f"[+] Found AES key: {key_bytes.hex()}")
                    return decrypted, key_bytes
    return None, None

def bruteforce_crc(data, target_crc, key_length=4):
    """Bruteforce CRC32 checksum to find a key."""
    print(f"[*] Bruteforcing CRC32 (Key length: {key_length})")
    for key in product(range(256), repeat=key_length):
        key_bytes = bytes(key)
        if binascii.crc32(data + key_bytes) == target_crc:
            print(f"[+] Found CRC key: {key_bytes.hex()}")
            return key_bytes
    return None

def main():
    parser = argparse.ArgumentParser(description="Firmware Bruteforce Tool")
    parser.add_argument("file", help="Encrypted firmware file")
    parser.add_argument("--mode", choices=["xor", "aes", "des", "crc"], required=True, help="Bruteforce mode")
    parser.add_argument("--key-length", type=int, default=16, help="Key length (for AES/XOR)")
    parser.add_argument("--iv", default="0000000000000000", help="IV (for AES/DES)")
    parser.add_argument("--target-crc", type=lambda x: int(x, 16), help="Target CRC32 (for CRC mode)")
    parser.add_argument("--output", help="Output decrypted file")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print("[-] File not found!")
        sys.exit(1)

    data = open(args.file, "rb").read()
    decrypted = None
    key = None

    if args.mode == "xor":
        decrypted, key = bruteforce_xor(data, args.key_length)
    elif args.mode == "aes":
        iv = binascii.unhexlify(args.iv) if args.iv else b'\x00' * 16
        decrypted, key = bruteforce_aes(data, args.key_length, iv)
    elif args.mode == "des":
        iv = binascii.unhexlify(args.iv) if args.iv else b'\x00' * 8
        decrypted, key = bruteforce_aes(data, 8, iv)  # DES uses 8-byte key
    elif args.mode == "crc":
        if not args.target_crc:
            print("[-] --target-crc required for CRC mode!")
            sys.exit(1)
        key = bruteforce_crc(data, args.target_crc, args.key_length)
    
    if decrypted is not None and args.output:
        with open(args.output, "wb") as f:
            f.write(decrypted)
        print(f"[+] Decrypted firmware saved to {args.output}")
    elif key is not None:
        print(f"[+] Found key: {key.hex()}")
    else:
        print("[-] No key found.")

if __name__ == "__main__":
    main()
