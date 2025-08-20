# Group Policy Password Decryptor

Passwords stored using Group Policy password encryption use a [known encryption key](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be), allowing for easy decryption.

Huge shout out to [reider-roque](https://github.com/reider-roque) as this is (sort of) a rewrite of their [gpprefdecrypt.py](https://github.com/reider-roque/pentest-tools/tree/master/password-cracking/gpprefdecrypt) tool. It gave me the info needed to re-create this in python3 with a slightly better UX.

# Usage

`python3 gpdecryptor.py -f/--file <password file>` - Decrypts password from file.

`python3 gpdecryptor.py -p "password"` - Decrypts specified password.

# License

GPLv3 as all good software should be.

# Disclaimer

The author will not be held liable for any misuse of this tool.
Please only use with express permission from the owner of the target system.

Don't be a skid :)
