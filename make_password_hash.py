"""
make_password_hash.py  -  makes the scrambled (hashed) password for the login

Run in the dashboard folder:   python make_password_hash.py
Type a password (it is not shown). Copy the printed line into
.streamlit/secrets.toml under [auth].
"""
import getpass

import bcrypt

pw = getpass.getpass("New dashboard password: ")
if len(pw) < 8:
    raise SystemExit("Please use at least 8 characters.")
if getpass.getpass("Type it again: ") != pw:
    raise SystemExit("The two passwords are different. Nothing was made.")

h = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
print()
print("Copy this line into .streamlit/secrets.toml under [auth]:")
print(f'password_hash = "{h}"')
