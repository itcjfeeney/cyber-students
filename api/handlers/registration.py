#Added code to encrypt user details and hash passwords

import os

from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from .base import BaseHandler

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

def aes_encrypt(plaintext):
    key = "thebestsecretkey"
	key_bytes = bytes(key, "utf-8")
	plaintext_bytes = bytes(plaintext, "utf-8")
    aes_cipher = Cipher(algorithms.AES(key_bytes),
                        modes.ECB(),
                        backend=default_backend())
    aes_encryptor = aes_cipher.encryptor()

    plaintext_bytes = bytes(plaintext, "utf-8")
    ciphertext_bytes = aes_encryptor.update(plaintext_bytes) + aes_encryptor.finalize()
    ciphertext = ciphertext_bytes.hex()

    return ciphertext
	

def hash_password(password):
    salt = os.urandom(16)
	kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    password_bytes = bytes(password, "utf-8")
    hashed_password = kdf.derive(password_bytes)
    print("Salt: " + salt.hex())
    print("Hashed password: " + hashed_password.hex())

    return hashed_password


class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return
		
		encrypted_email = aes_encrypt(email)
		encrypted_display_name = aes_encrypt(display_name)

        yield self.db.users.insert_one({
            'email': encrypted_email,
            'password': hashed_password,
            'displayName': encrypted_display_name
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()
