#Added dycrypt code for user details

import os

from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .base import BaseHandler

def aes_decrypt(ciphertext):
    key = "thebestsecretkey"
    key_bytes = bytes(key, "utf-8")
    aes_cipher = Cipher(algorithms.AES(key_bytes),
                        modes.ECB(),
                        backend=default_backend())
    aes_decryptor = aes_cipher.decryptor()

    plaintext_bytes = aes_decryptor.update(ciphertext_bytes)
    plaintext = str(plaintext_bytes, "utf-8")
    return plaintext

class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        yield self.db.users.update_one({
            'email': email
        }, {
            '$set': token
        })

        return token

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
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': aes_decrypt(email)
        }, {
          'password': 1
        })

        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return

        if user['password'] != password:
            self.send_error(403, message='The email address and password are invalid!')
            return

        token = yield self.generate_token(email)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()
