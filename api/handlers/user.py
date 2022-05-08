#Added code to dycrypt user details

import os

from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from tornado.web import authenticated

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .auth import AuthHandler

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

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        self.set_status(200)
        self.response['email'] = aes_decrypt(bytes.fromhex(self.current_user['email']))
        self.response['displayName'] = aes_decrypt(bytes.fromhex(self.current_user['display_name']))
        self.write_json()

    @coroutine
    @authenticated
    def put(self):
        try:
            body = json_decode(self.request.body)
            display_name = body['displayName']
            if not isinstance(display_name, str):
                raise Exception()
        except:
            self.send_error(400, message='You must provide a display name!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        yield self.db.users.update_one({
            'email': self.current_user['email'],
        }, {
            '$set': {
                'displayName': display_name
            }
        })

        self.current_user['display_name'] = display_name

        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['displayName'] = self.current_user['display_name']
        self.write_json()
