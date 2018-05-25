"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
import re
import json

class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
    
       
    def upload(self, name, value):
        # Replace with your implementation
        pat = r'[A-Za-z0-9]+'
        name = re.findall(pat, name)[-1]
        
        rand_key =  self.crypto.get_random_bytes(n = 16)
        rand_key_for_mac = self.crypto.get_random_bytes(n = 16)
        #encrypt the key using EL Gama.
        key = self.crypto.asymmetric_encrypt(message = rand_key, public_key = self.pks.get_encryption_key(self.username))
        
        msg = self.crypto.symmetric_encrypt(message = value, key = rand_key, cipher_name = 'AES', mode_name ='CTR', counter = self.crypto.new_counter(nbits = 128))

        sign = self.crypto.asymmetric_sign(message = key, private_key = self.rsa_priv_key)
        mac = self.crypto.message_authentication_code(message = msg, key = rand_key, hash_name='SHA256')
        
        file = key+'_'+msg +'_'+ mac+'_'+sign
        self.storage_server.put(id = self.username + name, value = file)
        return True
        
    def download(self, name):
        # Replace with your implementation
        
        
        pat = r'[^_]+'
        file = self.storage_server.get(self.username + name)
        
        if (file):
            self.storage_server.delete(id = self.username + name)
            items = re.findall(pat, file)
            if len(items) != 4:
                raise IntegrityError
            key = items[0]
            msg = items[1]
            sign = items[3]
            mac = items[2]

            verify = self.crypto.asymmetric_verify(message = key, signature = sign, public_key = self.pks.get_signature_key(self.username))
            if (not verify):
                raise IntegrityError
            else:
                decrypt_key = self.crypto.asymmetric_decrypt(private_key = self.elg_priv_key, ciphertext = key)
                if mac != self.crypto.message_authentication_code(message = msg, key = decrypt_key, hash_name = 'SHA256'):
                    raise IntegrityError
                else:
                    decrypted_msg = self.crypto.symmetric_decrypt(key = decrypt_key, ciphertext = msg, cipher_name = 'AES',mode_name = 'CTR', counter = self.crypto.new_counter(nbits=128))
                    
                    return decrypted_msg
        else: 
            return None
    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError
