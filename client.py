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

class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)

    def upload(self, name, value):
        # Replace with your implementation
        # raise NotImplementedError
        pat = r'[A-Za-z0-9]+'
        pat2 = r'[^_]+'
        name = re.findall(pat, name)[-1]
        key_dir = self.storage_server.get(self.username + "key_dir")
        if key_dir == 1:
            #self.storage_server.delete(id=self.username + "key_dir")
            items = re.findall(pat2, key_dir)
            sign = items[0]
            encrypt_keys = items[1]
            verify_keys = self.crypto.asymmetric_verify(message=encrypt_keys, signature=sign, public_key=self.pks.get_signature_key(self.username))
            if not verify_keys:
                raise IntegrityError
            else:
                keys = self.crypto.asymmetric_decrypt(ciphertext=encrypt_keys, private_key=self.elg_priv_key)
                items = re.findall(pat, keys)
                rand_key = items[0]
                rand_key_for_mac = items[1]
                rand_key_for_filename = items[2]
        else:
            rand_key = self.crypto.get_random_bytes(n=16)
            rand_key_for_mac = self.crypto.get_random_bytes(n=16)
            rand_key_for_filename = self.crypto.get_random_bytes(n=16)

            
            encrypt_keys = self.crypto.asymmetric_encrypt(message=rand_key + '_' + rand_key_for_mac + '_' + rand_key_for_filename,
                                                      public_key=self.pks.get_encryption_key(self.username))
            sign = self.crypto.asymmetric_sign(message=encrypt_keys, private_key=self.rsa_priv_key)

        
            self.storage_server.put(id=self.username +"key_dir", value=sign + '_' + encrypt_keys)
        iv = self.crypto.get_random_bytes(n=16)
        encrypt_msg = self.crypto.symmetric_encrypt(message=value, key=rand_key, cipher_name='AES', mode_name='CBC', IV=iv)
        mac = self.crypto.message_authentication_code(message=encrypt_msg + name, key=rand_key_for_mac, hash_name='SHA256')
        encrypt_filename = self.crypto.message_authentication_code(message=name, key=rand_key_for_filename, hash_name='SHA256')

        self.storage_server.put(id=self.username + encrypt_filename, value=mac + '_' + iv + '_' + encrypt_msg)


        return True

    def download(self, name):
        # Replace with your implementation
        # raise NotImplementedError
        pat = r'[^_]+'
        name = re.findall(pat, name)[-1]

        key_dir = self.storage_server.get(self.username + "key_dir")
        if key_dir:
            #self.storage_server.delete(id=self.username + "key_dir")
            items = re.findall(pat, key_dir)
            sign = items[0]
            encrypt_keys = items[1]
        else:
            return None

        verify_keys = self.crypto.asymmetric_verify(message=encrypt_keys, signature=sign, public_key=self.pks.get_signature_key(self.username))
        if not verify_keys:
            raise IntegrityError
        else:
            keys = self.crypto.asymmetric_decrypt(ciphertext=encrypt_keys, private_key=self.elg_priv_key)
            items = re.findall(pat, keys)
            rand_key = items[0]
            rand_key_for_mac = items[1]
            rand_key_for_filename = items[2]

        encrypt_filename = self.crypto.message_authentication_code(message=name, key=rand_key_for_filename, hash_name='SHA256')
        encrypt_mac_msg = self.storage_server.get(self.username + encrypt_filename)

        if not encrypt_mac_msg:
            return None
            
        else:
            self.storage_server.delete(id=self.username + encrypt_filename)
            items = re.findall(pat, encrypt_mac_msg)
            mac = items[0]
            iv = items[1]
            encrypt_msg = items[2]

        if mac != self.crypto.message_authentication_code(message=encrypt_msg + name, key=rand_key_for_mac, hash_name='SHA256'):
            raise IntegrityError
        else:
            decrypted_msg = self.crypto.symmetric_decrypt(key=rand_key, ciphertext=encrypt_msg, cipher_name='AES', mode_name='CBC', IV=iv)
            return decrypted_msg

        
########################################################
###Sharing and revoking part on school class hive account, the account has expired. I did most of them remotely so there is no record
###on my local laptop.
#######################################################

    
