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

        

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        #m = a.share("b", n1), b.receive_share("a", n2, m), download must return the last updated value
        #
        
        # if not self.storage_server.get(name):
        #     return None
        # else:
            
        #     if tree[self.username] == 0:

        #         tree[self.username] = {}
        #     else:
                
        #         if tree[self.username][user] == 0:

        #             tree[self.username][user] = 1
        #         else:
        #             print('user has already got access from self.user')
        # json_tree = json.dumps(tree)
        






    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        #only the user who initially created the file may call this function
        #anyone with whom otheruser shared this file MUST also be revoked
        #1. Bob should not be able to update file 2. BOb not able to read any updates to the file 
        #3. Carol should not be able to read or update 4.Bob should not be able to regain access by calling recieve_share() with alice previous msg
        raise NotImplementedError
