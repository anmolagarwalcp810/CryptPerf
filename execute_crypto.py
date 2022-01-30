# Write your script here
import os

import subprocess
import sys

# subprocess.check_call([sys.executable,"-m","pip","install","cryptography==36.0.1"])
# subprocess.check_call([sys.executable,"-m","pip3","install","cryptography==36.0.1"])

import cryptography.exceptions
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes, cmac, hmac, serialization, padding as padding2
from cryptography.hazmat.backends import default_backend


# print(RSA_SIZE)

class ExecuteCrypto(object): # Do not change this
    def __init__(self):
        self.RSA_ENCRYPT_SIZE = 128  # size is not 256 because of overhead, maximum allowed size was 190, but kept 128
        self.RSA_DECRYPT_SIZE = 256

    def generate_keys(self):
        """Generate keys"""

        # Write your script here
        symmetric_key = os.urandom(16)
        private_key_sender_rsa_ = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key_sender_rsa_ = private_key_sender_rsa_.public_key()
        private_key_receiver_rsa_ = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key_receiver_rsa_ = private_key_receiver_rsa_.public_key()
        # we use NIST P-256 (ec.SECP256R1()) as given in the question
        private_key_sender_ecc_ = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        public_key_sender_ecc_ = private_key_sender_ecc_.public_key()

        # now we need to serialize the private, public key objects
        private_key_sender_rsa = private_key_sender_rsa_.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
        public_key_sender_rsa = public_key_sender_rsa_.public_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo)

        private_key_receiver_rsa = private_key_receiver_rsa_.private_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
        public_key_receiver_rsa = public_key_receiver_rsa_.public_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo)

        private_key_sender_ecc = private_key_sender_ecc_.private_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
        public_key_sender_ecc = public_key_sender_ecc_.public_bytes(encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo)

        print("Symmetric Key") # Do not change this
        print(symmetric_key) # Do not change this
        print("Sender's RSA Public Key") # Do not change this
        print(public_key_sender_rsa) # Do not change this
        print("Sender's RSA Private Key") # Do not change this
        print(private_key_sender_rsa) # Do not change this
        print("Receiver's RSA Public Key") # Do not change this
        print(public_key_receiver_rsa) # Do not change this
        print("Receiver's RSA Private Key") # Do not change this
        print(private_key_receiver_rsa) # Do not change this
        print("Sender's ECC Public Key") # Do not change this
        print(public_key_sender_ecc) # Do not change this
        print("Sender's ECC Private Key") # Do not change this
        print(private_key_sender_ecc) # Do not change this

        return symmetric_key, \
                public_key_sender_rsa, private_key_sender_rsa, \
                public_key_receiver_rsa, private_key_receiver_rsa, \
                public_key_sender_ecc, private_key_sender_ecc # Do not change this

    def generate_nonces(self):
        """Generate nonces"""

        # Write your script here

        '''
        for aes-cbc, we use iv
        for aes-ctr, aes-gcm we use nonce
        we don't use nonce otherwise
        '''

        nonce_aes_cbc = os.urandom(16)
        nonce_aes_ctr = os.urandom(16)
        nonce_encrypt_rsa = None
        nonce_aes_cmac = None
        nonce_hmac = None
        nonce_tag_rsa = None
        nonce_ecdsa = None
        nonce_aes_gcm = os.urandom(16)



        print("Nonce for AES-128-CBC") # Do not change this
        print(nonce_aes_cbc) # Do not change this
        print("Nonce for AES-128-CTR") # Do not change this
        print(nonce_aes_ctr) # Do not change this
        print("NOnce for RSA-2048") # Do not change this
        print(nonce_encrypt_rsa) # Do not change this
        print("Nonce for AES-128-CMAC") # Do not change this
        print(nonce_aes_cmac) # Do not change this
        print("Nonce for SHA3-256-HMAC") # Do not change this
        print(nonce_hmac) # Do not change this
        print("Nonce for RSA-2048-SHA3-256") # Do not change this
        print(nonce_tag_rsa) # Do not change this
        print("Nonce for ECDSA") # Do not change this
        print(nonce_ecdsa) # Do not change this
        print("Nonce for AES-128-GCM") # Do not change this
        print(nonce_aes_gcm) # Do not change this

        return nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
                nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm # Do not change this

    def encrypt(self, algo, key, plaintext, nonce): # Do not change this
        """Encrypt the given plaintext"""

        # Write your script here
        if type(plaintext)!=type(bytes()):
            plaintext = bytes(plaintext,encoding='utf-8')

        if algo == 'AES-128-CBC-ENC': # Do not change this
            # Write your script here
            padder_object = padding2.PKCS7(128).padder()
            padded_data = padder_object.update(plaintext)+padder_object.finalize()
            encrytion_object = Cipher(algorithms.AES(key),modes.CBC(nonce),backend=default_backend()).encryptor()
            ciphertext = encrytion_object.update(padded_data) + encrytion_object.finalize()

        elif algo == 'AES-128-CTR-ENC': # Do not change this
            # Write your script here
            encryption_object = Cipher(algorithms.AES(key),modes.CTR(nonce),backend=default_backend()).encryptor()
            ciphertext = encryption_object.update(plaintext)+encryption_object.finalize()

        elif algo == 'RSA-2048-ENC': # Do not change this
            # Write your script here
            # here key is public key
            # we need to get the public key from the serialized key

            # maybe we need to break the plaintext into chunks of size 2048 bits, because rsa can only work with 2048 bits of data
            l = list(plaintext)
            divided_plaintext = [l[i:i+self.RSA_ENCRYPT_SIZE] for i in range(0,len(l),self.RSA_ENCRYPT_SIZE)]
            ciphertext = bytes()

            public_key = serialization.load_pem_public_key(key,backend=default_backend())
            count = 0
            for i in divided_plaintext:
                count+=1
                ciphertext += public_key.encrypt(bytes(i), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                             algorithm=hashes.SHA256(),label=None))

        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here


        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this

        return ciphertext # Do not change this

    def decrypt(self, algo, key, ciphertext, nonce): # Do not change this
        """Decrypt the given ciphertext"""
        # Write your script here
        if type(ciphertext)!=type(bytes()):
            ciphertext = bytes(ciphertext,encoding='utf-8')

        if algo=='AES-128-CBC-DEC': # Do not change this
            # Write your script here
            decryption_object = Cipher(algorithms.AES(key),modes.CBC(nonce),backend=default_backend()).decryptor()
            plaintext = decryption_object.update(ciphertext)+decryption_object.finalize()
            # now we need to unpad the plaintext
            unpadder_object = padding2.PKCS7(128).unpadder()
            plaintext = unpadder_object.update(plaintext)+unpadder_object.finalize()

        elif algo == 'AES-128-CTR-DEC': # Do not change this
            # Write your script here
            decryption_object = Cipher(algorithms.AES(key),modes.CTR(nonce),backend=default_backend()).decryptor()
            plaintext = decryption_object.update(ciphertext)+decryption_object.finalize()

        elif algo == 'RSA-2048-DEC': # Do not change this
            # Write your script here
            # we now need to load the serialized private key
            # we first need to divide the ciphertext (similar to encryption)
            l = list(ciphertext)
            divided_ciphertext = [l[i:i+self.RSA_DECRYPT_SIZE] for i in range(0,len(l),self.RSA_DECRYPT_SIZE)]
            plaintext = bytes()

            private_key = serialization.load_pem_private_key(key, password=None, backend=default_backend())
            for i in divided_ciphertext:
                plaintext += private_key.decrypt(bytes(i),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                            algorithm=hashes.SHA256(),label=None))

        else: # Do not change this
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here
        if algo!='RSA-2048-DEC':
            plaintext = plaintext.decode(encoding='utf-8')

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        return plaintext # Do not change this

    def generate_auth_tag(self, algo, key, plaintext, nonce): # Do not change this
        """Generate the authenticate tag for the given plaintext"""

        # Write your script here
        if type(plaintext)!=type(bytes()):
            plaintext = bytes(plaintext,encoding='utf-8')

        if algo =='AES-128-CMAC-GEN': # Do not change this
            # Write your script here
            cmac_object = cmac.CMAC(algorithm=algorithms.AES(key), backend=default_backend())
            cmac_object.update(plaintext)
            auth_tag = cmac_object.finalize()

        elif algo =='SHA3-256-HMAC-GEN': # Do not change this
            # Write your script here
            hmac_object = hmac.HMAC(key, hashes.SHA3_256(), backend=default_backend())
            hmac_object.update(plaintext)
            auth_tag = hmac_object.finalize()

        elif algo =='RSA-2048-SHA3-256-SIG-GEN': # Do not change this
            # Write your script here

            # here we need private key
            private_key = serialization.load_pem_private_key(key, password=None, backend=default_backend())
            auth_tag = private_key.sign(plaintext, padding.PSS(mgf=padding.MGF1(hashes.SHA3_256()),
                                                       salt_length=padding.PSS.MAX_LENGTH),hashes.SHA3_256())


        elif algo =='ECDSA-256-SHA3-256-SIG-GEN': # Do not change this
            # Write your script here
            private_key = serialization.load_pem_private_key(key, password=None, backend=default_backend())
            auth_tag = private_key.sign(plaintext, ec.ECDSA(hashes.SHA3_256()))

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here


        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this

        return auth_tag # Do not change this

    def verify_auth_tag(self, algo, key, plaintext, nonce, auth_tag): # Do not change this
        """Verify the authenticate tag for the given plaintext"""

        # Write your script here
        if type(plaintext)!=type(bytes()):
            plaintext = bytes(plaintext,encoding='utf-8')

        if algo =='AES-128-CMAC-VRF': # Do not change this
            # Write your script here
            cmac_object = cmac.CMAC(algorithm=algorithms.AES(key), backend=default_backend())
            cmac_object.update(plaintext)
            try:
                cmac_object.verify(auth_tag)
                auth_tag_valid = True
            except cryptography.exceptions.InvalidSignature:
                auth_tag_valid = False

        elif algo =='SHA3-256-HMAC-VRF': # Do not change this
            # Write your script here
            hmac_object = hmac.HMAC(key, hashes.SHA3_256(), backend=default_backend())
            hmac_object.update(plaintext)
            try:
                hmac_object.verify(auth_tag)
                auth_tag_valid = True
            except cryptography.exceptions.InvalidSignature:
                auth_tag_valid = False

        elif algo =='RSA-2048-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
            # here we need public key
            public_key = serialization.load_pem_public_key(key, backend=default_backend())
            try:
                public_key.verify(auth_tag, plaintext, padding.PSS(mgf=padding.MGF1(hashes.SHA3_256()),
                                                            salt_length=padding.PSS.MAX_LENGTH),hashes.SHA3_256())
                auth_tag_valid = True
            except cryptography.exceptions.InvalidSignature:
                auth_tag_valid = False

        elif algo =='ECDSA-256-SHA3-256-SIG-VRF': # Do not change this
            # Write your script here
            public_key = serialization.load_pem_public_key(key, backend=default_backend())
            try:
                public_key.verify(auth_tag,plaintext,ec.ECDSA(hashes.SHA3_256()))
                auth_tag_valid = True
            except cryptography.exceptions.InvalidSignature:
                auth_tag_valid = False

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Authentication Key") # Do not change this
        print(key) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this

        return auth_tag_valid # Do not change this

    def encrypt_generate_auth(self, algo, key_encrypt, key_generate_auth, plaintext, nonce): # Do not change this
        """Encrypt and generate the authentication tag for the given plaintext"""

        # Write your script here
        if type(plaintext)!=type(bytes()):
            plaintext = bytes(plaintext,encoding='utf-8')

        if algo == 'AES-128-GCM-GEN': # Do not change this
            # Write your script here
            aesgcm_object = AESGCM(key_encrypt)
            ciphertext = aesgcm_object.encrypt(nonce=nonce,data=plaintext,associated_data=None)
            auth_tag = ciphertext[len(ciphertext)-16:]
            ciphertext = ciphertext[:len(ciphertext)-16]

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Encryption Key") # Do not change this
        print(key_encrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_generate_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this

        return ciphertext, auth_tag # Do not change this

    def decrypt_verify_auth(self, algo, key_decrypt, key_verify_auth, ciphertext, nonce, auth_tag): # Do not change this
        """Decrypt and verify the authentication tag for the given plaintext"""

        # Write your script here
        if type(ciphertext)!=type(bytes()):
            plaintext = bytes(ciphertext,encoding='utf-8')

        if algo == 'AES-128-GCM-VRF': # Do not change this
            # Write your script here
            aesgcm_object = AESGCM(key_decrypt)
            ciphertext += auth_tag
            try:
                plaintext = aesgcm_object.decrypt(nonce=nonce,data=ciphertext,associated_data=None)
                auth_tag_valid = True
            except cryptography.exceptions.InvalidTag:
                plaintext = ""
                auth_tag_valid = False

        else:
            raise Exception("Unexpected algorithm") # Do not change this

        # Write your script here
        plaintext = plaintext.decode(encoding='utf-8')

        print("Algorithm") # Do not change this
        print(algo) # Do not change this
        print("Decryption Key") # Do not change this
        print(key_decrypt) # Do not change this
        print("Authentication Key") # Do not change this
        print(key_verify_auth) # Do not change this
        print("Plaintext") # Do not change this
        print(plaintext) # Do not change this
        print("Nonce") # Do not change this
        print(nonce) # Do not change this
        print("Ciphertext") # Do not change this
        print(ciphertext) # Do not change this
        print("Authentication Tag") # Do not change this
        print(auth_tag) # Do not change this
        print("Authentication Tag Valid") # Do not change this
        print(auth_tag_valid) # Do not change this

        return plaintext, auth_tag_valid # Do not change this

if __name__ == '__main__': # Do not change this
    ExecuteCrypto() # Do not change this
