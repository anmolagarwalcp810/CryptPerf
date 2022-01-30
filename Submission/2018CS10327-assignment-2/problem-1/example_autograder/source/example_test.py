from submissions.execute_crypto import ExecuteCrypto
import os
import time

execute_crypto_object = ExecuteCrypto()

symmetric_key, public_key_sender_rsa, private_key_sender_rsa, public_key_receiver_rsa, private_key_receiver_rsa, \
public_key_sender_ecc, private_key_sender_ecc = execute_crypto_object.generate_keys()

nonce_aes_cbc, nonce_aes_ctr, nonce_encrypt_rsa, nonce_aes_cmac, \
nonce_hmac, nonce_tag_rsa, nonce_ecdsa, nonce_aes_gcm = execute_crypto_object.generate_nonces()

ENC = "-ENC"
DEC = "-DEC"
GEN = "-GEN"
VRF = "-VRF"

'''
Since we assume that keys and nonce are already generated, we don't generate them inside function 
'''

aes_cbc = "AES-128-CBC"
aes_ctr = "AES-128-CTR"
rsa_2048 = "RSA-2048"
aes_cmac = "AES-128-CMAC"
sha3_hmac = "SHA3-256-HMAC"
rsa_auth = "RSA-2048-SHA3-256-SIG"
ecdsa_auth = "ECDSA-256-SHA3-256-SIG"
aes_gcm = "AES-128-GCM"


def run_encryption(algo,plaintext):
    # here we do everything from generating key, sending message sender to receiver and then returning decrypted output
    if algo==aes_cbc:
        t1 = time.time()
        ciphertext = execute_crypto_object.encrypt(algo+ENC,symmetric_key,plaintext,nonce_aes_cbc)
        t2 = time.time()
        output = execute_crypto_object.decrypt(algo+DEC,symmetric_key,ciphertext,nonce_aes_cbc)
        t3 = time.time()
        key_length_sender = len(symmetric_key)
        key_length_receiver = len(symmetric_key)
    elif algo==aes_ctr:
        t1 = time.time()
        ciphertext = execute_crypto_object.encrypt(algo + ENC, symmetric_key, plaintext, nonce_aes_cbc)
        t2 = time.time()
        output = execute_crypto_object.decrypt(algo + DEC, symmetric_key, ciphertext, nonce_aes_cbc)
        t3 = time.time()
        key_length_sender = len(symmetric_key)
        key_length_receiver = len(symmetric_key)
    elif algo==rsa_2048:
        t1 = time.time()
        ciphertext = execute_crypto_object.encrypt(algo+ENC,public_key_receiver_rsa,plaintext,nonce_encrypt_rsa)
        t2 = time.time()
        output = execute_crypto_object.decrypt(algo+DEC,private_key_receiver_rsa,ciphertext,nonce_encrypt_rsa)
        t3 = time.time()
        key_length_sender = len(public_key_receiver_rsa)
        key_length_receiver = len(private_key_receiver_rsa)
    else:
        ciphertext=0
        output=""
        key_length_sender = 0
        key_length_receiver = 0
        t1, t2, t3 = 0, 0, 0

    packet_length = len(ciphertext)

    return key_length_sender, key_length_receiver, packet_length, output, t1, t2, t3

def run_authentication(algo,plaintext):
    if algo==aes_cmac:
        t1 = time.time()
        auth_tag = execute_crypto_object.generate_auth_tag(algo+GEN,symmetric_key,plaintext,nonce_aes_cmac)
        t2 = time.time()
        auth_tag_valid = execute_crypto_object.verify_auth_tag(algo+VRF,symmetric_key,plaintext,nonce_aes_cmac,auth_tag)
        t3 = time.time()
        key_length_sender = len(symmetric_key)
        key_length_receiver = len(symmetric_key)
    elif algo==sha3_hmac:
        t1 = time.time()
        auth_tag = execute_crypto_object.generate_auth_tag(algo + GEN, symmetric_key, plaintext, nonce_hmac)
        t2 = time.time()
        auth_tag_valid = execute_crypto_object.verify_auth_tag(algo + VRF, symmetric_key, plaintext, nonce_hmac,auth_tag)
        t3 = time.time()
        key_length_sender = len(symmetric_key)
        key_length_receiver = len(symmetric_key)
    elif algo==rsa_auth:
        t1 = time.time()
        auth_tag = execute_crypto_object.generate_auth_tag(algo + GEN, private_key_sender_rsa, plaintext, nonce_tag_rsa)
        t2 = time.time()
        auth_tag_valid = execute_crypto_object.verify_auth_tag(algo + VRF, public_key_sender_rsa, plaintext, nonce_tag_rsa,auth_tag)
        t3 = time.time()
        key_length_sender = len(private_key_sender_rsa)
        key_length_receiver = len(public_key_sender_rsa)
    elif algo==ecdsa_auth:
        t1 = time.time()
        auth_tag = execute_crypto_object.generate_auth_tag(algo + GEN, private_key_sender_ecc, plaintext, nonce_ecdsa)
        t2 = time.time()
        auth_tag_valid = execute_crypto_object.verify_auth_tag(algo + VRF, public_key_sender_ecc, plaintext,nonce_ecdsa, auth_tag)
        t3 = time.time()
        key_length_sender = len(private_key_sender_ecc)
        key_length_receiver = len(public_key_sender_ecc)
    else:
        auth_tag = ""
        auth_tag_valid=""
        key_length_sender, key_length_receiver = 0, 0
        t1, t2, t3 = 0, 0, 0

    packet_length = len(plaintext) + len(auth_tag)

    return key_length_sender, key_length_receiver, packet_length, auth_tag_valid, t1, t2, t3

def run_authenticated_encryption(algo, plaintext):
    if algo==aes_gcm:
        t1 = time.time()
        ciphertext, auth_tag = execute_crypto_object.encrypt_generate_auth(algo+GEN,symmetric_key,symmetric_key,plaintext,nonce_aes_gcm)
        t2 = time.time()
        output, auth_tag_valid = execute_crypto_object.decrypt_verify_auth(algo+VRF,symmetric_key,symmetric_key,ciphertext,nonce_aes_gcm,auth_tag)
        t3 = time.time()
        key_length_sender, key_length_receiver = len(symmetric_key), len(symmetric_key)
    else:
        ciphertext, auth_tag = "", ""
        output, auth_tag_valid = "", False
        key_length_sender, key_length_receiver = 0, 0
        t1, t2, t3 = 0, 0, 0

    packet_length = len(ciphertext)+len(auth_tag)

    return key_length_sender, key_length_receiver, packet_length, output, t1, t2, t3, ciphertext, auth_tag, auth_tag_valid

# now we simply run the measurements and check whether they are running correctly
file = open('submissions/original_plaintext.txt', 'r')
plaintext = file.read()
file.close()

plaintext = bytes(plaintext,encoding='UTF-8')

algo = rsa_2048

avg_encrypt_time = 0
avg_decrypt_time = 0
count = 3

for _ in range(count):
    key_length_sender, key_length_receiver, packet_length, output, t1, t2, t3 = run_encryption(algo,plaintext)
    # key_length_sender, key_length_receiver, packet_length, output, t1, t2, t3 = run_authentication(algo,plaintext)
    # key_length_sender, key_length_receiver, packet_length, output, t1, t2, t3, _, _, _ = run_authenticated_encryption(algo,plaintext)

    # print(f"Encryption Time: {(t2-t1)*1000} ms \nDecryption Time: {(t3-t2)*1000} ms \nkey_length_sender: {key_length_sender*8}\n"
    #       f"key_length_receiver: {key_length_receiver*8}\npacket_length: {packet_length}\nplaintext: {output}")

    avg_encrypt_time += (t2 - t1)*1000
    avg_decrypt_time += (t3 - t2)*1000

avg_encrypt_time /= count
avg_decrypt_time /= count

print(f"Encryption Time: {avg_encrypt_time} ms \nDecryption Time: {avg_decrypt_time} ms")