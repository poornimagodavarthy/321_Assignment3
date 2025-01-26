import random
from hashlib import sha256
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

def diffie_hellman(message_a, message_b, q, alpha):
    #alice's private and public keys
    X_a = random.randint(0, q-1)
    Y_a = pow(alpha, X_a, q)

    #bob's private and public keys
    X_b = random.randint(0, q-1)
    Y_b = pow(alpha, X_b, q)

    #secrets
    S_a = pow(Y_b, X_a, q)
    S_b = pow(Y_a, X_b, q)

    # SHA256
    k_a = sha256(str(S_a).encode()).digest()[:16]
    k_b = sha256(str(S_b).encode()).digest()[:16]

    initialization_vector = get_random_bytes(16)

    #call encrypt and decrypt 
    encrypted_a = encrypt(message_a, k_a, initialization_vector)
    encrypted_b = encrypt(message_b, k_b, initialization_vector)
    decrypted_a = decrypt(encrypted_a, k_a, initialization_vector)
    decrypted_b = decrypt(encrypted_b, k_b, initialization_vector)
    print(encrypted_a, encrypted_b)
    print(decrypted_a, decrypted_b)

#same IV, do padding
def encrypt(message, key, IV):
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    ciphertext = b""
    block_size = AES.block_size
    message = message.encode()
    counter = 0
    while counter *16 < len(message):
        chunk = message[counter*16:min((counter+1)*16, len(message))]
        if not chunk:
            break
        if len(chunk) < block_size:
            chunk = pad(chunk, block_size, style='pkcs7')
        encrypted_chunk = cipher.encrypt(chunk)
        ciphertext += encrypted_chunk
        counter+=1
    return ciphertext

def decrypt(ciphertext, key, IV):
    cipher = AES.new(key, AES.MODE_CBC, iv=IV)
    return unpad(cipher.decrypt(ciphertext), AES.block_size, style="pkcs7").decode()

def main():
    message_a = "Hi Bob"
    message_b = "Hi Aleez"
    diffie_hellman(message_a, message_b, 37, 5)

main()