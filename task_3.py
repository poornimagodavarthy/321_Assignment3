from Cryptodome.Util import number

# Part 1: implement RSA from scratch
def key_generation(bits):
    #their mult needs to be close to target size ~ 1/2
    p = number.getPrime(bits//2)
    q = number.getPrime(bits//2)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e=65537
    d = mod_inverse(e, phi_n)
    public_key, private_key = (e, n), (d, n)
    return public_key, private_key

def mod_inverse(a, m):
    # x0 is the initial coefficient for a (trying to find mod inv for this)
    # x1 is the initial coefficient for m (phi n)
    given_m = m
    x0, x1 = 0, 1
    while a > 1:
        q = a // m
        a,m = m, a % m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += given_m
    return x1

def RSA_encryption(plaintext, public_key):
    e, n = public_key
    return pow(plaintext, e, n)

def RSA_decryption(ciphertext, private_key):
    d, n = private_key
    return pow(ciphertext, d, n)

def main():
    bits = 2048
    message = 4567890876543445678945678796543424567890
    public_key, private_key = key_generation(bits)
    ciphertext = RSA_encryption(message, public_key)
    decrypted = RSA_decryption(ciphertext, private_key)
    print(decrypted)
main()


# Part 2: demonstrate an MITM attack where attacker manipulates ciphertext to alter or decrypt message