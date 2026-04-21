import random
import hashlib

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5)+1):
        if n % i == 0:
            return False
    return True

def generate_prime():
    while True:
        num = random.randint(10**12, 10**13)  
        if is_prime(num):
            return num

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):                     
    original_phi = phi
    x0, x1 = 0, 1
    if phi == 1:
        return 0
    while e > 1:
        q = e // phi
        e, phi = phi, e % phi
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += original_phi
    return x1

def generate_keys():
    p = generate_prime()
    q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 3
    while gcd(e, phi) != 1:
        e += 2
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

def encrypt_vote(message, public_key):
    e, n = public_key
    m = int.from_bytes(message.encode(), 'big')
    c = pow(m, e, n)
    return c

def decrypt_vote(cipher, private_key):
    d, n = private_key
    m = pow(cipher, d, n)
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()

def hash_data(data):
    return int(hashlib.sha256(str(data).encode()).hexdigest(), 16)

def sign_data(data, private_key):
    d, n = private_key
    hashed = hash_data(data) % n             
    return pow(hashed, d, n)

def verify_signature(data, signature, public_key):
    e, n = public_key
    hashed = hash_data(data) % n             
    return hashed == pow(signature, e, n)