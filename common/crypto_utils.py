import random
import hashlib

# -----------------------------
# 1. Generate Prime Numbers
# -----------------------------
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5)+1):
        if n % i == 0:
            return False
    return True

def generate_prime():
    while True:
        num = random.randint(100, 300)
        if is_prime(num):
            return num

# -----------------------------
# 2. GCD + Inverse
# -----------------------------
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    for d in range(1, phi):
        if (d * e) % phi == 1:
            return d
    return None

# -----------------------------
# 3. RSA Key Generation
# -----------------------------
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

# -----------------------------
# 4. Encrypt / Decrypt
# -----------------------------
def encrypt_vote(message, public_key):
    e, n = public_key
    m = int.from_bytes(message.encode(), 'big')
    c = pow(m, e, n)
    return c

def decrypt_vote(cipher, private_key):
    d, n = private_key
    m = pow(cipher, d, n)
    message = m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()
    return message

# -----------------------------
# 5. Hash (SHA-256)
# -----------------------------
def hash_data(data):
    return int(hashlib.sha256(str(data).encode()).hexdigest(), 16)

# -----------------------------
# 6. Signature
# -----------------------------
def sign_data(data, private_key):
    d, n = private_key
    hashed = hash_data(data)
    signature = pow(hashed, d, n)
    return signature

# -----------------------------
# 7. Verify Signature
# -----------------------------
def verify_signature(data, signature, public_key):
    e, n = public_key
    hashed = hash_data(data)
    decrypted_hash = pow(signature, e, n)
    return hashed == decrypted_hash