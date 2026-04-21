import random
import hashlib

# -----------------------------
# 1. Prime Generation
# -----------------------------
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime():
    """Generate a random prime in [500, 1000] — large enough to encrypt small integers."""
    while True:
        num = random.randint(500, 1000)
        if is_prime(num):
            return num

# -----------------------------
# 2. GCD & Modular Inverse
# -----------------------------
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    # Extended Euclidean algorithm
    old_r, r = e, phi
    old_s, s = 1, 0
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
    return old_s % phi

# -----------------------------
# 3. RSA Key Generation
# -----------------------------
def generate_keys():
    """Return (public_key, private_key) as ((e, n), (d, n))."""
    p = generate_prime()
    q = generate_prime()
    while q == p:
        q = generate_prime()

    n   = p * q
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
    """Encrypt a short string message with RSA public key."""
    e, n = public_key
    m = int.from_bytes(message.encode(), 'big')
    assert m < n, f"Message ({m}) must be smaller than n ({n})"
    return pow(m, e, n)

def decrypt_vote(cipher, private_key):
    """Decrypt RSA ciphertext back to original string."""
    d, n = private_key
    m = pow(cipher, d, n)
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()

# -----------------------------
# 5. Hashing (SHA-256)
# -----------------------------
def hash_data(data):
    """Return SHA-256 digest as integer."""
    return int(hashlib.sha256(str(data).encode()).hexdigest(), 16)

# -----------------------------
# 6. Digital Signature
# -----------------------------
def sign_data(data, private_key):
    """
    Sign: S = hash(data) % n  raised to private exponent d.
    We reduce the hash mod n so it fits the RSA modulus.
    """
    d, n = private_key
    h = hash_data(data) % n   # reduce so h < n
    return pow(h, d, n)

def verify_signature(data, signature, public_key):
    """
    Verify: recompute hash(data) % n and compare with S^e mod n.
    Both sides use the same reduction so they must match.
    """
    e, n = public_key
    h = hash_data(data) % n   # same reduction as sign_data
    return pow(signature, e, n) == h
