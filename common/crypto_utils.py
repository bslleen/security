import hashlib
import random
import math

# ──────────────────────────────────────────────────────────────
# 1.  HELPER MATH FUNCTIONS
# ──────────────────────────────────────────────────────────────

def gcd(a: int, b: int) -> int:
    """Return the Greatest Common Divisor of a and b (Euclidean algorithm)."""
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e: int, phi: int) -> int:
    """
    Compute the modular inverse of e modulo phi using the
    Extended Euclidean Algorithm.

    Returns d such that (e * d) % phi == 1.
    Raises ValueError if the inverse does not exist.
    """
    original_phi = phi
    x0, x1 = 0, 1

    if phi == 1:
        return 0

    while e > 1:
        if phi == 0:
            raise ValueError(f"Modular inverse does not exist for e={e}, phi={original_phi}")
        q  = e // phi
        e, phi = phi, e % phi
        x0, x1 = x1 - q * x0, x0

    if x1 < 0:
        x1 += original_phi

    return x1


def is_prime(n: int, k: int = 10) -> bool:
    """
    Miller-Rabin primality test.

    Parameters
    ----------
    n : candidate integer
    k : number of rounds (higher = more accurate, default 10 is safe for
        numbers up to ~2^64)

    Returns True if n is *probably* prime, False if it is definitely composite.
    """
    if n < 2:
        return False
    # Small known primes
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)          # fast modular exponentiation (built-in)

        if x in (1, n - 1):
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False   # composite

    return True  # probably prime


def generate_prime(bits: int = 512) -> int:
    """
    Generate a random prime number of the specified bit-length.

    Parameters
    ----------
    bits : desired bit-length (default 512; use 256 for faster demo keys)
    """
    while True:
        # Generate a random odd number of the right size
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1))  # ensure highest bit is set
        candidate |= 1                   # ensure it is odd
        if is_prime(candidate):
            return candidate


# ──────────────────────────────────────────────────────────────
# 2.  RSA KEY GENERATION
# ──────────────────────────────────────────────────────────────

def generate_rsa_keypair(bits: int = 512) -> dict:
    """
    Generate an RSA key-pair from scratch.

    Parameters
    ----------
    bits : bit-length for each prime p and q (so the modulus n is ~2*bits long)

    Returns
    -------
    {
        "public_key":  (e, n),   # tuple – share this freely
        "private_key": (d, n)    # tuple – keep this SECRET
    }

    Algorithm
    ---------
    1. Choose two distinct primes p, q  of `bits` bits each.
    2. Compute n = p * q   (the RSA modulus).
    3. Compute φ(n) = (p-1)(q-1)  (Euler's totient).
    4. Choose e = 65537  (standard public exponent – coprime to φ(n)).
    5. Compute d = e⁻¹ mod φ(n)  (private exponent via extended Euclidean).
    """
    # Step 1 – generate two DISTINCT primes
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)

    # Step 2 – modulus
    n = p * q

    # Step 3 – Euler's totient
    phi_n = (p - 1) * (q - 1)

    # Step 4 – public exponent (65537 is standard; must be coprime with phi_n)
    e = 65537
    if gcd(e, phi_n) != 1:
        # Fallback: find a valid e
        e = 3
        while gcd(e, phi_n) != 1:
            e += 2

    # Step 5 – private exponent
    d = mod_inverse(e, phi_n)

    return {
        "public_key":  (e, n),
        "private_key": (d, n)
    }


# ──────────────────────────────────────────────────────────────
# 3.  HASHING (SHA-256)
# ──────────────────────────────────────────────────────────────

def hash_data(data: bytes | str, algorithm: str = "sha256") -> str:
    """
    Compute a cryptographic hash of *data*.

    Parameters
    ----------
    data      : bytes or str to hash
    algorithm : one of "sha256" (default), "sha512", "sha1", "md5"
                (sha256 recommended for this project)

    Returns
    -------
    Hex-encoded digest string (e.g. "a3f5...").
    """
    supported = {"sha256", "sha512", "sha1", "md5"}
    algorithm = algorithm.lower()
    if algorithm not in supported:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose from: {supported}")

    if isinstance(data, str):
        data = data.encode("utf-8")

    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


def hash_int(value: int, algorithm: str = "sha256") -> int:
    """
    Hash an integer and return the result as an integer.
    Used internally before signing so that sign_data() works on a fixed-size value.
    """
    hex_digest = hash_data(str(value).encode(), algorithm)
    return int(hex_digest, 16)


# ──────────────────────────────────────────────────────────────
# 4.  RSA ENCRYPTION / DECRYPTION
# ──────────────────────────────────────────────────────────────

def text_to_int(text: str) -> int:
    """
    Convert a UTF-8 string to a big integer by encoding it as bytes
    and interpreting those bytes as a big-endian integer.

    Example:  "Candidat_A"  →  some large integer M
    """
    return int.from_bytes(text.encode("utf-8"), byteorder="big")


def int_to_text(number: int) -> str:
    """
    Reverse of text_to_int.
    Converts a big integer back to its UTF-8 string representation.
    """
    byte_length = (number.bit_length() + 7) // 8
    return number.to_bytes(byte_length, byteorder="big").decode("utf-8")


def encrypt_vote(vote: str, server_public_key: tuple) -> int:
    """
    Encrypt a vote string using the SERVER's RSA public key.

    The client calls this before sending the ballot.

    Parameters
    ----------
    vote              : plaintext vote string (e.g. "Candidat_A")
    server_public_key : (e, n)  – the server's public key

    Returns
    -------
    C : int  – the ciphertext  C = M^e mod n

    Security guarantee
    ------------------
    Only the server (holder of d) can recover M from C.
    """
    e, n = server_public_key
    M = text_to_int(vote)

    if M >= n:
        raise ValueError(
            "Vote message is too large for this RSA key size. "
            "Use a larger key or a shorter candidate name."
        )

    C = pow(M, e, n)   # built-in pow with 3 args uses fast modular exponentiation
    return C


def decrypt_vote(ciphertext: int, server_private_key: tuple) -> str:
    """
    Decrypt a ciphertext using the SERVER's RSA private key.

    The server calls this during ballot counting (dépouillement).

    Parameters
    ----------
    ciphertext         : int C received from the client
    server_private_key : (d, n)  – must remain SECRET

    Returns
    -------
    vote : str  – the original candidate name
    """
    d, n = server_private_key
    M = pow(ciphertext, d, n)   # M = C^d mod n
    return int_to_text(M)


# ──────────────────────────────────────────────────────────────
# 5.  DIGITAL SIGNATURE (using voter's RSA key-pair)
# ──────────────────────────────────────────────────────────────

def sign_data(ciphertext: int, voter_private_key: tuple,
              hash_algo: str = "sha256") -> int:
    """
    Create a digital signature for the encrypted vote.

    The CLIENT (voter) calls this to prove authenticity and non-repudiation.

    Process
    -------
    1. Compute h = hash(C)  (as an integer, modulo n to stay in-range)
    2. Compute S = h^d mod n

    Parameters
    ----------
    ciphertext         : the encrypted vote integer C
    voter_private_key  : (d, n)  – the voter's private key
    hash_algo          : hashing algorithm ("sha256", "sha512", "sha1", "md5")

    Returns
    -------
    S : int  – the digital signature
    """
    d, n = voter_private_key

    # Hash the ciphertext and reduce mod n so S = h^d mod n is valid
    h = hash_int(ciphertext, hash_algo) % n

    S = pow(h, d, n)   # S = h^d mod n
    return S


def verify_signature(ciphertext: int, signature: int,
                     voter_public_key: tuple,
                     hash_algo: str = "sha256") -> bool:
    """
    Verify a voter's digital signature on the server side.

    The SERVER calls this to confirm the ballot was sent by the legitimate voter.

    Process
    -------
    1. Recover h' = S^e mod n  (using voter's PUBLIC key)
    2. Recompute h  = hash(C) mod n
    3. If h' == h  → signature is VALID

    Parameters
    ----------
    ciphertext       : the encrypted vote integer C
    signature        : the signature S received from the client
    voter_public_key : (e, n) – the voter's public key (stored by the server)
    hash_algo        : must match the algorithm used in sign_data()

    Returns
    -------
    True if the signature is valid, False otherwise.
    """
    e, n = voter_public_key

    # Recover hash from signature
    h_recovered = pow(signature, e, n)   # h' = S^e mod n

    # Recompute expected hash
    h_expected = hash_int(ciphertext, hash_algo) % n

    return h_recovered == h_expected


# ──────────────────────────────────────────────────────────────
# 6.  QUICK SELF-TEST
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  crypto_utils.py  –  Self-Test")
    print("=" * 60)

    # --- Key generation ---
    print("\n[1] Generating server RSA key-pair (512-bit) ...")
    server_keys  = generate_rsa_keypair(bits=512)
    server_pub   = server_keys["public_key"]
    server_priv  = server_keys["private_key"]
    print(f"    Server public  key  (e, n[:30]): {server_pub[0]}, {str(server_pub[1])[:30]}...")

    print("\n[2] Generating voter RSA key-pair (512-bit) ...")
    voter_keys  = generate_rsa_keypair(bits=512)
    voter_pub   = voter_keys["public_key"]
    voter_priv  = voter_keys["private_key"]
    print(f"    Voter  public  key  (e, n[:30]): {voter_pub[0]}, {str(voter_pub[1])[:30]}...")

    # --- Encryption / decryption ---
    vote = "Candidat_B"
    print(f"\n[3] Encrypting vote: '{vote}'")
    C = encrypt_vote(vote, server_pub)
    print(f"    Ciphertext C (first 40 digits): {str(C)[:40]}...")

    decrypted = decrypt_vote(C, server_priv)
    print(f"    Decrypted vote: '{decrypted}'")
    assert decrypted == vote, "❌ Decryption mismatch!"
    print("    ✅ Encryption/Decryption OK")

    # --- Hashing ---
    print("\n[4] Hashing test (SHA-256) ...")
    for algo in ["sha256", "sha512", "sha1", "md5"]:
        h = hash_data("Candidat_A", algo)
        print(f"    {algo:8s}: {h[:48]}...")

    # --- Signature ---
    print("\n[5] Digital signature (SHA-256) ...")
    S = sign_data(C, voter_priv, hash_algo="sha256")
    print(f"    Signature S (first 40 digits): {str(S)[:40]}...")

    valid = verify_signature(C, S, voter_pub, hash_algo="sha256")
    print(f"    Signature valid? {valid}")
    assert valid, "❌ Signature verification failed!"
    print("    ✅ Signature OK")

    # Tampered ciphertext should fail
    tampered = verify_signature(C + 1, S, voter_pub, hash_algo="sha256")
    print(f"    Tampered vote detected? {not tampered}")
    assert not tampered, "❌ Tampered vote was not detected!"
    print("    ✅ Tampering detection OK")

    print("\n" + "=" * 60)
    print("  All tests passed! crypto_utils.py is ready.")
    print("=" * 60)