from Crypto.Util.number import long_to_bytes, inverse, GCD
from sympy import randprime, isprime

# Provided values
w = 115017953136750842312826274882950615840
x = 16700949197226085826583888467555942943
y = 20681722155136911131278141581010571320
c = 2246028367836066762231325616808997113924108877001369440213213182152044731534905739635043920048066680458409222434813

# Assume p, q, r are in the range of randprime(0, 1<<128), we will attempt to reconstruct them
# These would ideally be found by some factorization process

# We try to find p
for candidate_p in range(2**127, 2**128):
    if isprime(candidate_p):
        # Check if it satisfies the mod condition
        if GCD(candidate_p, w) == 1 and GCD(candidate_p, x) == 1:
            if (x % candidate_p == w % candidate_p):
                p = candidate_p
                break

# We try to find q
for candidate_q in range(2**127, 2**128):
    if isprime(candidate_q):
        if (candidate_q % p == w) and (y % candidate_q == w):
            q = candidate_q
            break

# We try to find r
for candidate_r in range(2**127, 2**128):
    if isprime(candidate_r):
        if (candidate_r % p == x) and (candidate_r % q == y):
            r = candidate_r
            break

# If we've found p, q, r
if 'p' in locals() and 'q' in locals() and 'r' in locals():
    n = p * q * r
    e = 65537

    # Calculate phi(n)
    phi_n = (p-1) * (q-1) * (r-1)

    # Calculate the private key exponent
    d = inverse(e, phi_n)

    # Decrypt the message
    m = pow(c, d, n)
    plaintext = long_to_bytes(m)

    print("Decrypted message:", plaintext.decode())
else:
    print("Failed to reconstruct the primes p, q, and r.")
