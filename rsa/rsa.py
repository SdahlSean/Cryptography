import random
import math


# for computing the inverse of e mod φ(n)
def eea(ri_2, ri_1):  # ri_2 = e, ri_1 = φ(n)
    """extended euclidean algorithm"""
    s_1 = 1; t_1 = 0
    s_0 = 0; t_0 = 1
    i = 1
    ri_0 = None
    while ri_0 != 0:
        i += 1
        ri_0 = ri_2 % ri_1
        q = (ri_2 - ri_0) // ri_1
        s_1, s_0 = s_0, s_1 - q * s_0
        t_1, t_0 = t_0, t_1 - q * t_0
        ri_2, ri_1 = ri_1, ri_0
    return ri_2, s_1, t_1


def even_fact(p):
    """factorizes number in form 2 ** u * r, where r is odd"""
    r = p - 1
    u = 0
    while r % 2 == 0 and r != 1:
        u += 1
        r //= 2
    return u, r


# for testing if number given is prime
def mrt(p, s):  # p = number to test, s = safty_parameter
    """miller-rabin-test"""
    u, r = even_fact(p)
    for _ in range(s):
        a = random.randint(2, p-2)
        z = a ** r % p
        if z != 1 and z != p - 1:
            j = 1
            while j < u and z != p - 1:
                z = z ** 2 % p
                if z == 1:
                    return False
                j += 1
            if z != p - 1:
                return False
    return True


def generate_key(n_bits=1024, s=None):
    """generate an rsa public, private key pair"""
    # computing the safety parameter
    if s is None:
        if n_bits < 400:
            if n_bits < 250:
                s = 100
            elif n_bits < 300:
                s = 11
            else:
                s = 9
        else:
            if n_bits < 500:
                s = 6
            elif n_bits < 600:
                s = 5
            else:
                s = 3
    p = 2 * random.randint(int(2 ** (n_bits - 2)), int(2 ** (n_bits - 1))) - 1
    while not mrt(p, s):
        p = 2 * random.randint(int(2 ** (n_bits - 2)), int(2 ** (n_bits - 1))) - 1
    q = 2 * random.randint(int(2 ** (n_bits - 2)), int(2 ** (n_bits - 1))) - 1
    while not mrt(q, s) or p == q:
        q = 2 * random.randint(int(2 ** (n_bits - 2)), int(2 ** (n_bits - 1))) - 1
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = (2**16 + 1) % phi_n
    _, _, d = eea(phi_n, e)
    d %= phi_n
    return ((n, e), (n, d))  # (public_key, private_key)


# for checking if e is valid
def gcd(a, b):
    """compute greatest common divisor"""
    while b != 0:
        b, a = a % b, b
    return a


def is_prime(n):
    """checking if n is prime"""
    if n == 2:
        return True
    if n < 2 or n % 2 == 0:
        return False
    for i in range(3, int(n**(0.5)) + 1, 2):
        if n % i == 0:
            return False
    return True


def validate_key(p, q, e):
    """validate numbers p, q, e as an rsa key"""
    if p == q:
        raise ValueError('p and q must be different')
    if not is_prime(p) or not is_prime(q):
        raise ValueError('p and q must be prime')
    if not gcd((p - 1) * (q - 1), e) == 1:
        raise ValueError('the greates common divisor of phi_n and e must be 1')
    return True


def compute_key(p, q, e):
    """compute public and private rsa keys given p, q, e"""
    validate_key(p, q, e)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    _, _, d = eea(phi_n, e)
    return ((n, e), (n, d))  # (public_key, private_key)


encrypt = lambda x, n, e: x ** e % n  # rsa encryption function
decrypt = lambda y, n, d: y ** d % n  # rsa decryption function