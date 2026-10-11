"""
Demonstration of an educational public-key (RSA-like) cryptosystem.

This module only drives the scenario: it generates primes, chooses the key
material and prints a readable transcript. All the mathematical primitives
live in crypto_math.py so that the algorithms stay clean and testable.
"""

import argparse
import os
import random
import sys
import time

from crypto_math import (
    mod_exp,
    bin_sqrt,
    gcd,
    extended_gcd,
    mod_mul_inverse,
    trial_division,
    fermat_test,
)

# When a seed is supplied this holds a seeded generator so the whole run is
# reproducible; otherwise get_rand draws from the OS entropy source.
_rng = None


def show_stat(m, i, s=1, h=1):
    """
    Inline progress indicator (debug helper).

    Writes a carriage-return progress line every s-th step. Enable/disable by
    passing a large step s. flush() is required so the line is actually shown
    while a long computation is still running.
    """
    if i % s == 0:
        sys.stdout.write('\r')
        sys.stdout.write(f'{m}: {int(i / h * 100)}%')
        sys.stdout.flush()


def get_rand(b):
    """
    Return a random integer of b bytes.

    Uses os.urandom by default, or the seeded generator when --seed was given,
    so a run can be reproduced exactly.
    """
    if _rng is not None:
        return _rng.getrandbits(b * 8)
    return int.from_bytes(os.urandom(b), byteorder='little')


def gen_prime(b=6, certainty=10):
    """
    Generate a prime number of b bytes by trial division.

    trial_division is deterministic, so the generated prime is always genuine;
    the probabilistic fermat_test is intentionally not used here.
    """
    x = get_rand(b)
    t = time.time()
    while not trial_division(x):
        x = get_rand(b)
    print(f'  prime found in {time.time() - t:.3f} s')
    return x


def gen_close_primes(b=6):
    """
    Return two distinct primes of b bytes that are close to each other.

    Fermat's factorization (see fermat_factor) is fast only when the two
    factors are close, so the attack demonstration draws the second prime
    from the small numbers just above the first.
    """
    p = gen_prime(b)
    q = p + 2
    while not trial_division(q):
        q += 2
    return p, q


def fermat_factor(n, limit=1 << 20):
    """
    Factor an odd composite n = p * q with Fermat's method.

    Start at a = ceil(bin_sqrt(n)) and look for the first a whose square
    leaves a perfect square: a * a - n == b * b. Then the factors are
    p = a - b and q = a + b, because a * a - b * b = (a - b) * (a + b) = n.
    bin_sqrt provides both the starting point and the exact test for b.

    Fermat's method is fast when the two factors are close and degrades to
    trial division otherwise, hence the iteration limit: if it is hit, the
    factors are too far apart for this demonstration.
    """
    a = bin_sqrt(n)
    if a * a < n:
        a += 1  # ceil of the square root
    for _ in range(limit):
        b2 = a * a - n
        b = bin_sqrt(b2)
        if b * b == b2:  # b2 is a perfect square
            p, q = a - b, a + b
            if p == 1:  # a - b == 1 means the only factors are 1 and n
                raise ValueError(f'{n} is prime, nothing to factor')
            return p, q
        a += 1
    raise ValueError(
        f'no factors within {limit} steps; the factors of {n} are too far apart'
    )


def choose_exponent(m):
    """
    Pick the public exponent E with 1 < E < m and gcd(E, m) == 1.

    The common choice 65537 (the fourth Fermat number, 2 ** 16 + 1) is used
    when it fits; for tiny demonstration parameters the modulus can be smaller
    than 65537, so the smallest suitable odd exponent is chosen instead.
    D = mod_mul_inverse(E, m) is only meaningful when these conditions hold.

    The coprime test is done with the extended algorithm: E * x + m * y == g
    and a valid exponent needs g == 1, which is exactly Bezout's identity.
    """
    if 1 < 65537 < m and extended_gcd(65537, m)[0] == 1:
        return 65537
    e = 3
    while e < m and extended_gcd(e, m)[0] != 1:
        e += 2
    if not 1 < e < m:
        raise ValueError(
            f'no valid public exponent exists for modulus {m}; '
            'choose larger primes'
        )
    return e


def int_to_text(m):
    """Decode a message integer back to a UTF-8 string."""
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(length, 'big').decode('utf-8')


def text_to_int(text):
    """Encode a string into a single message integer."""
    return int.from_bytes(text.encode('utf-8'), 'big')


def run(p=None, q=None, bits=6, seed=None, message=None):
    """Run one full encryption/decryption demonstration and print the result."""
    global _rng

    if seed is not None:
        _rng = random.Random(seed)

    print('=' * 60)
    print('  RSA-LIKE PUBLIC-KEY DEMONSTRATION')
    print('=' * 60)

    print('\n[1] PRIME PARAMETERS')
    if p is None or q is None:
        p = p if p is not None else gen_prime(bits)
        q = q if q is not None else gen_prime(bits)
    print(f'  p = {p}')
    print(f'  q = {q}')

    N = p * q
    print(f'  N = p * q = {N}')

    # Carmichael function: lambda(N) is the exponent of the multiplicative
    # group modulo N, computed here as lcm(p - 1, q - 1).
    M = ((p - 1) * (q - 1)) // gcd(p - 1, q - 1)
    print(f'  lambda(N) = {M}')

    E = choose_exponent(M)
    D = mod_mul_inverse(E, M)
    print(f'  public exponent  E = {E}')
    print(f'  private exponent D = {D}   (D * E mod lambda = {D * E % M})')

    print('\n[2] MESSAGE -> INTEGER')
    if message is None:
        text = 'RSA!'
        m = text_to_int(text)
        print(f'  text    = {text!r}')
    else:
        m = message
        text = None
        print('  numeric input')
    print(f'  m = {m}')

    # Block splitting. r is the remainder modulo N and is the only part that
    # is actually encrypted. n is the quotient. The third value is the fixed
    # marker p = N - 1, so that (N - 1) ** E mod N = N - 1 for any odd E.
    # This is a deliberate teaching device: the marker proves the RSA
    # round-trip, and the reconstruction d = (p_dec + 1) * n + r_dec relies
    # on p_dec == N - 1. It also means the high part of the message is not
    # really hidden, so this scheme must not be used for real secrecy.
    n = m // N
    r = m % N
    block = N - 1

    print('\n[3] BLOCKS')
    print(f'  quotient  n = {n}')
    print(f'  remainder r = {r}')
    print(f'  marker    b = N - 1 = {block}')

    block_enc = mod_exp(block, E, N)
    r_enc = mod_exp(r, E, N)
    block_dec = mod_exp(block_enc, D, N)
    r_dec = mod_exp(r_enc, D, N)

    print('\n[4] ENCRYPTED (ciphertext)')
    print(f'  marker    = {block_enc}')
    print(f'  remainder = {r_enc}')

    print('\n[5] DECRYPTED')
    print(f'  marker    = {block_dec}')
    print(f'  remainder = {r_dec}')

    d = (block_dec + 1) * n + r_dec

    print('\n[6] RESULT')
    print(f'  recovered m = {d}')
    print(f'  matches original: {d == m}')
    if text is not None:
        print(f'  recovered text = {int_to_text(d)!r}')
    print('=' * 60)

    return d


def bezout_check(a, b):
    """
    Return the extended_gcd result plus the identity value a * x + b * y.

    Used by the --check bezout helper so the Bezout identity can be shown and
    verified without recomputing the coefficients.
    """
    g, x, y = extended_gcd(a, b)
    return g, x, y, a * x + b * y


def prime_check(n):
    """
    Compare the deterministic and probabilistic primality tests on n.

    Returns (trial_division(n), fermat_test(n, k)). The Fermat test accepts
    Carmichael numbers such as 561, which is exactly the contrast this helper
    is meant to demonstrate.
    """
    return trial_division(n), fermat_test(n, 20)


def run_attack(bits=6, seed=None):
    """
    Break an RSA key by factoring N with Fermat's method.

    The demonstration generates two primes that are deliberately close to each
    other, derives the key exactly as run() does, then recovers the factors
    from the public modulus alone. With p and q known the private exponent D
    can be rebuilt, so the "attack" shows why the primes must not be close in
    a real system.
    """
    global _rng
    if seed is not None:
        _rng = random.Random(seed)

    print('=' * 60)
    print('  FERMAT FACTORIZATION ATTACK ON N')
    print('=' * 60)

    p, q = gen_close_primes(bits)
    N = p * q
    M = ((p - 1) * (q - 1)) // gcd(p - 1, q - 1)
    E = choose_exponent(M)

    print('\n[1] VICTIM KEY (factors hidden in a real scenario)')
    print(f'  N = {N}')
    print(f'  E = {E}')

    print('\n[2] FACTORING N = p * q (Fermat, using bin_sqrt)')
    root = bin_sqrt(N)
    a = root + (0 if root * root == N else 1)  # ceil(sqrt(N))
    t = time.time()
    fp, fq = fermat_factor(N)
    elapsed = time.time() - t
    print(f'  a = ceil(sqrt(N)) = {a}')
    print(f'  found p = {fp}')
    print(f'  found q = {fq}')
    print(f'  p * q == N: {fp * fq == N}')
    print(f'  elapsed: {elapsed:.3f} s')

    print('\n[3] REBUILDING THE PRIVATE KEY')
    Mr = ((fp - 1) * (fq - 1)) // gcd(fp - 1, fq - 1)
    Dr = mod_mul_inverse(E, Mr)
    print(f'  recovered p = {fp}, q = {fq}')
    print(f'  recovered lambda(N) = {Mr}')
    print(f'  recovered private exponent D = {Dr}')

    print('\n[4] VERIFICATION')
    plaintext = 12345
    ciphertext = mod_exp(plaintext, E, N)
    recovered = mod_exp(ciphertext, Dr, N)
    print(f'  plaintext  m = {plaintext}')
    print(f'  ciphertext c = {ciphertext}')
    print(f'  c ** D mod N = {recovered}')
    print(f'  decryption works: {recovered == plaintext}')
    print('=' * 60)

    return fp, fq


def run_check(what, a=None, b=None, n=None):
    """Dispatch the --check helpers for sqrt, bezout and prime tests."""
    if what == 'sqrt':
        if a is None:
            raise ValueError('--sqrt-number is required for --check sqrt')
        floor = bin_sqrt(a)
        print(f'  bin_sqrt({a}) = {floor}')
        print(f'  floor ** 2 = {floor * floor}')
        print(f'  ceil  = {floor + (0 if floor * floor == a else 1)}')
        return floor
    if what == 'bezout':
        if a is None or b is None:
            raise ValueError('--bezout-a and --bezout-b are required for --check bezout')
        g, x, y, identity = bezout_check(a, b)
        print(f'  extended_gcd({a}, {b}) = ({g}, {x}, {y})')
        print(f'  gcd = {g}, math.gcd = {gcd(a, b)}')
        print(f'  {a} * {x} + {b} * {y} = {identity}')
        print(f'  identity holds: {identity == g}')
        return g, x, y
    if what == 'prime':
        if n is None:
            raise ValueError('--prime is required for --check prime')
        deterministic, probabilistic = prime_check(n)
        print(f'  n = {n}')
        print(f'  trial_division (deterministic) = {deterministic}')
        print(f'  fermat_test    (probabilistic) = {probabilistic}')
        print(f'  agreement: {deterministic == probabilistic}')
        if probabilistic and not deterministic:
            print('  note: fermat_test accepted a Carmichael number; '
                  'trial_division rejects it')
        return deterministic, probabilistic
    raise ValueError(f'unknown check: {what!r}')


def main():
    parser = argparse.ArgumentParser(
        description='Educational RSA-like public-key demonstration.'
    )
    parser.add_argument('--seed', type=int, default=None,
                        help='seed the random generator for reproducible output')
    parser.add_argument('--p', type=int, default=None,
                        help='explicit first prime (deterministic scenario)')
    parser.add_argument('--q', type=int, default=None,
                        help='explicit second prime (deterministic scenario)')
    parser.add_argument('--bits', type=int, default=6,
                        help='size in bytes of generated primes (default: 6)')
    parser.add_argument('--m', type=int, default=None, dest='message',
                        help='numeric message instead of the built-in text')
    parser.add_argument('--attack', action='store_true',
                        help='break a key by factoring N (Fermat, uses bin_sqrt)')
    parser.add_argument('--check', choices=('sqrt', 'bezout', 'prime'),
                        default=None, help='run a standalone math helper')
    parser.add_argument('--sqrt-number', type=int, default=None, dest='sqrt_number',
                        help='number for --check sqrt (uses bin_sqrt)')
    parser.add_argument('--bezout-a', type=int, default=None, dest='bezout_a',
                        help='first number for --check bezout (uses extended_gcd)')
    parser.add_argument('--bezout-b', type=int, default=None, dest='bezout_b',
                        help='second number for --check bezout (uses extended_gcd)')
    parser.add_argument('--prime', type=int, default=None,
                        help='number for --check prime (trial_division vs fermat_test)')
    args = parser.parse_args()

    if args.check is not None:
        a = args.sqrt_number if args.check == 'sqrt' else args.bezout_a
        try:
            run_check(args.check, a=a, b=args.bezout_b, n=args.prime)
        except ValueError as exc:
            parser.error(str(exc))
        return

    if args.attack:
        run_attack(bits=args.bits, seed=args.seed)
        return

    run(p=args.p, q=args.q, bits=args.bits, seed=args.seed, message=args.message)


if __name__ == '__main__':
    main()
