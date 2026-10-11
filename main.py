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


def choose_exponent(m):
    """
    Pick the public exponent E with 1 < E < m and gcd(E, m) == 1.

    The common choice 65537 (the fourth Fermat number, 2 ** 16 + 1) is used
    when it fits; for tiny demonstration parameters the modulus can be smaller
    than 65537, so the smallest suitable odd exponent is chosen instead.
    D = mod_mul_inverse(E, m) is only meaningful when these conditions hold.
    """
    if 1 < 65537 < m and gcd(65537, m) == 1:
        return 65537
    e = 3
    while e < m and gcd(e, m) != 1:
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
    args = parser.parse_args()
    run(p=args.p, q=args.q, bits=args.bits, seed=args.seed, message=args.message)


if __name__ == '__main__':
    main()
