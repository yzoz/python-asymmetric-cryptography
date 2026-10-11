"""
Demonstration of an educational public-key (RSA-like) cryptosystem.

This module only drives the scenario: it generates primes, chooses the key
material and prints a readable transcript. All the mathematical primitives
live in crypto_math.py and every text conversion lives in crypto_text.py, so
that the algorithms stay clean and testable.
"""

import argparse
import os
import random
import re
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
from crypto_text import (
    DEFAULT_MESSAGE,
    COLUMNS,
    BREAKDOWN_THRESHOLD,
    CATEGORY_ORDER,
    encoding_steps,
    char_records,
    char_categories,
    block_size,
    split_blocks,
)

# When a seed is supplied this holds a seeded generator so the whole run is
# reproducible; otherwise get_rand draws from the OS entropy source.
_rng = None

# Number of bases tried by fermat_test. For a composite that is not a
# Carmichael number the chance of a false "prime" is at most 2 ** -FERMAT_ROUNDS;
# at the default six-byte primes the whole test costs about a millisecond.
FERMAT_ROUNDS = 20

# The five smallest Carmichael numbers. They pass fermat_test for every base
# coprime to them, which is why the probabilistic test cannot be trusted alone.
CARMICHAEL_EXAMPLES = (561, 1105, 1729, 2465, 2821)

# A decimal rendering longer than this many digits is not printed: Python
# refuses int -> str beyond sys.get_int_max_str_digits() (4300 by default, and
# the conversion is quadratic in the digit count). The limit is approached with
# a safety margin and the value is summarised instead (see print_big_int).
BIG_INT_DIGITS = 4000

# Block transcript truncation: with more blocks than this, only the first and
# the last BLOCK_PRINT_EDGE are printed.
BLOCK_PRINT_LIMIT = 20
BLOCK_PRINT_EDGE = 3


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


def is_prime(x, prime_method='trial'):
    """
    Primality dispatcher selected by --prime.

    'trial' uses the deterministic trial_division; 'fermat' uses the
    probabilistic fermat_test (which accepts Carmichael numbers). It is used
    only for *generating* candidates: every chosen p and q is re-checked
    deterministically by validate_prime, so a Fermat false positive can never
    reach the key material.
    """
    if prime_method == 'fermat':
        return fermat_test(x, FERMAT_ROUNDS)
    return trial_division(x)


def common_divisor(a, b, gcd_method='euclid'):
    """
    Greatest common divisor dispatcher selected by --gcd.

    'euclid' uses gcd(); 'extended' uses extended_gcd() and keeps only the
    shared factor g (the Bezout coefficients are simply ignored here). Both
    return the same value, so the transcript is identical either way.
    """
    if gcd_method == 'extended':
        return extended_gcd(a, b)[0]
    return gcd(a, b)


def validate_prime(x, name, prime_method='trial'):
    """
    Assert that an explicitly supplied p or q is really prime.

    The check is always deterministic (trial_division), even when --prime
    fermat was selected: otherwise a Fermat false positive such as a Carmichael
    number would silently produce a broken key. A composite raises ValueError
    with a readable message; a Carmichael number is called out by name.
    """
    if trial_division(x):
        return
    if x in CARMICHAEL_EXAMPLES:
        raise ValueError(
            f'{name} = {x} is a composite Carmichael number: it passes '
            f'fermat_test yet is not prime (examples: '
            f'{", ".join(map(str, CARMICHAEL_EXAMPLES))})'
        )
    raise ValueError(f'{name} = {x} is not a prime number')


def gen_prime(b=6, prime_method='trial'):
    """
    Generate a prime number of b bytes.

    Candidates are tested with the method selected by --prime (trial_division
    or fermat_test). trial_division is deterministic; fermat_test is faster but
    probabilistic, so with --prime fermat a candidate may occasionally be a
    composite - the final key parameters are validated separately.
    """
    x = get_rand(b)
    t = time.time()
    while not is_prime(x, prime_method):
        x = get_rand(b)
    print(f'  prime found in {time.time() - t:.3f} s')
    return x


def looks_like_int(s):
    """
    Return True when s is an optionally signed run of decimal digits.

    Used by the CLI to decide whether --m is a numeric message or a text; a
    string such as 'hello' is text, while '-42' and '007' are numbers.
    """
    return re.fullmatch(r'[+-]?\d+', s) is not None


def gen_close_primes(b=6, prime_method='trial'):
    """
    Return two distinct primes of b bytes that are close to each other.

    Fermat's factorization (see fermat_factor) is fast only when the two
    factors are close, so the attack demonstration draws the second prime
    from the small numbers just above the first.
    """
    p = gen_prime(b, prime_method)
    q = p + 2
    while not is_prime(q, prime_method):
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


def choose_exponent(m, gcd_method='euclid'):
    """
    Pick the public exponent E with 1 < E < m and gcd(E, m) == 1.

    The common choice 65537 (the fourth Fermat number, 2 ** 16 + 1) is used
    when it fits; for tiny demonstration parameters the modulus can be smaller
    than 65537, so the smallest suitable odd exponent is chosen instead.
    D = mod_mul_inverse(E, m) is only meaningful when these conditions hold.

    The coprime test uses the method selected by --gcd; extended_gcd also
    returns the Bezout coefficients, of which only the shared factor is used
    here (a valid exponent needs g == 1).
    """
    if 1 < 65537 < m and common_divisor(65537, m, gcd_method) == 1:
        return 65537
    e = 3
    while e < m and common_divisor(e, m, gcd_method) != 1:
        e += 2
    if not 1 < e < m:
        raise ValueError(
            f'no valid public exponent exists for modulus {m}; '
            'choose larger primes'
        )
    return e


def print_categories(text):
    """
    Print a compact one-line-per-category summary of the characters in text.

    The counts make the composition of the default alphabet immediately
    visible (26 upper, 26 lower, 10 digits and the special characters).
    """
    groups = char_categories(text)
    print('  category    count  characters')
    for name in CATEGORY_ORDER:
        chars = groups[name]
        if not chars:
            continue
        shown = ''.join(chars)
        if len(shown) > 46:
            shown = shown[:43] + '...'
        print(f'  {name:<10} {len(chars):>5}  {shown}')


def print_char_table(text, columns=COLUMNS):
    """
    Print the per-character breakdown as a multi-column table.

    Each character becomes one cell of (index, char, code point, utf-8 hex).
    Cells are filled row by row (index 0,1,2,... then the next row), and the
    whole table is laid out in `columns` vertical groups.
    """
    records = char_records(text)
    rows = (len(records) + columns - 1) // columns

    header = '  {:>2}  {}  {:<6}  {}'.format('id', 'ch', 'code', 'hex')
    divider = '  --  --  ------  ---'
    print('   |  '.join([header] * columns))
    print('   |  '.join([divider] * columns))

    for r in range(rows):
        cells = []
        for c in range(columns):
            i = c * rows + r
            if i < len(records):
                index, ch, code, hexstr = records[i]
                # A space is invisible in the table, so it is shown as the
                # visible U+2420 symbol; every other character prints as is.
                display = '\u2420' if ch == ' ' else ch
                cells.append('  {:>2}  {}  {}  {}'.format(
                    index, display, code, hexstr))
            else:
                cells.append(' ' * 18)
        print('   |  '.join(cells))


def decimal_digits(x):
    """
    Upper bound on the number of decimal digits of a non-negative integer.

    Uses the bit length (log10(x) < bit_length(x) * log10(2)) so no decimal
    conversion is performed. This is what lets print_big_int decide *before*
    calling str() whether the value is safe to render: the int -> str limit and
    the quadratic cost are both avoided.
    """
    if x < 0:
        x = -x
    return x.bit_length() * 30103 // 100000 + 1  # log10(2) ~ 0.30103


def print_big_int(label, value, threshold=BIG_INT_DIGITS):
    """
    Print an integer, fully when short and as a summary when very long.

    Python refuses to convert a too-long integer to decimal (see the note on
    BIG_INT_DIGITS), so a long value is summarised instead of crashing: the
    digit count, the bit length and a truncated hexadecimal form are shown.
    The decision uses decimal_digits, so str() is never called on a value that
    would exceed the limit.
    """
    if decimal_digits(value) <= threshold:
        print(f'  {label} = {value}')
        return
    digits = decimal_digits(value)
    hexstr = format(value, 'x')
    print(f'  {label} = <{digits} decimal digits, skipped>')
    print(f'           bits = {value.bit_length()}, hex = 0x{hexstr[:32]}... '
          f'(truncated)')
    print('           note: full decimal form exceeds the int -> str limit; '
          'only the hexadecimal prefix is shown')


def print_blocks(blocks, E, D, N):
    """
    Encrypt and decrypt one list of byte blocks and print the transcript.

    Returns the list of (plain_int, cipher_int, back_int) triples so the
    caller can rebuild the message and verify the round-trip. When there are
    more than BLOCK_PRINT_LIMIT blocks only the first and the last
    BLOCK_PRINT_EDGE are printed (the computation stays complete).
    """
    results = []
    total = len(blocks)
    for i, block in enumerate(blocks):
        plain = int.from_bytes(block, 'big')
        cipher = mod_exp(plain, E, N)
        back = mod_exp(cipher, D, N)
        results.append((plain, cipher, back))
        if total > BLOCK_PRINT_LIMIT and not (
            i < BLOCK_PRINT_EDGE or i >= total - BLOCK_PRINT_EDGE
        ):
            if i == BLOCK_PRINT_EDGE:
                print(f'  ... {total - 2 * BLOCK_PRINT_EDGE} blocks omitted ...')
            continue
        print(f'  block {i}: plain = {plain}')
        print(f'           cipher = {cipher}')
        print(f'           back   = {back}   ok: {back == plain}')
    return results


def run(p=None, q=None, bits=6, seed=None, message=None, text=None,
        gcd_method='euclid', prime_method='trial'):
    """
    Run one full encryption/decryption demonstration and print the result.

    Two paths are supported:

    * text path (message is None): the text is encoded as UTF-8 and encrypted
      block by block, properly hiding every byte;
    * numeric path (message is an int): the historical single-value scheme
      with the fixed marker block N - 1 is kept.

    gcd_method and prime_method come from --gcd / --prime. A short educational
    note is printed only when a non-default algorithm was explicitly chosen.
    """
    global _rng

    if seed is not None:
        _rng = random.Random(seed)

    print('=' * 60)
    print('  RSA-LIKE PUBLIC-KEY DEMONSTRATION')
    print('=' * 60)

    if gcd_method == 'extended':
        print('  gcd: extended_gcd also returns the Bezout coefficients '
              '(g, x, y)')
        print('       with a*x + b*y = g; the shared factor g is the same as '
              'gcd returns.')
    if prime_method == 'fermat':
        print('  primality: fermat_test is probabilistic and accepts '
              'Carmichael numbers')
        print(f'             (e.g. {", ".join(map(str, CARMICHAEL_EXAMPLES))}); '
              f'p and q are re-checked deterministically anyway.')

    print('\n[1] PRIME PARAMETERS')
    if p is None or q is None:
        p = p if p is not None else gen_prime(bits, prime_method)
        q = q if q is not None else gen_prime(bits, prime_method)
    # Always verify deterministically, even with --prime fermat: a probabilistic
    # false positive must never reach the key material.
    validate_prime(p, 'p', prime_method)
    validate_prime(q, 'q', prime_method)
    print(f'  p = {p}')
    print(f'  q = {q}')

    N = p * q
    print(f'  N = p * q = {N}')

    # Carmichael function: lambda(N) is the exponent of the multiplicative
    # group modulo N, computed here as lcm(p - 1, q - 1).
    M = ((p - 1) * (q - 1)) // common_divisor(p - 1, q - 1, gcd_method)
    print(f'  lambda(N) = {M}')

    E = choose_exponent(M, gcd_method)
    D = mod_mul_inverse(E, M)
    print(f'  public exponent  E = {E}')
    print(f'  private exponent D = {D}   (D * E mod lambda = {D * E % M})')

    if message is None:
        text = text if text is not None else DEFAULT_MESSAGE
        print('\n[2] MESSAGE -> INTEGER')
        shown, data, hexstr, m = encoding_steps(text)
        print(f'  text    = {shown!r}')
        print(f'  UTF-8   = {data!r}')
        print(f'  hex     = {hexstr}')
        print_big_int('m (int)', m)

        print(f'\n[2b] CHARACTER BREAKDOWN   '
              f'(len {len(text)}, threshold {BREAKDOWN_THRESHOLD})')
        if len(text) <= BREAKDOWN_THRESHOLD:
            print_categories(text)
            print()
            print_char_table(text)
        else:
            print('  text is longer than the threshold; table skipped')

        k = block_size(N)
        blocks = split_blocks(data, k)
        print(f'\n[3] BLOCK SPLITTING   '
              f'(k = {k} bytes, N has {N.bit_length()} bits)')
        results = print_blocks(blocks, E, D, N)

        recovered = b''.join(
            back.to_bytes(len(block), 'big')
            for block, (_, _, back) in zip(blocks, results)
        )
        decoded = recovered.decode('utf-8')

        print('\n[6] RESULT')
        print_big_int('recovered int', int.from_bytes(recovered, 'big'))
        print(f'  recovered text = {decoded!r}')
        print(f'  matches original: {decoded == text}')
        print('=' * 60)
        return decoded

    print('\n[2] MESSAGE -> INTEGER')
    m = message
    print('  numeric input')
    print_big_int('m', m)

    # Block splitting. r is the remainder modulo N and is the only part that
    # is actually encrypted. n is the quotient. The third value is the fixed
    # marker b = N - 1, so that (N - 1) ** E mod N = N - 1 for any odd E.
    # This is a deliberate teaching device: the marker proves the RSA
    # round-trip, and the reconstruction d = (block_dec + 1) * n + r_dec relies
    # on block_dec == N - 1. It also means the high part of the message is not
    # really hidden, so this scheme must not be used for real secrecy.
    n = m // N
    r = m % N
    block = N - 1

    print('\n[3] BLOCKS')
    print_big_int('quotient  n', n)
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
    print_big_int('recovered int', d)
    print(f'  matches original: {d == m}')
    print('=' * 60)

    return d


def run_attack(bits=6, seed=None, gcd_method='euclid', prime_method='trial'):
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

    p, q = gen_close_primes(bits, prime_method)
    N = p * q
    M = ((p - 1) * (q - 1)) // common_divisor(p - 1, q - 1, gcd_method)
    E = choose_exponent(M, gcd_method)

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
    Mr = ((fp - 1) * (fq - 1)) // common_divisor(fp - 1, fq - 1, gcd_method)
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
    parser.add_argument('--m', type=str, default=None, dest='message',
                        help='message: a number is encrypted as a number, '
                             'anything else as UTF-8 text (default: built-in '
                             'alphabet message)')
    parser.add_argument('--text', type=str, default=None,
                        help='force a text message even when it looks numeric')
    parser.add_argument('--attack', action='store_true',
                        help='break a key by factoring N (Fermat, uses bin_sqrt)')
    parser.add_argument('--gcd', choices=('euclid', 'extended'),
                        default='euclid', dest='gcd_method',
                        help='gcd algorithm: euclid (default) or extended '
                             '(extended_gcd, also yields Bezout coefficients)')
    parser.add_argument('--prime', choices=('trial', 'fermat'),
                        default='trial', dest='prime_method',
                        help='primality test for generating p and q: trial '
                             '(deterministic, default) or fermat (probabilistic)')
    args = parser.parse_args()

    if args.attack:
        try:
            run_attack(bits=args.bits, seed=args.seed,
                       gcd_method=args.gcd_method,
                       prime_method=args.prime_method)
        except ValueError as exc:
            parser.error(str(exc))
        return

    # Resolve the CLI message into either a numeric message (int) or text.
    if args.text is not None:
        message, text = None, args.text
    elif args.message is not None and looks_like_int(args.message):
        # A decimal argument longer than the int -> str limit cannot be parsed
        # at all (the same CPython limit blocks str -> int for base 10), so it
        # is reported instead of raising a traceback.
        try:
            message, text = int(args.message), None
        except ValueError:
            digits = len(args.message.lstrip('+-'))
            parser.error(
                f'--m has {digits} digits, which exceeds the int -> str limit; '
                'use a shorter number or pass the value as text with --text'
            )
    elif args.message is not None:
        message, text = None, args.message
    else:
        message, text = None, None

    try:
        run(p=args.p, q=args.q, bits=args.bits, seed=args.seed,
            message=message, text=text,
            gcd_method=args.gcd_method, prime_method=args.prime_method)
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == '__main__':
    main()
