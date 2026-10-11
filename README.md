# Python public-key cryptography example

A study project: the simplest possible implementation of asymmetric
encryption with a public key in Python. The idea is close to RSA, but the code
is written to be read and understood rather than to be used in production.

Python's built-in math functions are **not** used inside the algorithms, for
clarity. Only basic operators are allowed:

* floor division
* modulo division
* exponentiation
* bitwise operators

The project has no third-party dependencies.

## Project layout

```
crypto_math.py     # pure mathematical primitives
crypto_text.py     # pure text <-> bytes <-> int helpers and block splitting
main.py            # scenario: key generation, encryption, transcript
test_math.py       # tests for crypto_math
test_crypto_text.py# tests for crypto_text
test_main.py       # tests for main (attack, CLI helpers, round-trip)
README.md          # this document
LICENSE            # MIT license
```

`crypto_math.py` and `crypto_text.py` are both side-effect free: no input or
output, no randomness, no access to files or the clock. `main.py` imports from
both and only prints the transcript.

## Implemented functions

In `crypto_math.py` (all side-effect free, no I/O and no randomness):

* `mod_exp(x, y, z)` — modular exponentiation by repeated squaring, for fast
  computation of large powers modulo `z`.
* `bin_sqrt(x)` — floor integer square root by binary search (like
  `math.isqrt`).
* `gcd(x, y)` — greatest common divisor by the Euclidean algorithm.
* `extended_gcd(a, b)` — extended Euclidean algorithm; returns `(g, x, y)`
  with `a*x + b*y = g = gcd(a, b)` (Bezout coefficients).
* `mod_mul_inverse(a, b)` — modular multiplicative inverse: the `x` such that
  `(x * a) % b == 1`.
* `trial_division(x)` — deterministic primality test by trying the divisors.
* `fermat_test(n, k)` — Fermat primality test, exponentially faster but
  **probabilistic**.

In `crypto_text.py` (also side-effect free):

* `DEFAULT_MESSAGE` — the built-in message: `A..Z`, `a..z`, `0..9` and the
  common special characters (94 characters in total, no space).
* `COLUMNS` — number of table columns used by the character breakdown (5).
* `BREAKDOWN_THRESHOLD` — `COLUMNS * len(DEFAULT_MESSAGE)` (470): the largest
  message for which the per-character table is printed.
* `text_to_int(text)` / `int_to_text(n)` — convert a string to a message
  integer and back using big-endian UTF-8.
* `encoding_steps(text)` — the whole chain `(text, bytes, hex, int)` shown in
  the transcript.
* `char_records(text)` — per character: `(index, char, 'U+XXXX', utf8_hex)`.
* `char_categories(text)` — group characters into uppercase / lowercase /
  digits / special / other.
* `block_size(modulus)` — largest block size in bytes that always stays below
  `modulus`.
* `split_blocks(data, k)` / `join_blocks(blocks, k)` — cut a byte string into
  blocks and rebuild it (leading zero bytes are preserved).

In `main.py`:

* `get_rand(b)` — a random integer of `b` bytes (`os.urandom`, or a seeded
  generator for reproducible runs).
* `gen_prime(b)` — generate a prime of `b` bytes using `trial_division`.
* `gen_close_primes(b)` — generate two primes of `b` bytes that are close to
  each other, for the factorization attack.
* `fermat_factor(n)` — factor `n = p * q` with Fermat's method (uses
  `bin_sqrt`); fast when the factors are close.
* `bezout_check(a, b)` — extended `gcd` plus a verification of Bezout's
  identity (uses `extended_gcd`).
* `prime_check(n)` — compare `trial_division` with `fermat_test` on one number.
* `looks_like_int(s)` — whether `--m` should be read as a number or as text.
* `show_stat(...)` — inline progress indicator (debug helper).
* the encryption scheme and its readable transcript.

## How the scheme works

The scheme follows the classic RSA key generation:

1. choose two primes `p` and `q`;
2. compute the modulus `N = p * q`;
3. compute the Carmichael function `lambda(N) = lcm(p - 1, q - 1)`
   (computed as `(p - 1) * (q - 1) // gcd(p - 1, q - 1)`). It plays the same
   role as Euler's totient `phi(N) = (p - 1) * (q - 1)` but is smaller;
4. choose the public exponent `E` with `1 < E < lambda(N)` and
   `gcd(E, lambda(N)) == 1` (the usual choice is `65537 = 2 ** 16 + 1`, the
   fourth Fermat number — note this is `2 ** 16 + 1`, not `2 ** 16`);
5. compute the private exponent `D = E ** -1 mod lambda(N)`, that is
   `(D * E) % lambda(N) == 1`.

Encryption raises each plaintext value to the power `E` modulo `N`; decryption
raises the ciphertext to the power `D` modulo `N`:

```
c = m ** E mod N
m = c ** D mod N
```

### Formulas

Modular exponentiation by repeated squaring:

```
mod_exp(x, y, z):
    r = 1
    while y:
        if y is odd: r = r * x mod z
        y = y // 2
        x = x * x mod z
    return r
```

Extended Euclidean algorithm gives Bezout coefficients, from which the
inverse is obtained:

```
extended_gcd(a, b) -> (g, x, y)  with a*x + b*y = g
mod_mul_inverse(a, b) -> x mod b
```

## Text encoding and block splitting

Text is encoded exactly the way UTF-8 works: every character is turned into
its bytes, the bytes are concatenated, and the result is read as one big
big-endian integer `m`. The transcript shows each step
(`text -> UTF-8 -> hex -> int`) and, for messages up to
`BREAKDOWN_THRESHOLD` characters, a per-character table
(`index`, `char`, `code point U+XXXX`, UTF-8 hex) laid out in `COLUMNS`
columns. The default message is the full alphabet plus digits plus the common
special characters, so the table shows one character of every kind.

A single character is far too small to be encrypted on its own, and encrypting
character by character would be weak anyway. Instead the message is split into
blocks:

```
k = (N.bit_length() - 1) // 8          # block size in bytes
for each block:  c = block ** E mod N  # encrypt
for each block:  r = c ** D mod N      # decrypt
```

`k` is chosen so that every `k`-byte block is smaller than `N`. All blocks but
the last are left-padded with zero bytes when the text is rebuilt, so leading
zero bytes are not lost. For the default 6-byte primes `k` is 11 bytes, so the
94-character default message is one block, while a longer sentence is split
into several and every block is genuinely encrypted.

### Legacy numeric path

When `--m` is a **number**, the historical single-value scheme is kept: `m` is
split against `N` as

* `n = m // N` — the quotient (a block counter, not encrypted);
* `r = m % N` — the remainder, this is the part actually encrypted;
* `block = N - 1` — a fixed marker.

The marker `N - 1` is a **deliberate teaching device**: for any odd `E`,

```
(N - 1) ** E mod N = N - 1
```

so the marker survives the round-trip unchanged and demonstrates that the RSA
formula works. Reconstruction is `d = (block_dec + 1) * n + r_dec`, which
relies on `block_dec == N - 1`. A direct consequence is that the marker does
**not** hide any information: in the numeric path only `r` is genuinely
encrypted. The text path above does not use the marker at all.

## Running

One command, sensible defaults:

```
python3 main.py
```

By default two 6-byte primes are generated and the built-in alphabet message
(`DEFAULT_MESSAGE`) is encoded and encrypted end to end, text block by block.

### Messages

```
python3 main.py --m "Hello, World! 123"   # text (not all digits -> text)
python3 main.py --text 12345              # force text even when numeric
python3 main.py --m 1234567               # a number -> legacy numeric path
python3 main.py --m "-42"                 # any signed integer is a number
```

* `--m` — the message: if it looks like an integer it is encrypted as a number
  (legacy numeric path), otherwise it is treated as UTF-8 text;
* `--text` — force the text path, which is the only way to send a message made
  of digits only.

The last result block prints `recovered int` and, on the text path,
`recovered text`; the numeric path prints `recovered int` only.

### Reproducible runs

```
python3 main.py --p 61 --q 53          # deterministic key parameters
python3 main.py --seed 42              # fix the random generator
python3 main.py --bits 8               # size of the generated primes
```

* `--seed` — seed the random generator so a run can be reproduced exactly;
* `--p`, `--q` — explicit primes (deterministic scenario);
* `--bits` — size in bytes of the generated primes.

### Factorization attack

`--attack` generates two deliberately close primes, publishes `N` and `E`,
then recovers the factors from `N` alone with Fermat's method and rebuilds the
private exponent `D`:

```
python3 main.py --attack --seed 42
```

Fermat's method is fast only when the factors are close, which is why the
attack uses `gen_close_primes`. `bin_sqrt` supplies both the starting value
`ceil(sqrt(N))` and the exact perfect-square test for each step.

### Math helpers

`--check` runs one primitive on demand, for inspection or teaching:

```
python3 main.py --check sqrt   --sqrt-number 12345        # bin_sqrt
python3 main.py --check bezout --bezout-a 240 --bezout-b 46  # extended_gcd
python3 main.py --check prime  --prime 561                # trial_division vs fermat_test
```

* `--check sqrt` — floor/ceiling square root of a number (uses `bin_sqrt`);
* `--check bezout` — Bezout coefficients and `gcd` of two numbers (uses
  `extended_gcd`);
* `--check prime` — deterministic `trial_division` next to probabilistic
  `fermat_test`, which visibly disagree on a Carmichael number such as `561`.

## Teaching limitations

This project is intentionally simple and **must not be used for real
cryptography**:

* **The legacy numeric path does not encrypt the whole number.** As explained
  above, only the remainder `r` is actually hidden; the marker `N - 1` is left
  in the clear. Use the text path for a scheme that encrypts every block.
* **The Fermat test is probabilistic.** `fermat_test` can accept a Carmichael
  number (such as `561`) as prime. The deterministic path used for the
  demonstration is `trial_division`; no stronger algorithm is added on
  purpose, to keep the code readable.
* Text is encoded without padding, so the scheme offers no semantic security.
* **Primes that are too close are factorable.** The `--attack` mode shows that
  when `p` and `q` are near each other, `N` can be split by Fermat's method in
  negligible time (a real key must use primes chosen independently and large
  enough that factoring is infeasible).

## Tests

The test suite uses only the standard `unittest` module:

```
python3 -m unittest
```

It is split by module: `test_math.py` checks the primitives against Python's
built-in equivalents (`pow`, `math.gcd`, `math.isqrt`) and the regression cases
for `trial_division` (`9`, `15`, `25` are composite) and `bin_sqrt(0) == 0`;
`test_crypto_text.py` checks the text/int round-trip, the per-character records
and categories, the block split/join (including leading zero bytes) and the
block size; `test_main.py` checks the Fermat attack, the CLI helper
`looks_like_int`, the end-to-end round-trip on fixed parameters and the two
output paths. Both pure modules are asserted to contain no I/O and no
randomness.

## License

Released under the MIT license. See [LICENSE](LICENSE).
