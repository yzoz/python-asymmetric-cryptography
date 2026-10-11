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
crypto_math.py   # pure mathematical primitives
main.py          # scenario: key generation, encryption, demonstration
test_main.py     # unittest test suite
README.md        # this document
LICENSE          # MIT license
```

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

In `main.py`:

* `get_rand(b)` — a random integer of `b` bytes (`os.urandom`, or a seeded
  generator for reproducible runs).
* `gen_prime(b)` — generate a prime of `b` bytes using `trial_division`.
* `show_stat(...)` — inline progress indicator (debug helper).
* `text_to_int` / `int_to_text` — convert a string to a message integer and
  back using big-endian UTF-8.
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

## Block encoding

The message integer `m` is split against the modulus `N`:

* `n = m // N` — the quotient (a block counter, not encrypted);
* `r = m % N` — the remainder, this is the part actually encrypted;
* `p = N - 1` — a fixed marker block.

The marker `N - 1` is a **deliberate teaching device**: for any odd `E`,

```
(N - 1) ** E mod N = N - 1
```

so the marker survives the round-trip unchanged and demonstrates that the RSA
formula works. Reconstruction is

```
d = (p_dec + 1) * n + r_dec
```

which relies on `p_dec == N - 1`. A direct consequence is that the marker
does **not** hide any information: in this toy scheme only `r` is genuinely
encrypted.

## Running

One command, sensible defaults:

```
python3 main.py
```

By default two 6-byte primes are generated and the string `"RSA!"` is encoded
and encrypted end to end.

### Reproducible runs

```
python3 main.py --p 61 --q 53          # deterministic key parameters
python3 main.py --seed 42              # fix the random generator
python3 main.py --bits 8               # size of the generated primes
python3 main.py --m 1234567            # encrypt a numeric message
```

* `--seed` — seed the random generator so a run can be reproduced exactly;
* `--p`, `--q` — explicit primes (deterministic scenario);
* `--bits` — size in bytes of the generated primes;
* `--m` — numeric message instead of the built-in text.

## Teaching limitations

This project is intentionally simple and **must not be used for real
cryptography**:

* **The marker block `p = N - 1` is not encrypted.** As explained above, only
  the remainder `r` is actually hidden; the reconstruction formula depends on
  `p_dec == N - 1`.
* **The Fermat test is probabilistic.** `fermat_test` can accept a Carmichael
  number (such as `561`) as prime. The deterministic path used for the
  demonstration is `trial_division`; no stronger algorithm is added on
  purpose, to keep the code readable.
* Text is encoded as one big integer without padding, so the scheme offers no
  semantic security.

## Tests

The test suite uses only the standard `unittest` module:

```
python3 -m unittest
```

It checks the primitives against Python's built-in equivalents
(`pow`, `math.gcd`, `math.isqrt`), the regression cases for `trial_division`
(`9`, `15`, `25` are composite) and `bin_sqrt(0) == 0`, the end-to-end
encrypt/decrypt round-trip on fixed parameters, the text encoding, and that
`crypto_math.py` is free of I/O and randomness.

## License

Released under the MIT license. See [LICENSE](LICENSE).
