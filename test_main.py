"""
Tests for the educational cryptography project.

Runs on the standard unittest module only, no third-party dependencies.
The mathematical primitives live in crypto_math and are checked against
Python's built-in equivalents; the end-to-end RSA round-trip is checked on
fixed parameters so the numbers stay deterministic.
"""

import math
import unittest

import crypto_math as cm
import main


class TestModExp(unittest.TestCase):
    def test_matches_builtin_pow(self):
        cases = [
            (2, 10, 1000), (3, 5, 7), (123456, 789, 10 ** 9 + 7),
            (5, 0, 13), (0, 5, 7), (7, 1, 11), (65537, 12345, 99991),
        ]
        for x, y, z in cases:
            with self.subTest(x=x, y=y, z=z):
                self.assertEqual(cm.mod_exp(x, y, z), pow(x, y, z))


class TestGcd(unittest.TestCase):
    def test_matches_math_gcd(self):
        cases = [(0, 5), (5, 0), (12, 18), (17, 5), (270, 192), (1, 1)]
        for a, b in cases:
            with self.subTest(a=a, b=b):
                self.assertEqual(cm.gcd(a, b), math.gcd(a, b))


class TestExtendedGcd(unittest.TestCase):
    def test_bezout_identity(self):
        cases = [(240, 46), (61 * 19, 53 * 19), (17, 3120), (3, 8), (1, 1)]
        for a, b in cases:
            with self.subTest(a=a, b=b):
                g, x, y = cm.extended_gcd(a, b)
                self.assertEqual(g, math.gcd(a, b))
                self.assertEqual(a * x + b * y, g)


class TestModMulInverse(unittest.TestCase):
    def test_inverse(self):
        cases = [(17, 3120), (3, 40), (7, 26), (65537, 103 * 97)]
        for a, b in cases:
            with self.subTest(a=a, b=b):
                self.assertEqual((cm.mod_mul_inverse(a, b) * a) % b, 1)


class TestBinSqrt(unittest.TestCase):
    def test_matches_isqrt(self):
        for x in [0, 1, 2, 3, 4, 8, 9, 10, 15, 16, 17, 99, 100, 10 ** 12]:
            with self.subTest(x=x):
                self.assertEqual(cm.bin_sqrt(x), math.isqrt(x))

    def test_zero(self):
        self.assertEqual(cm.bin_sqrt(0), 0)


class TestTrialDivision(unittest.TestCase):
    def test_perfect_squares_are_composite(self):
        # Regression: 9, 15 and 25 used to be reported as prime because the
        # upper bound of the divisor range excluded sqrt(x).
        for x in (9, 15, 25):
            with self.subTest(x=x):
                self.assertFalse(cm.trial_division(x))

    def test_small_numbers(self):
        for x in (0, 1):
            with self.subTest(x=x):
                self.assertFalse(cm.trial_division(x))
        self.assertTrue(cm.trial_division(2))
        self.assertFalse(cm.trial_division(4))

    def test_primes_and_composites(self):
        for x in (7, 13, 97, 101, 9973):
            with self.subTest(x=x):
                self.assertTrue(cm.trial_division(x))
        for x in (21, 49, 91, 1000, 9975):
            with self.subTest(x=x):
                self.assertFalse(cm.trial_division(x))

    def test_against_isqrt_range(self):
        for x in range(2, 500):
            with self.subTest(x=x):
                self.assertEqual(cm.trial_division(x), all(x % d for d in range(2, math.isqrt(x) + 1)))


class TestFermatTest(unittest.TestCase):
    def test_primes_pass(self):
        for x in (3, 5, 7, 13, 97, 101):
            with self.subTest(x=x):
                self.assertTrue(cm.fermat_test(x, 20))

    def test_carmichael_limitation(self):
        # 561 is a Carmichael number: the Fermat test cannot reject it, which
        # is exactly the documented limitation. trial_division must reject it.
        self.assertTrue(cm.fermat_test(561, 20))
        self.assertFalse(cm.trial_division(561))


class TestRoundTrip(unittest.TestCase):
    """End-to-end RSA round-trip on fixed parameters p=61, q=53, E=17."""

    def setUp(self):
        self.p, self.q, self.E = 61, 53, 17
        self.N = self.p * self.q
        self.M = ((self.p - 1) * (self.q - 1)) // math.gcd(self.p - 1, self.q - 1)
        self.D = cm.mod_mul_inverse(self.E, self.M)

    def _roundtrip(self, m):
        n = m // self.N
        r = m % self.N
        block = self.N - 1
        r_enc = cm.mod_exp(r, self.E, self.N)
        block_enc = cm.mod_exp(block, self.E, self.N)
        r_dec = cm.mod_exp(r_enc, self.D, self.N)
        block_dec = cm.mod_exp(block_enc, self.D, self.N)
        return (block_dec + 1) * n + r_dec

    def test_keys_are_valid(self):
        self.assertEqual(math.gcd(self.E, self.M), 1)
        self.assertEqual((self.D * self.E) % self.M, 1)

    def test_regular_message(self):
        for m in (42, 1234, 99999):
            with self.subTest(m=m):
                self.assertEqual(self._roundtrip(m), m)

    def test_remainder_zero(self):
        # m is a multiple of N, so r == 0.
        m = self.N * 3
        self.assertEqual(m % self.N, 0)
        self.assertEqual(self._roundtrip(m), m)

    def test_message_multiple_of_n_large(self):
        m = self.N * 12345
        self.assertEqual(self._roundtrip(m), m)

    def test_marker_block_is_fixed_point(self):
        # (N - 1) ** E mod N == N - 1 for any odd E.
        self.assertEqual(cm.mod_exp(self.N - 1, self.E, self.N), self.N - 1)


class TestTextEncoding(unittest.TestCase):
    def test_roundtrip(self):
        for text in ('RSA!', 'hello', 'Привет', 'x'):
            with self.subTest(text=text):
                self.assertEqual(main.int_to_text(main.text_to_int(text)), text)


class TestNoSideEffects(unittest.TestCase):
    def test_crypto_math_has_no_io(self):
        with open('crypto_math.py', encoding='utf-8') as fh:
            source = fh.read()
        for forbidden in ('print(', 'import random', 'random.', 'os.urandom', 'import os'):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
