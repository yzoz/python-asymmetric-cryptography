"""
Tests for the pure mathematical primitives in crypto_math.

Runs on the standard unittest module only, no third-party dependencies. Every
function is checked against Python's built-in equivalent (pow, math.gcd,
math.isqrt) and crypto_math is asserted to stay free of I/O and randomness.
"""

import math
import unittest

import crypto_math as cm


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


class TestNoSideEffects(unittest.TestCase):
    def test_crypto_math_has_no_io(self):
        with open('crypto_math.py', encoding='utf-8') as fh:
            source = fh.read()
        for forbidden in ('print(', 'import random', 'random.', 'os.urandom', 'import os'):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
