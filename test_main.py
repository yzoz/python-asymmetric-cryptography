"""
Tests for the scenario code in main.py.

Runs on the standard unittest module only. The pure primitives are covered by
test_math.py and test_crypto_text.py; here we check the pieces that live in
main: the Fermat attack, the CLI helpers, the block round-trip and the two
output paths (text vs numeric).
"""

import io
import math
import random
import unittest
from contextlib import redirect_stdout

import crypto_math as cm
import crypto_text as ct
import main


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


class TestFermatFactor(unittest.TestCase):
    def test_close_primes(self):
        for p, q in ((61, 53), (101, 103), (9973, 9967)):
            with self.subTest(p=p, q=q):
                self.assertEqual(
                    sorted(main.fermat_factor(p * q)), sorted((p, q))
                )

    def test_exact_square_is_factorable(self):
        # N = p * p: Fermat finds it on the first step with b == 0.
        p = 1009
        self.assertEqual(sorted(main.fermat_factor(p * p)), [p, p])

    def test_prime_is_rejected(self):
        with self.assertRaises(ValueError):
            main.fermat_factor(101)

    def test_far_apart_factors_hit_limit(self):
        with self.assertRaises(ValueError):
            main.fermat_factor(3 * 100003, limit=2)


class TestGenClosePrimes(unittest.TestCase):
    def test_primes_are_close_and_valid(self):
        main._rng = random.Random(1234)
        try:
            p, q = main.gen_close_primes(4)
        finally:
            main._rng = None
        self.assertNotEqual(p, q)
        self.assertTrue(cm.trial_division(p))
        self.assertTrue(cm.trial_division(q))
        self.assertLess(min(q - p, p - q), 1000)

    def test_fermat_factor_recovers_generated_primes(self):
        main._rng = random.Random(99)
        try:
            p, q = main.gen_close_primes(4)
        finally:
            main._rng = None
        self.assertEqual(sorted(main.fermat_factor(p * q)), sorted((p, q)))


class TestCheckHelpers(unittest.TestCase):
    def test_bezout_check_identity(self):
        for a, b in ((240, 46), (17, 3120), (1, 1)):
            with self.subTest(a=a, b=b):
                g, x, y, identity = main.bezout_check(a, b)
                self.assertEqual(g, math.gcd(a, b))
                self.assertEqual(identity, g)

    def test_prime_check_carmichael(self):
        deterministic, probabilistic = main.prime_check(561)
        self.assertFalse(deterministic)
        self.assertTrue(probabilistic)


class TestChooseExponent(unittest.TestCase):
    def test_smallest_coprime_for_tiny_modulus(self):
        # M smaller than 65537 forces the fallback smallest odd coprime.
        self.assertEqual(main.choose_exponent(40), 3)
        self.assertEqual(math.gcd(3, 40), 1)


class TestLooksLikeInt(unittest.TestCase):
    def test_numbers(self):
        for s in ('0', '42', '007', '-13', '+7'):
            with self.subTest(s=s):
                self.assertTrue(main.looks_like_int(s))

    def test_non_numbers(self):
        for s in ('', 'hello', '12a', '3.14', '1 2', 'A1'):
            with self.subTest(s=s):
                self.assertFalse(main.looks_like_int(s))


class TestRunPaths(unittest.TestCase):
    """run() prints a transcript; capture it and check the two code paths."""

    P, Q = 61, 53  # N = 3233, so the block size is 1 byte.

    def _run(self, **kwargs):
        buf = io.StringIO()
        with redirect_stdout(buf):
            result = main.run(p=self.P, q=self.Q, **kwargs)
        return result, buf.getvalue()

    def test_text_path_round_trip(self):
        text = 'Hello, World! 123'
        result, out = self._run(text=text)
        self.assertEqual(result, text)
        self.assertIn('recovered int', out)
        self.assertIn('recovered text', out)
        self.assertNotIn('recovered m', out)

    def test_text_path_long_message(self):
        # Longer than one modulus, so it must be split into many blocks.
        text = ct.DEFAULT_MESSAGE * 3
        result, out = self._run(text=text)
        self.assertEqual(result, text)
        self.assertIn('BLOCK SPLITTING', out)
        self.assertIn('block 0:', out)

    def test_text_path_character_breakdown_shown(self):
        _, out = self._run(text='AB!')
        self.assertIn('CHARACTER BREAKDOWN', out)
        self.assertIn('U+0041', out)

    def test_text_path_breakdown_skipped_when_long(self):
        text = 'a' * (ct.BREAKDOWN_THRESHOLD + 1)
        _, out = self._run(text=text)
        self.assertIn('CHARACTER BREAKDOWN', out)
        self.assertIn('table skipped', out)

    def test_default_message(self):
        result, out = self._run()
        self.assertEqual(result, ct.DEFAULT_MESSAGE)
        self.assertIn('recovered text', out)

    def test_numeric_path_has_no_recovered_text(self):
        result, out = self._run(message=12345)
        self.assertEqual(result, 12345)
        self.assertIn('recovered int', out)
        self.assertNotIn('recovered text', out)

    def test_numeric_path_keeps_marker(self):
        _, out = self._run(message=12345)
        self.assertIn('marker', out)


if __name__ == '__main__':
    unittest.main()
