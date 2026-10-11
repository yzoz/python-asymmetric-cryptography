"""
Tests for the scenario code in main.py.

Runs on the standard unittest module only. The pure primitives are covered by
test_math.py and test_crypto_text.py; here we check the pieces that live in
main: the Fermat attack, the CLI helpers, the block round-trip and the two
output paths (text vs numeric).
"""

import io
import math
import os
import random
import subprocess
import sys
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
    def test_common_divisor_agree(self):
        # Both --gcd methods must return the same g.
        for a, b in ((240, 46), (17, 3120), (1, 1), (61 * 19, 53 * 19)):
            with self.subTest(a=a, b=b):
                self.assertEqual(
                    main.common_divisor(a, b, 'euclid'),
                    main.common_divisor(a, b, 'extended'),
                )
                self.assertEqual(main.common_divisor(a, b, 'euclid'),
                                 math.gcd(a, b))

    def test_prime_dispatch(self):
        for x in (2, 3, 5, 7, 13, 97, 101):
            with self.subTest(x=x):
                self.assertTrue(main.is_prime(x, 'trial'))
                self.assertTrue(main.is_prime(x, 'fermat'))
        for x in (4, 9, 21, 561):
            with self.subTest(x=x):
                self.assertFalse(main.is_prime(x, 'trial'))


class TestValidatePrime(unittest.TestCase):
    def test_accepts_primes(self):
        for x in (2, 3, 61, 53, 9973):
            with self.subTest(x=x):
                main.validate_prime(x, 'p')

    def test_rejects_composite(self):
        with self.assertRaises(ValueError) as ctx:
            main.validate_prime(4, 'p')
        self.assertIn('not a prime', str(ctx.exception))

    def test_rejects_carmichael_by_name(self):
        with self.assertRaises(ValueError) as ctx:
            main.validate_prime(561, 'q')
        self.assertIn('Carmichael', str(ctx.exception))
        self.assertIn('561', str(ctx.exception))


class TestBigInt(unittest.TestCase):
    def test_short_value_printed_fully(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            main.print_big_int('x', 12345)
        self.assertIn('12345', buf.getvalue())

    def test_long_value_does_not_call_str(self):
        # A value far beyond the int -> str limit must be summarised, not
        # converted: the summary is produced without ever calling str(value).
        value = 10 ** 5000 + 7
        buf = io.StringIO()
        with redirect_stdout(buf):
            main.print_big_int('x', value)
        out = buf.getvalue()
        self.assertIn('decimal digits, skipped', out)
        self.assertIn('bits =', out)
        self.assertIn('hex = 0x', out)
        self.assertIn('(truncated)', out)

    def test_decimal_digits_bounds(self):
        for value in (0, 1, 9, 10, 99, 10 ** 12):
            with self.subTest(value=value):
                self.assertGreaterEqual(main.decimal_digits(value),
                                        len(str(value)))


class TestBlockTruncation(unittest.TestCase):
    def test_many_blocks_are_truncated(self):
        p, q = 61, 53  # N = 3233
        N = p * q
        E, D = 17, 2753
        blocks = [bytes([i % 256]) for i in range(60)]
        buf = io.StringIO()
        with redirect_stdout(buf):
            results = main.print_blocks(blocks, E, D, N)
        out = buf.getvalue()
        self.assertEqual(len(results), 60)  # computation stays complete
        self.assertIn('block 0:', out)
        self.assertIn('block 2:', out)
        self.assertIn('block 59:', out)
        self.assertNotIn('block 30:', out)
        self.assertIn('blocks omitted', out)

    def test_few_blocks_not_truncated(self):
        blocks = [bytes([i]) for i in range(5)]
        buf = io.StringIO()
        with redirect_stdout(buf):
            main.print_blocks(blocks, 17, 2753, 3233)
        self.assertIn('block 4:', buf.getvalue())
        self.assertNotIn('blocks omitted', buf.getvalue())


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

    def test_gcd_extended_same_result(self):
        text = 'Hello, World! 123'
        r_euclid, out_euclid = self._run(text=text, gcd_method='euclid')
        r_ext, out_ext = self._run(text=text, gcd_method='extended')
        self.assertEqual(r_euclid, r_ext)
        self.assertIn('Bezout', out_ext)
        self.assertNotIn('Bezout', out_euclid)

    def test_prime_fermat_same_result(self):
        text = 'Hello, World! 123'
        r_trial, out_trial = self._run(text=text, prime_method='trial')
        r_fermat, out_fermat = self._run(text=text, prime_method='fermat')
        self.assertEqual(r_trial, r_fermat)
        self.assertIn('Carmichael', out_fermat)
        self.assertNotIn('Carmichael', out_trial)

    def test_long_text_does_not_crash(self):
        # A message long enough that its integer exceeds the int -> str limit
        # must be summarised instead of raising ValueError.
        text = 'A' * 6000
        result, out = self._run(text=text)
        self.assertEqual(result, text)
        self.assertIn('decimal digits, skipped', out)

    def test_numeric_path_long_message_does_not_crash(self):
        message = int.from_bytes(b'\xff' * 5000, 'big')
        result, out = self._run(message=message)
        self.assertEqual(result, message)
        self.assertIn('decimal digits, skipped', out)

    def test_composite_p_raises_value_error(self):
        with self.assertRaises(ValueError):
            with redirect_stdout(io.StringIO()):
                main.run(p=4, q=53)

    def test_carmichael_p_raises_named_error(self):
        with self.assertRaises(ValueError) as ctx:
            with redirect_stdout(io.StringIO()):
                main.run(p=561, q=1105)
        self.assertIn('Carmichael', str(ctx.exception))


class TestCliErrors(unittest.TestCase):
    """The CLI must report edge cases without a traceback and exit with 2."""

    def _cli(self, *argv):
        proc = subprocess.run(
            [sys.executable, 'main.py', *argv],
            capture_output=True, text=True, cwd=os.path.dirname(__file__) or '.',
        )
        return proc

    def test_composite_prime_is_reported(self):
        proc = self._cli('--p', '4', '--q', '53')
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn('Traceback', proc.stderr)
        self.assertIn('error:', proc.stderr)

    def test_carmichael_prime_is_reported(self):
        proc = self._cli('--p', '561', '--q', '1105')
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn('Traceback', proc.stderr)
        self.assertIn('Carmichael', proc.stderr)

    def test_huge_decimal_message_is_reported(self):
        proc = self._cli('--p', '61', '--q', '53', '--m', '1' + '0' * 5000)
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn('Traceback', proc.stderr)
        self.assertIn('error:', proc.stderr)


if __name__ == '__main__':
    unittest.main()
