"""
Tests for the pure text helpers in crypto_text.

Runs on the standard unittest module only. The conversions are checked for
round-trip correctness on ASCII and non-ASCII input, the byte-level block
split/join is checked including leading zero bytes, and the module is asserted
to stay free of I/O and randomness like crypto_math.
"""

import unittest

import crypto_text as ct


class TestTextToInt(unittest.TestCase):
    def test_roundtrip(self):
        for text in ('RSA!', 'hello', 'Привет', 'x', '', ' '):
            with self.subTest(text=text):
                self.assertEqual(ct.int_to_text(ct.text_to_int(text)), text)

    def test_known_value(self):
        # b'AB' is 0x4142.
        self.assertEqual(ct.text_to_int('AB'), 0x4142)

    def test_empty_string_is_zero(self):
        self.assertEqual(ct.text_to_int(''), 0)
        self.assertEqual(ct.int_to_text(0), '')

    def test_utf8_is_big_endian(self):
        data = 'П'.encode('utf-8')  # two bytes: d0 9f
        self.assertEqual(ct.text_to_int('П'), int.from_bytes(data, 'big'))


class TestEncodingSteps(unittest.TestCase):
    def test_steps_are_consistent(self):
        text, data, hexstr, value = ct.encoding_steps('RSA!')
        self.assertEqual(text, 'RSA!')
        self.assertEqual(data, b'RSA!')
        self.assertEqual(hexstr, data.hex())
        self.assertEqual(value, int.from_bytes(data, 'big'))


class TestCharRecords(unittest.TestCase):
    def test_ascii_is_one_byte(self):
        records = ct.char_records('AB')
        self.assertEqual(records[0], (0, 'A', 'U+0041', '41'))
        self.assertEqual(records[1], (1, 'B', 'U+0042', '42'))

    def test_cyrillic_is_two_bytes(self):
        # Cyrillic characters encode to two UTF-8 bytes.
        records = ct.char_records('П')
        self.assertEqual(records[0], (0, 'П', 'U+041F', 'd09f'))

    def test_index_and_length(self):
        records = ct.char_records('abc')
        self.assertEqual([r[0] for r in records], [0, 1, 2])
        self.assertEqual(len(records), 3)


class TestCharCategories(unittest.TestCase):
    def test_groups_letters_digits_specials(self):
        groups = ct.char_categories('Aa1!')
        self.assertEqual(groups['uppercase'], ['A'])
        self.assertEqual(groups['lowercase'], ['a'])
        self.assertEqual(groups['digits'], ['1'])
        self.assertEqual(groups['special'], ['!'])
        self.assertEqual(groups['other'], [])

    def test_non_ascii_goes_to_other(self):
        groups = ct.char_categories('П')
        self.assertEqual(groups['other'], ['П'])

    def test_default_message_covers_all_categories(self):
        groups = ct.char_categories(ct.DEFAULT_MESSAGE)
        self.assertEqual(len(groups['uppercase']), 26)
        self.assertEqual(len(groups['lowercase']), 26)
        self.assertEqual(len(groups['digits']), 10)
        self.assertGreater(len(groups['special']), 0)
        self.assertEqual(groups['other'], [])


class TestBlockSize(unittest.TestCase):
    def test_block_value_stays_below_modulus(self):
        # For any modulus of at least 256 the block always fits.
        for modulus in (256, 61 * 53, 10 ** 20 + 7):
            with self.subTest(modulus=modulus):
                k = ct.block_size(modulus)
                self.assertGreaterEqual(k, 1)
                # The largest k-byte value is 256 ** k - 1.
                self.assertLessEqual(256 ** k, modulus)

    def test_tiny_modulus_gives_one_byte(self):
        # A modulus below 256 still returns the minimal one-byte block.
        self.assertEqual(ct.block_size(3), 1)


class TestSplitJoin(unittest.TestCase):
    def test_roundtrip_even(self):
        data = b'abcdef'
        self.assertEqual(ct.join_blocks(ct.split_blocks(data, 2), 2), data)

    def test_roundtrip_uneven(self):
        data = b'abcde'
        self.assertEqual(ct.join_blocks(ct.split_blocks(data, 2), 2), data)

    def test_leading_zero_bytes_survive(self):
        # The middle block starts with a zero byte: it must be restored on join.
        data = b'\x01\x00\x00\x02'
        self.assertEqual(ct.join_blocks(ct.split_blocks(data, 2), 2), data)

    def test_empty_data(self):
        self.assertEqual(ct.split_blocks(b'', 4), [])
        self.assertEqual(ct.join_blocks([], 4), b'')

    def test_bad_block_size(self):
        with self.assertRaises(ValueError):
            ct.split_blocks(b'abc', 0)


class TestNoSideEffects(unittest.TestCase):
    def test_crypto_text_has_no_io(self):
        with open('crypto_text.py', encoding='utf-8') as fh:
            source = fh.read()
        for forbidden in ('print(', 'import random', 'random.', 'os.urandom', 'import os'):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
