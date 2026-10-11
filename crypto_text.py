"""
Pure helpers that turn text into message integers (and into RSA blocks).

Like crypto_math.py this module is side-effect free: there is no input/output,
no randomness and no access to files, the clock or any generator. Text is
always encoded as big-endian UTF-8, which makes every conversion deterministic
and reversible.
"""

# The built-in demonstration message. It deliberately contains one character
# of every category the project wants to show: upper case letters, lower case
# letters, digits and the common special characters (no space).
DEFAULT_MESSAGE = (
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    'abcdefghijklmnopqrstuvwxyz'
    '0123456789'
    '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~'
)

# Number of characters printed per row in the character breakdown table.
COLUMNS = 5

# A per-character breakdown is only printed for messages up to this many
# characters: COLUMNS full table columns worth of DEFAULT_MESSAGE. This keeps
# the table at most COLUMNS * (number of rows of DEFAULT_MESSAGE) cells.
BREAKDOWN_THRESHOLD = COLUMNS * len(DEFAULT_MESSAGE)

# Categories used by char_categories, in display order.
CATEGORY_ORDER = ('uppercase', 'lowercase', 'digits', 'special', 'other')


def text_to_int(text):
    """Encode a string into a single big-endian message integer."""
    return int.from_bytes(text.encode('utf-8'), 'big')


def int_to_text(n):
    """Decode a message integer back to a UTF-8 string."""
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big').decode('utf-8')


def encoding_steps(text):
    """
    Return the full conversion chain for one string.

    The tuple is (text, utf8_bytes, hex_string, integer), which is exactly what
    the transcript shows so the reader can follow text -> bytes -> hex -> int.
    """
    data = text.encode('utf-8')
    return text, data, data.hex(), int.from_bytes(data, 'big')


def char_records(text):
    """
    Describe every character of text as the row (index, char, code, hex).

    * index is the 0-based position in the string;
    * code is the Unicode code point written as U+XXXX;
    * hex is the character's UTF-8 encoding in hexadecimal (1 byte for ASCII,
      2 or more for other scripts).

    The records are returned in string order; the caller decides how to lay
    them out.
    """
    records = []
    for index, ch in enumerate(text):
        data = ch.encode('utf-8')
        records.append((index, ch, f'U+{ord(ch):04X}', data.hex()))
    return records


def char_categories(text):
    """
    Group the characters of text by kind, preserving order inside each group.

    Returns a dict keyed by CATEGORY_ORDER. Anything that is ASCII but neither
    a letter nor a digit goes to 'special'; everything else (for example
    Cyrillic) goes to 'other'.
    """
    groups = {name: [] for name in CATEGORY_ORDER}
    for ch in text:
        if 'A' <= ch <= 'Z':
            groups['uppercase'].append(ch)
        elif 'a' <= ch <= 'z':
            groups['lowercase'].append(ch)
        elif '0' <= ch <= '9':
            groups['digits'].append(ch)
        elif ch.isascii():
            groups['special'].append(ch)
        else:
            groups['other'].append(ch)
    return groups


def block_size(modulus):
    """
    Largest block size in bytes whose value is always below the modulus.

    With k = (bit_length - 1) // 8 any k-byte value is less than 2 ** (8 * k),
    which is at most modulus, so every block is a valid RSA plaintext. At least
    one byte is returned, so a modulus below 256 still yields a one-byte block:
    in that case a block can exceed the modulus and the caller must use larger
    primes (the real scenario always does).
    """
    return max(1, (modulus.bit_length() - 1) // 8)


def split_blocks(data, k):
    """Split a byte string into blocks of k bytes (the last may be shorter)."""
    if k < 1:
        raise ValueError('block size must be at least 1 byte')
    return [data[i:i + k] for i in range(0, len(data), k)]


def join_blocks(blocks, k):
    """
    Rebuild the byte string from split_blocks.

    Every block except the last is left-padded with zero bytes back to length
    k, so leading zero bytes of the original message survive the round-trip.
    """
    last = len(blocks) - 1
    out = b''
    for i, block in enumerate(blocks):
        if i < last:
            block = b'\x00' * (k - len(block)) + block
        out += block
    return out
