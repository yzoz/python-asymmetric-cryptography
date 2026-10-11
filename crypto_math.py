"""
Pure mathematical primitives used by the cryptography demonstration.

Every function in this module is side-effect free: there is no input/output,
no randomness, and no access to files, the clock or any generator. Only the
basic Python operators (integer division, modulo, exponentiation, bitwise
operations) are used on purpose, so each algorithm stays readable and
self-contained.
"""


def mod_exp(x, y, z):
    """
    Modular exponentiation by repeated squaring.

    Returns (x ** y) % z without ever building the huge intermediate power,
    which is what makes it fast for very large numbers. Equivalent to the
    built-in pow(x, y, z).
    """
    r = 1
    while y:
        if y % 2:  # true when y is odd (lowest bit set)
            r = r * x % z
        y = y // 2  # integer division by two (y >>= 1)
        x = x ** 2 % z  # square and take the remainder
    return r


def bin_sqrt(x):
    """
    Floor integer square root of x found by binary search.

    Equivalent to math.isqrt(x). The result r is initialised to 0 so that
    bin_sqrt(0) == 0 instead of failing on an undefined variable.
    """
    r = 0
    start = 1
    end = x
    while start <= end:
        mid = (start + end) // 2
        if mid * mid == x:
            return mid
        elif mid * mid < x:
            start = mid + 1
            r = mid
        else:
            end = mid - 1
    return r


def gcd(x, y):
    """
    Greatest common divisor by the Euclidean algorithm.

    Expected number of steps for an input x:
    ((12 * math.log(2)) / math.pi ** 2) * math.log(x)
    """
    while y:
        x, y = y, x % y
    return x


def extended_gcd(a, b):
    """
    Extended Euclidean algorithm.

    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b). The coefficients
    come from Bezout's identity and are used below to build the modular
    multiplicative inverse.
    """
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


def mod_mul_inverse(a, b):
    """
    Modular multiplicative inverse.

    Returns x such that (x * a) % b == 1, which only exists when
    gcd(a, b) == 1. Callers that rely on it must check that condition first.
    """
    g, x, _ = extended_gcd(a, b)
    return x % b


def trial_division(x):
    """
    Deterministic primality test by trial division.

    Even numbers greater than two are composite and are rejected up front.
    Only odd divisors are tested, so the step is two. The upper bound of the
    range must be inclusive (bin_sqrt(x) + 1): the divisor equal to the exact
    square root is required to detect perfect squares such as 9 = 3 * 3,
    which would otherwise be reported as prime.
    """
    if x < 2:
        return False
    if x == 2:
        return True
    if not x & 1:  # x is even
        return False
    for y in range(3, bin_sqrt(x) + 1, 2):  # odd divisors up to and including sqrt(x)
        if not x % y:
            return False
    return True


def fermat_test(n, k):
    """
    Fermat primality test (probabilistic in nature).

    Checks a ** (n - 1) % n == 1 for k bases a in [2, n - 2]. Fermat's little
    theorem only gives a necessary condition: Carmichael numbers (for example
    561) satisfy it for every base that is coprime to them and are therefore
    reported as prime. For the demonstration the deterministic trial_division
    is the safe path; fermat_test is kept for contrast only.

    This educational version picks the bases deterministically (pseudo-random
    from the base index) so the module stays free of side effects and can be
    unit tested reproducibly.
    """
    if n < 2:
        return False
    if n < 4:
        return True
    for i in range(k):
        a = 2 + i % (n - 3)
        if gcd(a, n) != 1:
            # A shared factor already proves n is composite, but the Fermat
            # test is defined for bases coprime to n, so such bases are
            # skipped here; this is what lets Carmichael numbers slip through.
            continue
        if mod_exp(a, n - 1, n) != 1:
            return False
    return True
