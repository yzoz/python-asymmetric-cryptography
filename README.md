<h2>Python public-key cryptography example</h2>

<p>Simpliest as possible implementation of asymmetric encryption with Public-key in Python. Something like RSA, but easier and clearer.</p>

<p>Python's built-in math functions are not used for clarity.</p>

<p>
	<small>
		(:<br />
		<strong>Except for basic operators:</strong><br />
		Floor Division<br />
		Modulo Division<br />
		Exponent<br />
		Bitwise Operators<br />
		):
	</small>
</p>

<h3>Implemented functions:</h3>

<ul>
<li><strong>Binary search</strong> to find floor square root of positive integer</li>
<li><strong>Modular exponentiation</strong> by repeated squaring for fast computation of large positive integer powers of a number</li>
<li><strong>Euclidean algorithm</strong> for computing the greatest common divisor (GCD) of two numbers</li>
<li><strong>Extended Euclidean algorithm</strong> that computes coefficients of Bézout's identity to find Private-key exponent (modular multiplicative inverse of Public-key exponent)</li>
<li><strong>Trial division</strong> (easiest to understand of the integer factorization algorithms) to determine whether a number is a prime</li>
<li><strong>Fermat primality test</strong> to check it exponentially faster way</li>
</ul>

<p>Large messages are splitts into blocks.</p>