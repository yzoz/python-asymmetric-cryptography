import os
import math
import time
import sys
import random

def show_stat(m, i, s = 1, h = 1):
	if i % s == 0:
		sys.stdout.write('\r')
		sys.stdout.write(f'{m}: {int(i / h * 100)}%')
		#sys.stdout.flush()

#генерерируем случайное число размером b байт
def get_rand(b):
	return int.from_bytes(os.urandom(b), byteorder='little')

"""
Modular exponentiation by squaring.
pow(x, y, z)
"""
def mod_exp(x, y, z):
	r = 1
	while y:
		if y % 2: #если чётно (y & 1)
			r = r * x % z
		y = y // 2 #делим на цело на 2 (y >>= 1)
		x = x ** 2 % z #возводим в квадрат и находим остаток от деления
	return r

"""
binary search integer of square root of x
целый квадратный корень бинарным поиском
int(math.sqrt(x))
"""
def bin_sqrt(x):
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

"""
наибольший общий делитель по алгоритму Евклида (x > y)
предполагаемое количество шагов:
((12 * math.log(2)) / math.pow(math.pi, 2)) * math.log(x)
"""
def gcd(x, y):
	while(y): 
		x, y = y, x % y
	return x

"""
расширенный алгоритм Евклида
return (g, x, y) such that a*x + b*y = g = gcd(a, b)
"""
def extended_gcd(a, b):
	x0, x1, y0, y1 = 0, 1, 1, 0
	while a:
		q, b, a = b // a, a, b % a
		y0, y1 = y1, y0 - q * y1
		x0, x1 = x1, x0 - q * x1
	return b, x0, y0

"""
modular multiplicative inverse
модульная мультипликативная-обратная
return x such that (x * a) % b == 1
"""
def mod_mul_inverse(a, b):
	g, x, _ = extended_gcd(a, b)
	return x % b

#перебор делителей (истинный тест)
def trial_division(x):
	l = range(3, bin_sqrt(x), 2)
	i = 1
	if not x & 1: #x - чётное (x % 2)
		return False
	for y in l: #начиная с 3 до квадратного корня из х с шагом 2
		show_stat(f'CHECK {x}', i, 100000, len(l))
		if not x % y:
			return False
		i += 1
	return True

"""
тест Ферма (вероятностный тест)
экспонециально быстрее, чем перебор делителей
k - количество проверок
"""
def fermat_test(n, k):
	for _ in range(k):
		a = random.randint(2, n - 1)
		if mod_exp(a, n - 1, n) != 1: #возведение в степень по модулю
			return False
	return True

def gen_prime(b = 128, v = 'd', k = 10):
	x = get_rand(b)
	t = time.time()
	if v == 'd':
		check = lambda: trial_division(x)
	else:
		check = lambda: fermat_test(x, k)
	while not check():
		x = get_rand(b)
	print(f'\nTRUE in {time.time() - t} seconds')
	return x


def main():

	print('GEN PRIMES')
	p = gen_prime(6)
	q = gen_prime(6)
	#p = 3
	#q = 5
	N = p * q #модуль
	print('PUBLIC:', N)

	"""
	φ(pq):=(p − 1) * (q − 1) - функцияция Эйлера (Euler totient function)
	λ(pq):=lcm(p − 1, q − 1) - функция Кармайкла (Carmichael function)
	φ(N) = λ(N) * gcd(p − 1, q − 1)
	наименьшее общее кратное (least common multiple)
	lcm(a, b) = |a * b| // gcd(a, b)
	попросту λ меньше, но с теми же свойствами
	"""
	M = ((p - 1) * (q - 1)) // gcd(p - 1, q - 1)
	print('LAMBDA:', M)

	"""
	открытая экспонента (public exponent)
	1 < E < M
	число Ферма F(4) = 2 ** 16
	"""
	E = 65537

	D = mod_mul_inverse(E, M) #секретная экспонента
	print('PRIVATE:', D)

	m = get_rand(128)
	print(
f"""--------------
MES
--------------
{m}
--------------""")

	n = m // N #количество частей
	r = m % N #остаток
	p = N - 1 #часть
	print(
f"""Q: {n}
R: {r}
P: {p}""")

	p_enc = mod_exp(p, E, N)
	r_enc = mod_exp(r, E, N)

	p_dec = mod_exp(p_enc, D, N)
	r_dec = mod_exp(r_enc, D, N)

	print(
f"""ENCODED PATH: {p_enc}
ENCODED REMAINDER: {r_enc}
DECODED PATH: {p_dec}
DECODED REMAINDER: {r_dec}""")

	d = (p_dec + 1) * n + r_dec
	print(
f"""--------------
DECODED
--------------
{d}
--------------""")

main()