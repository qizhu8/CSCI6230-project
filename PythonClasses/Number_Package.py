#!/usr/bin/env python3
import numpy as np
import math

def is_prime(t):
    if t == 2 or t == 3:
        return True
    if t < 1 or t % 2 == 0 or t % 3 == 0:  # remove some easy cases
        return False
    # prime_flag = True
    # divisor = np.floor(np.sqrt(t))
    # while divisor > 1 and prime_flag:
    #     if t % divisor == 0:
    #         prime_flag = False
    #     else:
    #         divisor -= 1

    prime_flag = (len(factorize(t)) == 1)
    return prime_flag

def mult_inv_mod_N(a, N):
    if a < 0:
        a %= N
    if a == 1:
        return 1
    a, N = np.asarray(a, dtype=np.int64), np.asarray(N, dtype=np.int64)
    AN, Aa = np.array([1, 0], dtype=np.int64), np.array([0, 1], dtype=np.int64)

    N_org, a_org = N, a

    flag = True
    if N < a:
        Q = a // N
        a = a % N
        Aa -= Q * AN
        if a == 1 or a == 0:
            flag = False

    # print('Q', N, a, AN, Aa)
    while flag:
        Q = N // a
        N = N % a
        AN -= Q * Aa
        # print(Q, N, a, AN, Aa)
        if N == 1 or N == 0:
            break

        Q = a // N
        a = a % N
        Aa -= Q * AN
        # print(Q, N, a, AN, Aa)
        if a == 1 or a == 0:
            break

    if N == 0 or a == 0:
        return None

    if N == 1:
        # print('1=', AN[0], '*', N_org, '+', AN[1], '*', a_org)
        return AN[1] % N_org
    elif a == 1:
        # print('1=', Aa[0], '*', N_org, '+', Aa[1], '*', a_org)
        return Aa[1] % N_org


def find_prime_smaller_than_k(k, n_ignore=0):
    if k < 1:
        print('Please input a positive integer greater than 1')
        return None
    if k %2 == 0:
        k -= 1
    counter = 0
    while k > 0: # get rid of even numbers
        if is_prime(k):
            if counter >= n_ignore:
                return k
            else:
                counter += 1
        k -= 2
    return 1

def find_prime_greater_than_k(k, n_ignore=0):
    if k < 1:
        raise ValueError("k should be greater than 2")
    if k %2 == 0:
        k -= 1
    counter = 0
    while True:
        if is_prime(k):
            if counter >= n_ignore:
                return k
            else:
                counter += 1
        k += 2
    return 1

def random_prime_below_k(k):
    N = N / math.log(N) # approximate number of primes below k
    r = np.random.randint(N)

    return find_prime_smaller_than_k(k, r)

def random_prime_greater_than_k(k):
    N = N / math.log(N)
    r = np.random.randint(N)

    return find_prime_greater_than_k(k, r)

def eular_totient_function(k):
    if k < 0:
        return None
    if k == 1 or k == 2:
        return 1

    phi = 1
    for f in factorize(k):
        phi *= f - 1
    return phi

def factorize(k):
    # k = np.round(k)
    # if k < 0:
    #     return None
    # if k <= 3:
    #     return k
    #
    # factors = []
    # d = 2
    # ending_cond = np.sqrt(k)
    # while  d < ending_cond and k > 1:
    #     if k % d == 0:
    #         k /= d
    #         factors.append(d)
    #     else:
    #         if d == 2:
    #             d -= 1
    #         d += 2
    # if k != 1: # not prime
    #     factors.append(k)
    raw_factors = [k]
    factors = []
    while len(raw_factors) > 0:
        num_2b_factorized = raw_factors.pop(0)
        factor = pollard_rho(num_2b_factorized)
        if factor == 1 or factor == num_2b_factorized:
            factors.append(num_2b_factorized)
        else:
            raw_factors.append(factor)
            raw_factors.append(num_2b_factorized // factor)
    factors.sort()
    return factors

def exp_mod(a, e, n):
    # my version
    # e_b = bin(int(e))
    # cur_prod = 1
    # for s in e_b[:1:-1]:
    #     if s == '1':
    #         cur_prod *= a % n
    #         cur_prod %= n
    #     a = a*a % n
    #
    # return cur_prod

    ## buildin-function
    return pow(int(a), int(e), int(n))
# exp_mod = lambda a, b, n: pow(int(a), int(e), int(n))


def gcd(a, b):
    while a % b != 0:
        a, b = b, a % b
    return b

def miller_rabin_primality_check(n, round_max=100):
    if n %2 == 0 or n % 3 == 0 or n % 5 == 0:
        return False
    is_prime, round = True, 0
    while is_prime and round < round_max:
        maybe_prime = False
        s, d, j = 0, n-1, 0
        while d % 2 == 0:
            d >>= 1
            s += 1
        a = np.random.randint(n-1)
        if exp_mod(a, d, n) == 1:
            maybe_prime = True

        while not maybe_prime and j <= s-1:
            rst = exp_mod(a, 2**j * d, n)
            if rst == n-1:
                maybe_prime = True
            j += 1

        round += 1
        is_prime &= maybe_prime
    return is_prime

# find a factor of n
def pollard_rho(n):
    x, y = 2, 2
    cycle_size = 2
    factor = 1

    while factor == 1:
        cnt = 1
        while cnt <= cycle_size and factor <= 1:
            x = (x*x + 1) % n
            factor = gcd(x - y, n)
            cnt += 1
        cycle_size *= 2
        y = x
    return factor


# computing Jacob symbol
# Give credit to Coinmonks
# https://medium.com/coinmonks/probabilistic-encryption-using-the-goldwasser-micali-gm-method-7f9893a93ac9

# calculates jacobi symbol (a n)
def jacobi(a, n):
    if a == 0:
        return 0
    if a == 1:
        return 1
    e = 0
    a1 = a
    while e % 2 == 0:
        e += 1
        a1 /= 2
    assert 2**e * a1 == a
    s = 0
    if e % 2 == 0:
        s = 1
    elif n % 8 in {1, 7}:
        s = 1
    elif n % 8 in {3, 5}:
        s = -1
    if n % 4 == 3 and a1 % 4 == 3:
        s *= -1
    n1 = n % a1

    if a1 == 1:
        return s
    else:
        return s * jacobi(n1, a1)

# check whether n is a blum number
def is_blum(n):
    factors = factorize(n)
    if len(factors) != 2:
        # more than 2 prime factors
        return False

    prev_f = -1
    for f in factors:

        if f == prev_f or f % 4 != 3:
            return False
        prev_f = f
    return True

def blum_interger_generator(p_q_min, gap=-1):
    if p_q_min < 3:
        raise ValueError("p_q_max should be greater than 3")

    gap = max(0, gap)
    # p is searched by adding, q is searched by subtracting
    def prime_with_3_mod_4(p, plus_flag=True):
        p = p + 3 - (p % 4)
        while p > 0:
            if plus_flag:
                p += 4
            else:
                p -= 4
            if is_prime(p):
                return p
    base = np.random.randint(gap//2, gap)
    p = prime_with_3_mod_4(p_q_min+base, True)
    q = prime_with_3_mod_4(p_q_min-base, False )
    return p, q, p*q
