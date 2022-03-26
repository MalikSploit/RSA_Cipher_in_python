import random 
from math import floor
from math import sqrt


RANDOM_START = 1e3 #Generating random numbers from 1000
RANDOM_END = 1e5   # To 100 000


def is_prime(num):
    if num < 2:
        return False
    if num == 2:
        return True
    if num % 2 == 0:
        return False
    for i in range(3, floor(sqrt(num))):
        if num % i == 0:
            return False
    return True


# Euclid's greatest common divisor algorithm : this is how we can verify wether (e, φ) = 1 are coprime with the gcd(e, φ) = 1 condition
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# Extended Euclid's algorithm to find modular inverse in O(log m) so in linear time
# This is how we can find the d value which is the modular inverse of e in the RSA cryptosystem
def modular_inverse(a, b):
    # Of course because gcd(0,b)=b and a*x+b*y=b - so x=0 and y=1
    if a == 0:
        return b, 0, 1
    # So we use the Euclidean algorithm for gcd()
    # b%a is always the smaller number - and 'a' is the smaller integer always in this implementation
    div, x1, y1 = modular_inverse(b % a, a)
    # And we update the parameters for x, y accordingly
    x = y1 - (b // a) * x1
    y = x1
    # We use recursion so this is how we send the result to the previous stack frame
    return div, x, y


def generate_large_prime(start = RANDOM_START, end = RANDOM_END):
    # Generate a random number [RANDOM_START, RANDOM_END]
    num = random.randint(start, end)
    # And check wether it is prime or not
    while not is_prime(num):
        num = random.randint(start, end)
    # We know the number is prime
    return num


def generate_rsa_keys():
    # Generate the first huge random prime number
    p = generate_large_prime()
    q = generate_large_prime()
    # This si the trapdoor funciton : multiplying is fast but getting p and q from n is an expoentially slow operation
    n = p * q
    # Euler's tottient phi function
    phi = (p-1)*(q-1)
    e = random.randrange(1, phi)
    # We must make sure gd(e, phi) = 1 so e and phi are coprimes otherwise we cannot find d
    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)
    # d is the modular inverse of e
    # We put [1] because we want to get the index 1 which is the value of x
    d = modular_inverse(e, phi)[1]
    # Private key and the public key
    return (d, n), (e, n)

def encrypt(public_key, plain_text):
    # e and n are needed for encryption (these are public !!!)
    e, n = public_key
    # We use ASCII  representation for the characters and the transformation of every character is stored in an array
    cipher_text = []
    # Consider all the letters one by one and use modular exponentiation
    for char in plain_text:
        a = ord(char)
        cipher_text.append(pow(a, e, n))
    return cipher_text


def decrypt(private_key, cipher_text):
    # d and n are needed for decryption (these are private !!!)
    d, n = private_key
    plain_text = ''
    for num in cipher_text:
        a = pow(num, d, n)
        plain_text = plain_text + str(chr(a))
    return plain_text


if __name__ == '__main__':
    private_key, public_key = generate_rsa_keys()
    message = 'My name is Malik Makkes.'
    # print("Original message is : %s\n" % message)
    cipher = encrypt(public_key, message)
    print("The encrypted message is : %s\n" % cipher)
    plain = decrypt(private_key, cipher)
    print("The decrypted message is : %s\n" % plain)