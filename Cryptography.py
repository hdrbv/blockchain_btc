import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import random
import os
import binascii
import ecdsa  
import hashlib
import itertools
from hashlib import sha256
import time
import socket
import struct

#Example: G (x, y) in curve SECP256k1 (elliptic curve y2 = x3 + 7 over the real numbers)?
p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
x = 55066263022277343669578718895168534326250603453777594175500187360389116729240
y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
(x**3 + 7) % p == y**2 % p # True => in  

#Elliptic curve
def main():
    a = -1
    b = 1
    y, x = np.ogrid[-5:5:100j, -5:5:100j]
    plt.contour(x.ravel(), 
                y.ravel(), pow(y, 2) - pow(x, 3) - x * a - b, [0])
    plt.grid()
    plt.show()
        
main()

#Generate private key
private_key = ''.join(['%x' % random.randrange(16) for x in range(0, 64)])
private_key
len(private_key)

#or
private_key = os.urandom(32).hex()
private_key
len(private_key)

#ECDSA (Elliptic Curve Digital Signature Algorithm)
private_key = ecdsa.SigningKey.generate(curve = ecdsa.SECP256k1)
public_key = private_key.get_verifying_key()
binascii.hexlify(public_key.to_string()).decode('ascii').upper()

len(binascii.hexlify(public_key.to_string()).decode('ascii').upper())

len(binascii.hexlify(public_key.to_string()).decode('ascii').upper() + \
      binascii.hexlify(public_key.to_string()).decode('ascii').upper()
)

# Cуть Base58Check encoding в том, чтобы максимально кратко записать последовательность 
# байт в удобочитаемом формате и при этом сделать вероятность возможных опечаток еще меньше

#// Why base-58 instead of standard base-64 encoding?
#// - Don't want 0OIl characters that look the same in some fonts and
#//      could be used to create visually identical looking account numbers.
#// - A string with non-alphanumeric characters is not as easily accepted as an account number.
#// - E-mail usually won't line-break if there's no punctuation to break at.
#// - Doubleclicking selects the whole number as one word if it's all alphanumeric.
## https://github.com/bitcoin/bitcoin/blob/master/src/base58.h

#Base58Check encoding
b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
len(b58)

def base58encode(n):
    result = ''
    while n > 0:
        result = b58[int(n % 58)] + result
        n //= 58
    return result

# print "Base58 encode for '123123':", base58encode(123123)
# # Base58 encode for '123123': dbp
base58encode(123123)

# Will be used to decode raw bytes and then encode them to the base58
def base256decode(s) :
    result = 0
    for c in s :
        result = result * 256 + ord(chr(c))
    return result

def countLeadingZeroes(s) :
    count = 0
    for c in s:
        if c == '\0':
            count += 1
        else:
            break
    return count

def base58CheckEncode(prefix, payload) :
    s = (chr(prefix) + payload).encode()
    checksum = hashlib.sha256(hashlib.sha256(binascii.hexlify(s)).digest()).digest()[0:4]
    result = s + checksum
    return '1' * countLeadingZeroes(result) + base58encode(base256decode(result))

#Case
private_key = '0a56184c7a383d8bcce0c78e6e7a4b4b161b2f80a126caa48bde823a4625521f'

# WIF (Wallet Import Format). Строится он довольно просто:
# Берем приватный ключ, например 0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
# Записываем его в Base58Check с префиксом 0x80. Все.
def privateKeyToWif(key_hex) :
    return base58CheckEncode(0x80, str(binascii.hexlify(key_hex.encode('utf-8'))))

print("Private key in WIF format:", privateKeyToWif(private_key))

# Публичный ключ — это просто точка на прямой SECP256k1. 
# Первый и самый распространенный вариант его записи — uncompressed формат, 
# по 32 байта для X и Y координат. 
# Чтобы не возникало путаницы, используется префикс 0x04 и того 65 байт.

def privateKeyToPublicKey(s) :
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(s), 
                                      curve = ecdsa.SECP256k1)
    vk = sk.verifying_key
    return binascii.hexlify(('\04' + sk.verifying_key.to_string().decode('latin-1')).encode('utf-8'))
uncompressed_public_key = privateKeyToPublicKey(private_key)

print("Uncompressed public key: {}, size: {}".format(uncompressed_public_key, 
                                                     len(uncompressed_public_key) / 2))

# Второй формат называется compressed. Суть его в следующем: публичный ключ — 
# это точка на кривой, то есть пара чисел удовлетворяющая уравнению 
# y^2\ mod\ p = x^2 + ax + b \ (mod\ p). А значит можно записать только Х координату
# и если нам понадобится Y координата — просто решаем уравнение. 
# Тем самым мы уменьшаем размер публичного ключа почти на 50%!
# Единственный нюанс — если точка лежит на кривой, то для ее Х координаты очевидно существует два решения 
# такого уравнения. Обычно мы бы просто сохранили знак для Y координаты, 
# но когда речь идет о функции над конечным полем, то нужно воспользоваться следующим свойством: 
# если для Х координаты существуют решения уравнения, то 
# одна из точек будет иметь четную Y координату, а вторая — нечетную (опять же, можете сами в этом убедиться).
# В первом случае используется префикс 0x02, во втором — 0x03.

# Адрес получается из публичного ключа однозначным образом. 
# Более того, провести обратную операцию невозможно, 
# так как используются криптографически стойкие хэш функции — RIPEMD160 и SHA256. 
# Вот алгоритм перевода публичного ключа в адрес:
# 1) Возьмем приватный ключ, например 45b0c38fa54766354cf3409d38b873255dfa9ed3407a542ba48eb9cab9dfca67 
# 2) Получим из него публичный ключ в uncompressed формате, в данном случае это 04162ebcd38c90b56fbdb4b0390695afb471c944a6003cb334bbf030a89c42b584f089012beb4842483692bdff9fcab8676fed42c47bffb081001209079bbcb8db 
# 3) Считаем RIPEMD160(SHA256(public_key)), получается 5879DB1D96FC29B2A6BDC593E67EDD2C5876F64C
# 4) Переводим результат в Base58Check с префиксом 0x00 — 17JdJpDyu3tB5GD3jwZP784W5KbRdfb84X. Это и есть адрес.

def pubKeyToAddr(s) :
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(binascii.hexlify(s)).digest())
    return base58CheckEncode(0, str(ripemd160.digest()))

def keyToAddr(s) :
    return pubKeyToAddr(privateKeyToPublicKey(s))

print(keyToAddr("45b0c38fa54766354cf3409d38b873255dfa9ed3407a542ba48eb9cab9dfca67"))

