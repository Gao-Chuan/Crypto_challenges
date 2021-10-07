# [+] Opening connection to 127.0.0.1 on port 10087: Done
# 119e023f23c5ab9c6fb367b07477a69a633e2398b65ddd92d3bbd235ba5fa60aa7b601c49c37ff47164623967283e1552fbaec8b896de5e76795124f3b9f2ad7800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000280a7b601c49c37ff47164623967283e1552fbaec8b896de5e76795124f3b9f2ad716acb63c5bb03cb0d17cfddd1eaba61cc959c3be850a9c30ac6fd701234eefc9900979708b1e92cc41b36e18c7a3dc32dfda9a006029a448a30036ed83f992b6
# [*] Switching to interactive mode
# Welcome, somebody
# you can:
# 1. login
# 2. registe
# $ 1
# input your cookie:>>$ 119e023f23c5ab9c6fb367b07477a69a633e2398b65ddd92d3bbd235ba5fa60aa7b601c49c37ff47164623967283e1552fbaec8b896de5e76795124f3b9f2ad7800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000280a7b601c49c37ff47164623967283e1552fbaec8b896de5e76795124f3b9f2ad716acb63c5bb03cb0d17cfddd1eaba61cc959c3be850a9c30ac6fd701234eefc9900979708b1e92cc41b36e18c7a3dc32dfda9a006029a448a30036ed83f992b6
# input your password:>>$ pw
# welcome! 999999999\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10fw{c\x03a'Ews
# 1. pic1
# 2. pic2
# 3. flag
# $ 3
# flag{hm4c_with_h0rrib1e_c0der_1s_n0t_5ecure}
# Welcome, somebody
# you can:
# 1. login
# 2. registe
# $  [3]  + 24234 suspended (signal)  python writeup.py

from pwn import remote
from Crypto.Util.number import bytes_to_long, long_to_bytes
from os import urandom
from hashpumpy import hashpump

host = '127.0.0.1'
port = 10086


def xor(var, key):
    return bytes(a ^ b for a, b in zip(var, key))


bs = 16


def pad(s):
    return s + (bs - len(s) % bs) * bytes((bs - len(s) % bs, ))

l = remote(host, port)

l.recv()
l.send('2\n')
l.recv()
l.send('N\n')
l.recv()
username1 = '999999999'
l.send(username1 + '\n')
l.recv()
passwd = 'pw'
l.send(passwd + '\n')
l.recvline()
cookie1 = l.recvline()[:-1].decode('utf-8')
hash_old = cookie1[-64:]
original_data = bytes.fromhex(cookie1[:-64])
# 'isAdmin=False;pw=pw;un=999999999'


l.recv()
l.send('2\n')
l.recv()
l.send('N\n')
l.recv()
username2 = '9999999990000000000000000'
l.send(username2 + '\n')
l.recv()
passwd = 'pw'
l.send(passwd + '\n')
l.recvline()
cookie2 = l.recvline()[:-1].decode('utf-8')
cipher_old = cookie2[:-64]
oldblock = bytes.fromhex(cipher_old[-64:-32])
newblock = xor(xor(oldblock, 16*b'\x10'), b'isAdmin=True;'+3*b'\x03')

data_to_add = newblock + bytes.fromhex(cipher_old[-32:])
key_length = 16
h, c = hashpump(hash_old, original_data, original_data[-32:] + data_to_add, key_length)

new_cookie = c.hex() + h
print(new_cookie)
l.interactive()
l.recv()
l.send('1\n')
l.recv()
l.send(new_cookie + '\n')
l.recv()
l.send('pw\n')

l.interactive()

# original_data="product=Intel Core i7-7820X&price=599&timestamp=1526722377273504"
# data_to_add="&product=Flag"
# hexdigest="42b2444695e43df93a7ed54771bf0ccca1ca127a7c0e681686a90c5c7030e132"
# key_length=20


# for key_length in range(10,31):
# 	(h,order)=hashpumpy.hashpump(hexdigest, original_data, data_to_add, key_length)
# 	m=order+"&sign="+h
# 	exp(m)