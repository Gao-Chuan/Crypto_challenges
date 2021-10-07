from pwn import remote
from Crypto.Cipher import AES
import re
import binascii

def wp(flag, index):
    host = '127.0.0.1'
    port = 10086

    def dec(key, p):
        b = p
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.decrypt(b)

    l = remote(host, port)

    l.recv(numb = len("---start---"))

    k = b"\x01"*8


    for i in range(240):
        l.recv(numb = 5)
        l.send(k)
        l.recv(numb = 5)
        l.send(k)


    for i in range(len(flag)):
        l.recvline()
        if flag[i] == '0':
            l.send(b'0')
        else:
            l.send(b'1')

    gate_recv = l.recvuntil("---end---")[:-9]
    gate_recv = str(gate_recv)

    _gate = re.split(r'gate_[0-9]+\\n', gate_recv)[1:]
    gate = [[] for i in range(480)]


    for i in range(240):
        x = re.split(r'-', _gate[i])
        x[0] = bytearray.fromhex(x[0])
        x[1] = bytearray.fromhex(x[1])
        gate[i].append(x[0])
        gate[i].append(x[1])
        pi = dec(x[1] + k, x[0])
        gate[i].append(pi[8:])

    x = re.split(r'-', _gate[240 + index + 40])
    x[0] = bytearray.fromhex(x[0])
    pi = dec(gate[index + 40][2] + b'\x01'*8, x[0]).hex()

    # for i in range(index + 4):
    #     x = re.split(r'-', _gate[240 + i])
    #     x[0] = bytearray.fromhex(x[0])
    #     pi = dec(gate[i][2] + b'\x01'*8, x[0])
    #     print(pi.hex())


    l.close()

    if pi[0:4] == "0000":
        print("yes!")
        print(pi)
        return 0
    else:
        print("wrong")
        print(pi)
        return 1



if __name__ == "__main__":
    flag = "flag{"
    flag = ''.join('{:08b}'.format(ord(x), 'b') for x in flag)
    for i in range(200):
        flag1 = flag + '0' + '0' * (199 - i)
        flag2 = flag + '1' + '0' * (199 - i)
        r1 = wp(flag1, i)
        if r1 == 0:
            flag = flag + '0'
        else:
            r2 = wp(flag2, i)
            flag = flag + '1'
            assert r2 == 0, "wtf?"
    print(flag)
    print(binascii.unhexlify('%x' % int(flag, 2)))

