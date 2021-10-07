import random,sys,string
from hashlib import sha256
import socketserver
from Crypto.Cipher import AES
from Crypto.Util.number import getPrime, GCD, bytes_to_long, long_to_bytes, inverse
import os
import hashlib
from random import randint
from time import time, sleep

secret= os.urandom(16)
admin_key = os.urandom(16).hex()
aes_key = os.urandom(16)
iv = os.urandom(AES.block_size)
p = getPrime(256)
g = getPrime(128)
x = randint(1, p-2)
y = pow(g, x, p)

wel = b'Welcome, somebody\nyou can:\n1. login\n2. registe\n'

class process(socketserver.BaseRequestHandler):
    def justWaite(self):
        sleep(3)

    def _pad(self, s):
        s = bytes(s, 'utf-8')
        return s + (16 - len(s) % 16) * bytes((16 - len(s) % 16, ))

    def _unpad(self, s):
        return s[0:-s[-1]].decode('utf-8', 'ignore')

    def mac(self, msg):
        while True:
            k = int(time())
            if GCD(k, p-1) ==1:
                break
        r = pow(g, k, p)
        s = ((bytes_to_long(sha256(msg).digest()) - x*r)*inverse(k, p-1)) % (p-1)
        if s == 0:
            return self.mac(msg)
        else:
            return (msg.hex(), long_to_bytes(r).hex(), long_to_bytes(s).hex())

    def verifyMac(self, msg, r, s):
        msg = bytes.fromhex(msg)
        r = bytes_to_long(bytes.fromhex(r))
        s = bytes_to_long(bytes.fromhex(s))
        assert r < p and r > 0
        assert s < p-1 and s > 0
        assert pow(g, bytes_to_long(sha256(msg).digest()), p) == ((pow(y, r, p) * pow(r, s, p))%p)
        flag = True
        
        return msg, flag
    
    def encrypt(self, plain):
        plain = self._pad(plain)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = iv + cipher.encrypt(plain)
        return ciphertext

    def decrypt(self, ciphertext):
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        plain = cipher.decrypt(ciphertext[AES.block_size:])
        return self._unpad(plain)

    def adminLogin(self, username):
        self.request.send(b'1. pic1\n2. pic2\n3. flag\n')
        c = self.request.recv(2).decode('utf-8')[0]
        if c == '1':
            self.request.send(bytes('your gun:\n▄︻┻═┳一\n', 'UTF-8'))
        elif c == '2':
            self.request.send(bytes('your Knife:\n━╋▇▇▇◤\n', 'UTF-8'))
        elif c == '3':
            with open('flag') as f:
                flag = f.readline()
                self.request.send(flag.encode('utf-8') + b'\n')
        else:
            self.request.send(b'wrong num')

    def userLogin(self, username):
        self.request.send(b'1. pic1\n2. pic2\n')
        c = self.request.recv(2).decode('utf-8')[0]
        if c == '1':
            self.request.send(bytes('your gun:\n▄︻┻═┳一', 'UTF-8'))
        elif c == '2':
            self.request.send(bytes('your Knife:\n━╋▇▇▇◤', 'UTF-8'))
        else:
            self.request.send(b'wrong num')

    def handle(self):
        #self.justWaite()    

        while True:
            self.isAdmin = False
            self.request.send(wel)
            wel_choice = self.request.recv(2).decode('utf-8')[0]
            if wel_choice == '1':
                self.request.send(b'input your cookie:>>')
                msg = self.request.recv(513).decode('utf-8')[:-1]
                r = self.request.recv(513).decode('utf-8')[:-1]
                s = self.request.recv(513).decode('utf-8')[:-1]
                msg, flag = self.verifyMac(msg, r, s)
                msg = self.decrypt(msg)
                try:
                    for i in range(len(msg)-3):
                        if msg[i:i+3] == 'un=':
                            username = msg[i+3:]
                            username = username.split(';')[0]
                            break
                    
                    for i in range(len(msg)-3):
                        if msg[i:i+3] == 'pw=':
                            passwd = msg[i+3:]
                            passwd = passwd.split(';')[0]
                            break
                    
                    for i in range(len(msg)-8):
                        if msg[i:i+8] == 'isAdmin=':
                            if msg[i+8:i+13] == 'True;':
                                self.isAdmin = True
                                break

                except Exception as e:
                    print('error detected\n')
                    print(e)
                
                if flag == False:
                    self.request.send(b'dear %s, your cookie is broken\n'%(username.encode('utf-8')))
                    break
                self.request.send(b'input your password:>>')
                pw_t = self.request.recv(37).decode('utf-8')[:-1]
                if pw_t != passwd:
                    self.request.send(b'wrong passwd!')
                    break
                self.request.send(b'welcome! %s\n'%(username.encode('utf-8')))
                if self.isAdmin:
                    self.adminLogin(username)
                else:
                    self.userLogin(username)
                                
            elif wel_choice == '2':
                self.request.send(b'welcome! are you an admin?(Y/N)\n')
                reg_c = self.request.recv(2).decode('utf-8')[0]
                if reg_c == 'Y':
                    self.request.send(b'input admin key:>>')
                    u_key = self.request.recv(33).decode('utf-8')[:-1]
                    if u_key != admin_key:
                        break
                    else:
                        self.isAdmin = True
                self.request.send(b'input your name:>>\n')
                username = self.request.recv(37).decode('utf-8')[:-1]
                if 'admin' in username.lower():
                    self.request.send(b'no admin in username\n')
                self.request.send(b'input your pw:>>\n')
                passwd = self.request.recv(37).decode('utf-8')[:-1]
                if 'admin' in passwd.lower():
                    self.request.send(b'no admin in password\n')
                cookie = self.mac(self.encrypt('isAdmin='+str(self.isAdmin)+';pw='+passwd+';un='+username))
                self.request.send(b'your cookie:>>\n' + str(cookie).encode('utf-8') + b'\n')
            else:
                break

        self.request.close()


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10085
    server = ThreadedServer((HOST, PORT), process)
    server.allow_reuse_address = True
    server.serve_forever()
