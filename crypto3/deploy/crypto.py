import random,sys,string
from hashlib import sha256
import socketserver
from Crypto.Cipher import AES
import os
import hashlib
import time

secret= os.urandom(16)
admin_key = os.urandom(16).hex()
aes_key = os.urandom(16)
iv = os.urandom(AES.block_size)

wel = b'Welcome, somebody\nyou can:\n1. login\n2. registe\n'

class process(socketserver.BaseRequestHandler):
    def justWaite(self):
        time.sleep(3)

    def _pad(self, s):
        s = bytes(s, 'utf-8')
        return s + (16 - len(s) % 16) * bytes((16 - len(s) % 16, ))

    def _unpad(self, s):
        return s[0:-s[-1]].decode('utf-8', 'ignore')

    def mac(self, msg):
        hmac = sha256(secret + msg).digest()
        return (msg + hmac).hex()

    def verifyMac(self, mac):
        mac = bytes.fromhex(mac)
        hmac = mac[-32:]
        msg = mac[:-32]
        if hmac == sha256(secret + msg).digest():
            flag = True
        else:
            flag = False
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
            self.request.send(bytes('your Tu Long Knife:\n━╋▇▇▇◤\n', 'UTF-8'))
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
            self.request.send(bytes('your Tu Long Knife:\n━╋▇▇▇◤', 'UTF-8'))
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
                cookie = self.request.recv(513).decode('utf-8')[:-1]
                msg, flag = self.verifyMac(cookie)
                msg = self.decrypt(msg)
                try:
                    for i in range(len(msg)-3):
                        if msg[i:i+3] == 'un=':
                            username = msg[i+3:]
                            username = username.split(';')[0]
                    
                    for i in range(len(msg)-3):
                        if msg[i:i+3] == 'pw=':
                            passwd = msg[i+3:]
                            passwd = passwd.split(';')[0]
                    
                    for i in range(len(msg)-8):
                        if msg[i:i+8] == 'isAdmin=':
                            if msg[i+8:i+13] == 'True;':
                                self.isAdmin = True
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
                self.request.send(b'your cookie:>>\n' + cookie.encode('utf-8') + b'\n')
            else:
                break

        self.request.close()


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10086
    server = ThreadedServer((HOST, PORT), process)
    server.allow_reuse_address = True
    server.serve_forever()
