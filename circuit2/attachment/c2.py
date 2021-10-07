import socketserver
from os import urandom
from random import shuffle
from Crypto.Cipher import AES

wire = [0 for i in range(240 * 3 + 1)]
gate = [[] for i in range(480)]
keys = [["", ""] for i in range(240 * 3 + 1)]


def enc(key, p):
    b = b''
    if type(p) == bytes:
        b = p
    else:
        b = bytes(p, 'utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(b).hex()

def init():
    global wire
    wire = [0 for i in range(240 * 3 + 1)]
    global gate
    gate = [[] for i in range(480)]
    global keys
    keys = [["", ""] for i in range(240 * 3 + 1)]

    for i in range(len(keys)):
        keys[i][0] = urandom(8)
        keys[i][1] = urandom(8)
    
        
    keys[-1] = [b'\x00' * 8, b'\x01' * 8]
    wire[-1] = 1

    flag = ""
    with open("./flag.txt") as f:
        flag = f.readline()
    assert len(flag) == 30, "flag length error"
    flag = ''.join('{:08b}'.format(ord(x), 'b') for x in flag)
    assert len(flag) == 240

    for i in range(240):
        if '0' ==  flag[i]:
            wire[i] = 0
        elif '1' == flag[i]:
            wire[i] = 1
        else:
            raise ValueError("flag value error")

class process(socketserver.BaseRequestHandler):
    def send(self, s):
        s = str(s)
        self.request.send(bytes(s, 'utf-8'))
    
    def comp(self):
        for i in range(240):
            self.send('k{}_0:'.format(str(i)))
            keys[240+i][0] = self.request.recv(8)
            if len(keys[240+i][0]) != 8:
                self.send("error")
                return
            self.send('k{}_1:'.format(str(i)))
            keys[240+i][1] = self.request.recv(8)
            if len(keys[240+i][1]) != 8:
                self.send("error")
                return
        
        for i in range(240):
            self.send(str(i) + "'s bit:>>\n")
            b = self.request.recv(1)
            if b == b'0':
                wire[i+240] = 0
                if wire[i] == 0:
                    wire[i + 480] = 1
                    gate[i].append(enc(keys[i][0]+ keys[i+240][0], b"\x00"*8 + keys[i+480][wire[i+480]]))
                    gate[i].append(keys[i][0].hex())
                elif wire[i] == 1:
                    wire[i + 480] = 0
                    gate[i].append(enc(keys[i][1]+ keys[i+240][0], b"\x00"*8 + keys[i+480][wire[i+480]]))
                    gate[i].append(keys[i][1].hex())
            elif b == b'1':
                wire[i+240] = 1
                if wire[i] == 0:
                    wire[i + 480] = 0
                    gate[i].append(enc(keys[i][0]+ keys[i+240][1], b"\x00"*8 + keys[i+480][wire[i+480]]))
                    gate[i].append(keys[i][0].hex())
                elif wire[i] == 1:
                    wire[i + 480] = 1
                    gate[i].append(enc(keys[i][1]+ keys[i+240][1], b"\x00"*8 + keys[i+480][wire[i+480]]))
                    gate[i].append(keys[i][1].hex())
            else:
                self.send("error")
                return
        
        for i in range(240):
            if 0 == wire[480 + i]:
                wire[-1] = 0
                gate[i + 240].append(enc(keys[480 + i][0] + keys[-1][wire[-1]], b"\x00"*8 + keys[-1][wire[-1]]))
            elif 1 == wire[480 + i]:
                gate[i + 240].append(enc(keys[480 + i][1] + keys[-1][wire[-1]], b"\x00"*8 + keys[-1][wire[-1]]))
            else:
                self.send("error")
                return
        # I love saving memory! And I just don't want Bob know the result!

    def handle(self):
        self.send("---start---")

        init()
        self.comp()

        gate_send = ''

        for i in range(480):
            gate_send += "gate_{}\n".format(str(i))
            for e in gate[i]:
                gate_send += str(e)
                gate_send += '-'
        
        self.send(gate_send)

        self.send("---end---")
        self.request.close()


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10086
    server = ThreadedServer((HOST, PORT), process)
    server.allow_reuse_address = True
    server.serve_forever()
