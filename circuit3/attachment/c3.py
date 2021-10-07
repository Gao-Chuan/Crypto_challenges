import socketserver
from os import urandom
from random import shuffle
import time


wire = []
wire_num = 0
gate_num = 0
input_A_len = 0
input_B_len = 0
output_len = 0

def cf_run(input_A, input_B, cpath):
    with open(cpath, 'r') as cf:
        nums = cf.readline()
        _, wire_num = nums.strip().split(" ")
        wire_num = int(wire_num)
        wire = [0 for i in range(wire_num)]

        nums = cf.readline()
        input_A_len, input_B_len, output_len = nums.strip().split(" ")
        input_A_len = int(input_A_len)
        input_B_len = int(input_B_len)
        output_len = int(output_len)

        assert len(input_A)*8 == input_A_len
        assert len(input_B)*8 == input_B_len

        for i in range(len(input_A)):
            for j in range(8):
                wire[8*i + j] = (input_A[i] >> j) & 1

        for i in range(len(input_B)):
            for j in range(8):
                wire[input_A_len + 8*i + j] = (input_B[i] >> j) & 1
        
        cf.readline()
        

        for gateline in cf:
            gate = gateline.strip().split(" ")
            if gate[4] == 'INV':
                if wire[int(gate[2])] == 0:
                    wire[int(gate[3])] = 1
                elif wire[int(gate[2])] == 1:
                    wire[int(gate[3])] = 0
                else:
                    print("inv error!!!")
                    break
            elif gate[5] == "AND":
                wire[int(gate[4])] = wire[int(gate[3])] & wire[int(gate[2])]
            elif gate[5] == "XOR":
                wire[int(gate[4])] = wire[int(gate[3])] ^ wire[int(gate[2])]
            else:
                print(gate)
                print("gate error!!!")
                break
        
        output = ""
        for i in range(output_len):
            output += str(wire[-(output_len - i)])
        
        return output

class process(socketserver.BaseRequestHandler):
    def send(self, s):
        s = str(s)
        self.request.send(bytes(s, 'utf-8'))
    
    def handle(self):
        key = urandom(32)
        self.send("---start---")
        self.send("Give me your token\n")
        token = self.request.recv(21).strip().decode("utf-8") 

        self.send("Give me the circuit file's length.\n")
        l = self.request.recv(7).strip()
        length = 0
        try:
            length = int(l)
        except Exception:
            self.send("---end---")
            self.request.close()
            return
        if length > 50000:
            self.send("---end---")
            self.request.close()
            return

        self.send("length is:>>" + str(l)+"\n")

        # time.sleep(1)

        self.send("Give me the circuit file.\n")
        data = b""
        for i in range(length//1000):
            tmp = self.request.recv(1000)
            self.send("-")
            data += tmp
        tmp = b""
        tmp = self.request.recv(length % 1000)
        data += tmp

        self.send("received length:>>" + str(len(data))+"\n")
        
        if token.isdigit() is not True:
            self.send("---end---")
            self.request.close()
            return
            
        cpath = token + "circuit.txt"
        with open(cpath, 'wb') as f:
            f.write(data)
        
        res = cf_run(key, key, cpath)
        if res != "10000000000000000000000000000000":
            self.send("---end---")
            self.request.close()
            return

        for _ in range(100):
            x = urandom(32)
            res = cf_run(key, x, cpath)
            if res != "11111111111111111111111111111111":
                self.send("---end---")
                self.request.close()
                return
        
        self.send("Give me the key to unlock the flag.\n:>>")
        k = self.request.recv(33).strip()
        res = cf_run(key, k, cpath)
        if res != "10000000000000000000000000000000":
            self.send("---end---")
            self.request.close()
            return

        with open("flag.txt", 'r') as f:
            flag = f.readline()
            self.send(flag)
        self.send("---end---")
        self.request.close()
        return

class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

if __name__ == "__main__":
    HOST, PORT = '0.0.0.0', 10087
    server = ThreadedServer((HOST, PORT), process)
    server.allow_reuse_address = True
    server.serve_forever()
