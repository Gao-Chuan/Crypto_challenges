from pwn import remote
import time

def wp():
    host = '127.0.0.1'
    port = 10086

    l = remote(host, port)

    s = l.recv(numb = len("---start---"))
    print(s)
    s = l.recv(numb = len("Give me your token\n"))
    print(s)
    l.send("12345678901234567890")
    s = l.recv(numb = len("Give me the circuit file's length.\n"))
    print(s)
    data = b""
    with open("circuit.txt", 'r') as f:
        data = f.read()
    l.send(str(len(data)))
    s = l.recvline()
    print(s)
    # s = l.recv(numb = len("Give me the circuit file.\n"))
    s = l.recvline()
    print(s)
    for i in range(len(data) // 1000):
        l.send(data[i*1000 : (i+1)*1000])
        s = l.recv()
        print(s + bytes(str(i), 'utf-8'), end = "")
    print(data[ - (len(data) % 1000):])
    l.send(data[ - (len(data) % 1000):])
    print("data len:>>" + str(len(data)))
    s = l.recvline()
    print(s)
    l.recv(numb=len("Give me the key to unlock the flag.\n:>>"))
    l.send(b'\x00'*32 )
    flag = l.recv()
    print(flag)

if __name__ == "__main__":
    wp()

