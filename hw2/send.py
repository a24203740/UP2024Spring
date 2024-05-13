from pwn import *
import sys
import time

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: python3 {sys.argv[0]} <problemId>')
        sys.exit(1)
        
    problemId = sys.argv[1]
        
    f = open(f'{problemId}.s', 'r')
    code = f.read()
    f.close()
    # print(disasm(asm(code)))

    p = remote('up2.zoolab.org', int(problemId)+2500)
    # p.recvuntil("======".encode('utf-8'))
    # p.recvuntil("======".encode('utf-8'))

    
    p.send(code.encode('utf-8'))
    p.send("\n".encode('utf-8'))
    time.sleep(0.5)
    # p.recvuntil("======\n".encode('utf-8'))
    # print("======")
    # recv = p.recvuntil("======\n".encode('utf-8'))
    # print(recv.decode('utf-8')[:-1])
    # recv = p.recvlines(2)
    # [print(i.decode('utf-8')) for i in recv]
    print(p.recvall().decode('utf-8'))
    p.close()