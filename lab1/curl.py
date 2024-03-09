from pwn import *
r = remote("ipinfo.io", 80);
r.sendline(b'GET /ip HTTP/1.1')
r.sendline(b'Host: ipinfo.io')
r.sendline(b'User-Agent: curl/7.81.0')
r.sendline(b'Accept: */*')
# send an empty line to signal the end of the request
r.sendline(b'')

# receive the response
response = r.recvuntil(b'\r\n\r\n')
ip = r.recv(15)
# decode byte string
print(ip.decode('utf-8'))