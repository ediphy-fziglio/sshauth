import socket, os, struct, sys, subprocess, array
path=sys.argv[1]; mode=sys.argv[2]
try: os.unlink(path)
except FileNotFoundError: pass
s=socket.socket(socket.AF_UNIX); s.bind(path); s.listen(1)
c,_=s.accept()
def rx(n):
    b=b''
    while len(b)<n: b+=c.recv(n-len(b))
    return b
h=rx(8); assert h[:4]==b'SSHA' and h[4:6]==b'\0\1'
cmd=rx(struct.unpack('>H',h[6:8])[0]).decode()
if mode=='err':
    m=b'denied: '+cmd.encode(); c.sendall(b'ERR!'+struct.pack('>H',len(m))+m); sys.exit()
r,w=os.pipe()
c.sendmsg([b'OKAY'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[r]))]); os.close(r)
t=b'running: '+cmd.encode()+b'\n'; os.write(w,b'TEXT'+struct.pack('>H',len(t))+t)
p=subprocess.run(['sh','-c',cmd],stdin=c.makefile('rb'),stdout=subprocess.PIPE)
os.write(w,b'EXIT'+struct.pack('>i',p.returncode))
c.sendall(p.stdout); c.close()
