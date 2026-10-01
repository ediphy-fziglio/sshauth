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
args=rx(struct.unpack('>H',h[6:8])[0]).split(b'\0')
if mode=='err':
    m=b'denied: '+b' '.join(args); c.sendall(b'ERR!'+struct.pack('>H',len(m))+m); sys.exit()
r,w=os.pipe()
c.sendmsg([b'OKAY'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[r]))]); os.close(r)
t=b'running: '+repr(args).encode()+b'\n'; os.write(w,b'TEXT'+struct.pack('>H',len(t))+t)
p=subprocess.run(args,stdin=c.makefile('rb'),stdout=subprocess.PIPE)
# Send all output before EXIT: the client exits as soon as it reads EXIT.
c.sendall(p.stdout)
os.write(w,b'EXIT'+struct.pack('>i',p.returncode))
c.close()
