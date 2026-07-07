#!/usr/bin/env python3
import socket, json, sys, time
SOCK="qmp.sock"
def conn():
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.connect(SOCK)
    f=s.makefile("rw"); f.readline(); f.write(json.dumps({"execute":"qmp_capabilities"})+"\n"); f.flush(); f.readline(); return s,f
def cmd(f,e,**a):
    m={"execute":e}
    if a: m["arguments"]=a
    f.write(json.dumps(m)+"\n"); f.flush()
    while True:
        l=f.readline()
        if not l: return None
        o=json.loads(l)
        if "return" in o or "error" in o: return o
def keyev(f,q,d): cmd(f,"input-send-event",events=[{"type":"key","data":{"down":d,"key":{"type":"qcode","data":q}}}])
def keys(f,ks):
    for k in ks: keyev(f,k,True)
    time.sleep(0.03)
    for k in reversed(ks): keyev(f,k,False)
    time.sleep(0.02)
def rel(f,dx,dy):
    e=[]
    if dx:e.append({"type":"rel","data":{"axis":"x","value":int(dx)}})
    if dy:e.append({"type":"rel","data":{"axis":"y","value":int(dy)}})
    if e:cmd(f,"input-send-event",events=e)
def moveto(f,x,y):
    for _ in range(80): rel(f,-12,-12)
    time.sleep(0.15); ax,ay=int(x),int(y)
    while ax>0 or ay>0:
        dx=min(ax,12);dy=min(ay,12);rel(f,dx,dy);time.sleep(0.012);ax-=dx;ay-=dy
def click(f):
    cmd(f,"input-send-event",events=[{"type":"btn","data":{"button":"left","down":True}}]);time.sleep(0.05)
    cmd(f,"input-send-event",events=[{"type":"btn","data":{"button":"left","down":False}}])
CH={'[':'bracket_left',']':'bracket_right',' ':'spc','\n':'ret','-':'minus','/':'slash','.':'dot',':':('shift','semicolon'),'_':('shift','minus'),'=':'equal','$':('shift','4'),';':'semicolon',',':'comma','|':('shift','backslash'),'(':('shift','9'),')':('shift','0'),'<':('shift','comma'),'>':('shift','dot')}
for c in "abcdefghijklmnopqrstuvwxyz": CH[c]=c
for d in "0123456789": CH[d]=d
for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ": CH[c]=('shift',c.lower())
op=sys.argv[1]; s,f=conn()
if op=="screendump": cmd(f,"screendump",filename=sys.argv[2]); print("dumped")
elif op=="click": moveto(f,int(sys.argv[2]),int(sys.argv[3])); time.sleep(0.2); click(f); print("clicked")
elif op=="key":
    for ch in sys.argv[2:]: keys(f,ch.split("+")); time.sleep(0.12)
elif op=="type":
    for ch in sys.argv[2]:
        k=CH.get(ch)
        if k is None: continue
        keys(f,list(k) if isinstance(k,tuple) else [k]); time.sleep(0.05)
elif op=="drag":   # drag x1 y1 x2 y2 : press at (x1,y1), move to (x2,y2), release (for scrollbar thumb)
    x1,y1,x2,y2=int(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4]),int(sys.argv[5])
    moveto(f,x1,y1); time.sleep(0.2)
    cmd(f,"input-send-event",events=[{"type":"btn","data":{"button":"left","down":True}}]); time.sleep(0.12)
    ax,ay=x2-x1,y2-y1; n=max(abs(ax),abs(ay))//8+1
    for _ in range(n): rel(f,round(ax/n),round(ay/n)); time.sleep(0.02)
    time.sleep(0.12)
    cmd(f,"input-send-event",events=[{"type":"btn","data":{"button":"left","down":False}}]); print("dragged")
s.close()
