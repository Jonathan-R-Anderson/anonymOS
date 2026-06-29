#!/usr/bin/env python3
# §E7/F2 — entropy map of an install image. The encrypted partitions (system + outer)
# must be uniformly high-entropy: no zeros (which would prove "no real data") and no
# discontinuity (which would reveal the hidden-volume boundary). The GPT + ESP are
# legitimately low-entropy/structured (every encrypted-Linux disk looks like that).
import sys, math
SEC = 512
sysLBA, sysSec   = 131106, 131072       # §E4b geometry (64 MiB system)
outerLBA, outerSec = 262178, 786365     # outer = rest of a 512 MiB disk

f = open(sys.argv[1], 'rb')
def ent(b):
    if not b: return 0.0
    h=[0]*256
    for x in b: h[x]+=1
    n=len(b); e=0.0
    for c in h:
        if c:
            p=c/n; e-=p*math.log2(p)
    return e
def scan(lba, nsec, win=1<<20):
    start=lba*SEC; end=(lba+nsec)*SEC; pos=start; vals=[]
    while pos < end:
        f.seek(pos); b=f.read(min(win, end-pos))
        if len(b) < 4096: break
        vals.append(ent(b)); pos += win
    return (min(vals), sum(vals)/len(vals), max(vals)) if vals else (0,0,0)

regions = [("GPT/MBR",0,34), ("ESP (FAT)",34,131072),
           ("system (encrypted)",sysLBA,sysSec), ("outer (enc/random)",outerLBA,outerSec)]
res={}
for name,lba,nsec in regions:
    mn,av,mx = scan(lba,nsec)
    res[name]=(mn,av,mx)
    print(f"  {name:22s} min={mn:.3f} avg={av:.3f} max={mx:.3f} bits/byte")

smn = res["system (encrypted)"][0]; omn = res["outer (enc/random)"][0]
ok = smn > 7.9 and omn > 7.9
print(f"  [{'PASS' if ok else 'FAIL'}] encrypted partitions uniformly high-entropy "
      f"(min {min(smn,omn):.3f} > 7.9 → featureless: no zeros, no hidden-volume tell)")
sys.exit(0 if ok else 1)
