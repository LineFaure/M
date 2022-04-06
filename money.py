#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
! Caution: there is a lot of Bloomfilter packages -> use bloomfilterpy
Packages: pip3 install bloomfilterpy
Usage: run ./backend.py in background then run ./money.py -> basic tests of random transactions
Block = pk:48 + cert:96 + (val:2 + bal:4 + num:4 + dst:8 + date:4 + blf:[14-70] + hash:16) + sign:96 
"""
import ecc, random, backend
from bloomfilter import BloomFilter

CAPY, RATE = 10, .1
BFLT = 14
BLZ = 278 + BFLT 
BASE = 1000

def hsh(x): return ecc.hashlib.sha256(x).digest()[:16]
def now():  return int(ecc.time.mktime(ecc.time.gmtime()))

class agent:
    def __init__(s, root=None):
        s.r, s.c, s.o = root, None, ecc.ecdsa()
        s.k, s.tp, s.tn, s.n, s.z, s.f, s.com, s.un = ecc.ecdsa(), [], [], 0, 0, BloomFilter(CAPY, RATE), {}, {}
        s.k.generate()
        s.p = s.k.compress(s.k.pt)
        if root: s.c = s.r.register(s)        
        assert len(s.f.dumps()) == BFLT

    def register(s, x): return s.k.sign(x.p)
        
    def pay(s, d, v):
        s.com[d.p[:8]] = d
        b = (ecc.b2i(s.tn[-1][2:6]) if s.tn else BASE) + sum([ecc.b2i(x[144:144+2]) for x in s.tp]) - v
        if b < 0 or s == d: return        
        m0, s.z = ecc.i2b(0, 2) + ecc.i2b(BASE, 4) + ecc.i2b(0, 16) + s.f.dumps() + hsh(b''), b - BASE
        for x in s.tp:
            j = '%x'%ecc.b2i(x[:8] + x[150:154]) 
            s.f.put(j)
            assert j in s.f
        w = s.r if s.tn == [] else s.com[s.tn[-1][10:18]]
        c = s.p[:8] + ecc.i2b(s.n, 4)
        s.o.pt = s.o.uncompress(w.p[:48])
        t, s.tp = s.p + s.c + (s.tn[-1] if s.tn else m0 + s.k.sign(s.p + s.c + m0)) + b''.join(s.tp), []
        s.n += 1
        m = ecc.i2b(v, 2) + ecc.i2b(b, 4) + ecc.i2b(s.n, 4) + d.p[:8] + ecc.i2b(now(), 4) + s.f.dumps() + hsh(t)
        g = s.k.sign(s.p+s.c+m) 
        s.tn.append(m+g)
        return t + s.p + s.c + m + g 

    def get_paid(s, y):
        if y == None: return False
        n, k, f, u, d, p = len(y)//BLZ, None, None, None, None, None
        assert len(y)%BLZ == 0
        for i in range(n):
            e = y[i*BLZ:(i+1)*BLZ]
            m = e[144:-96]
            l, h, q, t = m[22:-16], m[-16:], m[6:10], m[18:22]
            v, b, s.o.pt = ecc.b2i(m[:2]), ecc.b2i(m[2:6]), s.o.uncompress(s.r.p)
            if i == 0:
                u, k, f, d, p, c = ecc.b2i(q)+1, b, BloomFilter.loads((l)), ecc.b2i(t), e[:48], e[48:144]
                assert s.o.verify(c, p) and backend.getYF(e[:8]) == ecc.b2i(q)
            elif i < n-1:
                k += v
                j = '%x'%ecc.b2i(e[:8] + q)
                if j in f: assert not backend.getFP(p[:8] + e[:8] + q)
                f.put(j)
                backend.setYF(p[:8] + e)
                assert backend.getFP(p[:8] + e[:8] + q) and j in f and s.o.verify(e[48:144], e[:48])
            else:
                s.z += v
                s.tp.append(e)
                backend.setFP(e)
                assert k-v == b and f.dumps() == l and h == hsh(y[:-BLZ]) and u == ecc.b2i(q) and d < ecc.b2i(t)
            s.o.pt = s.o.uncompress(e[:48])
            assert s.o.verify(e[-96:], e[:-96])
        return True

if __name__ == '__main__':
    root, NB, s, b = agent(), 10, 0, 0
    pop = (alice, bob, carol, dave, eve) = [agent(root) for i in range(5)]
    alice.get_paid(carol.pay(alice, 20))
    alice.get_paid( dave.pay(alice, 20))
    eve.get_paid(  alice.pay(eve,   35))
    bob.get_paid(  alice.pay(bob,  100))
    pop += [agent(root) for i in range(NB)]
    for i in range(100):
        while s == b: b, s = random.randint(0, NB-1), random.randint(0, NB-1)
        val = random.randint(1, 50)
        print ('#%02d %2d->%2d (%2d$): %s' % (i, b, s, val, pop[s].get_paid(pop[b].pay(pop[s], val))))
        b, s = 0, 0
    assert sum([x.z for x in pop]) == 0
# End ⊔net!
