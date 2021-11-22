#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
""" 
Usage: ./money.py -> run simple case
Purpose: Transpose on iOs using ble
(!) No strategy if Bloomfilter returns a false positive
Can one change BloomFilter setup dynamically ? 
<src:8><num:2><dst:8><mnt:4><bal:4><dat:4><bl:BSIZ><hash:16>
"""

import ecc, random
#from simplebloom import BloomFilter
from bloomfilter import BloomFilter

BSIZ = 70
Z10  = ecc.i2b(0, 10)
Z8  = ecc.i2b(0, 8)
SIZE = 96 + 48 + 30 + BSIZ + 16 + 96 # pk+msg+bl+sign
SAJ  = 8 + 4 + 4 + 144 + 96     # id+mnt+dat+ack+sign
BASE = 1000

L0=0
L1=138

def mnt(x): return ecc.i2b(x, 4)
def gm(x):  return ecc.b2i(x[18:22])
def bal(x): return ecc.i2b(x, 4)
def gb(x):  return ecc.b2i(x[22:26])

def num(x):  return ecc.i2b(x, 2)
def getn(x): return ecc.b2i(x[8:10])

def hsh(x):  return ecc.hashlib.sha256(x).digest()[:16]
def now():   return int(ecc.time.mktime(ecc.time.gmtime()))

def dat(d):  return ecc.i2b(d, 4)
def getd(x): return ecc.b2i(x[26:30])
def ddod(t): return ecc.time.strftime('%d/%m/%y %H:%M:%S', ecc.time.localtime(float(t)))

AA = ''
BB = ''
class agent:
    
    def __init__(s, root=None):
        s.k, s.o, s.z, s.root = ecc.ecdsa(), ecc.ecdsa(), 0, root
        s.k.generate()
        s.p = s.k.compress(s.k.pt)
        s.i = s.p[:8]
        s.c = root.k.sign(s.i) if root else None
        s.tp, s.tn, s.com, s.un = {}, [], {s.i:s}, {}

    def chresp(s, cand):
        assert cand not in s.un
        if ecc.b2i(cand[8:10]) == 0:
            s.un[cand] = True
            return s.p + s.k.sign(cand)
        for x in [y for y in s.tp if y[144:154] == cand]:
            s.un[cand] = True
            return s.p + s.k.sign(cand)
        return
        
    def pay(s, dst, mt):
        global AA
        global BB
        s.com[dst.i] = dst
        bf, ack, la = BloomFilter(100, 0.1), None, dat(now())
        assert len(bf.dumps()) == BSIZ
        m0 = s.tn[-1] if s.tn else s.i + num(0) + Z8 + mnt(0) + bal(BASE) + dat(0) + bf.dumps() + hsh(b'')
        b = gb(m0)
        if m0[10:18] in s.com: ack = s.com[m0[10:18]].chresp(s.i+m0[8:10])
        if m0[8:18] == Z10:    ack = s.root.chresp(s.i+m0[8:10])
        t = s.c + s.p + m0 + s.k.sign(m0)
        for x in [y for y in s.tp if s.tp[y] == True]:
            e, s.tp[x] = x[144:], False
            assert '%x'%ecc.b2i(e[:10]) not in bf
            bf.put('%x'%ecc.b2i(e[:10]))
            b += gm(e)
            t += x
        b -= mt
        s.z = b-BASE
        m = s.i + num(getn(m0)+1) + dst.i + mnt(mt) + bal(b) + la + bf.dumps() + hsh(t)
        AA = m[L0:L1]
        print ('A', AA)
        s.tn.append(m)
        return t + dst.i + mnt(mt) + la + ack + s.k.sign(m)
    
    def get(s, tt):
        # 138 long msg
        b = 0
        global BB
        global AA
        t, a = tt[:-SAJ], tt[-SAJ:]
        assert len(t)%SIZE == 0
        for i in range(len(t)//SIZE):
            m = t[i*SIZE:(i+1)*SIZE]
            c, p, e, g = m[:96], m[96:144], m[144:-96], m[-96:]
            if i == 0: c0, p0, e0, bf, src, b = c, p, e, BloomFilter.loads(e[-BSIZ-16:-16]), e[:8], gb(e)
            else:
                assert src == e[10:18]
                assert '%d'%ecc.b2i(e[:10]) not in bf
                bf.put('%x'%ecc.b2i(e[:10]))
                b += gm(e)
            assert s.root.k.verify(c, e[:8]) # certificate
            s.o.pt = s.o.uncompress(p)
            assert s.o.verify(g, e) # in signature
        b -= ecc.b2i(a[8:12])
        m1 = src + num(getn(e0)+1) + s.i + a[8:12] + bal(b) + a[12:16] + bf.dumps() + hsh(t)
        BB = m1[L0:L1]
        print ('B', BB)
        ak = a[-192:-96]
        s.o.pt = s.o.uncompress(a[16:16+48])
        for i in range(L1):
            print (i)
            assert AA[:i] == BB[:i]
        assert s.o.verify(ak, src+num(getn(e0))) # ack signature
        s.o.pt = s.o.uncompress(p0)
        assert p0[:8] == src
        #print ('B', gb(m1))
        assert s.o.verify(a[-96:], m1) # final signature
        s.tp[c0 + p0 + m1 + a[-96:]] = True
        s.z += ecc.b2i(a[8:12])

A = b'\x01\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
B = b'\x01\x03\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        
def case0():
    root = agent()
    (alice, bob, carol, dave, eve) = [agent(root) for x in range(5)]
    bob.get(alice.pay(bob, 50))
    ecc.time.sleep(1) # not same date
    bob.get(alice.pay(bob, 10))
    ecc.time.sleep(1) # not same date
    bob.get(alice.pay(bob, 20))
    dave.get(alice.pay(dave, 30))
    carol.get(bob.pay(carol, 20))
    eve.get(carol.pay(eve, 15))
    assert alice.z+bob.z+carol.z+dave.z+eve.z == 0
    
def case1():
    root = agent()
    p = [agent(root) for i in range(10)]
    for i in range(100):
        a, b = random.randint(0, 9), random.randint(0, 9)
        print (i, a, b)
        b, s = p[a], p[b]
        if s != b: s.get(b.pay(s, 10))
    assert sum([x.z for x in p]) == 0

if __name__ == '__main__':
    a = BloomFilter(100, 0.1)
    for i in range(1000): a.put('%d'%i)
    aa = a.dumps()
    print (len(aa))
    b = BloomFilter.loads(aa)
    for i in range(1000):b.put('%d'%i)
    bb = a.dumps()
    assert aa == bb
    case1()
    
# End ⊔net!
