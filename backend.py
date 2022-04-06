#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Usage: ./backend.py& -> run http server in background
This server is in charge of:
- YF: insure that no Y (Fork or Y Fraude) is possible: the last recipient is the good one
- FP: insure that all credit transactions are used once when the local Bloom Filter returns false positive
For real testing with smartphones, install the backend on Internet, not locally
"""

import ecc, dbm, socketserver, http.server, requests, threading

HOST, PORT = '127.0.0.1', 8000 
URL  = 'http://%s:%d' %(HOST, PORT)
BASE = 'base'

class handler(http.server.BaseHTTPRequestHandler):

    def wFP(s, x, n):
        with dbm.open(BASE, 'c') as b:
            if (x not in b) or (x in b and ecc.b2i(n) > ecc.b2i(b[x])): b[x] = n
    def wYF(s, x):
        with dbm.open(BASE, 'c') as b:
            if x not in b : b[x] = b''
    def rYF(s, d):
        with dbm.open(BASE) as b:
            return b[d] if d in b else b''
    def rFP(s, d):
        with dbm.open(BASE) as b:
            return b'' if d in b else b'NOTIN'
    
    def do_POST(s):
        d, r, o = s.rfile.read(int(s.headers['Content-Length'])), b'', ecc.ecdsa()
        if   len(d) == 8:  r = s.rYF(d) 
        elif len(d) == 20: r = s.rFP(d)
        elif len(d) == 292: 
            o.pt = o.uncompress(d[:48])
            if o.verify(d[-96:], d[:-96]): s.wFP(d[:8], d[150:154])
        elif len(d) == 300: 
            o.pt = o.uncompress(d[8:56])
            if o.verify(d[-96:], d[8:-96]): s.wYF(d[:8] + d[8:16] + d[158:162])
        s.send_response(200)
        s.send_header('Content-type', 'text/plain')
        s.end_headers()
        s.wfile.write(r)

def server():
    print ('run HTTP server')
    socketserver.TCPServer((HOST, PORT), handler).serve_forever()

def setYF(e):
    assert len(e) == 300
    requests.post(URL, data=e)

def setFP(e):
    assert len(e) == 292
    requests.post(URL, data=e)
    
def getYF(x):
    assert len(x) == 8
    r = requests.post(URL, data=x).content
    return ecc.b2i(r) if r else 0

def getFP(x):
    assert len(x) == 20
    return requests.post(URL, data=x).content == b''

if __name__ == '__main__':
    with dbm.open(BASE, 'c') as b: b[b''] = b''
    threading.Thread(target=server).start()

# End ⊔net!
