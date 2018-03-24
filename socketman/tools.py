#

import contextlib
import threading
import socket
from collections import deque
from  cStringIO import StringIO
import struct
import re

import logging
logger = logging.getLogger(__name__)
logtun = logging.getLogger(__name__ + ".Tunnel")

@contextlib.contextmanager
def released(lock):
    lock.release()
    try:
        yield
    finally:
        lock.acquire()

def sock_abort(s):
    # set the socket in abort mode for closing.
    # ignore errors here
    try:
        # no-linger on, and timeout 0, plus close, sends a reset
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        s.close()
    except socket.error:
        pass


def sock_eof(s):
    try:
        s.shutdown(socket.SHUT_WR)
    except socket.error:
        pass #other end may have aborted already

def sock_nonagle(s):
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)

def is_ipv4(s):
    """
    Check if a string matches an ipv4 address
    """
    return re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", s) is not None

def n2toi(b):
    "convert two bytes in nbo to int"
    return struct.unpack("!H", b)[0]

def iton2(i):
    return struct.pack("!u", i)

def n2toi(b):
    "convert four bytes in nbo to int"
    return struct.unpack("!I", b)[0]

def i_to_ipv4(i):
    buf = struct.pack("!I", i)
    return "%d.%d.%d.%d" % tuple(ord(b) for b in buf)

def n4_to_ipv4(s):
    "convert four bytes of IP in nbo to string"
    return "%d.%d.%d.%d" % tuple(ord(b) for b in s)

def ipv4_to_i(ip):
    "convert ipv4 string to native integer"
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError()
    b = "".join(chr(int(p)) for p in parts)
    return struct.unpack("!I", b)[0]


class StdSocketFactory(object):
    """
    Socket factory for standard sockets
    """
    def __call__(self, addr=None):
        return socket.socket()

class SendBuffer(object):
    """
    use this to coalesce multiple writes
    """
    def __init__(self, socket):
        self.socket = socket
        self.buf = StringIO()

    def send(self, d):
        self.buf.write(d)
        return len(d)

    def sendall(self, d):
        self.buf.write(d)

    def flush(self):
        self.socket.sendall(self.buf.getvalue())
        self.buf.close()
        self.buf = StringIO()


class RecvBuffer(object):
    '''
    Use this to speed up required reads of minimum length
    instead of piping them to the socket directly
    '''
    def __init__(self, socket, chunksize=1024*1024):
        self.socket = socket
        self.io = deque()
        self.length = 0
        self.chunksize = chunksize

    def getpeername(self):
        """convenience function to mirror socket"""
        return self.socket.getpeername()

    def __len__(self):
        return self.length

    def is_empty(self):
        return self.length == 0

    def peekn(self, n, raise_eof=True):
        r = self.recvn(n, raise_eof)
        self.unrecv(r)
        return r

    def recvn(self, n, raise_eof=True):
        bits = []
        remaining = n
        try:
            while remaining > 0:
                if not self.io:
                    if not self._fill():
                        break
                read = self.io[0].read(remaining)
                if not read:
                    self.io.popleft()
                    continue
                bits.append(read)
                remaining -= len(read)
            stuff = ''.join(bits)
            if remaining > 0:
                # couldn"t fill request, return null
                self.unrecv(stuff)
                stuff = ""
            if not stuff and raise_eof:
                raise EOFError()
            self.length -= len(stuff)
            return stuff
        except Exception:
            # place what we read back onto the left
            self.unrecv(''.join(bits))
            raise

    def recvstr0(self):
        '''receive a null terminated string'''
        bits = []
        try:
            while True:
                r = self.recvn(1, True)
                if r == '\0':
                    break
                bits.append(r)
            return "".join(bits)
        except Exception:
            self.unrecv(''.join(bits))
            raise

    def recvstrn(self):
        """ receive a string with an initial length byte"""
        n = ord(self.recvn(1))
        if not n:
            return ''
        try:
            return self.recvn(n)
        except Exception:
            self.unrecv(n)
            raise


    def remainder(self):
        rest = "".join(buf.read() for buf in self.io)
        self.io.clear()
        return rest

    def unrecv(self, data):
        """
        return previously read data back to the input
        """
        if data:
            self.io.appendleft(StringIO(data))
            self.length += len(data)

    def unrecvstr0(self, data):
        self.unread(data+"\0")

    def unrecvstrn(self, data):
        self.unread(chr(len(data)) + data)

    def _fill(self):
        read = self.socket.recv(self.chunksize)
        if read:
            self.length += len(read)
            self.io.append(StringIO(read))
            return True

