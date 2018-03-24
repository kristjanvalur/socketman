
#socketserver

"""
A simple alternative to the over-engineered one in the stdlib
"""

import socket
import logging
import threading
from contextlib import closing

from . import tools
from .tools import released

logger = logging.getLogger(__name__)



class Server(object):
    def __init__(self, in_factory, in_addr, handler):
        self.in_factory = in_factory or tools.StdSocketFactory()
        self.in_addr = in_addr
        self.handler = handler
        self.count = 0

    def run(self):
        s = self.in_factory(self.in_addr)

        # todo, deal with address conflicts here, by offering a timeout
        s.bind(self.in_addr)
        s.listen(5)
        # todo, might want to restart this if socket errors, because a listen
        # socket may become stale and need re-creating.
        try:
            self._run(s)
        finally:
            s.close()

    def _run(self, s):
        logger.info("Listening on %r", s.getsockname())
        while True:
            a, _ = s.accept()
            logger.info("Incoming Connection %.3d from %r", self.count, a.getpeername() )
            self.handle_accept(a)

    def handle_accept(self, a):
            t = threading.Thread(target=self._handle_accept, args=(self.count, a))
            self.count += 1
            try:
                t.start()
            except:
                a.close()
                raise

    # handle accepted connection on a thread
    def _handle_accept(self, ident, a):
        try:
            self.handler(a)
        except:
            logger.exception("trouble in handler")


class Tunnel(object):
    """
    A tunnel object that pipes data full-duplex between two sockets using threads.
    """
    chunksize = 1024*1024
    #chunksize = 100*1024
    def __init__(self, a, b, initial_a="", initial_b="", ident=None):
        """
        By convention, a is the accept socket.  transfer to it is called "up", other dir is "down"
        """
        self.lock = threading.Lock()
        self.ident = ident if ident else id(self)
        self.sock = [a, b]
        self.initial = [initial_a, initial_b]
        self.total = [0, 0]
        self.workers = 2
        tools.sock_nonagle(a)
        tools.sock_nonagle(b)
        a.settimeout(1.0)
        b.settimeout(1.0)


    def abort(self):
        socks, self.sock = self.sock, (None, None)
        for s in socks:
            if s:
                tools.sock_abort(s)
                s.close()

    def close(self):
        socks, self.sock = self.sock, (None, None)
        for s in socks:
            if s:
                s.close()

    def run(self):
        """
        run the tunnel.  First, start a thread
        """
        thread = threading.Thread(target=self.worker, args=(0,))
        logger.info("Tunnel connection %r starting", self.ident)
        try:
            thread.start()
        except Exception:
            self.abort()
            raise
        self.worker(1)

    def _worker(self, parity):
        try:
            self.worker(parity)
        except Exception:
            logtun.exception("problem in tunnel %d", parity)

    def worker(self, parity):
        # parity 0 reads from a, writes to b and vice versa
        with self.lock:
            try:
                self.process(parity)
            finally:
                self.workers -= 1
                if not self.workers:
                    if self.sock != (None, None):
                        logger.info("Tunnel connection %r closing cleanly after up:%d down:%d bytes" ,self.ident, self.total[0], self.total[1])
                    else:
                        logger.info("Tunnel connection %r closing abortively after up:%d down:%d bytes", self.ident, self.total[0], self.total[1])
                    self.close()

    def process(self, parity):
        r = parity
        w = not parity
        while True:
            # is initial data?
            s = self.initial[w]
            if s:
                self.initial[w] = ""
            else:
                # read from source
                s = self.sock[r]
            if not s:
                return
            try:
                cs = self.chunksize
                with released(self.lock):
                    data = s.recv(cs)
                #logger.debug("innerrecv %r, %r, %r, %r", s, cs, len(data), data[:200])
            except socket.timeout:
                continue
            except socket.error:
                self.abort()
                return

            # write to dest
            s = self.sock[w]
            if not s:
                return
            if not data:
                # eof
                with released(self.lock):
                    tools.sock_eof(s)
                return

            while data:
                try:
                    dd = data
                    with released(self.lock):
                        sent = s.send(dd)
                        #logger.debug("innersend %r, %r %r %r %r", s, len(data), len(dd), sent, dd[:min(200,sent)])
                except socket.timeout:
                    continue
                except socket.error:
                    self.abort()
                    return
                self.total[w] += sent
                data = data[sent:]

class ConnectHandler(object):
    """
    Socks handler.  We know socks4a at this moment, not socks5
    """
    logger = logging.getLogger(__name__ + '.ConnectHandler')
    def __init__(self, address, factory=None):
        self.address = address
        self.factory = factory or tools.StdSocketFactory()

    def __call__(self, incoming):
        with closing(incoming):
            outgoing = self.factory(self.address)
            with closing(outgoing):
                try:
                    outgoing.connect(self.address)
                except socket.error():
                    self.logger.info('failed to connect to %r', self.address)
                    tools.sock_abort(incoming)
                    return
                tunnel = Tunnel(outgoing, incoming, ident=incoming.getpeername())
                tunnel.run()
