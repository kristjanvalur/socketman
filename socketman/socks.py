#
# sockst
# define a Socks type proxy
#
import logging
import socket
import struct
import errno
from contextlib import closing

from . import tools
from . import socketserver

SOCKS_PORT = 1080 # well known socks port

CMD_CONNECT = 01
CMD_BIND    = 02
CMD_UDP     = 03

REQ_GRANTED = 0x5A
REQ_REJECTED = 0x5B
REQ_NOIDENT = 0x5C
REQ_BADID   = 0x5D

# address types for socks5
ATYPE_IPV4 = 0x01
ATYPE_DNS  = 0x03
ATYPE_IPV6 = 0x04

# authentication types for socks5
AUTH_NOAUTH = 0x00
AUTH_GSSAPI = 0x01
AUTH_UPASS = 0x02
AUTH_NONE = 0xff #nothing selected

# Socks4 status
S5S_GRANTED = 0x00      # request granted
S5S_FAILURE = 0x01      # general failure
S5S_NOTALLOWED = 0x02   # connection not allowed by ruleset
S5S_NONET = 0x03        # network unreachable
S5S_NOHOST = 0x04       # host unreachable
S5S_CONNREFUSED = 0x05  # connection refused by destination host
S5S_TTLEXP = 0x06       # TTL expired
S5S_NOCMD = 0x07        # command not supported / protocol error
S5S_NOADDR = 0x08       # address type not supported

logger = logging.getLogger("socketman.socks")


# socks 4 handshake functions.
def socks4_send_request(sock, cmd, address, uid=""):
    """
    Send a socks4 request
    """
    ip, port = address
    try:
        iip = tools.ipv4_to_i(ip)
        dns = None
    except ValueError:
        iip = 1
        dns = ip

    r = struct.pack("!BBHI", 4, cmd, port, iip)
    r += uid + "\0";
    if dns is not None:
        r += dns + "\0";
    logger.debug("SOCKS4 sending request to %r: %r, %r, %r", sock.getpeername(), cmd, address, uid)
    sock.sendall(r)

def socks4_recv_request(buf):
    """
    Read the SOCS 4 or 4A header.  Raises EOFError
    """
    chunk = buf.recvn(8)
    version, cmd, port, ip = struct.unpack("!BBHI", chunk)

    if ip > 0 and ip < 256:
        # version 4a"
        ip = None
    else:
        ip = tools.i_to_ipv4(ip)
    # early validation
    if version != 4 or cmd not in (CMD_CONNECT,):
        uid = ''
    else:
        uid = buf.recvstr0()
        if ip is None:
            ip = buf.recvstr0()
    r = {"version" : version, "cmd" : cmd, "address" : (ip, port), "uid" : uid}
    logger.debug("SOCKS4 received request from %r: %r", buf.getpeername(), r)
    return r

def socks4_send_response(sock, status, addr=None):
    ip, port = addr if addr else ("", 0)
    if ip:
        iip = tools.ipv4_to_i(ip)
    else:
        iip = 0
    resp = struct.pack("!BBHI", 0, status, port, iip)
    logger.debug("SOCKS4 sending response to %r: %x (%s:%d)", sock.getpeername(), status, ip, port);
    sock.sendall(resp)

def socks4_recv_response(buf):
    resp = buf.recvn(8)
    null, status, port, ip = struct.unpack("!BBHI", resp)
    ip = tools.i_to_ipv4(ip)
    address = (ip, port)
    if null == 0 and status == REQ_GRANTED:
        logger.debug("SOCKS4 request accepted from %r: %r", buf.getpeername(), address)
        return address
    if null != 0:
        logger.warning("SOCKS4 invalid response from %r: %r", buf.peername(), resp)
    else:
        logger.warning("SOCKS4 request rejected from %r: status %x", buf.peername(), status)
    return Null


def socks4_connect(sock, addr):
    """
    Given a fresh connection to a socks server, establish the forwarding connection
    """
    # can result in ECONNREFUSED, ECONNRESET, ECONNABORTED
    socks4_send_request(sock, CMD_CONNECT, addr)
    buf = tools.RecvBuffer(sock)
    return socks4_recv_response(buf), buf.remainder()


# socks 5 support.  Greeting and stuff.  Server side
def socks5_send_greeting_request(sock):
    """
    Send original client greeting with auth requests.
    """
    # no auth methods provided
    sock.sendall(struct.pack("!BB", 5, 0))

def socks5_recv_greeting_request(buf):
    resp1 = buf.recvn(1)
    ver = struct.unpack('!B', resp1)[0]
    if ver != 5:
        auth = []
    else:
        resp2 = buf.recvstrn()
        auth = [ord(c) for c in resp2]
    result = {"version" : ver, "auth" : []}
    logger.debug('SOCKS5 recv greeting %r', result)
    return result

def socks5_send_greeting_resp(s, meth):
    s.sendall(struct.pack("!BB", 5, meth))

def socks5_recv_greeting_resp(buf):
    resp = buf.recvn(2)
    ver, meth = struct.unpack("!BB", resp)
    if ver != 5:
        meth = AUTH_NONE
    result = {"version" : ver, "auth" : meth}
    logger.debug("SOCKS5 recv greeting resp: %r", result)
    return result

def socks5_send_conn_request(sock, cmd, address):
    atype, achunk = socks5_encode_addr(address)
    chunk = struct.pack('!BBBB', 5, cmd, 0, atype) + achunk
    sock.sendall(chunk)

def socks5_recv_conn_request(buf):
    resp1 = buf.recvn(4)
    ver, cmd, zero, atype = struct.unpack("!BBBB", resp1)
    if ver == 5 and zero == 0 and atype in (ATYPE_IPV4, ATYPE_DNS, ATYPE_IPV6):
        address = socks5_decode_addr(buf, atype)
    else:
        ver = 0
        address = "", 0
    req = {"version" : ver, "cmd" : cmd, "atype" : atype, "address" : address}
    logger.debug("SOCKS5 recv conn req: %r", req)
    return req

def socks5_send_conn_response(s, status, address=None):
    if address is None:
        address = ('', 0)
    atype, achunk = socks5_encode_addr(address)
    chunk = struct.pack("!BBBB", 5, status, 0, atype) + achunk
    s.sendall(chunk)

def socks5_recv_conn_response(buf):
    resp = buf.recvn(4)
    ver, status, null, atype = struct.unpack("!BBBB", resp)
    if ver != 5 or null != 0:
        status = S5S_NOCMD
        addr = ('', 0)
    else:
        address = socks5_decode_addr(buf, atype)
    result = {"version" : ver, "status" : status, "address" : address}
    logger.debug("SOCKS5 recv conn resp: %r", result)
    return result

def socks5_encode_addr(address):
    addr, port = address
    if tools.is_ipv4(addr):
        atype = ATYPE_IPV4
    else:
        atype = ATYPE_DNS
    if atype == ATYPE_IPV4:
        chunk = struct.pack("!I", tools.ipv4_to_i(addr))
    elif atype == ATYPE_DNS:
        chunk = struct.pack("!B", len(addr)) + addr
    else:
        a = (addr + "\0" * 16)[:16]
        chunk += a
    chunk += struct.pack("!H", port)
    return atype, chunk

def socks5_decode_addr(buf, atype):
    if atype == ATYPE_IPV4:
        addr, port = struct.unpack("!IH", buf.recvn(6))
        addr = tools.i_to_ipv4(addr)
    elif atype == ATYPE_DNS:
        addr = buf.recvstrn()
        port = struct.unpack("!H", buf.recvn(2))[0]
    elif atype == ATYPE_IPV6:
        addr = buf.recvn(16)
        port = struct.unpack("!H", buf.recvn(2))[0]
    else:
        logger.warning("SOCKS5 got unsupported atype %r", atype)
        addr, port = '', 0
    return addr, port

def socks5_connect(sock, address):
    o = tools.SendBuffer(sock)

    # send both greeting and connection request in one go
    socks5_send_greeting_request(o)
    socks5_send_conn_request(o, CMD_CONNECT, address)
    o.flush()
    buf = tools.RecvBuffer(sock)
    resp1 = socks5_recv_greeting_resp(buf)
    if resp1["auth"] != AUTH_NOAUTH:
        logger.warning("socks5 no authorization for %r", sock.getpeername())
        return None
    resp2 = socks5_recv_conn_response(buf)
    if resp2['status'] == S5S_GRANTED:
        return resp2['address'], buf.remainder()
    else:
        logger.warning("socks5 connection refused with 0x%x", resp2['status'])



class SocksHandler(object):
    """
    Socks handler.  We know socks4a at this moment, not socks5
    """
    def __init__(self, factory=None):
        self.factory = factory or tools.StdSocketFactory()

    def __call__(self, incoming):
        buf = tools.RecvBuffer(incoming)
        outgoing = None
        try:
            outgoing = self.handshake(buf, incoming)
        except (EOFError, socket.error) as e:
            logger.debug("handshake aborted by peer: %r", e, exc_info=True)
        if not outgoing:
            incoming.close()
            return

        # create tunnel
        initial_cargo = buf.remainder()
        tunnel = socketserver.Tunnel(outgoing, incoming, initial_cargo, "", ident=incoming.getpeername())
        tunnel.run()

    def handshake(self, r, w):
        version = ord(r.peekn(1))
        if version not in (4, 5):
            logger.warning("rejecting invalid version %r", s4r["version"])
            w.close()
            return
        if version == 4:
            return self.handshake4(r, w)
        else:
            return self.handshake5(r, w)

    def handshake4(self, r, w):
        """
        Perform the socks handshake
        """
        s4r = socks4_recv_request(r)
        if s4r['version'] != 4:
            logger.warning("SOCKS4 rejecting invalid version %r", s4r["version"])
            return
        if s4r['cmd'] != CMD_CONNECT:
            logger.warning("SOCKS4 rejecting unsupported command %r", s4r["cmd"])
            socks4_send_response(w, REQ_REJECTED)
            return
        addr = s4r['address']
        outgoing = self.factory(addr)
        try:
            logger.debug("SOCKS4 connecting to %r", addr)
            outgoing.connect(addr)
        except socket.error:
            logger.warning("SOCKS4 outgoing connection to %r failed", addr)
            outgoing.close()
            try:
                socks4_send_response(w, REQ_REJECTED)
            except socket.error:
                pass
            return
        try:
            socks4_send_response(w, REQ_GRANTED, outgoing.getpeername())
        except socket.error:
            tools.sock_abort(outgoing)
            raise
        logger.info("SOCKS4 connection from %r to %r established", r.getpeername(), outgoing.getpeername())
        return outgoing

    def handshake5(self, r, w):
        # create an output buffer to help streamline double response i
        o = tools.SendBuffer(w)
        req = socks5_recv_greeting_request(r)
        if req['version'] != 5:
            logger.warning("SOCKS5 rejecting invalid version %r", req["version"])
            return
        # only support no-auth for now
        if req['auth'] and AUTH_NOAUTH not in req['auth']:
            socks5_send_greeting_resp(o, AUTH_NONE)
            logger.warning("SOCKS5 authentication methods %r not supported", req["auth"])
            return
        socks5_send_greeting_resp(o, AUTH_NOAUTH)

        # now, if there is incoming data, we just continue, otherwise we have to flush
        if r.is_empty():
            o.flush()

        req = socks5_recv_conn_request(r)
        if req['version'] != 5:
            logger.warning("SOCKS5 rejecting invalid version %r", req["version"])
            return
        if req['cmd'] != CMD_CONNECT:
            logger.warning("SOCKS5 rejecting unsupported command %r", req["cmd"])
            socks5_send_conn_response(o, S5S_NOCMD)
            o.flush()
            return
        if req['atype'] not in (ATYPE_IPV4, ATYPE_DNS):
            logger.warning("SOCKS5 rejecting unsupported atype %r", req["atype"])
            socks5_send_conn_response(o, S5S_NOADDR)
            o.flush()
            return

        # ok, try to establish connection
        addr = req['address']
        outgoing = self.factory(addr)
        try:
            logger.debug("SOCKS5 connecting to %r", addr)
            outgoing.connect(addr)
        except socket.error as e:
            logger.warning("SOCKS5 outgoing connection to %r failed with %r", addr, e)
            outgoing.close()
            try:
                if e.errno == errno.ECONNREFUSED:
                    resp = S5S_CONNREFUSED
                elif e.errno == errno.ENETUNREACH:
                    resp = S5S_NONET
                elif e.errno == errno.EHOSTUNREACH:
                    resp = S5S_NOHOST
                else:
                    resp = S5S_FAILURE
                socks5_send_conn_response(o, resp)
                o.flush()
            except socket.error:
                pass
            return
        addr = outgoing.getpeername()
        try:
            socks5_send_conn_response(o, S5S_GRANTED, addr)
            o.flush()
        except socket.error:
            tools.sock_abort(outgoing)
            raise
        logger.info("SOCKS5 connection from %r to %r established", r.getpeername(), outgoing.getpeername())
        return outgoing



class SocksWrapper(object):
    '''
    This wraps a socket into a socks connection.  The inner socket
    is the connection to the socks server, the outer represents
    the connection through it.
    '''
    def __init__(self, inner, socks_addr):
        self.inner = inner
        self.socks_addr = socks_addr
        self._peername = None
        self.remainder = None

    def __repr__(self):
        return "<%s through %r using %r>" % (type(self).__name__, self.socks_addr, self.inner)

    def getpeername(self):
        if self._peername is None:
            raise socket.error(errno.ENOTCONN, 'not connected')
        return self._peername

    def connect(self, address):
        # first, connect inner socket to the socks server
        self.inner.connect(self.socks_addr)
        # then perform the socks handshake
        try:
            addr, remainder = self._socks_connect(self.inner, address)
        except socket.error as e:
            if isinstance(e, socket.timeout):
                raise
            raise socket.error(errno.ECONNREFUSED, 'socks handshake failed')
        if not addr:
            raise socket.error(errno.ECONNREFUSED, 'socks connection rejected')
        self.remainder = tools.RecvBuffer(remainder) if remainder else None
        self._peername = addr

    def recv(self, n):
        '''
        read first from the incoming remainder from the handshake, then directly frmo the
        inner socket
        '''
        if self.remainder:
            r = self.remainder.recv(n)
            if r or n == 0:
                return r
            self.remainder = None
        return self.inner.recv(n)

    def __getattr__(self, attr):
        '''
        delegate all operations to the wrapped socket
        '''
        # can optimize by storing the attribute on the object.
        return getattr(self.inner, attr)

class Socks4Wrapper(SocksWrapper):
    def _socks_connect(self, sock, address):
        return socks4_connect(sock, address)

class Socks5Wrapper(SocksWrapper):
    def _socks_connect(self, sock, address):
        return socks5_connect(sock, address)


class SocksSocketFactory(object):
    '''
    A factory that returns a a socks connection over an inner connection connected to a socks_address
    '''
    def __init__(self, socks_address, inner_factory=None):
        self.socks_address = socks_address
        self.inner_factory = inner_factory or tools.StdSocketFactory()

    def __call__(self, address=None):
        inner = self.inner_factory(self.socks_address)
        return self._wrapperclass(inner, self.socks_address)

class Socks4SocketFactory(SocksSocketFactory):
    _wrapperclass = Socks4Wrapper


class Socks5SocketFactory(SocksSocketFactory):
    _wrapperclass = Socks5Wrapper


def main():
    in_factory = out_factory = tools.StdSocketFactory()
    handler = SocksHandler(out_factory)
    server = socketserver.SocketServer(in_factory, ("", SOCKS_PORT), handler)
    server.run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
