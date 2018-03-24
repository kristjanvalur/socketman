# coding: utf8
# test socket proxy

import sys
import argparse
import socket
import threading
import struct
import contextlib
import logging
import random

import sores

logger = logging.getLogger(__name__)

@contextlib.contextmanager
def released(lock):
	lock.release()
	try:
		yield
	finally:
		lock.acquire()

def sock_abort(s):
	s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 0, 0))
	s.shutdown(socket.SHUT_RDWR)
	s.close()



class SocketSocketFactory(object):
	def __call__(self):
		return socket.socket()

class SoresSocketFactory(object):
	def __init__(self, api, address=''):
		self.client = sores.SoresClient(api)
		self.address = address

	def __call__(self):
		return sores.Socket(self.client, address=self.address)



class Tunnel(object):
	chunksize = 1024*1024
	#chunksize = 100*1024
	def __init__(self, id, a, b):
		self.lock = threading.Lock()
		self.id = id
		self.sock = [a, b]
		self.workers = 2
		a.settimeout(1.0)
		b.settimeout(1.0)


	def abort(self):
		socks, self.sock = self.sock, (None, None)
		for s in socks:
			if s:
				sock_abort(s)

	def close(self):
		socks, self.sock = self.sock, (None, None)
		for s in socks:
			if s:
				s.close()

	def sock_halfclose(self, s):
		if s:
			with released(self.lock):
				s.shutdown(socket.SHUT_WR)

	def worker(self, parity):
		with self.lock:
			try:
				self.process(parity)
			finally:
				self.workers -= 1
				if not self.workers:
					if self.sock != (None, None):
						print "Connection %.3d closing cleanly\n" % (self.id,),
					else:
						print "Connection %.3d closing abortively\n" % (self.id,),
					socks = self.sock
					self.sock = None
					for s in socks:
						if s:
							s.close()

	def process(self, parity):
		r = parity
		w = not parity
		while True:

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
				self.sock_halfclose(s)
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
				data = data[sent:]


class Proxy(object):

	def __init__(self, in_factory, in_addr, out_factory, out_addr):
		self.in_factory = in_factory
		self.in_addr = in_addr
		self.out_factory = out_factory
		self.out_addr = out_addr

	def run(self):
		s = in_factory()
		s.bind(self.in_addr)
		s.listen(5)
		i = 0
		logger.info("Listening on %r", s.getsockname())
		while True:
			a, addr = s.accept()
			logger.info("Incoming Connection %.3d from %r", i, addr )
			t = threading.Thread(target=self.handle_accept, args=(i, a))
			i += 1
			try:
				t.start()
			except:
				a.close()
				raise

	# handle accepted connection on a thread
	def handle_accept(self, id, a):
		s = None
		try:
			s = self.out_factory()
			logger.info("Outgoing Connection %.3d connecting to %r\n", id, out_addr)
			try:
				s.connect(out_addr)
			except socket.error as e:
				logger.warning("Outgoing Connection %.3d failed to connect: %r", id, e)
				sock_abort(a)
				s.close()
				return

			tunnel = Tunnel(id, a, s)
			t = threading.Thread(target=tunnel.worker, args=(0,))
			t.start()
		except:
			a.close()
			if s:
				s.close()
			raise
		tunnel.worker(1)


if __name__ == "__main__":
	logging.basicConfig(level=logging.DEBUG)
	logging.getLogger('requests').setLevel(logging.WARN)

	addr = sys.argv[1]
	if sys.argv[2] == "b":
		in_factory = SoresSocketFactory("http://127.0.0.1:8000/sores/default/api/", sys.argv[1])
		out_factory = SocketSocketFactory()
		in_addr = (None, 8010)
		out_addr = ("www.vedur.is", 80)
		p = Proxy(in_factory, in_addr, out_factory, out_addr)
	else:
		in_factory = SocketSocketFactory()
		out_factory = SoresSocketFactory("http://127.0.0.1:8000/sores/default/api/", sys.argv[1])
		in_addr = ("", 8010)
		out_addr = (sys.argv[1], 8010)

	p = Proxy(in_factory, in_addr, out_factory, out_addr)
	p.run()

