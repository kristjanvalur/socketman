# coding: utf8
# test socket proxy
import argparse
import sys
import logging

from . import socketserver, tools, socks

logger = logging.getLogger("socketman.server")

def parse_addr(a, default_port=None):
	s = a.split(":", 1) if a else ()
	if len(s) == 0:
		s = ('',)
	if len(s) == 1:
		if default_port is None:
			raise ValueError("no port")
		s = '', default_port
	return s[0], int(s[1])

def run_tunnel(bind_addr, dest_addr):
	logger.info("starting tunnel from %r to %r", bind_addr, dest_addr)

	handler = socketserver.ConnectHandler(dest_addr)
	server = socketserver.Server(None, bind_addr, handler)
	server.run()

def run_socks(bind_addr):
	logger.info("starting socks at %r", bind_addr)
	handler = socks.SocksHandler()
	server = socketserver.Server(None, bind_addr, handler)
	server.run()

def setup_logging(level):
	if not level:
		level = logging.INFO
	else:
		level = level.upper()
	logging.basicConfig(level=level)
	logging.getLogger('requests').setLevel(logging.WARN)

def main():
	parser = argparse.ArgumentParser(description='sockets tunnel code')
	parser.add_argument('mode', choices=['tunnel', 'socks'])
	parser.add_argument('-b', '--bind', help='listen address')
	parser.add_argument('-c', '--connect', help='connect address')
	parser.add_argument('-l', '--loglevel')
	args = parser.parse_args()
	setup_logging(args.loglevel)
	if args.mode == "tunnel":
		if not args.bind:
			parser.error("the 'tunnel' mode requires a --bind argument")
		if not args.connect:
			parser.error("the 'tunnel' mode requires a --connect argument")

		source = parse_addr(args.bind)
		dest = parse_addr(args.connect)
		run_tunnel(source, dest)
	else:
		source = parse_addr(args.bind, socks.SOCKS_PORT)
		run_socks(source)




if __name__ == '__main__':
	main()
