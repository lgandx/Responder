import os
import socketserver
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from servers.bounded import BoundedThreadingTCPMixIn
from servers.bounded import BoundedThreadingUDPMixIn


class _UDPHandler(socketserver.BaseRequestHandler):
	handled = []
	started = threading.Event()
	release = threading.Event()

	def handle(self):
		data, _ = self.request
		type(self).handled.append(data)
		type(self).started.set()
		type(self).release.wait(2.0)


class _UDPServer(BoundedThreadingUDPMixIn, socketserver.UDPServer):
	pass


class _SmallUDPServer(BoundedThreadingUDPMixIn, socketserver.UDPServer):
	worker_threads = 1
	max_pending_requests = 1


class _FilteredUDPServer(BoundedThreadingUDPMixIn, socketserver.UDPServer):
	def should_drop_request(self, request, client_address):
		data, _ = request
		return data == b'drop'


class _TCPHandler(socketserver.BaseRequestHandler):
	def handle(self):
		pass


class _TCPServer(BoundedThreadingTCPMixIn, socketserver.TCPServer):
	allow_reuse_address = True
	max_concurrent_requests = 1


class _FakeSocket:
	def __init__(self):
		self.shutdown_called = False
		self.closed = False

	def shutdown(self, how):
		self.shutdown_called = True

	def close(self):
		self.closed = True


class BoundedUDPMixInTest(unittest.TestCase):
	def setUp(self):
		_UDPHandler.handled = []
		_UDPHandler.started = threading.Event()
		_UDPHandler.release = threading.Event()

	def tearDown(self):
		_UDPHandler.release.set()

	def test_worker_pool_handles_datagrams(self):
		server = _UDPServer(('127.0.0.1', 0), _UDPHandler)
		self.addCleanup(server.server_close)
		server.process_request((b'first', server.socket), ('127.0.0.1', 1000))
		self.assertTrue(_UDPHandler.started.wait(2.0))
		self.assertEqual(_UDPHandler.handled, [b'first'])

	def test_full_queue_drops_instead_of_spawning_threads(self):
		server = _SmallUDPServer(('127.0.0.1', 0), _UDPHandler)
		self.addCleanup(server.server_close)
		server.process_request((b'first', server.socket), ('127.0.0.1', 1000))
		self.assertTrue(_UDPHandler.started.wait(2.0))
		server.process_request((b'second', server.socket), ('127.0.0.1', 1001))
		server.process_request((b'third', server.socket), ('127.0.0.1', 1002))
		self.assertEqual(server._drops.total, 1)
		_UDPHandler.release.set()
		self._wait_until(lambda: len(_UDPHandler.handled) == 2)
		self.assertEqual(_UDPHandler.handled, [b'first', b'second'])

	def test_should_drop_request_hook_filters_before_queueing(self):
		server = _FilteredUDPServer(('127.0.0.1', 0), _UDPHandler)
		self.addCleanup(server.server_close)
		server.process_request((b'drop', server.socket), ('127.0.0.1', 1000))
		self.assertEqual(_UDPHandler.handled, [])
		self.assertEqual(server._request_queue.qsize(), 0)

	@staticmethod
	def _wait_until(predicate, timeout=2.0):
		step = 0.01
		waited = 0.0
		while not predicate() and waited < timeout:
			time.sleep(step)
			waited += step
		return predicate()


class BoundedTCPMixInTest(unittest.TestCase):
	def test_refuses_connection_when_cap_is_reached(self):
		server = _TCPServer(('127.0.0.1', 0), _TCPHandler)
		self.addCleanup(server.server_close)
		self.assertTrue(server._request_slots.acquire(blocking=False))
		request = _FakeSocket()
		server.process_request(request, ('127.0.0.1', 1000))
		self.assertTrue(request.shutdown_called)
		self.assertTrue(request.closed)
		self.assertEqual(server._drops.total, 1)
		server._request_slots.release()

	def test_runtime_error_on_thread_start_drops_connection(self):
		server = _TCPServer(('127.0.0.1', 0), _TCPHandler)
		self.addCleanup(server.server_close)
		request = _FakeSocket()
		with mock.patch.object(threading.Thread, 'start', side_effect=RuntimeError("can't start new thread")):
			server.process_request(request, ('127.0.0.1', 1000))
		self.assertTrue(request.shutdown_called)
		self.assertTrue(request.closed)
		self.assertEqual(server._drops.total, 1)
		# The slot must be released again, or every later connection is refused.
		self.assertTrue(server._request_slots.acquire(blocking=False))
		server._request_slots.release()


if __name__ == '__main__':
	unittest.main()
