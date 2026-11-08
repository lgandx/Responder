#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import queue
import threading
import time

try:
	from socketserver import TCPServer, ThreadingMixIn
except ImportError:
	from SocketServer import TCPServer, ThreadingMixIn


class DropCounter:
	"""Count dropped requests and print a summary at most every interval."""

	def __init__(self, label, interval=10.0):
		self.label = label
		self.interval = interval
		self._dropped = 0
		self.total = 0
		self._last_report = 0.0
		self._lock = threading.Lock()

	def record(self):
		now = time.monotonic()
		with self._lock:
			self._dropped += 1
			self.total += 1
			if now - self._last_report < self.interval:
				return
			dropped = self._dropped
			self._dropped = 0
			self._last_report = now
		print('[*] %s: dropped %d requests because the handler pool is busy' % (self.label, dropped))


class BoundedThreadingUDPMixIn(ThreadingMixIn):
	"""Fixed UDP worker pool fed by a bounded queue.

	ThreadingMixIn starts a new thread for every datagram. A flood can then
	exhaust the process thread limit, after which every listener in the
	process fails to start handlers. This mixin starts a small pool once and
	queues datagrams for it; when the queue is full, new datagrams are
	dropped and counted instead of spawning more threads.
	"""

	worker_threads = 8
	max_pending_requests = 512

	def __init__(self, *args, **kwargs):
		self._request_queue = queue.Queue(maxsize=self.max_pending_requests)
		self._workers = []
		self._workers_lock = threading.Lock()
		self._shutdown = threading.Event()
		self._drops = DropCounter(self.__class__.__name__)
		super().__init__(*args, **kwargs)

	def should_drop_request(self, request, client_address):
		"""Override to filter cheaply before a datagram is queued."""
		return False

	def process_request(self, request, client_address):
		if self.should_drop_request(request, client_address):
			self.shutdown_request(request)
			return

		self._ensure_workers()
		try:
			self._request_queue.put_nowait((request, client_address))
		except queue.Full:
			self._drops.record()
			self.shutdown_request(request)

	def _ensure_workers(self):
		if self._workers:
			return
		with self._workers_lock:
			if self._workers:
				return
			for _ in range(self.worker_threads):
				worker = threading.Thread(target=self._worker_loop, name='responder-udp-worker')
				worker.daemon = True
				worker.start()
				self._workers.append(worker)

	def _worker_loop(self):
		while not self._shutdown.is_set():
			try:
				item = self._request_queue.get(timeout=0.5)
			except queue.Empty:
				continue
			if item is None:
				break
			request, client_address = item
			try:
				self.process_request_thread(request, client_address)
			except Exception:
				self.handle_error(request, client_address)
			finally:
				self._request_queue.task_done()

	def server_close(self):
		# ThreadingMixIn.server_close() joins self._threads, which is only
		# populated by its own process_request(). This mixin never uses it.
		self._shutdown.set()
		with self._workers_lock:
			workers, self._workers = self._workers, []
		for _ in workers:
			try:
				self._request_queue.put_nowait(None)
			except queue.Full:
				pass
		for worker in workers:
			worker.join(timeout=1.0)
		TCPServer.server_close(self)


class BoundedThreadingTCPMixIn(ThreadingMixIn):
	"""ThreadingMixIn with a cap on concurrent handler threads.

	Starting a thread per connection is fine until the process thread limit
	is reached; at that point start() raises RuntimeError and socketserver
	prints a traceback for every new connection. Refuse connections past the
	cap and treat a failed thread start as a dropped connection.
	"""

	max_concurrent_requests = 128

	def __init__(self, *args, **kwargs):
		self._request_slots = threading.BoundedSemaphore(self.max_concurrent_requests)
		self._drops = DropCounter(self.__class__.__name__)
		super().__init__(*args, **kwargs)

	def process_request(self, request, client_address):
		if not self._request_slots.acquire(blocking=False):
			self._drops.record()
			self.shutdown_request(request)
			return
		try:
			thread = threading.Thread(
				target=self.process_request_thread,
				args=(request, client_address),
			)
			thread.daemon = self.daemon_threads
			thread.start()
		except RuntimeError:
			self._request_slots.release()
			self._drops.record()
			self.shutdown_request(request)
		except Exception:
			self._request_slots.release()
			self.shutdown_request(request)
			raise

	def process_request_thread(self, request, client_address):
		try:
			super().process_request_thread(request, client_address)
		finally:
			self._request_slots.release()

	def server_close(self):
		# See BoundedThreadingUDPMixIn.server_close(); _threads is unused.
		TCPServer.server_close(self)
