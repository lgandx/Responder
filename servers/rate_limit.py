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
import threading
import time


class RateLimiter:
	"""Allow one event per key per window.

	Keys are pruned once their window has passed, and the map is capped, so
	a spoofed-source flood cannot grow it without bound.
	"""

	def __init__(self, window=1.0, max_keys=8192):
		self.window = window
		self.max_keys = max_keys
		self._lock = threading.Lock()
		self._last_seen = {}
		self._last_prune = 0.0

	def allow(self, key, now=None):
		if now is None:
			now = time.monotonic()
		with self._lock:
			self._prune(now)
			last = self._last_seen.get(key)
			if last is not None:
				if now - last < self.window:
					return False
				self._last_seen[key] = now
				return True
			if len(self._last_seen) >= self.max_keys:
				return False
			self._last_seen[key] = now
			return True

	def _prune(self, now):
		if now - self._last_prune < self.window:
			return
		self._last_prune = now
		cutoff = now - self.window
		for key in [key for key, seen in self._last_seen.items() if seen <= cutoff]:
			del self._last_seen[key]


class TokenBucketLimiter:
	"""Per-key token bucket with a bounded key map.

	Used to cap how many datagrams a single source can submit. Buckets that
	have refilled completely are dropped during pruning, so idle sources do
	not keep memory allocated.
	"""

	def __init__(self, rate=50.0, capacity=100.0, max_keys=4096, prune_interval=5.0):
		self.rate = float(rate)
		self.capacity = float(capacity)
		self.max_keys = max_keys
		self.prune_interval = prune_interval
		self._lock = threading.Lock()
		self._buckets = {}
		self._last_prune = 0.0

	def allow(self, key, now=None):
		if now is None:
			now = time.monotonic()
		with self._lock:
			self._prune(now)
			bucket = self._buckets.get(key)
			if bucket is None:
				if len(self._buckets) >= self.max_keys:
					return False
				bucket = [self.capacity, now]
				self._buckets[key] = bucket
			else:
				elapsed = max(0.0, now - bucket[1])
				bucket[0] = min(self.capacity, bucket[0] + elapsed * self.rate)
				bucket[1] = now
			if bucket[0] < 1.0:
				return False
			bucket[0] -= 1.0
			return True

	def _prune(self, now):
		if now - self._last_prune < self.prune_interval:
			return
		self._last_prune = now
		for key in list(self._buckets):
			tokens, updated = self._buckets[key]
			if tokens + (now - updated) * self.rate >= self.capacity:
				del self._buckets[key]


def is_mdns_response(data):
	"""True when the mDNS header has QR=1 (a response, not a query)."""
	if len(data) < 3:
		return False
	flags = data[2] if isinstance(data[2], int) else ord(data[2])
	return bool(flags & 0x80)


class MDNSRequestFilter:
	"""Cheap pre-queue filter for mDNS datagrams.

	Responder only has to answer queries, so responses (QR=1) are dropped.
	Identical questions from the same source are suppressed for one second,
	which is the interval RFC 6762 already asks queriers to respect, and a
	per-source token bucket stops one host from filling the handler queue.
	"""

	def __init__(self, query_window=1.0, source_rate=50.0, source_burst=100.0):
		self._queries = RateLimiter(window=query_window, max_keys=8192)
		self._sources = TokenBucketLimiter(rate=source_rate, capacity=source_burst, max_keys=4096)

	def should_drop(self, data, client_address, now=None):
		if len(data) < 12:
			return True
		if is_mdns_response(data):
			return True
		if now is None:
			now = time.monotonic()
		source = client_address[0].replace('::ffff:', '')
		if not self._sources.allow(source, now):
			return True
		# The question section starts at byte 12. The transaction ID is the
		# only part that changes between retransmits of the same question.
		key = (source, bytes(data[12:]))
		return not self._queries.allow(key, now)
