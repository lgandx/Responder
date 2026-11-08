import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from servers.rate_limit import MDNSRequestFilter
from servers.rate_limit import RateLimiter
from servers.rate_limit import TokenBucketLimiter
from servers.rate_limit import is_mdns_response


def mdns_query(name=b'\x05local', txid=0x1234, flags=b'\x00\x00'):
	return (
		struct.pack('>H', txid)
		+ flags
		+ b'\x00\x01'      # QDCOUNT
		+ b'\x00\x00'      # ANCOUNT
		+ b'\x00\x00'      # NSCOUNT
		+ b'\x00\x00'      # ARCOUNT
		+ name
		+ b'\x00\x01'      # QTYPE A
		+ b'\x00\x01'      # QCLASS IN
	)


class RateLimiterTest(unittest.TestCase):
	def test_allows_one_event_per_window(self):
		limiter = RateLimiter(window=1.0)
		self.assertTrue(limiter.allow('key', now=10.0))
		self.assertFalse(limiter.allow('key', now=10.5))
		self.assertTrue(limiter.allow('key', now=11.1))

	def test_prunes_expired_keys_so_the_map_is_bounded(self):
		limiter = RateLimiter(window=1.0, max_keys=2)
		self.assertTrue(limiter.allow('a', now=0.0))
		self.assertTrue(limiter.allow('b', now=0.0))
		self.assertFalse(limiter.allow('c', now=0.0))
		self.assertTrue(limiter.allow('c', now=2.0))


class TokenBucketLimiterTest(unittest.TestCase):
	def test_caps_burst_then_refills(self):
		limiter = TokenBucketLimiter(rate=1.0, capacity=2.0)
		self.assertTrue(limiter.allow('a', now=0.0))
		self.assertTrue(limiter.allow('a', now=0.0))
		self.assertFalse(limiter.allow('a', now=0.0))
		self.assertTrue(limiter.allow('a', now=1.0))
		self.assertFalse(limiter.allow('a', now=1.0))

	def test_refuses_new_keys_when_map_is_full(self):
		limiter = TokenBucketLimiter(rate=1.0, capacity=1.0, max_keys=2)
		self.assertTrue(limiter.allow('a', now=0.0))
		self.assertTrue(limiter.allow('b', now=0.0))
		self.assertFalse(limiter.allow('c', now=0.0))


class MDNSRequestFilterTest(unittest.TestCase):
	def setUp(self):
		self.filter = MDNSRequestFilter()
		self.source = ('192.0.2.10', 5353)

	def test_detects_response_flag(self):
		self.assertFalse(is_mdns_response(mdns_query()))
		self.assertTrue(is_mdns_response(mdns_query(flags=b'\x84\x00')))
		self.assertFalse(is_mdns_response(b'\x00\x00'))

	def test_drops_responses(self):
		self.assertTrue(self.filter.should_drop(mdns_query(flags=b'\x84\x00'), self.source))

	def test_drops_short_packets(self):
		self.assertTrue(self.filter.should_drop(b'\x00' * 11, self.source))

	def test_allows_first_query(self):
		self.assertFalse(self.filter.should_drop(mdns_query(), self.source, now=100.0))

	def test_drops_retransmit_within_one_second(self):
		self.assertFalse(self.filter.should_drop(mdns_query(), self.source, now=100.0))
		self.assertTrue(self.filter.should_drop(mdns_query(txid=0x9999), self.source, now=100.5))

	def test_allows_retransmit_after_one_second(self):
		self.assertFalse(self.filter.should_drop(mdns_query(), self.source, now=100.0))
		self.assertFalse(self.filter.should_drop(mdns_query(txid=0x9999), self.source, now=101.1))

	def test_allows_different_questions_from_the_same_source(self):
		self.assertFalse(self.filter.should_drop(mdns_query(name=b'\x04host'), self.source, now=100.0))
		self.assertFalse(self.filter.should_drop(mdns_query(name=b'\x05other'), self.source, now=100.1))

	def test_normalizes_ipv4_mapped_source(self):
		self.assertFalse(self.filter.should_drop(mdns_query(), ('::ffff:192.0.2.10', 5353), now=100.0))
		self.assertTrue(self.filter.should_drop(mdns_query(), ('192.0.2.10', 5353), now=100.5))


if __name__ == '__main__':
	unittest.main()
