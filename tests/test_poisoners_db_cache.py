import os
import sqlite3
import sys
import tempfile
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# utils exits at import time when these runtime dependencies are missing.
# They are not used by the database code under test.
for _name in ('netifaces', 'aioquic'):
	if _name not in sys.modules:
		sys.modules[_name] = types.ModuleType(_name)

settings_stub = types.ModuleType('settings')
settings_stub.Config = types.SimpleNamespace(DatabaseFile=None)
sys.modules.setdefault('settings', settings_stub)

import utils


class SavePoisonersToDbCacheTest(unittest.TestCase):
	def setUp(self):
		fd, self.db_path = tempfile.mkstemp(suffix='.db')
		os.close(fd)
		os.unlink(self.db_path)
		settings_stub.Config.DatabaseFile = self.db_path
		db = sqlite3.connect(self.db_path)
		try:
			db.execute(
				'CREATE TABLE Poisoned (timestamp TEXT, Poisoner TEXT, SentToIp TEXT, '
				'ForName TEXT, AnalyzeMode TEXT)',
			)
			db.commit()
		finally:
			db.close()
		utils._poisoners_db_cache.clear()

	def tearDown(self):
		for path in (self.db_path, self.db_path + '-wal', self.db_path + '-shm'):
			if os.path.exists(path):
				os.unlink(path)

	def rows(self):
		db = sqlite3.connect(self.db_path)
		try:
			return db.execute('SELECT Poisoner, SentToIp, ForName, AnalyzeMode FROM Poisoned').fetchall()
		finally:
			db.close()

	def event(self, **overrides):
		event = {
			'Poisoner': 'MDNS',
			'SentToIp': '192.0.2.10',
			'ForName': 'host.local',
			'AnalyzeMode': '0',
		}
		event.update(overrides)
		return event

	def test_repeated_event_writes_one_row(self):
		utils.SavePoisonersToDb(self.event())
		utils.SavePoisonersToDb(self.event())
		self.assertEqual(self.rows(), [('MDNS', '192.0.2.10', 'host.local', '0')])

	def test_different_event_writes_another_row(self):
		utils.SavePoisonersToDb(self.event())
		utils.SavePoisonersToDb(self.event(ForName='other.local'))
		self.assertEqual(len(self.rows()), 2)

	def test_ipv4_mapped_address_is_normalized_before_caching(self):
		utils.SavePoisonersToDb(self.event(SentToIp='::ffff:192.0.2.10'))
		utils.SavePoisonersToDb(self.event(SentToIp='192.0.2.10'))
		self.assertEqual(self.rows(), [('MDNS', '192.0.2.10', 'host.local', '0')])

	def test_cache_is_bounded(self):
		original = utils._POISONERS_DB_CACHE_MAX
		utils._POISONERS_DB_CACHE_MAX = 2
		try:
			for i in range(3):
				utils.SavePoisonersToDb(self.event(ForName='host%d.local' % i))
			self.assertEqual(len(utils._poisoners_db_cache), 2)
		finally:
			utils._POISONERS_DB_CACHE_MAX = original


if __name__ == '__main__':
	unittest.main()
