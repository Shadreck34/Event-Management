"""Lightweight shim that delegates MySQLdb names to pymysql equivalents.

This package exists so code that imports `MySQLdb` (from mysqlclient) can run
when using PyMySQL as the underlying driver. It re-exports common symbols
and provides a `constants` module (implemented in constants.py) which
re-exports pymysql.constants.* submodules.
"""

import importlib
import sys

try:
	_pymysql = importlib.import_module('pymysql')
except Exception:
	_pymysql = None

# Re-export a small set of names expected by mysqlclient clients
if _pymysql is not None:
	try:
		connect = _pymysql.connect
	except Exception:
		pass

	# Provide cursors and connections modules namespace via pymysql
	try:
		cursors = importlib.import_module('pymysql.cursors')
	except Exception:
		cursors = None

	try:
		connections = importlib.import_module('pymysql.connections')
	except Exception:
		connections = None

	# expose short-hands commonly used
	__all__ = ['connect', 'cursors', 'connections', 'constants']
else:
	__all__ = ['constants']

