"""Shim module that re-exports pymysql.constants submodules so code that
imports `from MySQLdb.constants import COMMAND` will work when using PyMySQL.
"""
from importlib import import_module

try:
    _pymysql_constants = import_module('pymysql.constants')
except Exception:
    _pymysql_constants = None

# Re-export known submodules if available
for sub in ('COMMAND', 'CLIENT', 'FIELD_TYPE', 'FLAG', 'CR', 'ER', 'SERVER_STATUS'):
    try:
        mod = import_module(f'pymysql.constants.{sub}')
        globals()[sub] = mod
        if _pymysql_constants is not None:
            try:
                setattr(_pymysql_constants, sub, mod)
            except Exception:
                pass
    except Exception:
        pass

# Also copy any names from base pymysql.constants
if _pymysql_constants is not None:
    for name in dir(_pymysql_constants):
        if not name.startswith('_') and name not in globals():
            try:
                globals()[name] = getattr(_pymysql_constants, name)
            except Exception:
                pass

__all__ = [k for k in globals().keys() if not k.startswith('_')]
