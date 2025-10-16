import importlib
import sys
importlib.invalidate_caches()
try:
    import MySQLdb.constants as c
    print('MySQLdb.constants imported, has COMMAND=', hasattr(c, 'COMMAND'))
    try:
        from MySQLdb.constants import COMMAND as CMD
        print('Imported COMMAND ok, sample attrs:', [a for a in dir(CMD) if not a.startswith('_')][:10])
    except Exception as e:
        print('Failed to import COMMAND:', type(e).__name__, e)
except Exception as e:
    print('Failed to import MySQLdb.constants:', type(e).__name__, e)
