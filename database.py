import os
import sqlite3
from flask import g

# Check for a cloud DATABASE_URL (PostgreSQL)
DATABASE_URL = os.environ.get("DATABASE_URL")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SQLITE_DB = os.path.join(BASE_DIR, "database.db")

# Detect which database engine is active
IS_POSTGRES = DATABASE_URL is not None


class DictRow(dict):
    """A dict subclass that also supports index-based access like sqlite3.Row."""
    def __init__(self, cursor_description, row_tuple):
        keys = [col[0] for col in cursor_description]
        super().__init__(zip(keys, row_tuple))
        self._keys = keys
        self._values = list(row_tuple)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)

    def keys(self):
        return self._keys


class PgCursorWrapper:
    """Wraps a psycopg2 cursor to behave like sqlite3's cursor with Row factory."""
    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, sql, params=None):
        # Convert SQLite-style '?' placeholders to PostgreSQL '%s'
        sql = sql.replace("?", "%s")
        if params:
            self._cursor.execute(sql, params)
        else:
            self._cursor.execute(sql)
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        return DictRow(self._cursor.description, row)

    def fetchall(self):
        rows = self._cursor.fetchall()
        if not rows or not self._cursor.description:
            return []
        return [DictRow(self._cursor.description, r) for r in rows]


class PgConnectionWrapper:
    """Wraps a psycopg2 connection to provide a sqlite3-compatible interface."""
    def __init__(self, conn):
        self._conn = conn

    def execute(self, sql, params=None):
        cursor = PgCursorWrapper(self._conn.cursor())
        cursor.execute(sql, params)
        return cursor

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()

    def cursor(self):
        return PgCursorWrapper(self._conn.cursor())


def get_db():
    if "db" not in g:
        if IS_POSTGRES:
            import psycopg2
            conn = psycopg2.connect(DATABASE_URL)
            g.db = PgConnectionWrapper(conn)
        else:
            conn = sqlite3.connect(SQLITE_DB)
            conn.row_factory = sqlite3.Row
            g.db = conn
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()