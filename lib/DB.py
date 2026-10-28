"""SQLite database adapter for WAScope."""
import os
import sqlite3
from pathlib import Path
from dotenv import find_dotenv, load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(find_dotenv(".env", usecwd=True) or ROOT / ".env")
DB_PATH = Path(os.getenv("WASCOPE_DB_PATH", str(ROOT / "data" / "wascope.sqlite3")))
if not DB_PATH.is_absolute():
    DB_PATH = ROOT / DB_PATH
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
SCHEMA_PATH = ROOT / "sql" / "lmad_sqlite.sql"


class DB:
    def __init__(self):
        self.conn = sqlite3.connect(str(DB_PATH), timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        if SCHEMA_PATH.exists():
            with SCHEMA_PATH.open("r", encoding="utf-8") as schema:
                self.conn.executescript(schema.read())
            self.conn.commit()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def close(self):
        conn = getattr(self, "conn", None)
        if conn is not None:
            conn.close()
            self.conn = None

    def is_connected(self):
        if getattr(self, "conn", None) is None:
            self.conn = sqlite3.connect(str(DB_PATH), timeout=30)
            self.conn.row_factory = sqlite3.Row

    def query(self, sql, params=()):
        self.is_connected()
        cur = self.conn.execute(sql, params)
        if cur.description is None:
            self.conn.commit()
            return []
        return [dict(row) for row in cur.fetchall()]

    def __add(self, table, fields, values):
        self.is_connected()
        field_names = [f.strip() for f in fields.split(",")]
        if isinstance(values, dict):
            data = values
            field_names = list(data.keys())
            vals = list(data.values())
        else:
            # Compatibility for legacy callers passing comma-separated SQL values.
            # New code should pass a dict so data is parameterized safely.
            raise TypeError("SQLite inserts require values as a dictionary")
        placeholders = ",".join("?" for _ in field_names)
        sql = "INSERT INTO {} ({}) VALUES ({})".format(
            table, ",".join(field_names), placeholders
        )
        self.conn.execute(sql, vals)
        self.conn.commit()

    def add_scanner(self, table="scanner", fields="url,json,create_time", values=None):
        self.__add(table, fields, values)

    def add_request_record(self, table="request_record", fields="", values=None):
        self.__add(table, fields, values)

    def add_request_record_second(self, table="request_record_second", fields="", values=None):
        self.__add(table, fields, values)

    def query_data(self, table, where="1=1", fields="*", params=()):
        return self.query("SELECT {} FROM {} WHERE {}".format(fields, table, where), params)

    def query_request_record(self, where="1=1", fields="*", params=()):
        return self.query_data("request_record", where, fields, params)

    def query_request_record_second(self, where="1=1", fields="*", params=()):
        return self.query_data("request_record_second", where, fields, params)
