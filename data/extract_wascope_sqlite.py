#!/usr/bin/env python3
"""Safely export useful WAScope SQLite findings to CSV.

The script is designed for the SQLite WAScope fork whose main tables are
`request_record` and `request_record_second`.

Privacy safeguards:
- Opens the database read-only; it never modifies the source database.
- Does NOT export raw response bodies, request headers, cookies, auth tokens,
  raw sensitive values, or query-string values.
- Exports the names/labels of fields matched by WAScope's privacy dictionary.
- Removes query strings and masks numeric/UUID path segments in exported URLs.

Usage (from the WAScope project folder):
    python extract_wascope_sqlite.py --db data/wascope.sqlite3 --host localhost

If the database is in another location, pass its full path to --db.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

CAPTURE_TABLE_CANDIDATES = ("request_record", "request_records")
REPLAY_TABLE_CANDIDATES = ("request_record_second", "request_records_second", "replay_record")
SKIP_DIRS = {".git", ".venv", "venv", "venv311", "env", "node_modules", "__pycache__", "site-packages"}


def quote_ident(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def find_column(columns: list[str], candidates: tuple[str, ...]) -> str | None:
    lookup = {c.lower(): c for c in columns}
    for candidate in candidates:
        if candidate.lower() in lookup:
            return lookup[candidate.lower()]
    return None


def find_table(tables: list[str], candidates: tuple[str, ...]) -> str | None:
    lookup = {t.lower(): t for t in tables}
    for candidate in candidates:
        if candidate.lower() in lookup:
            return lookup[candidate.lower()]
    return None


def discover_databases(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in root.rglob("*"):
        if any(part.lower() in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file() and path.suffix.lower() in {".db", ".sqlite", ".sqlite3"}:
            # SQLite sidecar files are not databases.
            if path.name.lower().endswith(("-wal", "-shm")):
                continue
            found.append(path.resolve())
    return sorted(set(found))


def open_read_only(db_path: Path) -> sqlite3.Connection:
    # Path.as_uri() handles Windows drive letters and spaces safely.
    uri = db_path.resolve().as_uri() + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def get_schema(conn: sqlite3.Connection) -> dict[str, list[str]]:
    table_rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    schema: dict[str, list[str]] = {}
    for row in table_rows:
        table = row[0]
        cols = conn.execute(f"PRAGMA table_info({quote_ident(table)})").fetchall()
        schema[table] = [col[1] for col in cols]
    return schema


def safe_endpoint(raw_url: Any) -> str:
    """Keep endpoint path only; drop query values and mask likely object IDs."""
    text = str(raw_url or "").strip()
    if not text:
        return ""
    try:
        parsed = urlsplit(text)
        path = parsed.path if (parsed.scheme or parsed.netloc) else text.split("?", 1)[0].split("#", 1)[0]
    except Exception:
        path = text.split("?", 1)[0].split("#", 1)[0]

    parts = []
    for part in path.split("/"):
        if not part:
            parts.append(part)
        elif re.fullmatch(r"\d+", part):
            parts.append("{numeric_id}")
        elif re.fullmatch(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", part):
            parts.append("{uuid}")
        else:
            parts.append(part)
    return "/".join(parts)


def field_labels(raw: Any) -> list[str]:
    """Extract dictionary-match labels/keys, never the associated values."""
    if raw is None:
        return []
    if isinstance(raw, (dict, list)):
        parsed = raw
    else:
        text = str(raw).strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            # Don't export unparsed content: it may contain an actual sensitive value.
            return ["[non_json_indicator_recorded]"]

    labels: set[str] = set()

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for key, value in item.items():
                key_text = str(key).strip()
                if key_text and not re.fullmatch(r"\d+", key_text):
                    # Keep field labels only, not matched values.
                    labels.add(key_text[:100])
                if isinstance(value, (dict, list)):
                    walk(value)
        elif isinstance(item, list):
            for value in item:
                if isinstance(value, (dict, list)):
                    walk(value)
                elif isinstance(value, str) and value.strip() and len(value) < 80:
                    # For list-style path matches, keep label-like strings only.
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", value):
                        labels.add(value[:100])

    walk(parsed)
    return sorted(labels)


def parse_param_names(raw: Any) -> list[str]:
    """Return parameter names only; drop their values."""
    if raw is None:
        return []
    text = str(raw).strip()
    if not text:
        return []
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return sorted(str(k) for k in obj.keys())
        if isinstance(obj, list):
            names = []
            for item in obj:
                if isinstance(item, dict):
                    names.extend(str(k) for k in item.keys())
                elif isinstance(item, (list, tuple)) and item:
                    names.append(str(item[0]))
            return sorted(set(names))
    except json.JSONDecodeError:
        pass
    # Query-string / form-data case: retain keys only.
    try:
        return sorted({key for key, _value in parse_qsl(text.lstrip("?"), keep_blank_values=True)})
    except Exception:
        return []


def as_count(value: Any) -> int:
    try:
        return int(value or 0)
    except (ValueError, TypeError):
        return 0


def get_rows(conn: sqlite3.Connection, table: str, host_filter: str | None) -> list[dict[str, Any]]:
    sql = f"SELECT * FROM {quote_ident(table)}"
    params: tuple[Any, ...] = ()
    if host_filter:
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({quote_ident(table)})").fetchall()]
        host_col = find_column(cols, ("host", "hostname"))
        if host_col:
            sql += f" WHERE lower(CAST({quote_ident(host_col)} AS TEXT)) LIKE ?"
            params = (f"%{host_filter.lower()}%",)
    return [dict(row) for row in conn.execute(sql, params).fetchall()]


def first(row: dict[str, Any], candidates: tuple[str, ...]) -> Any:
    lookup = {str(k).lower(): k for k in row.keys()}
    for candidate in candidates:
        key = lookup.get(candidate.lower())
        if key is not None:
            return row.get(key)
    return None


def export_csv(path: Path, columns: list[str], rows: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Automatically extract privacy-indicator metadata from a SQLite WAScope database."
    )
    parser.add_argument("--db", help="Path to the WAScope SQLite database. If omitted, search the current folder.")
    parser.add_argument("--host", default="localhost", help="Host filter (default: localhost). Use --host all to include every host.")
    parser.add_argument("--out", default="wascope_extracted", help="Output folder (default: ./wascope_extracted).")
    args = parser.parse_args()

    root = Path.cwd()
    if args.db:
        db_path = Path(args.db).expanduser()
        if not db_path.is_absolute():
            db_path = root / db_path
        db_path = db_path.resolve()
        if not db_path.is_file():
            print(f"ERROR: Database file not found: {db_path}")
            return 2
    else:
        candidates = discover_databases(root)
        if len(candidates) == 0:
            print(f"ERROR: No .db/.sqlite/.sqlite3 database found under: {root}")
            print("Run from your WAScope project folder or pass --db <database-file>.")
            return 2
        if len(candidates) > 1:
            print("More than one SQLite database was found. Choose the correct one with --db:")
            for item in candidates:
                print(f"  {item}")
            return 2
        db_path = candidates[0]

    host_filter = None if args.host.lower() == "all" else args.host
    out_dir = Path(args.out).expanduser()
    if not out_dir.is_absolute():
        out_dir = root / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        conn = open_read_only(db_path)
    except sqlite3.Error as exc:
        print(f"ERROR: Could not open database read-only: {exc}")
        return 2

    try:
        schema = get_schema(conn)
        tables = list(schema)
        captured_table = find_table(tables, CAPTURE_TABLE_CANDIDATES)
        replay_table = find_table(tables, REPLAY_TABLE_CANDIDATES)

        # Save a simple schema report so mismatches can be diagnosed without sharing the DB.
        schema_lines = [f"Database: {db_path}", "", "Tables and columns:"]
        for table, cols in schema.items():
            schema_lines.append(f"- {table}: {', '.join(cols)}")
        (out_dir / "database_schema.txt").write_text("\n".join(schema_lines), encoding="utf-8")

        if not captured_table and not replay_table:
            print("ERROR: No WAScope request tables were found.")
            print("Tables discovered:", ", ".join(tables) if tables else "(none)")
            print(f"See schema report: {out_dir / 'database_schema.txt'}")
            return 2

        captured_rows = get_rows(conn, captured_table, host_filter) if captured_table else []
        replay_rows = get_rows(conn, replay_table, host_filter) if replay_table else []

    except sqlite3.Error as exc:
        print(f"ERROR: SQLite query failed: {exc}")
        return 2
    finally:
        conn.close()

    # Export captured rows with any dictionary indicator. Values, raw bodies and headers are excluded.
    captured_export: list[dict[str, Any]] = []
    for row in captured_rows:
        response_count = as_count(first(row, ("response_exists_sensitive",)))
        path_count = as_count(first(row, ("path_exist_sensitive", "path_exists_sensitive")))
        get_count = as_count(first(row, ("get_exist_sensitive", "get_exists_sensitive")))
        post_count = as_count(first(row, ("post_exist_sensitive", "post_exists_sensitive")))
        labels = {
            "response": field_labels(first(row, ("response_sensitive",))),
            "path": field_labels(first(row, ("path_sensitive",))),
            "get": field_labels(first(row, ("get_sensitive",))),
            "post": field_labels(first(row, ("post_sensitive",))),
        }
        if not (response_count or path_count or get_count or post_count or any(labels.values())):
            continue
        captured_export.append({
            "record_id": first(row, ("id", "flow_id")),
            "host": first(row, ("host", "hostname")),
            "method": str(first(row, ("method", "http_method")) or "").upper(),
            "endpoint": safe_endpoint(first(row, ("url", "request_url"))),
            "response_indicator_count": response_count,
            "path_indicator_count": path_count,
            "get_indicator_count": get_count,
            "post_indicator_count": post_count,
            "response_field_labels": "; ".join(labels["response"]),
            "path_field_labels": "; ".join(labels["path"]),
            "get_field_labels": "; ".join(labels["get"]),
            "post_field_labels": "; ".join(labels["post"]),
            "created_at": first(row, ("create_time", "timestamp", "created_at")),
        })

    # Export replay rows with response indicators only; redact all matched values.
    replay_export: list[dict[str, Any]] = []
    for row in replay_rows:
        count = as_count(first(row, ("response_exists_sensitive",)))
        labels = field_labels(first(row, ("response_sensitive",)))
        # Include indicator-free rows too, so the CSV can show the replay denominator.
        replay_export.append({
            "host": first(row, ("host", "hostname")),
            "method": str(first(row, ("method", "http_method")) or "").upper(),
            "original_endpoint": safe_endpoint(first(row, ("origin_url", "original_url"))),
            "replayed_endpoint": safe_endpoint(first(row, ("url", "request_url"))),
            "generated_parameter_names": "; ".join(parse_param_names(first(row, ("gen_params",)))),
            "response_indicator_count": count,
            "response_field_labels": "; ".join(labels),
            "has_privacy_indicator": "yes" if count > 0 else "no",
            "created_at": first(row, ("create_time", "timestamp", "created_at")),
        })

    export_csv(
        out_dir / "captured_flagged_records_redacted.csv",
        ["record_id", "host", "method", "endpoint", "response_indicator_count",
         "path_indicator_count", "get_indicator_count", "post_indicator_count",
         "response_field_labels", "path_field_labels", "get_field_labels",
         "post_field_labels", "created_at"],
        captured_export,
    )
    export_csv(
        out_dir / "replay_records_redacted.csv",
        ["host", "method", "original_endpoint", "replayed_endpoint",
         "generated_parameter_names", "response_indicator_count", "response_field_labels",
         "has_privacy_indicator", "created_at"],
        replay_export,
    )

    # Aggregate by original endpoint to support endpoint-level charts.
    endpoint_stats: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"replay_records": 0, "flagged_replay_records": 0, "indicator_count_total": 0, "field_labels": set()}
    )
    for item in replay_export:
        key = (item["method"], item["original_endpoint"])
        bucket = endpoint_stats[key]
        bucket["replay_records"] += 1
        bucket["flagged_replay_records"] += 1 if item["has_privacy_indicator"] == "yes" else 0
        bucket["indicator_count_total"] += as_count(item["response_indicator_count"])
        if item["response_field_labels"]:
            bucket["field_labels"].update(x.strip() for x in item["response_field_labels"].split(";") if x.strip())

    endpoint_export = []
    for (method, endpoint), stats in endpoint_stats.items():
        endpoint_export.append({
            "method": method,
            "original_endpoint": endpoint,
            "replay_records": stats["replay_records"],
            "flagged_replay_records": stats["flagged_replay_records"],
            "flagged_percentage": round(100 * stats["flagged_replay_records"] / stats["replay_records"], 2) if stats["replay_records"] else 0,
            "total_indicator_count": stats["indicator_count_total"],
            "matched_field_labels": "; ".join(sorted(stats["field_labels"])),
        })
    endpoint_export.sort(key=lambda x: (x["flagged_replay_records"], x["replay_records"]), reverse=True)
    export_csv(
        out_dir / "endpoint_replay_summary.csv",
        ["method", "original_endpoint", "replay_records", "flagged_replay_records",
         "flagged_percentage", "total_indicator_count", "matched_field_labels"],
        endpoint_export,
    )

    summary = {
        "database": str(db_path),
        "host_filter": host_filter or "ALL",
        "captured_table": captured_table,
        "replay_table": replay_table,
        "captured_rows_read": len(captured_rows),
        "captured_rows_with_indicators_exported": len(captured_export),
        "replay_rows_read": len(replay_rows),
        "replay_rows_with_indicators": sum(1 for r in replay_export if r["has_privacy_indicator"] == "yes"),
        "replay_rows_without_indicators": sum(1 for r in replay_export if r["has_privacy_indicator"] == "no"),
        "unique_replay_endpoints": len(endpoint_export),
        "output_directory": str(out_dir.resolve()),
        "privacy_note": "Raw response bodies, matched values, headers, cookies, auth tokens and query values were not exported.",
    }
    (out_dir / "extraction_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\nWAScope SQLite extraction completed.")
    print(f"Database: {db_path}")
    print(f"Host filter: {host_filter or 'ALL'}")
    print(f"Captured rows read: {len(captured_rows)}")
    print(f"Captured rows with indicators: {len(captured_export)}")
    print(f"Replay rows read: {len(replay_rows)}")
    print(f"Replay rows with indicators: {summary['replay_rows_with_indicators']}")
    print(f"Unique replay endpoints: {len(endpoint_export)}")
    print(f"\nFiles saved in: {out_dir.resolve()}")
    print(" - captured_flagged_records_redacted.csv")
    print(" - replay_records_redacted.csv")
    print(" - endpoint_replay_summary.csv")
    print(" - extraction_summary.json")
    print(" - database_schema.txt")
    print("\nNote: an indicator is not proof of a vulnerability; manual authorization testing is still required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
