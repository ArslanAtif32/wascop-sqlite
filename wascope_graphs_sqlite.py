#!/usr/bin/env python3
"""Create aggregate graphs from a SQLite-adapted WAScope database.

Default database: <WAScope project>/data/wascope.sqlite3
Expected tables: request_record and request_record_second.
The script exports aggregate counts and URL paths only. It does not export
response bodies, query-string values, cookies, tokens, or detected personal data.
"""
from __future__ import annotations

import argparse
import csv
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

try:
    import matplotlib.pyplot as plt
except ImportError:
    print("Missing dependency: matplotlib")
    print("Install with: python -m pip install matplotlib")
    sys.exit(2)


def as_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def endpoint_only(value: object) -> str:
    """Remove query strings and fragments to avoid exposing parameter values."""
    text = str(value or "")
    try:
        parsed = urlsplit(text)
        if parsed.scheme or parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return text.split("?", 1)[0].split("#", 1)[0]
    except Exception:
        return text.split("?", 1)[0].split("#", 1)[0]


def write_csv(path: Path, headers: list[str], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


def list_tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [row[0] for row in rows]


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    # Table names come only from sqlite_master, not directly from user input.
    escaped = table.replace('"', '""')
    rows = conn.execute(f'PRAGMA table_info("{escaped}")').fetchall()
    return {row[1] for row in rows}


def choose_column(columns: set[str], candidates: tuple[str, ...], required: bool = True) -> str | None:
    lower_map = {col.lower(): col for col in columns}
    for candidate in candidates:
        if candidate.lower() in lower_map:
            return lower_map[candidate.lower()]
    if required:
        raise ValueError(
            "Could not find any expected column: " + ", ".join(candidates)
            + ". Available columns: " + ", ".join(sorted(columns))
        )
    return None


def quoted(column: str) -> str:
    return '"' + column.replace('"', '""') + '"'


def find_table(tables: list[str], candidates: tuple[str, ...]) -> str | None:
    lower_map = {name.lower(): name for name in tables}
    for candidate in candidates:
        if candidate.lower() in lower_map:
            return lower_map[candidate.lower()]
    return None


def fetch_records(conn: sqlite3.Connection, table: str, host_filter: str, replay: bool) -> tuple[list[dict], dict[str, str]]:
    cols = table_columns(conn, table)
    host_col = choose_column(cols, ("host", "hostname"))
    method_col = choose_column(cols, ("method", "http_method"), required=False)
    url_col = choose_column(cols, (("origin_url", "original_url") if replay else ("url", "request_url", "uri")), required=False)
    response_col = choose_column(cols, ("response_exists_sensitive", "response_exist_sensitive", "response_sensitive"), required=False)

    if replay:
        # Some forks retain both original and replayed URLs. The original URL is
        # preferred for grouping; otherwise group by the available URL column.
        if url_col is None:
            url_col = choose_column(cols, ("url", "request_url", "uri"))
    else:
        if url_col is None:
            url_col = choose_column(cols, ("url", "request_url", "uri"))

    path_col = choose_column(cols, ("path_exist_sensitive", "path_exists_sensitive"), required=False)
    get_col = choose_column(cols, ("get_exist_sensitive", "get_exists_sensitive"), required=False)
    post_col = choose_column(cols, ("post_exist_sensitive", "post_exists_sensitive"), required=False)

    selected: list[str] = []
    aliases: dict[str, str] = {}
    for alias, col in (("method", method_col), ("url", url_col),
                       ("response_sensitive", response_col), ("path_sensitive", path_col),
                       ("get_sensitive", get_col), ("post_sensitive", post_col)):
        if col:
            selected.append(f'{quoted(col)} AS "{alias}"')
            aliases[alias] = col

    # A contains match handles host values stored either as 'localhost' or
    # 'localhost:3000'. Host is matched case-insensitively.
    sql = (
        f'SELECT {", ".join(selected)} FROM "{table.replace(chr(34), chr(34)*2)}" '
        f'WHERE lower(CAST({quoted(host_col)} AS TEXT)) LIKE ?'
    )
    rows = conn.execute(sql, (f"%{host_filter.lower()}%",)).fetchall()
    return [dict(row) for row in rows], aliases


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate graphs from SQLite-based WAScope results.")
    parser.add_argument(
        "--db", default="data/wascope.sqlite3",
        help="SQLite database path (default: data/wascope.sqlite3 relative to this script's folder)",
    )
    parser.add_argument("--host", required=True, help="Host filter, e.g. localhost")
    parser.add_argument("--out", default="wascope_graphs", help="Output directory (default: wascope_graphs)")
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    db_path = Path(args.db)
    if not db_path.is_absolute():
        db_path = script_dir / db_path
    db_path = db_path.resolve()

    if not db_path.exists():
        print(f"SQLite database not found: {db_path}")
        print("Pass its actual location using --db, for example: --db data/wascope.sqlite3")
        return 2

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
    except sqlite3.Error as exc:
        print(f"Could not open SQLite database: {exc}")
        return 2

    try:
        tables = list_tables(conn)
        captured_table = find_table(tables, ("request_record", "request_records"))
        replay_table = find_table(tables, ("request_record_second", "request_records_second", "replay_record"))

        if not captured_table:
            print("Could not find the captured-requests table.")
            print("Tables found:", ", ".join(tables) if tables else "(none)")
            print("Expected a table named request_record.")
            return 2

        captured, captured_cols = fetch_records(conn, captured_table, args.host, replay=False)
        replayed: list[dict] = []
        replay_cols: dict[str, str] = {}
        if replay_table:
            replayed, replay_cols = fetch_records(conn, replay_table, args.host, replay=True)
        else:
            print("Note: replay table not found; replay graph will not be generated.")

    except (sqlite3.Error, ValueError) as exc:
        print(f"Could not read WAScope SQLite tables: {exc}")
        print("Check that your SQLite fork uses the expected WAScope table/column names.")
        return 2
    finally:
        conn.close()

    if not captured and not replayed:
        print(f"No records found for host containing '{args.host}'.")
        print("Check the host value, Config.py host filter, proxy capture, and database path.")
        return 1

    out_dir = Path(args.out)
    if not out_dir.is_absolute():
        out_dir = script_dir / out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # Graph 1: locations where captured request records contained indicators.
    # The categories can overlap because one record may have multiple flags.
    indicator_columns = {
        "Response fields": "response_sensitive",
        "URL path": "path_sensitive",
        "GET parameters": "get_sensitive",
        "POST parameters": "post_sensitive",
    }
    indicator_counts = {
        label: sum(as_int(row.get(alias)) > 0 for row in captured) if alias in captured_cols else 0
        for label, alias in indicator_columns.items()
    }
    indicator_rows = [
        {"indicator_location": label, "records_with_indicator": count}
        for label, count in indicator_counts.items()
    ]
    write_csv(out_dir / "captured_indicator_counts.csv",
              ["indicator_location", "records_with_indicator"], indicator_rows)

    if captured:
        labels = list(indicator_counts.keys())
        values = list(indicator_counts.values())
        fig, ax = plt.subplots(figsize=(9, 5))
        bars = ax.bar(labels, values)
        ax.set_title("WAScope: captured records with privacy-field indicators")
        ax.set_ylabel("Number of request records")
        ax.set_xlabel("Where the indicator was found")
        ax.tick_params(axis="x", rotation=15)
        ax.bar_label(bars, padding=3)
        ax.grid(axis="y", alpha=0.25)
        fig.tight_layout()
        fig.savefig(out_dir / "01_captured_indicators.png", dpi=180)
        plt.close(fig)

    # Graph 2: replayed responses containing privacy-related indicators.
    grouped: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"replayed_variants": 0, "responses_with_sensitive_indicators": 0}
    )
    for row in replayed:
        method = str(row.get("method") or "unknown").upper()
        endpoint = endpoint_only(row.get("url"))
        key = (method, endpoint)
        grouped[key]["replayed_variants"] += 1
        if as_int(row.get("response_sensitive")) > 0:
            grouped[key]["responses_with_sensitive_indicators"] += 1

    replay_rows = []
    for (method, endpoint), counts in grouped.items():
        replay_rows.append({
            "method": method,
            "original_api_endpoint": endpoint,
            **counts,
        })
    replay_rows.sort(key=lambda row: (
        row["responses_with_sensitive_indicators"], row["replayed_variants"]
    ), reverse=True)
    write_csv(out_dir / "replay_results_by_endpoint.csv",
              ["method", "original_api_endpoint", "replayed_variants",
               "responses_with_sensitive_indicators"], replay_rows)

    if replay_rows:
        top = replay_rows[:12]
        labels = [f"{r['method']} {r['original_api_endpoint']}" for r in top]
        values = [r["responses_with_sensitive_indicators"] for r in top]
        fig, ax = plt.subplots(figsize=(11, max(5, 0.45 * len(top))))
        bars = ax.barh(labels[::-1], values[::-1])
        ax.set_title("WAScope replay: responses with privacy-field indicators")
        ax.set_xlabel("Number of replay response records flagged")
        ax.set_ylabel("Original API endpoint")
        ax.bar_label(bars, padding=3)
        ax.grid(axis="x", alpha=0.25)
        fig.tight_layout()
        fig.savefig(out_dir / "02_replay_indicators_by_endpoint.png", dpi=180)
        plt.close(fig)

    summary = [
        {"metric": "captured_request_records", "value": len(captured)},
        {"metric": "replay_response_records", "value": len(replayed)},
        {"metric": "captured_response_records_with_sensitive_indicators", "value": indicator_counts["Response fields"]},
        {"metric": "captured_path_records_with_sensitive_indicators", "value": indicator_counts["URL path"]},
        {"metric": "captured_get_records_with_sensitive_indicators", "value": indicator_counts["GET parameters"]},
        {"metric": "captured_post_records_with_sensitive_indicators", "value": indicator_counts["POST parameters"]},
        {"metric": "replay_records_with_sensitive_indicators", "value": sum(as_int(row.get("response_sensitive")) > 0 for row in replayed)},
        {"metric": "unique_original_api_endpoints_replayed", "value": len({endpoint_only(row.get("url")) for row in replayed})},
    ]
    write_csv(out_dir / "run_summary.csv", ["metric", "value"], summary)

    print(f"SQLite database: {db_path}")
    print(f"Captured table: {captured_table} ({len(captured)} records)")
    print(f"Replay table: {replay_table or 'not found'} ({len(replayed)} records)")
    print(f"Host filter: {args.host}")
    print(f"Outputs saved in: {out_dir.resolve()}")
    if captured and not any(indicator_counts.values()):
        print("Warning: captured rows found, but no matching sensitive-indicator columns had positive values.")
    if not replayed:
        print("Note: no replay records found; run WAScope's replay stage before expecting Graph 2.")
    print("Important: indicator counts are not automatically confirmed vulnerabilities.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
