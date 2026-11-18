#!/usr/bin/env python3
"""Classify WAScope response-side privacy indicators into useful categories.

Reads request_record (captured traffic) and request_record_second (replay
traffic) from a WAScope SQLite database in READ-ONLY mode.

IMPORTANT:
- The script reads field/parameter NAMES from *_sensitive JSON columns.
- It NEVER exports or prints actual sensitive values, raw request/response bodies,
  cookies, authorization headers, tokens, or generated parameter values.
- A matched field name is a candidate indicator, NOT proof of data leakage.
- Request-side matches are reported separately and are NOT labelled leaks.

Usage:
    python wascope_leak_classifier.py --db "wascope(1).sqlite3"
    python wascope_leak_classifier.py --db "wascope(1).sqlite3" --host cmitinterns.punjab.gov.pk
    python wascope_leak_classifier.py --db "wascope(1).sqlite3" --include-request-indicators

Outputs (by default, next to this script):
    wascope_leak_classification.csv
    wascope_leak_summary.txt
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any, Iterable

# Patterns are applied to the final JSON property name (the leaf), not blindly
# to the whole nested path. Known configuration/asset-manifest branches are
# excluded because words such as "payment", "email" or "login" there often
# describe feature flags or filenames rather than personal/financial values.
EXCLUDED_METADATA_ROOTS = {"flags", "experiments_data", "hashtable", "assetgroups"}

EXACT_CREDENTIAL_FIELDS = {
    "password", "passwd", "passcode", "pwd", "username", "user_name",
    "login", "login_id", "email", "e_mail", "access_token", "refresh_token",
    "auth_token", "captcha_token", "token", "secret", "client_secret",
    "api_key", "authorization", "credential", "session_id", "session_token",
    "sid", "jwt",
}
EXACT_PII_FIELDS = {
    "email", "e_mail", "phone", "mobile", "telephone", "tel", "address",
    "street_address", "postal_address", "billing_address", "shipping_address",
    "dob", "birthdate", "date_of_birth", "national_id", "identity_number",
    "id_card", "passport_number", "ssn", "first_name", "last_name", "full_name",
    "person_name", "candidate_name", "gender", "sex", "nationality",
}
EXACT_FINANCIAL_FIELDS = {
    "bank_account", "account_number", "iban", "routing_number", "card_number",
    "credit_card_number", "debit_card_number", "credit_card", "debit_card",
    "pan", "cvv", "cvc", "billing_address", "payment_details", "payment_method",
    "transaction_details", "custom_payment_method_data", "external_payment_method_data",
    "wallet", "salary", "pension", "tax", "invoice",
}
EXACT_ACCESS_ID_FIELDS = {
    "user_id", "uid", "customer_id", "account_id", "member_id", "owner_id",
    "resource_id", "subject_id", "profile_id", "tenant_id",
}
CATEGORY_ORDER = [
    "Login credentials",
    "Personal information (PII)",
    "Financial information",
    "Account / resource identifiers (access-control review)",
]


def field_leaf(field_name: str) -> str:
    """Return the final JSON property, dropping numeric array indexes."""
    value = field_name.strip().lower()
    # WAScope uses dot notation for nested keys and array indexes.
    parts = [part for part in re.split(r"[./]", value) if part and not part.isdigit()]
    return parts[-1] if parts else value


def is_metadata_branch(field_name: str) -> bool:
    first = re.split(r"[./]", field_name.strip(), maxsplit=1)[0].lower()
    return first in EXCLUDED_METADATA_ROOTS


def qi(identifier: str) -> str:
    """Quote an SQLite identifier safely."""
    return '"' + identifier.replace('"', '""') + '"'


def normalise_host(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urlsplit(raw if "://" in raw else "//" + raw)
    return (parsed.hostname or raw).lower()


def safe_endpoint(value: Any) -> str:
    """Keep host/path only. Remove query strings and fragments."""
    raw = str(value or "").strip()
    if not raw:
        return "(unknown endpoint)"
    parsed = urlsplit(raw if "://" in raw else "//" + raw)
    host = parsed.netloc or parsed.hostname or ""
    path = parsed.path or "/"
    # Mask obvious dynamic IDs in paths.
    path = re.sub(r"(?i)(?<=/)[0-9a-f]{8}-[0-9a-f-]{27,}(?=/|$)", "{uuid}", path)
    path = re.sub(r"(?<=/)\d+(?=/|$)", "{id}", path)
    return f"{host}{path}" if host else path


def extract_names(raw: Any) -> set[str]:
    """Extract JSON object keys/list labels only; never return associated values."""
    if raw is None:
        return set()
    text = str(raw).strip()
    if not text:
        return set()
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return set()

    names: set[str] = set()
    if isinstance(value, dict):
        # WAScope sensitive maps use matched field labels as object keys.
        names.update(str(key).strip() for key in value.keys())
    elif isinstance(value, list):
        # Some Analyzer outputs may serialize labels as a list.
        for item in value:
            if isinstance(item, str):
                names.add(item.strip())
            elif isinstance(item, dict):
                names.update(str(key).strip() for key in item.keys())
    return {name for name in names if name and len(name) <= 160}


def classify_field(field_name: str) -> list[str]:
    """Classify a matched response property name; a field may have two labels."""
    if is_metadata_branch(field_name):
        return []

    leaf = field_leaf(field_name)
    # Support controlled suffix forms such as user_email / contact_phone,
    # but avoid loose substring matches (e.g. login-logos.png or feature flags).
    tokens = {token for token in re.split(r"[^a-z0-9]+", leaf) if token}
    labels: list[str] = []

    credential = (
        leaf in EXACT_CREDENTIAL_FIELDS
        or leaf.endswith(("_password", "_passwd", "_passcode", "_pwd", "_token", "_secret", "_api_key"))
        or leaf.endswith(("_session_id", "_session_token"))
        or leaf.endswith(("_username", "_user_name"))
    )
    pii = (
        leaf in EXACT_PII_FIELDS
        or leaf.endswith(("_email", "_e_mail", "_phone", "_mobile", "_telephone", "_address"))
        or leaf.endswith(("_date_of_birth", "_birthdate", "_first_name", "_last_name", "_full_name"))
    )
    financial = (
        leaf in EXACT_FINANCIAL_FIELDS
        or leaf.endswith(("_bank_account", "_account_number", "_card_number", "_payment_details", "_payment_method", "_transaction_details"))
    )
    access_identifier = leaf in EXACT_ACCESS_ID_FIELDS or leaf.endswith(("_user_id", "_customer_id", "_account_id", "_owner_id", "_resource_id"))

    if credential:
        labels.append("Login credentials")
    if pii:
        labels.append("Personal information (PII)")
    if financial:
        labels.append("Financial information")
    if access_identifier:
        labels.append("Account / resource identifiers (access-control review)")
    return labels


def schema_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1].lower() for row in conn.execute(f"PRAGMA table_info({qi(table)})")}


def require_tables(conn: sqlite3.Connection) -> None:
    tables = {row[0].lower() for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    )}
    required = {"request_record", "request_record_second"}
    missing = required - tables
    if missing:
        raise RuntimeError("Missing required WAScope table(s): " + ", ".join(sorted(missing)))

    required_columns = {
        "request_record": {"host", "method", "url", "response_sensitive", "response_exists_sensitive"},
        "request_record_second": {"host", "method", "url", "origin_url", "response_sensitive", "response_exists_sensitive"},
    }
    for table, expected in required_columns.items():
        missing_cols = expected - schema_columns(conn, table)
        if missing_cols:
            raise RuntimeError(f"Table {table} is missing columns: {', '.join(sorted(missing_cols))}")


def positive_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def collect_rows(
    conn: sqlite3.Connection,
    host_filter: str | None,
    include_request_indicators: bool,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    # 1) Original intercepted traffic: response_sensitive is response-side evidence.
    capture_rows = conn.execute("SELECT * FROM request_record").fetchall()
    for row in capture_rows:
        host = normalise_host(row["host"])
        if not host or (host_filter and host != host_filter.lower()):
            continue
        endpoint = safe_endpoint(row["url"])
        method = str(row["method"] or "").upper()
        match_count = positive_int(row["response_exists_sensitive"])
        names = extract_names(row["response_sensitive"])
        for field in sorted(names, key=str.lower):
            categories = classify_field(field)
            for category in categories:
                results.append({
                    "host": host,
                    "method": method,
                    "endpoint": endpoint,
                    "evidence_source": "Captured response",
                    "category": category,
                    "field_name": field,
                    "wascope_response_match_count": match_count,
                    "interpretation": "Response field-name indicator; manually verify the returned value and access context.",
                })

        # 2) Request-side field matches are deliberately labelled separately.
        # They are useful context but must not be represented as leaked data.
        if include_request_indicators:
            for column, label in (
                ("path_sensitive", "Request path indicator"),
                ("get_sensitive", "GET parameter indicator"),
                ("post_sensitive", "POST parameter indicator"),
            ):
                if column not in row.keys():
                    continue
                for field in sorted(extract_names(row[column]), key=str.lower):
                    for category in classify_field(field):
                        results.append({
                            "host": host,
                            "method": method,
                            "endpoint": endpoint,
                            "evidence_source": label,
                            "category": category,
                            "field_name": field,
                            "wascope_response_match_count": 0,
                            "interpretation": "Request-side parameter indicator only; this is NOT proof that the server leaked data.",
                        })

    # 3) Replay traffic: strongest response-side candidate signal available here.
    replay_rows = conn.execute("SELECT * FROM request_record_second").fetchall()
    for row in replay_rows:
        host = normalise_host(row["host"])
        if not host or (host_filter and host != host_filter.lower()):
            continue
        endpoint = safe_endpoint(row["origin_url"] or row["url"])
        method = str(row["method"] or "").upper()
        match_count = positive_int(row["response_exists_sensitive"])
        names = extract_names(row["response_sensitive"])
        for field in sorted(names, key=str.lower):
            categories = classify_field(field)
            for category in categories:
                results.append({
                    "host": host,
                    "method": method,
                    "endpoint": endpoint,
                    "evidence_source": "Replay response",
                    "category": category,
                    "field_name": field,
                    "wascope_response_match_count": match_count,
                    "interpretation": "Replay response field-name indicator; manual authorization and value verification required.",
                })

    return results


def write_outputs(rows: list[dict[str, Any]], output_dir: Path, db_path: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "wascope_leak_classification.csv"
    summary_path = output_dir / "wascope_leak_summary.txt"

    columns = [
        "host", "method", "endpoint", "evidence_source", "category",
        "field_name", "wascope_response_match_count", "interpretation",
    ]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["category"]].append(row)

    lines = [
        "WASCOPE PRIVACY INDICATOR CLASSIFICATION",
        "=" * 72,
        f"Database: {db_path.name}",
        "Database access: READ-ONLY",
        "Values printed/exported: NONE (field names and metadata only)",
        "",
        "IMPORTANT: Category matches indicate field names in stored responses, not confirmed leaks.",
        "Request-side indicators, when enabled, are shown separately and are not leakage evidence.",
        "",
    ]

    for category in CATEGORY_ORDER:
        category_rows = grouped.get(category, [])
        lines.append(f"{category.upper()} ({len(category_rows)} indicator row(s))")
        lines.append("-" * 72)
        if not category_rows:
            lines.append("No matching response field names found.")
        else:
            seen = set()
            for item in category_rows:
                key = (item["host"], item["endpoint"], item["evidence_source"], item["field_name"], item["method"])
                if key in seen:
                    continue
                seen.add(key)
                lines.append(
                    f"[{item['evidence_source']}] {item['host']} | {item['method']} | "
                    f"{item['endpoint']} | field: {item['field_name']}"
                )
        lines.append("")

    lines += [
        "HOW TO INTERPRET THE THREE RESEARCH OBJECTIVES",
        "- Login credentials: matched password/token/session/authentication fields are credential indicators.",
        "- PII: matched identity/contact fields are personal-information indicators.",
        "- Financial: matched bank/card/payment fields are financial-information indicators.",
        "- Account/resource identifiers are separated for access-control review, not automatically called leaks.",
        "- Unauthorized access is NOT established by field names. Verify using controlled accounts and permissions.",
        "- Check field values securely in the application; do not include secrets in the assignment or CSV.",
    ]
    summary_path.write_text("\n".join(lines), encoding="utf-8")
    return csv_path, summary_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Classify WAScope captured/replayed response field names into privacy categories."
    )
    parser.add_argument("--db", required=True, help="Path to wascope.sqlite3")
    parser.add_argument("--host", help="Optional exact host filter, e.g. localhost")
    parser.add_argument("--out", default="wascope_classification_output", help="Output directory")
    parser.add_argument(
        "--include-request-indicators", action="store_true",
        help="Also include path/GET/POST request-side matches (clearly labelled, not leaks).",
    )
    args = parser.parse_args()

    db_path = Path(args.db).expanduser().resolve()
    if not db_path.is_file():
        parser.error(f"Database file not found: {db_path}")

    try:
        uri = db_path.as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        conn.row_factory = sqlite3.Row
        try:
            require_tables(conn)
            rows = collect_rows(conn, args.host, args.include_request_indicators)
        finally:
            conn.close()

        output_dir = Path(args.out).expanduser().resolve()
        csv_path, summary_path = write_outputs(rows, output_dir, db_path)

        totals = Counter(row["category"] for row in rows)
        hosts = sorted({row["host"] for row in rows})
        endpoints = sorted({(row["host"], row["endpoint"]) for row in rows})

        print("\nWAScope classification completed")
        print("=" * 48)
        print(f"Database: {db_path}")
        print(f"Categorized indicator rows: {len(rows)}")
        print(f"Hosts with category indicators: {len(hosts)}")
        print(f"Distinct host/endpoint pairs: {len(endpoints)}")
        print("\nCategory totals (a field may appear in more than one category):")
        for category in CATEGORY_ORDER:
            print(f"  {category}: {totals.get(category, 0)}")
        print("\nDetected response field names:")
        for category in CATEGORY_ORDER:
            category_rows = [row for row in rows if row["category"] == category]
            unique_items = sorted({
                (row["evidence_source"], row["host"], row["endpoint"], row["field_name"])
                for row in category_rows
            })
            print(f"\n{category}:")
            if not unique_items:
                print("  No matching response field names found.")
            for source, host, endpoint, field_name in unique_items:
                print(f"  [{source}] {host} | {endpoint} | {field_name}")
        print("\nOutput files:")
        print(f"  CSV: {csv_path}")
        print(f"  Summary: {summary_path}")
        print("\nNo field values, cookies, passwords, tokens or raw response bodies were printed.")
        print("Remember: these are candidate field-name indicators, not confirmed vulnerabilities.")
        return 0
    except (sqlite3.Error, RuntimeError, OSError) as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
