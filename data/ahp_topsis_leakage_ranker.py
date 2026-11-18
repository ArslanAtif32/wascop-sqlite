#!/usr/bin/env python3
"""WAScope remediation-first prioritisation using AHP + TOPSIS.

Purpose
-------
Convert the field-name indicators exported by wascope_leak_classifier.py into
an actionable remediation plan. Related fields are consolidated into issues,
for example: username/user/email/password/pass/token/session -> Login and
authentication data exposure.

IMPORTANT
---------
* Only response-side indicators are included by default. Request parameters
  such as email/password are not evidence that the API returned those values.
* Email is classified as a login identifier only on a login/authentication
  endpoint; elsewhere it is treated as PII.
* user_id/account_id/customer_id/owner_id are listed separately for access-
  control review. An identifier is not itself proof of broken access control.
* A field-name match is a candidate indicator, not a confirmed vulnerability.
* Renaming a parameter (e.g. changing `email` to `user`) is NOT a security fix.
  The recommendations focus on response minimisation, authorization, secret
  handling and validation.

Run
---
python ahp_topsis_remediation_ranker.py --input wascope_leak_classification.csv
python ahp_topsis_remediation_ranker.py --host cmitinterns.punjab.gov.pk
python ahp_topsis_remediation_ranker.py --include-request-indicators  # review-only

Python 3.9+, standard library only. No network access and no DB writes.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# AHP LEVEL 1: category priority.
# Order: Login/authentication, Financial, Personal/PII.
# Judgment: login credentials are prioritised first because their compromise
# may enable account takeover; financial details are next; general PII follows.
# Saaty ratios: Login/Financial=2, Login/PII=3, Financial/PII=2.
# These are provisional analyst judgments, not expert-validated weights.
# ---------------------------------------------------------------------------
CATEGORY_NAMES = [
    "Login and authentication data",
    "Financial information",
    "Personal information (PII)",
]
CATEGORY_MATRIX = [
    [1,   2,   3],
    [1/2, 1,   2],
    [1/3, 1/2, 1],
]

# ---------------------------------------------------------------------------
# AHP LEVEL 2: endpoint remediation ranking criteria.
# Higher scores mean stronger evidence / higher remediation priority.
# ---------------------------------------------------------------------------
CRITERIA = [
    "Data sensitivity",
    "Evidence strength",
    "Repeatability of indicators",
    "Endpoint exposure proxy",
    "Distinct sensitive fields",
    "Asset criticality proxy",
]
CRITERIA_MATRIX = [
    [1,   2,   3,   4,   5,   3],
    [1/2, 1,   2,   3,   4,   2],
    [1/3, 1/2, 1,   2,   3,   2],
    [1/4, 1/3, 1/2, 1,   2,   1/2],
    [1/5, 1/4, 1/3, 1/2, 1,   1/3],
    [1/3, 1/2, 1/2, 2,   3,   1],
]
RANDOM_INDEX = {1: 0.0, 2: 0.0, 3: 0.58, 4: 0.90, 5: 1.12,
                6: 1.24, 7: 1.32, 8: 1.41, 9: 1.45, 10: 1.49}

ACCESS_CONTROL_CATEGORY = "Account / resource identifiers (access-control review)"

# Field-name patterns. These patterns classify names, not the values.
FINANCIAL_RE = re.compile(
    r"bank|iban|routing_number|account_number|card_number|credit_card|debit_card|"
    r"payment|billing|transaction|wallet|salary|invoice|cvv|cvc|pan|financial|tax",
    re.I,
)
IDENTIFIER_RE = re.compile(
    r"(?:^|[._-])(?:user|account|customer|owner|member|profile|resource)[._-]?(?:id|uuid|key)(?:$|[._-])|"
    r"^(?:account_id|user_id|customer_id|owner_id|member_id|profile_id|resource_id)$",
    re.I,
)
LOGIN_RE = re.compile(
    r"password|passwd|passcode|(?:^|[._-])pass(?:$|[._-])|(?:^|[._-])pwd(?:$|[._-])|username|user_name|(?:^|[._-])user(?:$|[._-])|"
    r"login|auth|access_token|refresh_token|auth_token|captcha_token|client_token|client_secret|"
    r"session|(?:^|[._-])sid(?:$|[._-])|api_key|authorization|credential|secret|jwt",
    re.I,
)
PII_RE = re.compile(
    r"email|e_mail|phone|mobile|telephone|(?:^|[._-])tel(?:$|[._-])|address|street|postal|"
    r"first_name|last_name|full_name|person_name|birth|(?:^|[._-])dob(?:$|[._-])|"
    r"national_id|identity_number|passport|gender|(?:^|[._-])sex(?:$|[._-])|"
    r"nationality|education|student_name",
    re.I,
)
LOGIN_CONTEXT_RE = re.compile(r"login|log-in|sign[_-]?in|auth(?:entication)?", re.I)

REMEDIATION = {
    "Login and authentication data": {
        "issue": "Login / authentication response exposes credential-like field names",
        "action": (
            "Review the login/authentication response. Never return passwords, password hashes, "
            "client secrets, session secrets or reusable authentication tokens to the browser "
            "unless a specific token is deliberately issued for that client. Stop echoing secrets, "
            "rotate/revoke any confirmed exposed tokens, enforce server-side authentication and "
            "authorization, and set session cookies Secure, HttpOnly and an appropriate SameSite policy."
        ),
        "verification": (
            "Inspect the actual redacted response; confirm no password/hash/secret is returned. "
            "Check token scope, expiry and cookie flags. Test unauthenticated and separate test "
            "accounts to ensure responses contain only the requesting user's permitted data."
        ),
        "field_examples": "user, username, email (on login endpoints), password, pass, passwd, pwd, token, session, sid, client_secret, captcha_token",
    },
    "Financial information": {
        "issue": "Financial or payment-related response data may be exposed",
        "action": (
            "Return only the minimum payment metadata required by the client. Do not expose full "
            "card numbers, CVV/CVC, bank details, payment secrets or internal transaction data. "
            "Use the payment provider's tokenisation, mask account/card identifiers, and enforce "
            "object-level authorization on every payment or billing record."
        ),
        "verification": (
            "Inspect actual response values using test data; verify card/bank values are masked or "
            "tokenised, CVV is never retained or returned, and one test account cannot retrieve "
            "another account's payment records."
        ),
        "field_examples": "bank_account, account_number, iban, card_number, payment_details, transaction, wallet, billing, cvv, cvc",
    },
    "Personal information (PII)": {
        "issue": "Personal or contact information may be overexposed in API responses",
        "action": (
            "Apply response-field allowlists and data minimisation. Remove personal fields not "
            "needed by the client, mask contact/identity values where possible, and apply "
            "record-level authorization before returning a person's profile."
        ),
        "verification": (
            "Check whether each returned personal field is necessary. Use two controlled test "
            "accounts to confirm profile, contact and identity data cannot be retrieved across users."
        ),
        "field_examples": "name, email (outside login context), phone, mobile, address, dob, birthdate, national_id, passport, gender",
    },
}


def ahp_weights(matrix: list[list[float]]) -> tuple[list[float], float, float, float]:
    n = len(matrix)
    if not n or any(len(row) != n for row in matrix):
        raise ValueError("AHP matrix must be square")
    for i in range(n):
        if not math.isclose(matrix[i][i], 1.0):
            raise ValueError("AHP diagonal values must be 1")
        for j in range(n):
            if matrix[i][j] <= 0 or not math.isclose(matrix[i][j] * matrix[j][i], 1.0, rel_tol=1e-8, abs_tol=1e-8):
                raise ValueError("AHP matrix must be positive and reciprocal")
    w = [1.0 / n] * n
    for _ in range(10000):
        prod = [sum(matrix[i][j] * w[j] for j in range(n)) for i in range(n)]
        total = sum(prod)
        new = [v / total for v in prod]
        if max(abs(new[i] - w[i]) for i in range(n)) < 1e-13:
            w = new
            break
        w = new
    aw = [sum(matrix[i][j] * w[j] for j in range(n)) for i in range(n)]
    lam = sum(aw[i] / w[i] for i in range(n)) / n
    ci = 0.0 if n <= 2 else max(0.0, (lam - n) / (n - 1))
    ri = RANDOM_INDEX.get(n, 0.0)
    cr = 0.0 if n <= 2 or not ri else ci / ri
    return w, lam, ci, cr


def as_int(value: Any) -> int:
    try:
        return max(0, int(float(value or 0)))
    except (TypeError, ValueError):
        return 0


def is_private_host(host: str) -> bool:
    h = host.lower().strip()
    if h in {"localhost", "127.0.0.1", "::1"} or h.endswith(".localhost"):
        return True
    parts = h.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        a, b, c, d = [int(x) for x in parts]
        if all(0 <= x <= 255 for x in (a, b, c, d)):
            return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
    return False


def asset_score(endpoint: str) -> float:
    p = endpoint.lower()
    if any(x in p for x in ("login", "auth", "session", "token", "payment", "billing", "account", "profile", "user")):
        return 5.0
    if any(x in p for x in ("static", "assets", ".js", ".css", "manifest", "favicon")):
        return 1.5
    if "/api/" in p or "/rest/" in p:
        return 3.5
    return 2.5


def classify_field(field_name: str, endpoint: str) -> str | None:
    raw = field_name.lower().strip()
    # A dotted JSON path may include parent labels such as "payment-element".
    # Classify using the last non-array component first, otherwise a PII leaf
    # like "email" can be incorrectly labelled financial just because a parent
    # object is called "payment-element". Keep full-name checks for compound keys.
    parts = [p for p in re.split(r"[.\[\]/]+", raw) if p and not p.isdigit()]
    leaf = parts[-1] if parts else raw
    login_context = bool(LOGIN_CONTEXT_RE.search(endpoint))
    if FINANCIAL_RE.search(leaf):
        return "Financial information"
    if IDENTIFIER_RE.search(leaf) or IDENTIFIER_RE.search(raw):
        return ACCESS_CONTROL_CATEGORY
    if LOGIN_RE.search(leaf) or LOGIN_RE.search(raw):
        return "Login and authentication data"
    if "email" in leaf and login_context:
        return "Login and authentication data"
    if PII_RE.search(leaf):
        return "Personal information (PII)"
    # Legacy classifier categories are handled as a fallback by normalise_old_category.
    return None


def normalise_old_category(value: str) -> str | None:
    v = value.strip().lower()
    if v in {"login credentials", "login and authentication data", "credential", "credentials"}:
        return "Login and authentication data"
    if v in {"personal information (pii)", "personal information", "pii"}:
        return "Personal information (PII)"
    if v in {"financial information", "financial"}:
        return "Financial information"
    if v == ACCESS_CONTROL_CATEGORY.lower():
        return ACCESS_CONTROL_CATEGORY
    return None


def load_findings(input_path: Path, host_filter: str | None, include_request: bool):
    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    access: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    field_seen = set()
    with input_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        required = {"host", "method", "endpoint", "evidence_source", "category", "field_name"}
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError("Input missing columns: " + ", ".join(sorted(missing)))
        for row in reader:
            host = str(row.get("host", "")).strip().lower()
            if not host or (host_filter and host != host_filter.lower()):
                continue
            method = str(row.get("method", "")).upper().strip()
            endpoint = str(row.get("endpoint", "")).strip() or "(unknown endpoint)"
            source = str(row.get("evidence_source", "")).strip()
            field = str(row.get("field_name", "")).strip()
            if not field:
                continue
            request_side = any(s in source.lower() for s in ("request", "parameter", "path indicator"))
            if request_side and not include_request:
                continue
            category = classify_field(field, endpoint) or normalise_old_category(str(row.get("category", "")))
            if category is None:
                continue
            key = (host, method, endpoint, category)
            bucket = access if category == ACCESS_CONTROL_CATEGORY else grouped
            item = bucket.setdefault(key, {
                "host": host, "method": method, "endpoint": endpoint, "category": category,
                "fields": set(), "captured_rows": 0, "replay_rows": 0,
                "request_rows": 0, "evidence_sources": set(), "match_counts": 0,
            })
            # Deduplicate field list but count distinct evidence rows, including
            # repeat appearances in replay results.
            row_key = (key, field.lower(), source.lower(), str(row.get("wascope_response_match_count", "")))
            if row_key not in field_seen:
                field_seen.add(row_key)
                item["fields"].add(field)
                item["evidence_sources"].add(source)
                if request_side:
                    item["request_rows"] += 1
                elif "replay" in source.lower():
                    item["replay_rows"] += 1
                else:
                    item["captured_rows"] += 1
            item["match_counts"] += as_int(row.get("wascope_response_match_count", 0))
    return list(grouped.values()), list(access.values())


def score_endpoint(item: dict[str, Any], category_weight: float, max_category_weight: float) -> dict[str, float]:
    total_rows = item["captured_rows"] + item["replay_rows"]
    repeatability = min(5.0, 1.0 + math.log2(max(1, total_rows)))
    return {
        "Data sensitivity": 1.0 + 4.0 * category_weight / max_category_weight,
        "Evidence strength": 5.0 if item["replay_rows"] else 3.0,
        "Repeatability of indicators": repeatability,
        "Endpoint exposure proxy": 1.0 if is_private_host(item["host"]) else 4.0,
        "Distinct sensitive fields": float(min(5, max(1, len(item["fields"])))),
        "Asset criticality proxy": asset_score(item["endpoint"]),
    }


def topsis(items: list[dict[str, Any]], weights: list[float]) -> list[dict[str, Any]]:
    if not items:
        return []
    raw = [[float(x["scores"][c]) for c in CRITERIA] for x in items]
    norms = [math.sqrt(sum(row[j] ** 2 for row in raw)) for j in range(len(CRITERIA))]
    norm = [[(raw[i][j] / norms[j] if norms[j] else 0.0) * weights[j] for j in range(len(CRITERIA))] for i in range(len(items))]
    best = [max(row[j] for row in norm) for j in range(len(CRITERIA))]
    worst = [min(row[j] for row in norm) for j in range(len(CRITERIA))]
    result = []
    for i, item in enumerate(items):
        d_best = math.sqrt(sum((norm[i][j] - best[j]) ** 2 for j in range(len(CRITERIA))))
        d_worst = math.sqrt(sum((norm[i][j] - worst[j]) ** 2 for j in range(len(CRITERIA))))
        closeness = d_worst / (d_best + d_worst) if d_best + d_worst else 0.0
        result.append({**item, "topsis_score": closeness * 100.0, "topsis_closeness": closeness})
    result.sort(key=lambda x: (-x["topsis_closeness"], x["category"], x["host"], x["endpoint"]))
    for i, x in enumerate(result, 1):
        x["priority_rank"] = i
    return result


def csv_write(path: Path, rows: list[dict[str, Any]], columns: list[str]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        for row in rows:
            clean = {}
            for c in columns:
                v = row.get(c, "")
                if isinstance(v, (set, list, tuple)):
                    v = "; ".join(str(z) for z in sorted(v, key=str.lower))
                elif isinstance(v, float):
                    v = f"{v:.4f}"
                clean[c] = v
            w.writerow(clean)


def build_outputs(args: argparse.Namespace) -> tuple[int, int]:
    cat_w, cat_lam, cat_ci, cat_cr = ahp_weights(CATEGORY_MATRIX)
    cat_weights = dict(zip(CATEGORY_NAMES, cat_w))
    crit_w, crit_lam, crit_ci, crit_cr = ahp_weights(CRITERIA_MATRIX)
    findings, access_rows = load_findings(args.input, args.host, args.include_request_indicators)
    if not findings:
        raise ValueError("No response-side category indicators found. Check input/host filter; request indicators are excluded by default.")
    max_w = max(cat_weights.values())
    prepared = []
    for item in findings:
        item["scores"] = score_endpoint(item, cat_weights[item["category"]], max_w)
        prepared.append(item)
    ranked = topsis(prepared, crit_w)
    args.output.mkdir(parents=True, exist_ok=True)

    # Detailed ranked table: one row per endpoint + remediation issue.
    detail_rows = []
    detail_columns = [
        "priority_rank", "topsis_score_0_100", "remediation_group", "issue", "host", "method", "endpoint",
        "field_names_to_review", "evidence_sources", "captured_response_rows", "replay_response_rows",
        "category_ahp_weight", *CRITERIA, "recommended_fix", "verification_steps", "status_note",
    ]
    for x in ranked:
        rem = REMEDIATION[x["category"]]
        detail_rows.append({
            "priority_rank": x["priority_rank"], "topsis_score_0_100": x["topsis_score"],
            "remediation_group": x["category"], "issue": rem["issue"], "host": x["host"],
            "method": x["method"], "endpoint": x["endpoint"],
            "field_names_to_review": x["fields"], "evidence_sources": x["evidence_sources"],
            "captured_response_rows": x["captured_rows"], "replay_response_rows": x["replay_rows"],
            "category_ahp_weight": cat_weights[x["category"]], **x["scores"],
            "recommended_fix": rem["action"], "verification_steps": rem["verification"],
            "status_note": "Candidate indicator only; no confirmed unauthorized disclosure established by field names alone.",
        })
    csv_write(args.output / "endpoint_remediation_ranking.csv", detail_rows, detail_columns)

    # Remediation summary: one clean row per action group, in AHP category order.
    summary_rows = []
    for rank, category in enumerate(CATEGORY_NAMES, 1):
        category_items = [x for x in ranked if x["category"] == category]
        if not category_items:
            continue
        fields = set()
        endpoints = set()
        hosts = set()
        replay = captured = 0
        sources = set()
        for x in category_items:
            fields.update(x["fields"])
            endpoints.add(f"{x['method']} {x['endpoint']}")
            hosts.add(x["host"])
            replay += x["replay_rows"]
            captured += x["captured_rows"]
            sources.update(x["evidence_sources"])
        rem = REMEDIATION[category]
        summary_rows.append({
            "fix_priority": rank, "remediation_group": category,
            "category_ahp_weight_percent": cat_weights[category] * 100,
            "endpoint_findings": len(category_items), "unique_endpoints": len(endpoints),
            "unique_hosts": len(hosts), "captured_response_evidence_rows": captured,
            "replay_response_evidence_rows": replay,
            "fields_found": sorted(fields, key=str.lower),
            "common_fields_to_check": REMEDIATION[category]["field_examples"],
            "affected_endpoints": sorted(endpoints, key=str.lower),
            "evidence_sources": sorted(sources, key=str.lower),
            "recommended_fix": rem["action"], "verification_steps": rem["verification"],
            "status": "Review required; not a confirmed vulnerability",
        })
    csv_write(args.output / "remediation_priority_plan.csv", summary_rows, list(summary_rows[0].keys()))

    # Access-control indicators stay separate from the three leakage categories.
    access_rows.sort(key=lambda x: (x["host"], x["endpoint"], sorted(x["fields"], key=str.lower)[0] if x["fields"] else ""))
    access_csv = []
    for x in access_rows:
        access_csv.append({
            "host": x["host"], "method": x["method"], "endpoint": x["endpoint"],
            "identifier_field": x["fields"], "evidence_sources": x["evidence_sources"],
            "review_action": "Use two authorized test accounts. Verify whether changing the object identifier returns another user's record; record only confirmed cross-account access.",
            "status": "Identifier indicator only; access-control weakness not established.",
        })
    if access_csv:
        csv_write(args.output / "access_control_review.csv", access_csv, list(access_csv[0].keys()))
    else:
        csv_write(args.output / "access_control_review.csv", [], ["host", "method", "endpoint", "identifier_field", "evidence_sources", "review_action", "status"])

    csv_write(args.output / "ahp_category_weights.csv", [
        {"fix_priority": i + 1, "category": c, "ahp_weight": cat_weights[c], "weight_percent": cat_weights[c] * 100,
         "judgment": "Provisional; login/authentication first, financial second, PII third. Validate with expert assessment."}
        for i, c in enumerate(CATEGORY_NAMES)
    ], ["fix_priority", "category", "ahp_weight", "weight_percent", "judgment"])
    csv_write(args.output / "ahp_criterion_weights.csv", [
        {"criterion": c, "ahp_weight": w, "weight_percent": w * 100,
         "note": "Transparent heuristic. See README/report for limitations."}
        for c, w in zip(CRITERIA, crit_w)
    ], ["criterion", "ahp_weight", "weight_percent", "note"])

    consistency = {
        "category_level": {"lambda_max": cat_lam, "CI": cat_ci, "CR": cat_cr,
                           "CR_below_0_10": cat_cr < 0.10, "matrix_order": CATEGORY_NAMES,
                           "pairwise_matrix": CATEGORY_MATRIX, "weights": cat_weights},
        "ranking_criteria_level": {"lambda_max": crit_lam, "CI": crit_ci, "CR": crit_cr,
                                   "CR_below_0_10": crit_cr < 0.10, "matrix_order": CRITERIA,
                                   "pairwise_matrix": CRITERIA_MATRIX,
                                   "weights": dict(zip(CRITERIA, crit_w))},
    }
    (args.output / "ahp_consistency_and_matrices.json").write_text(json.dumps(consistency, indent=2), encoding="utf-8")

    # Text report in the requested remediation-first format.
    lines = [
        "WASCOPE REMEDIATION-FIRST PRIORITY REPORT (AHP + TOPSIS)",
        "=" * 78,
        f"Input CSV: {args.input}", f"Host filter: {args.host or 'ALL HOSTS'}",
        f"Endpoint/category findings ranked: {len(ranked)}",
        "Evidence basis: response-side field names only by default.",
        "",
        "FIX THESE CATEGORIES IN THIS ORDER",
        "-" * 78,
    ]
    for x in summary_rows:
        lines.extend([
            f"{x['fix_priority']}. {x['remediation_group']} (AHP weight: {x['category_ahp_weight_percent']:.2f}%)",
            f"   Fields observed in this dataset: {', '.join(x['fields_found']) or 'No field-name indicators found'}",
            f"   Other related field names to inspect: {x['common_fields_to_check']}",
            f"   Affected endpoints: {x['unique_endpoints']} across {x['unique_hosts']} host(s)",
            f"   Response evidence: captured={x['captured_response_evidence_rows']}, replay={x['replay_response_evidence_rows']}",
            f"   Recommended remediation: {x['recommended_fix']}",
            f"   Verification: {x['verification_steps']}",
            "",
        ])
    lines += ["TOP ENDPOINT REMEDIATION FINDINGS", "-" * 78]
    for x in ranked[:15]:
        lines.append(
            f"{x['priority_rank']}. [{x['category']}] {x['host']} | {x['method']} {x['endpoint']} | "
            f"Fields: {', '.join(sorted(x['fields'], key=str.lower))} | TOPSIS={x['topsis_score']:.2f}/100"
        )
    lines += [
        "", "IMPORTANT INTERPRETATION", "-" * 78,
        "Do not rename `email`, `user` or `password` parameters as a security fix. Parameter names are not the root cause.",
        "First determine whether the field occurs in a request or a response. A request-only email/password parameter is expected in many login flows and is not evidence of leakage.",
        "Never return passwords, password hashes, reusable secrets or session tokens in API responses.",
        "Email is assigned to the login group only when its endpoint path indicates login/authentication; otherwise it is treated as PII.",
        "Account/resource identifiers are separated for manual object-level authorization testing.",
        "TOPSIS ranks candidate endpoint/category groups within this dataset. Scores are relative, not probabilities or CVSS values.",
        "AHP judgements and URL/host proxies are provisional. A low CR verifies arithmetic consistency, not empirical validity.",
        "Check target ownership and authorization before testing or making remediation claims.",
    ]
    (args.output / "remediation_priority_report.txt").write_text("\n".join(lines), encoding="utf-8")

    print("Remediation-first AHP-TOPSIS analysis completed.")
    print(f"Ranked endpoint/category findings: {len(ranked)}")
    print(f"Access-control identifier groups for manual review: {len(access_rows)}")
    print(f"AHP category weights: Login={cat_weights[CATEGORY_NAMES[0]]*100:.2f}%, Financial={cat_weights[CATEGORY_NAMES[1]]*100:.2f}%, PII={cat_weights[CATEGORY_NAMES[2]]*100:.2f}%")
    print(f"AHP category CR={cat_cr:.5f}; ranking criteria CR={crit_cr:.5f}")
    print(f"Output folder: {args.output.resolve()}")
    print("Main readable output: remediation_priority_report.txt")
    return len(ranked), len(access_rows)


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    default_input = script_dir / "wascope_leak_classification.csv"
    if not default_input.is_file():
        default_input = script_dir / "wascope_classification_output" / "wascope_leak_classification.csv"
    parser = argparse.ArgumentParser(description="Generate remediation-first WAScope AHP-TOPSIS rankings.")
    parser.add_argument("--input", type=Path, default=default_input, help="Input from wascope_leak_classifier.py")
    parser.add_argument("--output", type=Path, default=script_dir / "ahp_topsis_remediation_results", help="Output folder")
    parser.add_argument("--host", default=None, help="Optional exact host filter")
    parser.add_argument("--include-request-indicators", action="store_true", help="Include request-only names for review; not treated as leakage proof")
    args = parser.parse_args()
    args.input = args.input.expanduser().resolve()
    args.output = args.output.expanduser().resolve()
    if args.host:
        args.host = args.host.strip().lower()
    return args


if __name__ == "__main__":
    try:
        build_outputs(parse_args())
    except (OSError, ValueError, csv.Error) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
