#!/usr/bin/env python3
"""
Fetch newly published / modified CVEs from NVD, enrich with CISA KEV and EPSS,
apply the watchlist, and write a dated JSON snapshot to data/.

Usage:
    python scripts/fetch_vulns.py                # last 24h, ending now (UTC)
    python scripts/fetch_vulns.py --hours 48     # wider window (e.g. after a missed run)
    python scripts/fetch_vulns.py --date 2026-09-10  # backfill a specific day

Environment:
    NVD_API_KEY   optional, raises NVD rate limit from 5 to 50 req / 30 s
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
CONFIG = ROOT / "config" / "watchlist.yml"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "vuln-daily-report/1.0"})


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def nvd_ts(dt: datetime) -> str:
    """NVD wants ISO-8601 with milliseconds and no timezone suffix (UTC assumed)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def get_with_retry(url, params=None, headers=None, tries=5, backoff=6):
    for attempt in range(1, tries + 1):
        try:
            r = SESSION.get(url, params=params, headers=headers, timeout=60)
            if r.status_code == 200:
                return r
            if r.status_code in (403, 429, 503):
                wait = backoff * attempt
                print(f"  {r.status_code} from {url} - retrying in {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            r.raise_for_status()
        except requests.RequestException as e:
            print(f"  request error: {e} - attempt {attempt}/{tries}", file=sys.stderr)
            time.sleep(backoff * attempt)
    raise RuntimeError(f"Failed to fetch {url} after {tries} attempts")


def load_watchlist():
    if not CONFIG.exists():
        return {"keywords": [], "min_cvss": 0.0}
    with open(CONFIG) as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("keywords", [])
    cfg.setdefault("min_cvss", 0.0)
    cfg["keywords"] = [k.lower() for k in cfg["keywords"]]
    return cfg


# --------------------------------------------------------------------------- #
# NVD
# --------------------------------------------------------------------------- #
def fetch_nvd(start: datetime, end: datetime, date_field: str):
    """date_field is 'pub' (newly published) or 'lastMod' (published or modified)."""
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    sleep_between = 1.0 if api_key else 7.0  # stay under 5 req / 30 s without a key

    params = {
        f"{date_field}StartDate": nvd_ts(start),
        f"{date_field}EndDate": nvd_ts(end),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    items = []
    while True:
        r = get_with_retry(NVD_URL, params=params, headers=headers)
        payload = r.json()
        items.extend(payload.get("vulnerabilities", []))
        total = payload.get("totalResults", 0)
        params["startIndex"] += payload.get("resultsPerPage", 2000)
        print(f"  NVD ({date_field}): {len(items)}/{total}")
        if params["startIndex"] >= total:
            break
        time.sleep(sleep_between)
    return items


def parse_cvss(metrics: dict):
    """Return (score, severity, vector, version) preferring v4.0 > v3.1 > v3.0 > v2."""
    for key, ver in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key) or []
        if not entries:
            continue
        # Prefer the NVD-authored entry when several exist
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return score, (severity or "").upper(), data.get("vectorString", ""), ver
    return None, "", "", ""


def normalise_nvd(item: dict) -> dict:
    cve = item["cve"]
    desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    score, severity, vector, ver = parse_cvss(cve.get("metrics", {}))
    cwes = sorted(
        {
            d["value"]
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("value", "").startswith("CWE-")
        }
    )
    refs = [r["url"] for r in cve.get("references", [])][:5]
    # Vendor/product hints from CPE configurations (best effort)
    products = set()
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) > 4:
                    products.add(f"{parts[3]}:{parts[4]}")
    return {
        "cve_id": cve["id"],
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "status": cve.get("vulnStatus", ""),
        "cvss_score": score,
        "cvss_severity": severity,
        "cvss_vector": vector,
        "cvss_version": ver,
        "cwe": ", ".join(cwes),
        "vendor_product": ", ".join(sorted(products)[:10]),
        "description": desc,
        "references": refs,
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
    }


# --------------------------------------------------------------------------- #
# CISA KEV
# --------------------------------------------------------------------------- #
def fetch_kev() -> dict:
    r = get_with_retry(KEV_URL)
    data = r.json()
    print(f"  KEV catalogue: {len(data.get('vulnerabilities', []))} entries")
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}


# --------------------------------------------------------------------------- #
# EPSS
# --------------------------------------------------------------------------- #
def fetch_epss(cve_ids):
    """Exploit Prediction Scoring System from FIRST. Batched, best effort."""
    scores = {}
    ids = list(cve_ids)
    for i in range(0, len(ids), 100):
        batch = ids[i : i + 100]
        try:
            r = get_with_retry(EPSS_URL, params={"cve": ",".join(batch)}, tries=2)
            for row in r.json().get("data", []):
                scores[row["cve"]] = {
                    "epss": float(row.get("epss", 0)),
                    "epss_percentile": float(row.get("percentile", 0)),
                }
        except Exception as e:  # EPSS is enrichment only; never fail the run on it
            print(f"  EPSS batch failed: {e}", file=sys.stderr)
        time.sleep(1)
    print(f"  EPSS: scored {len(scores)}/{len(ids)}")
    return scores


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=24, help="lookback window in hours")
    ap.add_argument("--date", help="YYYY-MM-DD: fetch that calendar day (UTC) instead")
    args = ap.parse_args()

    if args.date:
        start = datetime.strptime(args.date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        report_date = args.date
    else:
        end = datetime.now(timezone.utc).replace(microsecond=0)
        start = end - timedelta(hours=args.hours)
        report_date = end.strftime("%Y-%m-%d")

    print(f"Window: {start.isoformat()} -> {end.isoformat()}")
    watch = load_watchlist()

    # 1. NVD - newly published and recently modified (union)
    print("Fetching NVD...")
    raw = {}
    for item in fetch_nvd(start, end, "pub"):
        raw[item["cve"]["id"]] = item
    time.sleep(7 if not os.getenv("NVD_API_KEY") else 1)
    for item in fetch_nvd(start, end, "lastMod"):
        raw.setdefault(item["cve"]["id"], item)
    records = [normalise_nvd(v) for v in raw.values()]
    print(f"  {len(records)} unique CVEs in window")

    # 2. KEV - flag anything in the catalogue, and add KEV entries added today
    print("Fetching CISA KEV...")
    kev = fetch_kev()
    seen = {r["cve_id"] for r in records}
    for cve_id, k in kev.items():
        if k.get("dateAdded") >= start.strftime("%Y-%m-%d") and cve_id not in seen:
            # KEV added a CVE we didn't pull (older CVE, newly exploited) - include it
            records.append(
                {
                    "cve_id": cve_id,
                    "published": "",
                    "last_modified": "",
                    "status": "KEV",
                    "cvss_score": None,
                    "cvss_severity": "",
                    "cvss_vector": "",
                    "cvss_version": "",
                    "cwe": "",
                    "vendor_product": f"{k.get('vendorProject','')}:{k.get('product','')}".lower(),
                    "description": k.get("shortDescription", ""),
                    "references": [],
                    "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
            )
    for r in records:
        k = kev.get(r["cve_id"])
        r["kev"] = bool(k)
        r["kev_date_added"] = k.get("dateAdded", "") if k else ""
        r["kev_due_date"] = k.get("dueDate", "") if k else ""
        r["kev_required_action"] = k.get("requiredAction", "") if k else ""
        r["kev_ransomware"] = (k.get("knownRansomwareCampaignUse", "") if k else "") == "Known"
        if k and not r["vendor_product"]:
            r["vendor_product"] = f"{k.get('vendorProject','')}:{k.get('product','')}".lower()

    # 3. EPSS
    print("Fetching EPSS...")
    epss = fetch_epss([r["cve_id"] for r in records])
    for r in records:
        e = epss.get(r["cve_id"], {})
        r["epss"] = e.get("epss")
        r["epss_percentile"] = e.get("epss_percentile")

    # 4. Watchlist matching + priority
    for r in records:
        hay = f"{r['description']} {r['vendor_product']}".lower()
        hits = [k for k in watch["keywords"] if k in hay]
        r["watchlist_hits"] = ", ".join(hits)
        r["watchlist_match"] = bool(hits)
        score = r["cvss_score"] or 0
        if r["kev"] or (r["epss"] or 0) >= 0.5:
            r["priority"] = "P1 - Act now"
        elif score >= 9.0 or ((r["epss"] or 0) >= 0.1 and score >= 7.0):
            r["priority"] = "P2 - High"
        elif score >= 7.0:
            r["priority"] = "P3 - Medium"
        else:
            r["priority"] = "P4 - Low / Unscored"

    # 5. Diff against previous snapshot
    prev_files = sorted(DATA_DIR.glob("*.json"))
    prev_ids = set()
    if prev_files:
        with open(prev_files[-1]) as f:
            prev_ids = {r["cve_id"] for r in json.load(f).get("records", [])}
    for r in records:
        r["new_today"] = r["cve_id"] not in prev_ids

    # Sort: KEV first, then CVSS desc
    records.sort(
        key=lambda r: (not r["kev"], -(r["cvss_score"] or 0), r["cve_id"]),
    )

    snapshot = {
        "report_date": report_date,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": {
            "total": len(records),
            "kev": sum(r["kev"] for r in records),
            "critical": sum(r["cvss_severity"] == "CRITICAL" for r in records),
            "high": sum(r["cvss_severity"] == "HIGH" for r in records),
            "medium": sum(r["cvss_severity"] == "MEDIUM" for r in records),
            "low": sum(r["cvss_severity"] == "LOW" for r in records),
            "unscored": sum(r["cvss_score"] is None for r in records),
            "watchlist": sum(r["watchlist_match"] for r in records),
            "new_today": sum(r["new_today"] for r in records),
        },
        "watchlist_keywords": watch["keywords"],
        "records": records,
    }

    DATA_DIR.mkdir(exist_ok=True)
    out = DATA_DIR / f"{report_date}.json"
    with open(out, "w") as f:
        json.dump(snapshot, f, indent=1)
    print(f"Wrote {out}  ({snapshot['counts']})")


if __name__ == "__main__":
    main()
