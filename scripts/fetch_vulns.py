#!/usr/bin/env python3
"""
Daily vulnerability fetcher.

Daily-bucket rule:
  - "New" means the advisory/CVE was PUBLISHED inside this report window.
  - Older items are never reclassified as "New" because their lastModified/updated
    timestamp changed.
  - Older items are included only as "Updated" when a security-relevant change is
    detected (for example: CVSS added/changed, severity/vector changed, or a
    remediation/fixed version changed).
  - CISA KEV additions remain a separate "Added to KEV" event.
  - Historical daily snapshots are immutable: a CVE published on Sep 15 remains
    in the Sep 15 snapshot even if it is updated on Sep 16.

Usage:
    python scripts/fetch_vulns.py
    python scripts/fetch_vulns.py --hours 24
    python scripts/fetch_vulns.py --date 2026-09-16
"""
import argparse
import io
import json
import os
import sys
import time
import zipfile
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
VULNRICH_RAW = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"
GHSA_URL = "https://api.github.com/advisories"
OSV_BUCKET = "https://osv-vulnerabilities.storage.googleapis.com"

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "vuln-daily-report/3.0"})


def nvd_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def get_with_retry(url, params=None, headers=None, tries=5, backoff=6, ok404=False):
    for attempt in range(1, tries + 1):
        try:
            r = SESSION.get(url, params=params, headers=headers, timeout=90)
            if r.status_code == 200:
                return r
            if r.status_code == 404:
                if ok404:
                    return None
                raise RuntimeError(
                    f"404 from {url}. For NVD this usually means the API key is invalid "
                    "or not activated."
                )
            if r.status_code in (403, 429, 503):
                wait = backoff * attempt
                print(f"  {r.status_code} from {url} - retrying in {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue
            r.raise_for_status()
        except requests.RequestException as exc:
            print(f"  request error: {exc} - attempt {attempt}/{tries}", file=sys.stderr)
            time.sleep(backoff * attempt)
    raise RuntimeError(f"Failed to fetch {url} after {tries} attempts")


def load_config():
    cfg = {}
    if CONFIG.exists():
        with open(CONFIG, encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}

    cfg.setdefault("keywords", [])
    cfg.setdefault("modified_lookback_days", 30)
    cfg.setdefault("include_updated", True)
    cfg.setdefault("sources", {})
    cfg["sources"].setdefault("vulnrichment", True)
    cfg["sources"].setdefault("ghsa", True)
    cfg["sources"].setdefault("osv", True)
    cfg.setdefault("osv_ecosystems", ["Go", "PyPI", "Maven", "npm", "NuGet"])
    cfg.setdefault("max_enrich_calls", 400)
    cfg["keywords"] = [str(k).lower() for k in cfg["keywords"]]
    return cfg


def blank_record(item_id):
    return {
        "cve_id": item_id,
        "aliases": [],
        "sources": [],
        "reason": "New",
        "published": "",
        "last_modified": "",
        "status": "",
        "cvss_score": None,
        "cvss_severity": "",
        "cvss_vector": "",
        "cvss_version": "",
        "cvss_source": "",
        "cwe": "",
        "vendor_product": "",
        "ecosystem_package": "",
        "patched_version": "",
        "ssvc_exploitation": "",
        "ssvc_automatable": "",
        "description": "",
        "references": [],
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{item_id}" if item_id.startswith("CVE-") else "",
        "advisory_url": "",
        "kev": False,
        "kev_date_added": "",
        "kev_due_date": "",
        "kev_required_action": "",
        "kev_ransomware": False,
        "epss": None,
        "epss_percentile": None,
        "watchlist_hits": "",
        "watchlist_match": False,
        "priority": "P4 - Low / Unscored",
    }


def severity_from_score(score):
    if score is None:
        return ""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return ""


def fetch_nvd(start, end, date_field, api_key):
    headers = {"apiKey": api_key} if api_key else {}
    sleep_between = 1.0 if api_key else 7.0
    params = {
        f"{date_field}StartDate": nvd_ts(start),
        f"{date_field}EndDate": nvd_ts(end),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    items = []
    while True:
        payload = get_with_retry(NVD_URL, params=params, headers=headers).json()
        items.extend(payload.get("vulnerabilities", []))
        total = payload.get("totalResults", 0)
        params["startIndex"] += payload.get("resultsPerPage", 2000)
        print(f"  NVD ({date_field}): {len(items)}/{total}")
        if params["startIndex"] >= total:
            break
        time.sleep(sleep_between)
    return items


def parse_cvss(metrics):
    best = None
    for key, ver in (
        ("cvssMetricV40", "4.0"),
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        for entry in metrics.get(key) or []:
            data = entry.get("cvssData", {})
            score = data.get("baseScore")
            if score is None:
                continue
            rank = 0 if entry.get("type") == "Primary" else 1
            candidate = (
                rank,
                score,
                (data.get("baseSeverity") or entry.get("baseSeverity") or "").upper(),
                data.get("vectorString", ""),
                ver,
                "NVD" if rank == 0 else entry.get("source", "ADP"),
            )
            if best is None or candidate[0] < best[0]:
                best = candidate
        if best and best[0] == 0:
            break

    if not best:
        return None, "", "", "", ""
    _, score, severity, vector, version, source = best
    return score, severity or severity_from_score(score), vector, version, source


def normalise_nvd(item):
    cve = item["cve"]
    record = blank_record(cve["id"])
    record["sources"].append("NVD")
    record["published"] = cve.get("published", "")
    record["last_modified"] = cve.get("lastModified", "")
    record["status"] = cve.get("vulnStatus", "")
    record["description"] = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    (
        record["cvss_score"],
        record["cvss_severity"],
        record["cvss_vector"],
        record["cvss_version"],
        record["cvss_source"],
    ) = parse_cvss(cve.get("metrics", {}))

    record["cwe"] = ", ".join(
        sorted(
            {
                d["value"]
                for weakness in cve.get("weaknesses", [])
                for d in weakness.get("description", [])
                if d.get("value", "").startswith("CWE-")
            }
        )
    )
    record["references"] = [x["url"] for x in cve.get("references", [])][:5]

    products = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) > 4:
                    products.add(f"{parts[3]}:{parts[4]}")
    record["vendor_product"] = ", ".join(sorted(products)[:10])
    return record


def load_previous_snapshot(report_date):
    previous = sorted(p for p in DATA_DIR.glob("*.json") if p.stem < report_date)
    if not previous:
        return {}

    try:
        with open(previous[-1], encoding="utf-8") as f:
            snapshot = json.load(f)
        return {r["cve_id"]: r for r in snapshot.get("records", [])}
    except Exception as exc:
        print(f"  (couldn't read prior snapshot: {exc})", file=sys.stderr)
        return {}


def meaningful_nvd_change(previous, current):
    """Return a short reason only for security-relevant NVD changes."""
    if not previous:
        # If the first time we see an older CVE it is already scored, don't
        # call that a meaningful update unless it was newly published today.
        return ""

    old_score = previous.get("cvss_score")
    new_score = current.get("cvss_score")
    if old_score is None and new_score is not None:
        return "CVSS added"
    if old_score is not None and new_score is not None and float(old_score) != float(new_score):
        return f"CVSS changed ({old_score} → {new_score})"

    if previous.get("cvss_severity") != current.get("cvss_severity"):
        return "Severity changed"

    if previous.get("cvss_vector") != current.get("cvss_vector") and current.get("cvss_vector"):
        return "CVSS vector changed"

    if previous.get("ssvc_exploitation") != current.get("ssvc_exploitation"):
        if current.get("ssvc_exploitation"):
            return "SSVC exploitation changed"

    return ""


def fetch_kev():
    data = get_with_retry(KEV_URL).json()
    print(f"  KEV catalogue: {len(data.get('vulnerabilities', []))} entries")
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}


def fetch_epss(cve_ids):
    scores = {}
    ids = [c for c in cve_ids if c.startswith("CVE-")]
    for i in range(0, len(ids), 100):
        batch = ids[i:i + 100]
        try:
            response = get_with_retry(
                EPSS_URL, params={"cve": ",".join(batch)}, tries=2
            )
            for row in response.json().get("data", []):
                scores[row["cve"]] = (
                    float(row.get("epss", 0)),
                    float(row.get("percentile", 0)),
                )
        except Exception as exc:
            print(f"  EPSS batch failed: {exc}", file=sys.stderr)
        time.sleep(1)
    print(f"  EPSS: scored {len(scores)}/{len(ids)}")
    return scores


def vulnrich_path(cve_id):
    _, year, number = cve_id.split("-")
    return f"{year}/{number[:-3]}xxx/{cve_id}.json"


def enrich_vulnrichment(records, max_calls):
    targets = [
        r for r in records
        if r["cvss_score"] is None and r["cve_id"].startswith("CVE-")
    ][:max_calls]

    hit = 0
    for record in targets:
        try:
            response = get_with_retry(
                f"{VULNRICH_RAW}/{vulnrich_path(record['cve_id'])}",
                tries=2,
                backoff=2,
                ok404=True,
            )
        except Exception as exc:
            print(f"  Vulnrichment {record['cve_id']}: {exc}", file=sys.stderr)
            continue
        if response is None:
            continue

        doc = response.json()
        adps = doc.get("containers", {}).get("adp", [])
        for adp in adps:
            for metric in adp.get("metrics", []):
                for key, version in (
                    ("cvssV4_0", "4.0"),
                    ("cvssV3_1", "3.1"),
                    ("cvssV3_0", "3.0"),
                ):
                    cv = metric.get(key)
                    if cv and cv.get("baseScore") is not None and record["cvss_score"] is None:
                        record["cvss_score"] = cv["baseScore"]
                        record["cvss_severity"] = (
                            cv.get("baseSeverity")
                            or severity_from_score(cv["baseScore"])
                        ).upper()
                        record["cvss_vector"] = cv.get("vectorString", "")
                        record["cvss_version"] = version
                        record["cvss_source"] = "CISA-ADP"

                other = metric.get("other", {})
                if other.get("type") == "ssvc":
                    options = {
                        k: v
                        for option in other.get("content", {}).get("options", [])
                        for k, v in option.items()
                    }
                    record["ssvc_exploitation"] = options.get("Exploitation", "")
                    record["ssvc_automatable"] = options.get("Automatable", "")

            if not record["cwe"]:
                cwes = {
                    d.get("cweId")
                    for pt in adp.get("problemTypes", [])
                    for d in pt.get("descriptions", [])
                    if d.get("cweId")
                }
                record["cwe"] = ", ".join(sorted(cwes))

            if not record["vendor_product"]:
                affected = adp.get("affected", [])
                record["vendor_product"] = ", ".join(
                    sorted(
                        {
                            f"{a.get('vendor', '').lower()}:{a.get('product', '').lower()}"
                            for a in affected
                            if a.get("vendor")
                        }
                    )[:10]
                )

        if adps:
            record["sources"].append("Vulnrichment")
            hit += 1
        time.sleep(0.3)

    print(f"  Vulnrichment: enriched {hit}/{len(targets)} unscored CVEs")


def fetch_ghsa(start, end):
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    out = []
    for field in ("published", "updated"):
        params = {
            field: f"{start.strftime('%Y-%m-%dT%H:%M:%SZ')}..{end.strftime('%Y-%m-%dT%H:%M:%SZ')}",
            "type": "reviewed",
            "per_page": 100,
        }
        url = GHSA_URL
        while url:
            response = get_with_retry(url, params=params, headers=headers, tries=3)
            out.extend(response.json())
            url = response.links.get("next", {}).get("url")
            params = None
            time.sleep(0.5)

    unique = {a["ghsa_id"]: a for a in out}
    print(f"  GHSA: {len(unique)} reviewed advisories")
    return list(unique.values())


def apply_ghsa(record, advisory):
    record["sources"].append("GHSA")
    record["aliases"] = sorted(set(record["aliases"]) | {advisory["ghsa_id"]})
    record["advisory_url"] = advisory.get("html_url", "")

    packages = sorted(
        {
            f"{v['package']['ecosystem']}:{v['package']['name']}"
            for v in advisory.get("vulnerabilities", [])
            if v.get("package")
        }
    )
    fixed = sorted(
        {
            v.get("first_patched_version")
            for v in advisory.get("vulnerabilities", [])
            if v.get("first_patched_version")
        }
    )
    if packages:
        record["ecosystem_package"] = ", ".join(packages[:6])
    if fixed:
        record["patched_version"] = ", ".join(fixed[:6])

    if record["cvss_score"] is None:
        severities = advisory.get("cvss_severities") or {}
        cv = severities.get("cvss_v4") or severities.get("cvss_v3") or advisory.get("cvss") or {}
        if cv.get("score"):
            record["cvss_score"] = cv["score"]
            record["cvss_vector"] = cv.get("vector_string", "") or ""
            record["cvss_version"] = "4.0" if "CVSS:4" in record["cvss_vector"] else "3.1"
            record["cvss_severity"] = (
                advisory.get("severity") or severity_from_score(cv["score"])
            ).upper()
            record["cvss_source"] = "GHSA"

    if not record["cwe"]:
        record["cwe"] = ", ".join(
            c["cwe_id"] for c in (advisory.get("cwes") or [])[:5]
        )


def ghsa_changed(previous, current):
    if not previous:
        return ""

    if previous.get("patched_version") != current.get("patched_version") and current.get("patched_version"):
        return "Fix/version updated"

    if previous.get("cvss_score") != current.get("cvss_score"):
        return "CVSS changed"

    if previous.get("cvss_severity") != current.get("cvss_severity"):
        return "Severity changed"

    return ""


def merge_ghsa(records_by_id, advisories, start_iso, previous):
    for advisory in advisories:
        cve = advisory.get("cve_id")
        key = cve or advisory["ghsa_id"]
        published = advisory.get("published", "")
        is_new = published >= start_iso

        if key in records_by_id:
            record = records_by_id[key]
            old = previous.get(key)
            before = dict(record)
            apply_ghsa(record, advisory)
            if not is_new and record.get("reason") != "New":
                change = ghsa_changed(old, record)
                if change:
                    record["reason"] = f"Updated - {change}"
            continue

        record = blank_record(key)
        record["published"] = published
        record["last_modified"] = advisory.get("updated", "")
        record["status"] = "GHSA"
        record["description"] = advisory.get("description") or advisory.get("summary", "")
        apply_ghsa(record, advisory)

        if is_new:
            record["reason"] = "New"
            records_by_id[key] = record
        else:
            change = ghsa_changed(previous.get(key), record)
            if change:
                record["reason"] = f"Updated - {change}"
                records_by_id[key] = record


def fetch_osv(ecosystems, start, end):
    """OSV is intentionally bucketed by published date, not modified date."""
    entries = []
    lo = start.strftime("%Y-%m-%dT%H:%M:%S")
    hi = end.strftime("%Y-%m-%dT%H:%M:%S")

    for ecosystem in ecosystems:
        url = f"{OSV_BUCKET}/{ecosystem}/all.zip"
        try:
            response = get_with_retry(url, tries=2, ok404=True)
        except Exception as exc:
            print(f"  OSV {ecosystem}: {exc}", file=sys.stderr)
            continue
        if response is None:
            print(f"  OSV {ecosystem}: no dump found", file=sys.stderr)
            continue

        count = 0
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            for name in archive.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    vulnerability = json.loads(archive.read(name))
                except Exception:
                    continue

                stamp = (vulnerability.get("published") or vulnerability.get("modified") or "")[:19]
                if lo <= stamp < hi:
                    vulnerability["_ecosystem"] = ecosystem
                    entries.append(vulnerability)
                    count += 1

        print(f"  OSV {ecosystem}: {count} entries published in window")

    return entries


def merge_osv(records_by_id, entries, start_iso):
    for vulnerability in entries:
        ids = [vulnerability["id"]] + vulnerability.get("aliases", [])
        cve = next((i for i in ids if i.startswith("CVE-")), None)
        ghsa = next((i for i in ids if i.startswith("GHSA-")), None)
        key = cve or ghsa or vulnerability["id"]

        record = records_by_id.get(key)
        if record is None and ghsa and ghsa in records_by_id:
            record = records_by_id[ghsa]

        if record is None:
            record = blank_record(key)
            record["published"] = vulnerability.get("published", "")
            record["last_modified"] = vulnerability.get("modified", "")
            record["status"] = "OSV"
            record["description"] = vulnerability.get("details") or vulnerability.get("summary", "")
            record["reason"] = "New"
            records_by_id[key] = record

        record["sources"].append("OSV")
        record["aliases"] = sorted(set(record["aliases"]) | {i for i in ids if i != record["cve_id"]})
        if not record["advisory_url"]:
            record["advisory_url"] = f"https://osv.dev/vulnerability/{vulnerability['id']}"

        packages, fixed = set(), set()
        for affected in vulnerability.get("affected", []):
            package = affected.get("package", {})
            if package.get("name"):
                packages.add(f"{package.get('ecosystem', vulnerability['_ecosystem'])}:{package['name']}")
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if event.get("fixed"):
                        fixed.add(event["fixed"])

        if packages and not record["ecosystem_package"]:
            record["ecosystem_package"] = ", ".join(sorted(packages)[:6])
        if fixed and not record["patched_version"]:
            record["patched_version"] = ", ".join(sorted(fixed)[:6])

        if record["cvss_score"] is None and not record["cvss_vector"]:
            for severity in vulnerability.get("severity", []):
                if str(severity.get("type", "")).startswith("CVSS") and severity.get("score"):
                    record["cvss_vector"] = severity["score"]
                    record["cvss_severity"] = (
                        (vulnerability.get("database_specific") or {}).get("severity") or ""
                    ).upper()
                    record["cvss_source"] = "OSV"
                    break


def priority_for(record):
    score = record["cvss_score"] or 0
    epss = record["epss"] or 0

    if record["kev"] or epss >= 0.5 or record["ssvc_exploitation"] == "active":
        return "P1 - Act now"
    if score >= 9.0 or (epss >= 0.1 and score >= 7.0) or record["ssvc_exploitation"] == "poc":
        return "P2 - High"
    if score >= 7.0:
        return "P3 - Medium"
    return "P4 - Low / Unscored"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--date", help="YYYY-MM-DD: fetch that UTC calendar day")
    args = parser.parse_args()

    if args.date:
        start = datetime.strptime(args.date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        end = start + timedelta(days=1)
        report_date = args.date
    else:
        end = datetime.now(timezone.utc).replace(microsecond=0)
        start = end - timedelta(hours=args.hours)
        report_date = end.strftime("%Y-%m-%d")

    start_iso = start.strftime("%Y-%m-%dT%H:%M:%S")
    print(f"Window: {start.isoformat()} -> {end.isoformat()}")

    cfg = load_config()
    api_key = (os.getenv("NVD_API_KEY") or "").strip()
    previous = load_previous_snapshot(report_date)

    print(f"  NVD API key: {'yes' if api_key else 'no - public rate limit'}")

    # ------------------------------------------------------------------
    # 1. NVD NEW: published date is the daily bucket.
    # ------------------------------------------------------------------
    records_by_id = {}
    for item in fetch_nvd(start, end, "pub", api_key):
        record = normalise_nvd(item)
        record["reason"] = "New"
        records_by_id[record["cve_id"]] = record

    n_new = len(records_by_id)
    n_updated = 0

    # ------------------------------------------------------------------
    # 2. NVD UPDATES: modified date is used ONLY to discover candidates.
    #    An older CVE is added only if a meaningful security field changed.
    # ------------------------------------------------------------------
    if cfg["include_updated"]:
        time.sleep(1 if api_key else 7)
        cutoff = (
            end - timedelta(days=cfg["modified_lookback_days"])
        ).strftime("%Y-%m-%dT%H:%M:%S")

        for item in fetch_nvd(start, end, "lastMod", api_key):
            cid = item["cve"]["id"]

            # Already present because it was genuinely published today.
            if cid in records_by_id:
                continue

            published = item["cve"].get("published", "")[:19]
            if not published or published < cutoff:
                continue

            current = normalise_nvd(item)
            old = previous.get(cid)
            change = meaningful_nvd_change(old, current)

            if not change:
                continue

            current["reason"] = f"Updated - {change}"
            records_by_id[cid] = current
            n_updated += 1

    print(f"  NVD: {n_new} new, {n_updated} meaningful updates")

    # ------------------------------------------------------------------
    # 3. KEV
    # ------------------------------------------------------------------
    print("Fetching CISA KEV...")
    kev = fetch_kev()

    for cve_id, item in kev.items():
        if (
            item.get("dateAdded", "") >= start.strftime("%Y-%m-%d")
            and cve_id not in records_by_id
        ):
            record = blank_record(cve_id)
            record["reason"] = "Added to KEV"
            record["status"] = "KEV"
            record["description"] = item.get("shortDescription", "")
            record["vendor_product"] = (
                f"{item.get('vendorProject', '')}:{item.get('product', '')}".lower()
            )
            records_by_id[cve_id] = record

    for record in records_by_id.values():
        item = kev.get(record["cve_id"])
        if item:
            record["sources"].append("KEV")
            record["kev"] = True
            record["kev_date_added"] = item.get("dateAdded", "")
            record["kev_due_date"] = item.get("dueDate", "")
            record["kev_required_action"] = item.get("requiredAction", "")
            record["kev_ransomware"] = (
                item.get("knownRansomwareCampaignUse", "") == "Known"
            )
            if not record["vendor_product"]:
                record["vendor_product"] = (
                    f"{item.get('vendorProject', '')}:{item.get('product', '')}".lower()
                )

    # ------------------------------------------------------------------
    # 4. Vulnrichment
    # ------------------------------------------------------------------
    if cfg["sources"]["vulnrichment"]:
        print("Fetching CISA Vulnrichment...")
        try:
            enrich_vulnrichment(
                list(records_by_id.values()),
                cfg["max_enrich_calls"],
            )
        except Exception as exc:
            print(f"  Vulnrichment failed: {exc}", file=sys.stderr)

    # ------------------------------------------------------------------
    # 5. GHSA
    # ------------------------------------------------------------------
    if cfg["sources"]["ghsa"]:
        print("Fetching GitHub Security Advisories...")
        try:
            merge_ghsa(
                records_by_id,
                fetch_ghsa(start, end),
                start_iso,
                previous,
            )
        except Exception as exc:
            print(f"  GHSA failed: {exc}", file=sys.stderr)

    # ------------------------------------------------------------------
    # 6. OSV: published date only
    # ------------------------------------------------------------------
    if cfg["sources"]["osv"] and cfg["osv_ecosystems"]:
        print("Fetching OSV.dev...")
        try:
            merge_osv(
                records_by_id,
                fetch_osv(cfg["osv_ecosystems"], start, end),
                start_iso,
            )
        except Exception as exc:
            print(f"  OSV failed: {exc}", file=sys.stderr)

    records = list(records_by_id.values())

    # ------------------------------------------------------------------
    # 7. EPSS
    # ------------------------------------------------------------------
    print("Fetching EPSS...")
    epss = fetch_epss([r["cve_id"] for r in records])
    for record in records:
        if record["cve_id"] in epss:
            record["epss"], record["epss_percentile"] = epss[record["cve_id"]]

    # ------------------------------------------------------------------
    # 8. Watchlist + priority
    # ------------------------------------------------------------------
    for record in records:
        record["sources"] = sorted(set(record["sources"]))
        target = f"{record['vendor_product']} {record['ecosystem_package']}".lower()
        if not target.strip():
            target = record["description"].lower()

        hits = [k for k in cfg["keywords"] if k in target]
        record["watchlist_hits"] = ", ".join(hits)
        record["watchlist_match"] = bool(hits)
        record["priority"] = priority_for(record)

    # New first, then updated/KEV, with highest priority first.
    reason_rank = {
        "New": 0,
        "Added to KEV": 1,
    }
    records.sort(
        key=lambda r: (
            reason_rank.get(r["reason"].split(" - ")[0], 2),
            r["priority"],
            -(r["cvss_score"] or 0),
            r["cve_id"],
        )
    )

    snapshot = {
        "report_date": report_date,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": {
            "total": len(records),
            "new": sum(r["reason"] == "New" for r in records),
            "updated": sum(r["reason"].startswith("Updated") for r in records),
            "kev_added": sum(r["reason"] == "Added to KEV" for r in records),
            "kev": sum(r["kev"] for r in records),
            "critical": sum(r["cvss_severity"] == "CRITICAL" for r in records),
            "high": sum(r["cvss_severity"] == "HIGH" for r in records),
            "medium": sum(r["cvss_severity"] == "MEDIUM" for r in records),
            "low": sum(r["cvss_severity"] == "LOW" for r in records),
            "unscored": sum(r["cvss_score"] is None for r in records),
            "watchlist": sum(r["watchlist_match"] for r in records),
            "ghsa": sum("GHSA" in r["sources"] for r in records),
            "osv": sum("OSV" in r["sources"] for r in records),
        },
        "watchlist_keywords": cfg["keywords"],
        "sources_enabled": [s for s, on in cfg["sources"].items() if on] + ["nvd", "kev", "epss"],
        "records": records,
    }

    DATA_DIR.mkdir(exist_ok=True)
    output = DATA_DIR / f"{report_date}.json"
    with open(output, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=1)

    print(f"Wrote {output}")
    print(snapshot["counts"])


if __name__ == "__main__":
    main()
