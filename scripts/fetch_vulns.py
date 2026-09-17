#!/usr/bin/env python3
"""
Daily vulnerability fetcher.

Sources
  NVD            new CVEs published in the window (+ CVEs published in the last
                 N days that were modified in the window - "Updated" rows)
  CISA KEV       actively exploited flag, due dates; KEV additions become rows
  FIRST EPSS     exploit probability
  Vulnrichment   CISA ADP scoring/SSVC for CVEs NVD hasn't scored yet
  GHSA           GitHub Security Advisories - package ecosystem, fixed version
  OSV.dev        additional ecosystems (configurable), aliases, fixed versions

Usage
  python scripts/fetch_vulns.py                  # last 24h
  python scripts/fetch_vulns.py --hours 48
  python scripts/fetch_vulns.py --date 2026-09-16

Environment
  NVD_API_KEY    optional; 50 req/30s instead of 5
  GITHUB_TOKEN   optional; set automatically in Actions - raises GHSA rate limit
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
SESSION.headers.update({"User-Agent": "vuln-daily-report/2.0"})


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def nvd_ts(dt: datetime) -> str:
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
                msg = r.headers.get("message", "")
                raise RuntimeError(
                    f"404 from {url}. Header message: '{msg}'. For NVD this usually means "
                    f"NVD_API_KEY is invalid or not activated - remove the secret or request a "
                    f"new key at https://nvd.nist.gov/developers/request-an-api-key"
                )
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


def load_config():
    cfg = {}
    if CONFIG.exists():
        with open(CONFIG) as f:
            cfg = yaml.safe_load(f) or {}
    cfg.setdefault("keywords", [])
    cfg.setdefault("min_cvss", 0.0)
    cfg.setdefault("modified_lookback_days", 30)
    cfg.setdefault("include_updated", True)
    cfg.setdefault("sources", {})
    cfg["sources"].setdefault("vulnrichment", True)
    cfg["sources"].setdefault("ghsa", True)
    cfg["sources"].setdefault("osv", True)
    cfg.setdefault("osv_ecosystems", ["Go", "PyPI", "Maven", "npm", "NuGet"])
    cfg.setdefault("max_enrich_calls", 400)
    cfg["keywords"] = [k.lower() for k in cfg["keywords"]]
    return cfg


def blank_record(cve_id: str) -> dict:
    return {
        "cve_id": cve_id,
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
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id.startswith("CVE-") else "",
        "advisory_url": "",
        "kev": False,
        "kev_date_added": "",
        "kev_due_date": "",
        "kev_required_action": "",
        "kev_ransomware": False,
        "epss": None,
        "epss_percentile": None,
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


# --------------------------------------------------------------------------- #
# NVD
# --------------------------------------------------------------------------- #
def fetch_nvd(start: datetime, end: datetime, date_field: str, api_key: str):
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


def parse_cvss(metrics: dict):
    """(score, severity, vector, version, source) preferring NVD Primary, then any."""
    best = None
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        for e in metrics.get(key) or []:
            data = e.get("cvssData", {})
            score = data.get("baseScore")
            if score is None:
                continue
            rank = 0 if e.get("type") == "Primary" else 1
            cand = (rank, score, (data.get("baseSeverity") or e.get("baseSeverity") or "").upper(),
                    data.get("vectorString", ""), ver, "NVD" if rank == 0 else e.get("source", "ADP"))
            if best is None or cand[0] < best[0]:
                best = cand
        if best and best[0] == 0:
            break
    if not best:
        return None, "", "", "", ""
    _, score, sev, vec, ver, src = best
    return score, sev or severity_from_score(score), vec, ver, src


def normalise_nvd(item: dict) -> dict:
    cve = item["cve"]
    r = blank_record(cve["id"])
    r["sources"].append("NVD")
    r["published"] = cve.get("published", "")
    r["last_modified"] = cve.get("lastModified", "")
    r["status"] = cve.get("vulnStatus", "")
    r["description"] = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    r["cvss_score"], r["cvss_severity"], r["cvss_vector"], r["cvss_version"], r["cvss_source"] = parse_cvss(cve.get("metrics", {}))
    r["cwe"] = ", ".join(sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", []) if d.get("value", "").startswith("CWE-")}))
    r["references"] = [x["url"] for x in cve.get("references", [])][:5]
    products = set()
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) > 4:
                    products.add(f"{parts[3]}:{parts[4]}")
    r["vendor_product"] = ", ".join(sorted(products)[:10])
    return r


# --------------------------------------------------------------------------- #
# CISA KEV
# --------------------------------------------------------------------------- #
def fetch_kev() -> dict:
    data = get_with_retry(KEV_URL).json()
    print(f"  KEV catalogue: {len(data.get('vulnerabilities', []))} entries")
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}


# --------------------------------------------------------------------------- #
# EPSS
# --------------------------------------------------------------------------- #
def fetch_epss(cve_ids):
    scores = {}
    ids = [c for c in cve_ids if c.startswith("CVE-")]
    for i in range(0, len(ids), 100):
        batch = ids[i : i + 100]
        try:
            r = get_with_retry(EPSS_URL, params={"cve": ",".join(batch)}, tries=2)
            for row in r.json().get("data", []):
                scores[row["cve"]] = (float(row.get("epss", 0)), float(row.get("percentile", 0)))
        except Exception as e:
            print(f"  EPSS batch failed: {e}", file=sys.stderr)
        time.sleep(1)
    print(f"  EPSS: scored {len(scores)}/{len(ids)}")
    return scores


# --------------------------------------------------------------------------- #
# CISA Vulnrichment (only for CVEs NVD hasn't scored)
# --------------------------------------------------------------------------- #
def vulnrich_path(cve_id: str) -> str:
    _, year, num = cve_id.split("-")
    return f"{year}/{num[:-3]}xxx/{cve_id}.json"


def enrich_vulnrichment(records, max_calls):
    targets = [r for r in records if r["cvss_score"] is None and r["cve_id"].startswith("CVE-")][:max_calls]
    hit = 0
    for r in targets:
        try:
            resp = get_with_retry(f"{VULNRICH_RAW}/{vulnrich_path(r['cve_id'])}", tries=2, backoff=2, ok404=True)
        except Exception as e:
            print(f"  Vulnrichment {r['cve_id']}: {e}", file=sys.stderr)
            continue
        if resp is None:
            continue
        doc = resp.json()
        adps = doc.get("containers", {}).get("adp", [])
        for adp in adps:
            for m in adp.get("metrics", []):
                for key, ver in (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0")):
                    c = m.get(key)
                    if c and c.get("baseScore") is not None and r["cvss_score"] is None:
                        r["cvss_score"] = c["baseScore"]
                        r["cvss_severity"] = (c.get("baseSeverity") or severity_from_score(c["baseScore"])).upper()
                        r["cvss_vector"] = c.get("vectorString", "")
                        r["cvss_version"] = ver
                        r["cvss_source"] = "CISA-ADP"
                other = m.get("other", {})
                if other.get("type") == "ssvc":
                    opts = {k: v for o in other.get("content", {}).get("options", []) for k, v in o.items()}
                    r["ssvc_exploitation"] = opts.get("Exploitation", "")
                    r["ssvc_automatable"] = opts.get("Automatable", "")
            if not r["cwe"]:
                cwes = {d.get("cweId") for pt in adp.get("problemTypes", []) for d in pt.get("descriptions", []) if d.get("cweId")}
                r["cwe"] = ", ".join(sorted(cwes))
            if not r["vendor_product"]:
                aff = adp.get("affected", [])
                r["vendor_product"] = ", ".join(sorted({f"{a.get('vendor','').lower()}:{a.get('product','').lower()}" for a in aff if a.get("vendor")})[:10])
        if adps:
            r["sources"].append("Vulnrichment")
            hit += 1
        time.sleep(0.3)
    print(f"  Vulnrichment: enriched {hit}/{len(targets)} unscored CVEs")


# --------------------------------------------------------------------------- #
# GitHub Security Advisories
# --------------------------------------------------------------------------- #
def fetch_ghsa(start: datetime, end: datetime):
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    out = []
    for field in ("published", "updated"):
        params = {field: f"{start.strftime('%Y-%m-%dT%H:%M:%SZ')}..{end.strftime('%Y-%m-%dT%H:%M:%SZ')}",
                  "type": "reviewed", "per_page": 100}
        url = GHSA_URL
        while url:
            r = get_with_retry(url, params=params, headers=headers, tries=3)
            out.extend(r.json())
            url = r.links.get("next", {}).get("url")
            params = None
            time.sleep(0.5)
    uniq = {a["ghsa_id"]: a for a in out}
    print(f"  GHSA: {len(uniq)} reviewed advisories")
    return list(uniq.values())


def merge_ghsa(records_by_id, advisories, start_iso):
    for a in advisories:
        cve = a.get("cve_id")
        key = cve or a["ghsa_id"]
        r = records_by_id.get(key)
        if r is None:
            r = blank_record(key)
            r["published"] = a.get("published", "")
            r["last_modified"] = a.get("updated", "")
            r["status"] = "GHSA"
            r["description"] = a.get("description") or a.get("summary", "")
            r["reason"] = "New" if (a.get("published", "") >= start_iso) else "Updated"
            records_by_id[key] = r
        r["sources"].append("GHSA")
        r["aliases"] = sorted(set(r["aliases"]) | {a["ghsa_id"]})
        r["advisory_url"] = a.get("html_url", "")
        pk = sorted({f"{v['package']['ecosystem']}:{v['package']['name']}" for v in a.get("vulnerabilities", []) if v.get("package")})
        fixed = sorted({v.get("first_patched_version") for v in a.get("vulnerabilities", []) if v.get("first_patched_version")})
        if pk:
            r["ecosystem_package"] = ", ".join(pk[:6])
        if fixed:
            r["patched_version"] = ", ".join(fixed[:6])
        if r["cvss_score"] is None:
            sevs = a.get("cvss_severities") or {}
            cv = sevs.get("cvss_v4") or sevs.get("cvss_v3") or a.get("cvss") or {}
            if cv.get("score"):
                r["cvss_score"] = cv["score"]
                r["cvss_vector"] = cv.get("vector_string", "") or ""
                r["cvss_version"] = "4.0" if "CVSS:4" in r["cvss_vector"] else "3.1"
                r["cvss_severity"] = (a.get("severity") or severity_from_score(cv["score"])).upper()
                r["cvss_source"] = "GHSA"
        if not r["cwe"]:
            r["cwe"] = ", ".join(c["cwe_id"] for c in (a.get("cwes") or [])[:5])


# --------------------------------------------------------------------------- #
# OSV.dev (ecosystem dumps; filter to window)
# --------------------------------------------------------------------------- #
def fetch_osv(ecosystems, start: datetime, end: datetime):
    entries = []
    lo, hi = start.strftime("%Y-%m-%dT%H:%M:%S"), end.strftime("%Y-%m-%dT%H:%M:%S")
    for eco in ecosystems:
        url = f"{OSV_BUCKET}/{eco}/all.zip"
        try:
            r = get_with_retry(url, tries=2, ok404=True)
        except Exception as e:
            print(f"  OSV {eco}: {e}", file=sys.stderr)
            continue
        if r is None:
            print(f"  OSV {eco}: no dump found (check ecosystem name)", file=sys.stderr)
            continue
        n = 0
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            for name in z.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    v = json.loads(z.read(name))
                except Exception:
                    continue
                mod = (v.get("modified") or "")[:19]
                if lo <= mod <= hi:
                    v["_ecosystem"] = eco
                    entries.append(v)
                    n += 1
        print(f"  OSV {eco}: {n} entries modified in window")
    return entries


def merge_osv(records_by_id, entries, start_iso):
    for v in entries:
        ids = [v["id"]] + v.get("aliases", [])
        cve = next((i for i in ids if i.startswith("CVE-")), None)
        ghsa = next((i for i in ids if i.startswith("GHSA-")), None)
        key = cve or ghsa or v["id"]
        r = records_by_id.get(key)
        if r is None and ghsa and ghsa in records_by_id:
            r = records_by_id[ghsa]
        if r is None:
            r = blank_record(key)
            r["published"] = v.get("published", "")
            r["last_modified"] = v.get("modified", "")
            r["status"] = "OSV"
            r["description"] = v.get("details") or v.get("summary", "")
            r["reason"] = "New" if (v.get("published") or "") >= start_iso else "Updated"
            records_by_id[key] = r
        r["sources"].append("OSV")
        r["aliases"] = sorted(set(r["aliases"]) | {i for i in ids if i != r["cve_id"]})
        if not r["advisory_url"]:
            r["advisory_url"] = f"https://osv.dev/vulnerability/{v['id']}"
        pk, fixed = set(), set()
        for a in v.get("affected", []):
            p = a.get("package", {})
            if p.get("name"):
                pk.add(f"{p.get('ecosystem', v['_ecosystem'])}:{p['name']}")
            for rng in a.get("ranges", []):
                for ev in rng.get("events", []):
                    if ev.get("fixed"):
                        fixed.add(ev["fixed"])
        if pk and not r["ecosystem_package"]:
            r["ecosystem_package"] = ", ".join(sorted(pk)[:6])
        if fixed and not r["patched_version"]:
            r["patched_version"] = ", ".join(sorted(fixed)[:6])
        if r["cvss_score"] is None and not r["cvss_vector"]:
            for sev in v.get("severity", []):
                if str(sev.get("type", "")).startswith("CVSS") and sev.get("score"):
                    r["cvss_vector"] = sev["score"]
                    r["cvss_severity"] = ((v.get("database_specific") or {}).get("severity") or "").upper()
                    r["cvss_source"] = "OSV"
                    break


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--date", help="YYYY-MM-DD: fetch that calendar day (UTC)")
    args = ap.parse_args()

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
    print(f"  NVD API key: {'yes (' + api_key[:4] + '...)' if api_key else 'no - public rate limit'}")

    # ---- 1. NVD: new + meaningful updates -------------------------------- #
    print("Fetching NVD...")
    records_by_id = {}
    for item in fetch_nvd(start, end, "pub", api_key):
        r = normalise_nvd(item)
        r["reason"] = "New"
        records_by_id[r["cve_id"]] = r
    n_new = len(records_by_id)

    n_upd = 0
    if cfg["include_updated"]:
        time.sleep(1 if api_key else 7)
        cutoff = (end - timedelta(days=cfg["modified_lookback_days"])).strftime("%Y-%m-%dT%H:%M:%S")
        for item in fetch_nvd(start, end, "lastMod", api_key):
            cid = item["cve"]["id"]
            if cid in records_by_id:
                continue
            pub = item["cve"].get("published", "")[:19]
            if pub < cutoff:
                continue  # old CVE, metadata churn - ignore
            r = normalise_nvd(item)
            if r["cvss_score"] is None:
                continue  # still unscored, nothing new to tell the team
            r["reason"] = "Updated"
            records_by_id[cid] = r
            n_upd += 1
    print(f"  {n_new} new, {n_upd} recently-published CVEs updated with a score")

    # ---- 2. KEV ---------------------------------------------------------- #
    print("Fetching CISA KEV...")
    kev = fetch_kev()
    for cve_id, k in kev.items():
        if k.get("dateAdded", "") >= start.strftime("%Y-%m-%d") and cve_id not in records_by_id:
            r = blank_record(cve_id)
            r["status"] = "KEV"
            r["reason"] = "Added to KEV"
            r["description"] = k.get("shortDescription", "")
            r["vendor_product"] = f"{k.get('vendorProject','')}:{k.get('product','')}".lower()
            records_by_id[cve_id] = r
    for r in records_by_id.values():
        k = kev.get(r["cve_id"])
        if k:
            r["sources"].append("KEV")
            r["kev"] = True
            r["kev_date_added"] = k.get("dateAdded", "")
            r["kev_due_date"] = k.get("dueDate", "")
            r["kev_required_action"] = k.get("requiredAction", "")
            r["kev_ransomware"] = k.get("knownRansomwareCampaignUse", "") == "Known"
            if not r["vendor_product"]:
                r["vendor_product"] = f"{k.get('vendorProject','')}:{k.get('product','')}".lower()

    # ---- 3. Vulnrichment for unscored ------------------------------------ #
    if cfg["sources"]["vulnrichment"]:
        print("Fetching CISA Vulnrichment for unscored CVEs...")
        try:
            enrich_vulnrichment(list(records_by_id.values()), cfg["max_enrich_calls"])
        except Exception as e:
            print(f"  Vulnrichment failed (continuing): {e}", file=sys.stderr)

    # ---- 4. GHSA --------------------------------------------------------- #
    if cfg["sources"]["ghsa"]:
        print("Fetching GitHub Security Advisories...")
        try:
            merge_ghsa(records_by_id, fetch_ghsa(start, end), start_iso)
        except Exception as e:
            print(f"  GHSA failed (continuing): {e}", file=sys.stderr)

    # ---- 5. OSV ---------------------------------------------------------- #
    if cfg["sources"]["osv"] and cfg["osv_ecosystems"]:
        print("Fetching OSV.dev dumps...")
        try:
            merge_osv(records_by_id, fetch_osv(cfg["osv_ecosystems"], start, end), start_iso)
        except Exception as e:
            print(f"  OSV failed (continuing): {e}", file=sys.stderr)

    records = list(records_by_id.values())

    # ---- 6. EPSS --------------------------------------------------------- #
    print("Fetching EPSS...")
    epss = fetch_epss([r["cve_id"] for r in records])
    for r in records:
        e = epss.get(r["cve_id"])
        if e:
            r["epss"], r["epss_percentile"] = e

    # ---- 7. Watchlist + priority ----------------------------------------- #
    for r in records:
        r["sources"] = sorted(set(r["sources"]))
        target = f"{r['vendor_product']} {r['ecosystem_package']}".lower()
        if not target.strip():
            target = r["description"].lower()  # no CPE yet - fall back to text
        hits = [k for k in cfg["keywords"] if k in target]
        r["watchlist_hits"] = ", ".join(hits)
        r["watchlist_match"] = bool(hits)
        score = r["cvss_score"] or 0
        ep = r["epss"] or 0
        if r["kev"] or ep >= 0.5 or r["ssvc_exploitation"] == "active":
            r["priority"] = "P1 - Act now"
        elif score >= 9.0 or (ep >= 0.1 and score >= 7.0) or r["ssvc_exploitation"] == "poc":
            r["priority"] = "P2 - High"
        elif score >= 7.0:
            r["priority"] = "P3 - Medium"
        else:
            r["priority"] = "P4 - Low / Unscored"

    records.sort(key=lambda r: (not r["kev"], r["priority"], -(r["cvss_score"] or 0), r["cve_id"]))

    snapshot = {
        "report_date": report_date,
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": {
            "total": len(records),
            "new": sum(r["reason"] == "New" for r in records),
            "updated": sum(r["reason"] != "New" for r in records),
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
    out = DATA_DIR / f"{report_date}.json"
    with open(out, "w") as f:
        json.dump(snapshot, f, indent=1)
    print(f"Wrote {out}\n  {snapshot['counts']}")


if __name__ == "__main__":
    main()
