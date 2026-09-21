#!/usr/bin/env python3
"""
Post-build notification: email and/or webhook for watchlist-matched CVEs.

Reads the day's JSON snapshot, filters records where watchlist_match is True,
and outputs:
  - An HTML email body (to stdout or a file)
  - A JSON webhook payload (to a file)
  - Sets GITHUB_OUTPUT variables for downstream workflow steps

Usage (inside GitHub Actions):
    python scripts/notify_watchlist.py                          # latest snapshot
    python scripts/notify_watchlist.py --date 2026-09-17        # specific day
    python scripts/notify_watchlist.py --webhook-url https://... # POST directly
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"


def load_snapshot(date=None):
    if date:
        path = DATA_DIR / f"{date}.json"
    else:
        files = sorted(DATA_DIR.glob("*.json"))
        if not files:
            raise SystemExit("No snapshots found in data/")
        path = files[-1]
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_html_email(snapshot, matches, repo_url):
    """Return a self-contained HTML email string."""
    report_date = snapshot["report_date"]
    counts = snapshot["counts"]

    rows = []
    for r in matches:
        severity = r.get("cvss_severity") or "—"
        score = r.get("cvss_score")
        score_str = f"{score}" if score is not None else "—"
        epss = r.get("epss")
        epss_str = f"{epss:.3f}" if epss is not None else "—"
        kev_badge = "🔴 KEV" if r.get("kev") else ""
        link = r.get("nvd_url") or r.get("advisory_url") or ""
        cve_cell = f'<a href="{link}" style="color:#1a0dab">{r["cve_id"]}</a>' if link else r["cve_id"]
        desc = (r.get("description") or "")[:200]
        if len(r.get("description") or "") > 200:
            desc += "…"

        sev_colors = {
            "CRITICAL": ("#C00000", "#fff"),
            "HIGH": ("#E97132", "#fff"),
            "MEDIUM": ("#F2C94C", "#000"),
            "LOW": ("#8FBC8F", "#000"),
        }
        bg, fg = sev_colors.get(severity, ("#eee", "#333"))

        rows.append(f"""<tr>
  <td style="padding:6px 8px;border-bottom:1px solid #e0e0e0;white-space:nowrap;font-weight:600">{r.get('priority','')}</td>
  <td style="padding:6px 8px;border-bottom:1px solid #e0e0e0">{cve_cell}</td>
  <td style="padding:6px 8px;border-bottom:1px solid #e0e0e0;text-align:center">
    <span style="background:{bg};color:{fg};padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700">{severity}</span>
  </td>
  <td style="padding:6px 8px;border-bottom:1px solid #e0e0e0;text-align:right">{score_str}</td>
  <td style="padding:6px 8px;border-bottom:1px solid #e0e0e0;text-align:right">{epss_str}</td>
  <td style="padding:6px 8px;border-bottom:1px solid #e0e0e0;text-align:center">{kev_badge}</td>
  <td style="padding:6px 8px;border-bottom:1px solid #e0e0e0;color:#2e7d32;font-weight:600">{r.get('watchlist_hits','')}</td>
  <td style="padding:6px 8px;border-bottom:1px solid #e0e0e0;color:#555;font-size:12px;max-width:400px">{desc}</td>
</tr>""")

    table_rows = "\n".join(rows)

    # Summary counts for the header
    crit = sum(1 for r in matches if r.get("cvss_severity") == "CRITICAL")
    high = sum(1 for r in matches if r.get("cvss_severity") == "HIGH")
    kev_count = sum(1 for r in matches if r.get("kev"))

    dashboard_url = ""
    if repo_url:
        owner_repo = repo_url.rstrip("/").split("github.com/")[-1]
        dashboard_url = f"https://{owner_repo.split('/')[0]}.github.io/{owner_repo.split('/')[1]}/"

    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#222;margin:0;padding:20px;background:#f6f6f6">
<div style="max-width:960px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;border:1px solid #e0e0e0">

  <div style="background:#1F3864;color:#fff;padding:20px 24px">
    <h1 style="margin:0;font-size:20px;font-weight:600">⚠️ Watchlist Alert — {report_date}</h1>
    <p style="margin:6px 0 0;font-size:13px;opacity:0.85">
      {len(matches)} vulnerabilities matched your watchlist
      ({crit} critical, {high} high, {kev_count} in KEV)
      out of {counts['total']} total entries today.
    </p>
  </div>

  <div style="padding:20px 24px">
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead>
        <tr style="background:#f0f0f0">
          <th style="padding:8px;text-align:left;border-bottom:2px solid #ccc">Priority</th>
          <th style="padding:8px;text-align:left;border-bottom:2px solid #ccc">CVE / Advisory</th>
          <th style="padding:8px;text-align:center;border-bottom:2px solid #ccc">Severity</th>
          <th style="padding:8px;text-align:right;border-bottom:2px solid #ccc">CVSS</th>
          <th style="padding:8px;text-align:right;border-bottom:2px solid #ccc">EPSS</th>
          <th style="padding:8px;text-align:center;border-bottom:2px solid #ccc">KEV</th>
          <th style="padding:8px;text-align:left;border-bottom:2px solid #ccc">Watchlist Hit</th>
          <th style="padding:8px;text-align:left;border-bottom:2px solid #ccc">Description</th>
        </tr>
      </thead>
      <tbody>
        {table_rows}
      </tbody>
    </table>
  </div>

  <div style="padding:12px 24px 20px;font-size:13px;color:#666;border-top:1px solid #e0e0e0">
    <p style="margin:0">
      {'<a href="' + dashboard_url + '" style="color:#1F3864;font-weight:600">View full dashboard</a> · ' if dashboard_url else ''}
      Total today: {counts['total']} entries
      ({counts['critical']} critical, {counts['high']} high,
       {counts['medium']} medium, {counts['low']} low,
       {counts['unscored']} unscored).
      Window: {snapshot['window_start'][:16]} → {snapshot['window_end'][:16]} UTC.
    </p>
  </div>

</div>
</body>
</html>"""
    return html


def build_markdown_issue(snapshot, matches, repo_url, branch="main", max_rows=60):
    """Return a Markdown body for a GitHub Issue (GitHub emails assignees)."""
    report_date = snapshot["report_date"]
    counts = snapshot["counts"]
    year, month = report_date[:4], report_date[5:7]

    crit = sum(1 for r in matches if r.get("cvss_severity") == "CRITICAL")
    high = sum(1 for r in matches if r.get("cvss_severity") == "HIGH")
    kev_count = sum(1 for r in matches if r.get("kev"))

    lines = [
        f"**{len(matches)} vulnerabilities matched the watchlist** on {report_date} "
        f"({crit} critical, {high} high, {kev_count} in KEV) out of {counts['total']} entries.",
        "",
        "| Priority | ID | Sev | CVSS | EPSS | KEV | Watchlist hit | Description |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in matches[:max_rows]:
        score = r.get("cvss_score")
        epss = r.get("epss")
        link = r.get("nvd_url") or r.get("advisory_url") or ""
        cve = f"[{r['cve_id']}]({link})" if link else r["cve_id"]
        desc = (r.get("description") or "").replace("|", "\\|").replace("\n", " ")[:140]
        if len(r.get("description") or "") > 140:
            desc += "…"
        lines.append(
            f"| {r.get('priority','')} | {cve} | {r.get('cvss_severity') or '—'} | "
            f"{score if score is not None else '—'} | "
            f"{f'{epss:.3f}' if epss is not None else '—'} | "
            f"{'🔴' if r.get('kev') else ''} | {r.get('watchlist_hits','')} | {desc} |"
        )
    if len(matches) > max_rows:
        lines.append(f"\n_…and {len(matches) - max_rows} more in the full report._")

    if repo_url:
        owner_repo = repo_url.rstrip("/").split("github.com/")[-1]
        owner, repo = owner_repo.split("/")[:2]
        lines += [
            "",
            f"📊 [Dashboard](https://{owner}.github.io/{repo}/) · "
            f"📥 [Excel]({repo_url}/blob/{branch}/reports/{year}/{month}/vulns-{report_date}.xlsx) · "
            f"📄 [PDF]({repo_url}/blob/{branch}/reports/{year}/{month}/vulns-{report_date}.pdf)",
        ]
    lines += ["", f"_Window {snapshot['window_start'][:16]} → {snapshot['window_end'][:16]} UTC. "
                  "Generated automatically by the daily vulnerability workflow._"]
    return "\n".join(lines)


def build_webhook_payload(snapshot, matches, repo_url):
    """Return a JSON-serialisable dict for webhook consumers."""
    report_date = snapshot["report_date"]
    counts = snapshot["counts"]

    items = []
    for r in matches:
        items.append({
            "cve_id": r["cve_id"],
            "priority": r.get("priority", ""),
            "cvss_score": r.get("cvss_score"),
            "cvss_severity": r.get("cvss_severity", ""),
            "epss": r.get("epss"),
            "kev": r.get("kev", False),
            "watchlist_hits": r.get("watchlist_hits", ""),
            "vendor_product": r.get("vendor_product", ""),
            "ecosystem_package": r.get("ecosystem_package", ""),
            "reason": r.get("reason", ""),
            "description": (r.get("description") or "")[:300],
            "nvd_url": r.get("nvd_url", ""),
        })

    return {
        "report_date": report_date,
        "window_start": snapshot["window_start"],
        "window_end": snapshot["window_end"],
        "total_today": counts["total"],
        "watchlist_matches": len(matches),
        "critical_matches": sum(1 for r in matches if r.get("cvss_severity") == "CRITICAL"),
        "high_matches": sum(1 for r in matches if r.get("cvss_severity") == "HIGH"),
        "kev_matches": sum(1 for r in matches if r.get("kev")),
        "dashboard_url": repo_url or "",
        "items": items,
    }


def post_webhook(url, payload, secret=None):
    """POST the payload to a webhook URL. Returns True on success."""
    headers = {"Content-Type": "application/json"}
    if secret:
        import hashlib, hmac
        body = json.dumps(payload).encode()
        sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        headers["X-Signature-256"] = f"sha256={sig}"

    try:
        r = requests.post(url, json=payload, headers=headers, timeout=30)
        print(f"Webhook response: {r.status_code}")
        r.raise_for_status()
        return True
    except Exception as exc:
        print(f"Webhook failed: {exc}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Notify on watchlist-matched CVEs")
    parser.add_argument("--date", help="Report date (YYYY-MM-DD). Default: latest.")
    parser.add_argument("--repo-url", default=os.getenv("REPO_URL", ""))
    parser.add_argument("--webhook-url", default=os.getenv("WEBHOOK_URL", ""),
                        help="POST payload to this URL")
    parser.add_argument("--webhook-secret", default=os.getenv("WEBHOOK_SECRET", ""),
                        help="HMAC secret for webhook signature")
    parser.add_argument("--out-html", default="", help="Write HTML email to this file")
    parser.add_argument("--out-md", default="", help="Write Markdown issue body to this file")
    parser.add_argument("--branch", default=os.getenv("GITHUB_REF_NAME", "main"))
    parser.add_argument("--out-json", default="", help="Write JSON payload to this file")
    args = parser.parse_args()

    snapshot = load_snapshot(args.date)
    report_date = snapshot["report_date"]
    records = snapshot.get("records", [])

    matches = [r for r in records if r.get("watchlist_match")]

    # Sort: P1 first, then by CVSS descending
    matches.sort(key=lambda r: (r.get("priority", "P4"), -(r.get("cvss_score") or 0)))

    print(f"Report {report_date}: {len(records)} total, {len(matches)} watchlist matches")

    if not matches:
        print("No watchlist matches — skipping notification.")
        # Still set outputs so the workflow can branch
        gh_out = os.getenv("GITHUB_OUTPUT")
        if gh_out:
            with open(gh_out, "a") as f:
                f.write(f"watchlist_count=0\nshould_notify=false\n")
        return

    # Build outputs
    html_body = build_html_email(snapshot, matches, args.repo_url)
    payload = build_webhook_payload(snapshot, matches, args.repo_url)

    if args.out_html:
        Path(args.out_html).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out_html).write_text(html_body, encoding="utf-8")
        print(f"Wrote HTML: {args.out_html}")

    if args.out_md:
        Path(args.out_md).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out_md).write_text(
            build_markdown_issue(snapshot, matches, args.repo_url, args.branch), encoding="utf-8")
        print(f"Wrote Markdown: {args.out_md}")

    if args.out_json:
        Path(args.out_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out_json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Wrote JSON: {args.out_json}")

    # Fire webhook if URL is set
    if args.webhook_url:
        post_webhook(args.webhook_url, payload, args.webhook_secret)

    # Set GitHub Actions outputs
    gh_out = os.getenv("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as f:
            f.write(f"watchlist_count={len(matches)}\n")
            f.write(f"should_notify=true\n")
            crit = sum(1 for r in matches if r.get("cvss_severity") == "CRITICAL")
            high = sum(1 for r in matches if r.get("cvss_severity") == "HIGH")
            f.write(f"subject=Watchlist alert {report_date}: {len(matches)} CVEs ({crit} critical, {high} high)\n")
            if args.out_html:
                f.write(f"html_file={args.out_html}\n")


if __name__ == "__main__":
    main()
