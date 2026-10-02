#!/usr/bin/env python3
"""Delete snapshots and reports older than N days (default: retention_days in
config/watchlist.yml, else 10). Dates come from the file names, not mtimes.

    python scripts/cleanup_old.py              # use config
    python scripts/cleanup_old.py --days 10
    python scripts/cleanup_old.py --dry-run
"""
import argparse
import json
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")


def configured_days():
    cfg = ROOT / "config" / "watchlist.yml"
    if cfg.exists():
        data = yaml.safe_load(cfg.read_text(encoding="utf-8")) or {}
        return int(data.get("retention_days", 10))
    return 10


def file_date(path):
    m = DATE_RE.search(path.name)
    return date.fromisoformat(m.group(1)) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    days = args.days if args.days is not None else configured_days()
    cutoff = datetime.now(timezone.utc).date() - timedelta(days=days)
    print(f"Keeping files dated on or after {cutoff} ({days} days)")

    removed = 0
    snapshots = sorted((ROOT / "data").glob("*.json"), key=lambda p: file_date(p) or date.min)
    newest = snapshots[-1] if snapshots else None   # always kept: used to detect updates
    candidates = snapshots + list((ROOT / "reports").rglob("vulns-*.*"))
    for path in sorted(candidates):
        d = file_date(path)
        if d and d < cutoff and path != newest:
            print(("would delete " if args.dry_run else "deleted ") + str(path.relative_to(ROOT)))
            if not args.dry_run:
                path.unlink()
            removed += 1

    # remove empty month/year folders under reports/
    if not args.dry_run:
        for folder in sorted((ROOT / "reports").rglob("*"), reverse=True):
            if folder.is_dir() and not any(p for p in folder.iterdir() if p.name != ".DS_Store"):
                for junk in folder.iterdir():
                    junk.unlink()
                folder.rmdir()

    # keep the dashboard's "Previous reports" list in step
    archive_path = ROOT / "docs" / "archive.json"
    if archive_path.exists() and not args.dry_run:
        archive = json.loads(archive_path.read_text(encoding="utf-8"))
        kept = [a for a in archive if date.fromisoformat(a["date"]) >= cutoff]
        archive_path.write_text(json.dumps(kept, indent=1), encoding="utf-8")

    print(f"{removed} file(s) {'to delete' if args.dry_run else 'deleted'}")


if __name__ == "__main__":
    main()
