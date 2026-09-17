#!/usr/bin/env python3
"""
Build the daily Excel/PDF reports and GitHub Pages dashboard.

The snapshot is already bucketed by Published Date in fetch_vulns.py.
Therefore an older CVE that was updated today appears only in today's
"Updated" section; it does not become a new vulnerability in today's
"New" bucket. Yesterday's snapshot remains unchanged.
"""
import argparse
import html
import json
import os
import re
from pathlib import Path

from openpyxl import Workbook
from openpyxl.formatting.rule import CellIsRule
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, TableStyle
from reportlab.platypus import Table as RLTable

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
REPORT_DIR = ROOT / "reports"
DOCS_DIR = ROOT / "docs"

SEVERITY_FILL = {
    "CRITICAL": "C00000",
    "HIGH": "E97132",
    "MEDIUM": "F2C94C",
    "LOW": "8FBC8F",
}
SEVERITY_FONT = {
    "CRITICAL": "FFFFFF",
    "HIGH": "FFFFFF",
    "MEDIUM": "000000",
    "LOW": "000000",
}

COLUMNS = [
    ("Priority", "priority", 16),
    ("Reason", "reason", 22),
    ("ID", "cve_id", 18),
    ("CVSS", "cvss_score", 7),
    ("Severity", "cvss_severity", 10),
    ("Score src", "cvss_source", 10),
    ("KEV", "kev", 6),
    ("EPSS", "epss", 7),
    ("SSVC", "ssvc_exploitation", 12),
    ("Watchlist", "watchlist_hits", 16),
    ("Vendor / Product", "vendor_product", 28),
    ("Package", "ecosystem_package", 28),
    ("Fixed in", "patched_version", 14),
    ("Sources", "sources", 18),
    ("Published", "published", 12),
    ("Last Modified", "last_modified", 15),
    ("KEV Due", "kev_due_date", 11),
    ("CWE", "cwe", 12),
    ("Description", "description", 90),
    ("Link", "nvd_url", 42),
]

_ILLEGAL_XLSX = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def load_snapshot(date=None):
    files = sorted(DATA_DIR.glob("*.json"))
    if not files:
        raise SystemExit("No snapshots in data/. Run fetch_vulns.py first.")
    path = DATA_DIR / f"{date}.json" if date else files[-1]
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def clean(value):
    return _ILLEGAL_XLSX.sub("", str(value))


def fmt(value):
    if value is None:
        return ""
    if isinstance(value, list):
        return clean(", ".join(str(x) for x in value))
    if isinstance(value, bool):
        return "Yes" if value else ""
    if isinstance(value, float):
        return round(value, 3)
    if isinstance(value, str):
        if len(value) > 10 and len(value) >= 5 and value[4] == "-" and "T" in value:
            return value[:10]
        return clean(value)
    return value


def write_sheet(ws, records, title):
    ws.title = title[:31]
    ws.append([c[0] for c in COLUMNS])

    for record in records:
        ws.append([fmt(record.get(c[1])) for c in COLUMNS])

    header_font = Font(name="Arial", bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor="1F3864")

    for cell in ws[1]:
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = Alignment(vertical="center", wrap_text=True)

    for row in ws.iter_rows(min_row=2):
        for cell in row:
            cell.font = Font(name="Arial", size=10)
            cell.alignment = Alignment(vertical="top", wrap_text=True)

    for index, (_, _, width) in enumerate(COLUMNS, start=1):
        ws.column_dimensions[get_column_letter(index)].width = width

    ws.freeze_panes = "D2"
    ws.auto_filter.ref = ws.dimensions

    link_col = [c[0] for c in COLUMNS].index("Link") + 1
    for index, record in enumerate(records, start=2):
        cell = ws.cell(row=index, column=link_col)
        if not cell.value:
            cell.value = record.get("advisory_url") or ""
        if cell.value:
            cell.hyperlink = cell.value
            cell.font = Font(
                name="Arial",
                size=10,
                color="0563C1",
                underline="single",
            )

    if ws.max_row > 1:
        severity_col = get_column_letter(
            [c[0] for c in COLUMNS].index("Severity") + 1
        )
        rng = f"{severity_col}2:{severity_col}{ws.max_row}"

        for severity, fill in SEVERITY_FILL.items():
            ws.conditional_formatting.add(
                rng,
                CellIsRule(
                    operator="equal",
                    formula=[f'"{severity}"'],
                    fill=PatternFill("solid", fgColor=fill),
                    font=Font(
                        color=SEVERITY_FONT[severity],
                        bold=True,
                    ),
                ),
            )

        kev_col = get_column_letter(
            [c[0] for c in COLUMNS].index("KEV") + 1
        )
        ws.conditional_formatting.add(
            f"{kev_col}2:{kev_col}{ws.max_row}",
            CellIsRule(
                operator="equal",
                formula=['"Yes"'],
                fill=PatternFill("solid", fgColor="7030A0"),
                font=Font(color="FFFFFF", bold=True),
            ),
        )


def build_xlsx(snapshot, output):
    records = snapshot["records"]
    counts = snapshot["counts"]

    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"

    rows = [
        ("Daily Vulnerability Report", ""),
        ("Report date", snapshot["report_date"]),
        (
            "Window (UTC)",
            f"{snapshot['window_start'][:16]} to {snapshot['window_end'][:16]}",
        ),
        (
            "Generated",
            snapshot["generated_at"][:19].replace("T", " ") + " UTC",
        ),
        ("", ""),
        ("Total entries", counts["total"]),
        ("  New - published today", counts.get("new", 0)),
        ("  Significant updates", counts.get("updated", 0)),
        ("  Added to CISA KEV", counts.get("kev_added", 0)),
        ("In CISA KEV", counts["kev"]),
        ("Critical", counts["critical"]),
        ("High", counts["high"]),
        ("Medium", counts["medium"]),
        ("Low", counts["low"]),
        ("Unscored", counts["unscored"]),
        ("Watchlist matches", counts["watchlist"]),
        ("From GitHub Advisories", counts.get("ghsa", 0)),
        ("From OSV.dev", counts.get("osv", 0)),
        ("", ""),
        (
            "Daily bucketing rule",
            "New = published during this report window. Older CVEs remain in their original publication-day report.",
        ),
        (
            "Update rule",
            "Older items are shown only when a meaningful security-related change is detected.",
        ),
        ("", ""),
        ("Priority rules", ""),
        (
            "P1 - Act now",
            "In CISA KEV, or EPSS >= 0.50, or SSVC exploitation = active",
        ),
        (
            "P2 - High",
            "CVSS >= 9.0, or CVSS >= 7.0 with EPSS >= 0.10, or SSVC exploitation = poc",
        ),
        ("P3 - Medium", "CVSS >= 7.0"),
        ("P4 - Low / Unscored", "Everything else"),
    ]

    for row in rows:
        ws.append(list(row))

    ws["A1"].font = Font(name="Arial", size=14, bold=True)
    for row in ws.iter_rows(min_row=2):
        row[0].font = Font(name="Arial", bold=True)
        row[1].font = Font(name="Arial")

    ws.column_dimensions["A"].width = 38
    ws.column_dimensions["B"].width = 85

    write_sheet(wb.create_sheet(), records, "All CVEs")
    write_sheet(
        wb.create_sheet(),
        [r for r in records if r["reason"] == "New"],
        "New Today",
    )
    write_sheet(
        wb.create_sheet(),
        [r for r in records if r["reason"].startswith("Updated")],
        "Significant Updates",
    )
    write_sheet(
        wb.create_sheet(),
        [r for r in records if r["reason"] == "Added to KEV"],
        "Added to KEV",
    )
    write_sheet(
        wb.create_sheet(),
        [r for r in records if r["kev"]],
        "KEV - Exploited",
    )
    write_sheet(
        wb.create_sheet(),
        [r for r in records if r["cvss_severity"] in ("CRITICAL", "HIGH")],
        "Critical & High",
    )

    if snapshot.get("watchlist_keywords"):
        write_sheet(
            wb.create_sheet(),
            [r for r in records if r["watchlist_match"]],
            "Watchlist",
        )

    write_sheet(
        wb.create_sheet(),
        [r for r in records if r.get("ecosystem_package")],
        "Packages (GHSA-OSV)",
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    wb.save(output)


def build_pdf(snapshot, output):
    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        "body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
    )
    small = ParagraphStyle(
        "small",
        parent=body,
        fontSize=7,
        leading=9,
        textColor=colors.grey,
    )

    doc = SimpleDocTemplate(
        str(output),
        pagesize=landscape(A4),
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title=f"Daily Vulnerability Report {snapshot['report_date']}",
    )

    counts = snapshot["counts"]
    records = snapshot["records"]

    story = [
        Paragraph(
            f"Daily Vulnerability Report - {snapshot['report_date']}",
            styles["Title"],
        ),
        Paragraph(
            f"Window (UTC): {snapshot['window_start'][:16]} to "
            f"{snapshot['window_end'][:16]} &nbsp;|&nbsp; "
            f"Sources: NVD, CISA KEV, EPSS, Vulnrichment, GHSA, OSV &nbsp;|&nbsp; "
            f"Generated {snapshot['generated_at'][:19].replace('T', ' ')} UTC",
            small,
        ),
        Spacer(1, 6),
    ]

    summary = [
        [
            "Total",
            "New",
            "Updated",
            "KEV added",
            "KEV",
            "Critical",
            "High",
            "Medium",
            "Unscored",
            "Watchlist",
        ],
        [
            counts["total"],
            counts.get("new", 0),
            counts.get("updated", 0),
            counts.get("kev_added", 0),
            counts["kev"],
            counts["critical"],
            counts["high"],
            counts["medium"],
            counts["unscored"],
            counts["watchlist"],
        ],
    ]

    table = RLTable(summary, hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3864")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ]
        )
    )
    story += [table, Spacer(1, 10)]

    def detail_table(items, heading):
        story.append(Paragraph(heading, styles["Heading2"]))
        if not items:
            story.append(Paragraph("None in this window.", body))
            story.append(Spacer(1, 6))
            return

        data = [[
            "ID",
            "Reason",
            "CVSS",
            "Sev",
            "KEV",
            "EPSS",
            "Vendor / Product / Package",
            "Description",
        ]]

        for record in items:
            description = record["description"]
            if len(description) > 380:
                description = description[:377] + "..."

            link = record.get("nvd_url") or record.get("advisory_url") or "#"

            data.append(
                [
                    Paragraph(
                        f'<a href="{html.escape(link)}" color="blue">'
                        f'{html.escape(record["cve_id"])}</a>',
                        body,
                    ),
                    Paragraph(html.escape(record.get("reason", "")), body),
                    fmt(record["cvss_score"]),
                    record["cvss_severity"][:4],
                    "Yes" if record["kev"] else "",
                    fmt(record["epss"]),
                    Paragraph(
                        html.escape(
                            (
                                record["vendor_product"]
                                or record.get("ecosystem_package", "")
                            )[:120]
                        ),
                        body,
                    ),
                    Paragraph(html.escape(description), body),
                ]
            )

        table = RLTable(
            data,
            colWidths=[
                28 * mm,
                32 * mm,
                12 * mm,
                12 * mm,
                10 * mm,
                12 * mm,
                52 * mm,
                115 * mm,
            ],
            repeatRows=1,
        )

        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3864")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [colors.white, colors.HexColor("#F7F7F7")],
            ),
        ]

        for index, record in enumerate(items, start=1):
            severity = record["cvss_severity"]
            if severity in SEVERITY_FILL:
                style.append(
                    (
                        "BACKGROUND",
                        (3, index),
                        (3, index),
                        colors.HexColor("#" + SEVERITY_FILL[severity]),
                    )
                )
                style.append(
                    (
                        "TEXTCOLOR",
                        (3, index),
                        (3, index),
                        colors.HexColor("#" + SEVERITY_FONT[severity]),
                    )
                )

            if record["kev"]:
                style.append(
                    (
                        "BACKGROUND",
                        (4, index),
                        (4, index),
                        colors.HexColor("#7030A0"),
                    )
                )
                style.append(
                    (
                        "TEXTCOLOR",
                        (4, index),
                        (4, index),
                        colors.white,
                    )
                )

        table.setStyle(TableStyle(style))
        story.append(table)
        story.append(Spacer(1, 8))

    detail_table(
        [r for r in records if r["reason"] == "New"],
        "New today - published in this report window",
    )
    detail_table(
        [r for r in records if r["reason"].startswith("Updated")],
        "Significant updates today - original Published Date retained",
    )
    detail_table(
        [r for r in records if r["reason"] == "Added to KEV"],
        "Added to CISA KEV today",
    )
    detail_table(
        [r for r in records if r["priority"].startswith("P1") and r["reason"] == "New"],
        "P1 new today",
    )
    detail_table(
        [r for r in records if r["priority"].startswith("P2") and r["reason"] == "New"],
        "P2 new today",
    )

    story.append(
        Paragraph(
            "Historical reports are not rewritten when an older CVE changes. "
            "A CVE published on an earlier date remains in that earlier daily report; "
            "a meaningful change is shown separately in the update section for the "
            "date on which the change was detected.",
            small,
        )
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    doc.build(story)


def build_dashboard(snapshot, xlsx_rel, pdf_rel, repo_url):
    DOCS_DIR.mkdir(exist_ok=True)
    archive_path = DOCS_DIR / "archive.json"

    archive = []
    if archive_path.exists():
        with open(archive_path, encoding="utf-8") as f:
            archive = json.load(f)

    archive = [a for a in archive if a["date"] != snapshot["report_date"]]
    archive.append(
        {
            "date": snapshot["report_date"],
            "counts": snapshot["counts"],
            "xlsx": xlsx_rel,
            "pdf": pdf_rel,
        }
    )
    archive.sort(key=lambda a: a["date"], reverse=True)
    archive = archive[:10]

    with open(archive_path, "w", encoding="utf-8") as f:
        json.dump(archive, f, indent=1)

    counts = snapshot["counts"]
    records = snapshot["records"]
    blob = repo_url.rstrip("/") + "/blob/main/"

    def row(record):
        severity = record["cvss_severity"]
        reason_class = "new" if record.get("reason") == "New" else "upd"
        return (
            "<tr>"
            f"<td class='pri'>{html.escape(record['priority'])}</td>"
            f"<td><span class='rsn {reason_class}'>"
            f"{html.escape(record.get('reason', 'New'))}</span></td>"
            f"<td><a href='{record.get('nvd_url') or record.get('advisory_url') or '#'}' "
            f"target='_blank'>{html.escape(record['cve_id'])}</a></td>"
            f"<td class='num'>{fmt(record['cvss_score'])}</td>"
            f"<td><span class='sev {severity.lower()}'>{html.escape(severity)}</span></td>"
            f"<td>{'<span class=kev>KEV</span>' if record['kev'] else ''}</td>"
            f"<td class='num'>{fmt(record['epss'])}</td>"
            f"<td>{html.escape(record['watchlist_hits'])}</td>"
            f"<td>{html.escape((record['vendor_product'] or record.get('ecosystem_package', ''))[:80])}"
            f"{('<br><small>fixed: ' + html.escape(record['patched_version'][:50]) + '</small>') if record.get('patched_version') else ''}</td>"
            f"<td class='src'>{html.escape(', '.join(record.get('sources', [])))}</td>"
            f"<td class='desc'>{html.escape(record['description'][:300])}"
            f"{'...' if len(record['description']) > 300 else ''}</td>"
            "</tr>"
        )

    history_rows = "".join(
        f"<tr><td>{a['date']}</td>"
        f"<td class='num'>{a['counts']['total']}</td>"
        f"<td class='num'>{a['counts'].get('new', 0)}</td>"
        f"<td class='num'>{a['counts'].get('updated', 0)}</td>"
        f"<td class='num'>{a['counts']['kev_added']}</td>"
        f"<td class='num'>{a['counts']['critical']}</td>"
        f"<td class='num'>{a['counts']['high']}</td>"
        f"<td><a href='{blob}{a['xlsx']}'>Excel</a> &middot; "
        f"<a href='{blob}{a['pdf']}'>PDF</a></td></tr>"
        for a in archive
    )

    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Daily Vulnerability Report - {snapshot['report_date']}</title>
<style>
:root{{--ink:#1a1a1a;--muted:#6b6b6b;--line:#e3e3e3;--navy:#1F3864;--bg:#fafafa}}
body{{font:14px/1.45 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:var(--bg);margin:0;padding:24px}}
h1{{font-size:22px;margin:0 0 4px}}
.sub{{color:var(--muted);font-size:13px;margin-bottom:18px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-bottom:18px}}
.card{{background:#fff;border:1px solid var(--line);border-radius:8px;padding:12px 14px}}
.card b{{display:block;font-size:26px;line-height:1.1}}
.card span{{color:var(--muted);font-size:12px}}
.dl a{{display:inline-block;background:var(--navy);color:#fff;text-decoration:none;padding:8px 14px;border-radius:6px;margin-right:8px;font-size:13px}}
.tools{{margin:18px 0 8px;display:flex;gap:10px;flex-wrap:wrap;align-items:center}}
input,select{{padding:6px 8px;border:1px solid var(--line);border-radius:6px;font-size:13px}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);font-size:13px}}
th,td{{padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top;text-align:left}}
th{{background:var(--navy);color:#fff;position:sticky;top:0;cursor:pointer;white-space:nowrap}}
td.num{{text-align:right;font-variant-numeric:tabular-nums}}
td.desc{{color:#333;max-width:520px}}
td.pri{{white-space:nowrap;font-weight:600}}
.sev{{padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700}}
.sev.critical{{background:#C00000;color:#fff}}
.sev.high{{background:#E97132;color:#fff}}
.sev.medium{{background:#F2C94C}}
.sev.low{{background:#8FBC8F}}
.kev{{background:#7030A0;color:#fff;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700}}
.rsn{{padding:2px 6px;border-radius:4px;font-size:11px;white-space:nowrap}}
.rsn.new{{background:#DCE6F5;color:#1F3864}}
.rsn.upd{{background:#EEE;color:#555}}
td.src{{font-size:11px;color:#555;white-space:nowrap}}
td small{{color:#2e7d32}}
details{{margin-top:24px}}
summary{{cursor:pointer;font-weight:600}}
footer{{color:var(--muted);font-size:12px;margin-top:24px}}
</style>
</head>
<body>
<h1>Daily Vulnerability Report</h1>
<div class="sub">
{snapshot['report_date']} &nbsp;|&nbsp;
window {snapshot['window_start'][:16]} to {snapshot['window_end'][:16]} UTC
&nbsp;|&nbsp; sources: NVD, CISA KEV, EPSS, CISA Vulnrichment, GitHub Advisories, OSV.dev
</div>

<div class="cards">
<div class="card"><b style="color:#1F3864">{counts.get('new',0)}</b><span>New today</span></div>
<div class="card"><b style="color:#6b6b6b">{counts.get('updated',0)}</b><span>Significant updates</span></div>
<div class="card"><b style="color:#7030A0">{counts.get('kev_added',0)}</b><span>Added to KEV today</span></div>
<div class="card"><b>{counts['total']}</b><span>Total feed entries</span></div>
<div class="card"><b style="color:#C00000">{counts['critical']}</b><span>Critical</span></div>
<div class="card"><b style="color:#E97132">{counts['high']}</b><span>High</span></div>
<div class="card"><b>{counts['medium']}</b><span>Medium</span></div>
<div class="card"><b>{counts['unscored']}</b><span>Unscored</span></div>
<div class="card"><b>{counts['watchlist']}</b><span>Watchlist</span></div>
<div class="card"><b>{counts.get('ghsa',0)}</b><span>Packages (GHSA)</span></div>
</div>

<div class="dl">
<a href="{blob}{xlsx_rel}">Download Excel</a>
<a href="{blob}{pdf_rel}">Download PDF</a>
</div>

<div class="tools">
<input id="q" placeholder="Filter by CVE, vendor, keyword..." size="36">
<select id="sev">
<option value="">All severities</option>
<option>CRITICAL</option>
<option>HIGH</option>
<option>MEDIUM</option>
<option>LOW</option>
</select>
<select id="rsn">
<option value="">New + Updated</option>
<option value="New">New only</option>
<option value="Updated">Updated only</option>
<option value="KEV">Added to KEV</option>
</select>
<label><input type="checkbox" id="kevonly"> KEV only</label>
<label><input type="checkbox" id="wlonly"> Watchlist only</label>
<span id="count" class="sub" style="margin:0"></span>
</div>

<table id="t">
<thead>
<tr>
<th>Priority</th><th>Reason</th><th>ID</th><th>CVSS</th><th>Severity</th>
<th>KEV</th><th>EPSS</th><th>Watchlist</th><th>Vendor / Product / Package</th>
<th>Sources</th><th>Description</th>
</tr>
</thead>
<tbody>
{''.join(row(record) for record in records)}
</tbody>
</table>

<details>
<summary>Previous reports ({len(archive)})</summary>
<table>
<thead>
<tr><th>Date</th><th>Total</th><th>New</th><th>Updated</th><th>KEV added</th><th>Critical</th><th>High</th><th>Files</th></tr>
</thead>
<tbody>{history_rows}</tbody>
</table>
</details>

<footer>
Generated {snapshot['generated_at'][:19].replace('T',' ')} UTC by GitHub Actions.
<b>New</b> = published in this report window.
<b>Updated</b> = an older item with a meaningful security-related change detected today.
A CVE keeps its original Published Date and remains in that historical day's report.
<b>Added to KEV</b> = CISA added the CVE to the Known Exploited Vulnerabilities catalogue today.
</footer>

<script>
const q=document.getElementById('q');
const sev=document.getElementById('sev');
const kev=document.getElementById('kevonly');
const wl=document.getElementById('wlonly');
const rsn=document.getElementById('rsn');
const rows=[...document.querySelectorAll('#t tbody tr')];

function apply(){{
  const search=q.value.toLowerCase();
  const severity=sev.value;
  const reason=rsn.value;
  let shown=0;

  rows.forEach(r=>{{
    const text=r.innerText.toLowerCase();
    const cells=r.children;
    const actualReason=cells[1].innerText.trim();

    const reasonOk =
      !reason ||
      (reason==='New' && actualReason==='New') ||
      (reason==='Updated' && actualReason.startsWith('Updated')) ||
      (reason==='KEV' && actualReason==='Added to KEV');

    const ok =
      (!search || text.includes(search)) &&
      (!severity || cells[4].innerText===severity) &&
      (!kev.checked || cells[5].innerText==='KEV') &&
      (!wl.checked || cells[7].innerText.trim()!=='') &&
      reasonOk;

    r.style.display=ok?'':'none';
    if(ok) shown++;
  }});

  document.getElementById('count').textContent=shown+' of '+rows.length+' shown';
}}

[q,sev,kev,wl,rsn].forEach(e=>e.addEventListener('input',apply));
apply();

document.querySelectorAll('#t th').forEach((th,i)=>th.addEventListener('click',()=>{{
  const asc=th.dataset.asc!=='1';
  th.dataset.asc=asc?'1':'0';
  const tb=document.querySelector('#t tbody');
  [...tb.rows].sort((a,b)=>{{
    const x=a.children[i].innerText;
    const y=b.children[i].innerText;
    const nx=parseFloat(x);
    const ny=parseFloat(y);
    const cmp=(!isNaN(nx)&&!isNaN(ny)) ? nx-ny : x.localeCompare(y);
    return asc?cmp:-cmp;
  }}).forEach(r=>tb.appendChild(r));
}}));
</script>
</body>
</html>"""

    with open(DOCS_DIR / "index.html", "w", encoding="utf-8") as f:
        f.write(page)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--date")
    parser.add_argument(
        "--repo-url",
        default=None,
        help="https://github.com/org/repo (for dashboard links)",
    )
    args = parser.parse_args()

    snapshot = load_snapshot(args.date)
    report_date = snapshot["report_date"]
    year, month = report_date[:4], report_date[5:7]

    xlsx = REPORT_DIR / year / month / f"vulns-{report_date}.xlsx"
    pdf = REPORT_DIR / year / month / f"vulns-{report_date}.pdf"

    build_xlsx(snapshot, xlsx)
    build_pdf(snapshot, pdf)

    repo_url = args.repo_url or (
        f"https://github.com/{os.getenv('GITHUB_REPOSITORY', 'ORG/REPO')}"
    )
    build_dashboard(
        snapshot,
        str(xlsx.relative_to(ROOT)),
        str(pdf.relative_to(ROOT)),
        repo_url,
    )

    gh_out = os.getenv("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as f:
            f.write(
                f"xlsx={xlsx}\npdf={pdf}\nreport_date={report_date}\n"
            )
            f.write(
                f"summary=New {snapshot['counts']['new']} | "
                f"Updated {snapshot['counts']['updated']} | "
                f"KEV added {snapshot['counts']['kev_added']} | "
                f"Critical {snapshot['counts']['critical']} | "
                f"High {snapshot['counts']['high']} | "
                f"Watchlist {snapshot['counts']['watchlist']}\n"
            )

    print(f"Built {xlsx}")
    print(f"      {pdf}")
    print(f"      {DOCS_DIR / 'index.html'}")


if __name__ == "__main__":
    main()
