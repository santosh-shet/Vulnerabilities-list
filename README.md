# Daily vulnerability report

Pulls **newly published CVEs from NVD**, fills scoring gaps from **CISA
Vulnrichment**, flags anything in **CISA KEV** (actively exploited), adds **EPSS**
exploit-probability scores, merges package advisories from **GitHub Security
Advisories** and **OSV.dev**, matches against a **watchlist** of your
vendors/products, and every day:

1. stores a JSON snapshot in `data/YYYY-MM-DD.json` (so history and diffs live in Git)
2. builds `reports/YYYY/MM/vulns-YYYY-MM-DD.xlsx` and `.pdf`
3. publishes a filterable dashboard to GitHub Pages (`docs/index.html`)
4. keeps 10 days of history downloadable from the dashboard

Everything runs in GitHub Actions - no servers, no email setup. Share the
dashboard URL with your team; it refreshes automatically every morning.

## Setup (10 minutes)

1. **Create a private repo** and push these files.
2. **Enable Pages**: Settings > Pages > Source: *GitHub Actions*.
3. **Secrets** (Settings > Secrets and variables > Actions):

   | Secret | Purpose |
   |---|---|
   | `NVD_API_KEY` | Optional. Free at https://nvd.nist.gov/developers/request-an-api-key. Without it the run is slower (5 req / 30 s) but works. |

4. **Edit `config/watchlist.yml`** with the vendors and technologies in your estate.
5. **Run it once manually**: Actions > *Daily vulnerability report* > *Run workflow*.
   Or run **Backfill last N days** (defaults to 10) to populate history in one go.

6. **Share the dashboard URL**: `https://<org-or-user>.github.io/<repo>/`
   (shown under Settings > Pages once the first run completes).

From then on it runs at **06:00 UTC** every day (07:00 CET / 08:00 CEST), so the
data is fresh well before 10:00 CET. Change the cron in
`.github/workflows/daily-vulns.yml` if needed - remember cron is always UTC.

## What is a "row"?

| Reason | Meaning |
|---|---|
| **New** | Published in the 24-hour window. Typically 100-150 CVEs plus 20-60 package advisories. |
| **Updated** | Published in the last 30 days and, in the window, received its first CVSS score. This is how yesterday's "Unscored" items come back once analysed. |
| **Added to KEV** | An older CVE CISA just confirmed as exploited. |

Older CVEs that NVD merely re-processed (CPE tweaks, re-scoring, bulk enrichment)
are **not** included - that was the cause of 3,000-row days. Tune with
`include_updated` and `modified_lookback_days` in `config/watchlist.yml`.

## Sources

| Source | What it adds | Toggle |
|---|---|---|
| NVD 2.0 | CVE, description, NVD CVSS, CPE vendor/product | always |
| CISA KEV | Exploited flag, due date, ransomware use | always |
| FIRST EPSS | Exploit probability (0-1) | always |
| CISA Vulnrichment | CVSS + SSVC (exploitation: none/poc/active) for CVEs NVD hasn't scored | `sources.vulnrichment` |
| GitHub Security Advisories | Package ecosystem, name, first fixed version; GHSA-only advisories become rows | `sources.ghsa` |
| OSV.dev | Same for the ecosystems in `osv_ecosystems`; PYSEC/GO/etc. IDs become rows | `sources.osv` |

## Priority rules

| Priority | Rule |
|---|---|
| P1 - Act now | In CISA KEV, **or** EPSS >= 0.50, **or** SSVC exploitation = active |
| P2 - High | CVSS >= 9.0, **or** CVSS >= 7.0 with EPSS >= 0.10, **or** SSVC exploitation = poc |
| P3 - Medium | CVSS >= 7.0 |
| P4 - Low / Unscored | Everything else. Many brand-new CVEs are unscored for 1-3 days while NVD analyses them - they reappear scored in later runs. |

Adjust in `fetch_vulns.py` (search for `priority`).

## Output

- **Excel**: Summary, All CVEs, KEV - Exploited, Critical & High, Watchlist, Packages (GHSA-OSV) sheets.
  Filterable, frozen headers, severity colour-coded, NVD hyperlinks.
- **PDF**: one-page summary plus P1/P2 detail - meant for people who won't open a spreadsheet.
- **Dashboard**: latest day with search, New/Updated + severity + KEV + watchlist filters, sorting, download buttons, and a 10-day history table.

## Backfill / missed run

```
Run workflow  ->  date: 2026-09-08     # one specific day
Run workflow  ->  hours: 72            # rolling window
```

## Notes

- **Who can see the dashboard:** on GitHub Free/Pro/Team, a Pages site is
  public even when the repo is private - anyone with the URL can open it.
  The CVE data is public anyway, but your watchlist matches reveal your tech
  stack. If that matters, either (a) use GitHub Enterprise Cloud, which supports
  access-controlled Pages, or (b) share the repo itself with the team and have
  them open `docs/index.html` / the Excel files from there instead of Pages.
- GitHub disables scheduled workflows after 60 days with no repo activity.
  The daily bot commit counts as activity, so this won't trigger unless the
  job itself is failing - check the Actions tab if the dashboard goes stale.
- If your org blocks GitHub-hosted runners from reaching nvd.nist.gov, switch
  `runs-on` to a self-hosted runner.
- To include your scanner findings later (Tenable, Qualys, Defender), add a
  fetcher that writes records in the same shape as `normalise_nvd()` and the
  reports/dashboard work unchanged.
