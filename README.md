# Daily Vulnerability Report

A GitHub Actions-based daily vulnerability feed that collects
vulnerability intelligence from multiple public sources, keeps daily
history in Git, generates Excel/PDF reports, publishes a filterable
GitHub Pages dashboard, and highlights vulnerabilities affecting
technologies on a configurable watchlist.

## What it does

The pipeline:

1.  Pulls newly published CVEs from **NVD**.
2.  Uses **CISA Vulnrichment** to fill scoring/SSVC gaps where
    available.
3.  Checks the **CISA Known Exploited Vulnerabilities (KEV)** catalogue.
4.  Adds **FIRST EPSS** exploit-probability scores.
5.  Merges **GitHub Security Advisories (GHSA)**.
6.  Merges **OSV.dev** advisories for configured ecosystems.
7.  Applies the configured **technology watchlist**.
8.  Calculates a priority from KEV, EPSS, SSVC and CVSS.
9.  Stores a JSON snapshot in `data/YYYY-MM-DD.json`.
10. Builds:

-   `reports/YYYY/MM/vulns-YYYY-MM-DD.xlsx`
-   `reports/YYYY/MM/vulns-YYYY-MM-DD.pdf`

11. Publishes a filterable dashboard to GitHub Pages at
    `docs/index.html`.
12. Keeps historical daily reports in Git.
13. If watchlist matches are found, prepares a **GitHub Issue alert**
    and can also send the same alert to an external webhook if
    configured.

Everything runs in **GitHub Actions**. No application server is
required.

------------------------------------------------------------------------

## Dashboard

The dashboard is published through GitHub Pages.

Example:

`https://<org-or-user>.github.io/<repo>/`

For this repository:

`https://santosh-shet.github.io/Vulnerabilities-list/`

The dashboard provides:

-   New today
-   Significant updates
-   Added to KEV today
-   Total feed entries
-   Critical / High / Medium / Unscored counts
-   Watchlist count
-   GHSA package count
-   Excel download
-   PDF download
-   Search by CVE, vendor, product or keyword
-   Severity filter
-   New / Updated / KEV filter
-   KEV-only filter
-   Watchlist-only filter
-   Vendor / Product / Package dropdown
-   Top Critical Vendor / Product / Package
-   Sortable result table
-   Previous report history

------------------------------------------------------------------------

# Setup

## 1. Create the repository

Create the repository and push the project files.

The important directories/files are:

``` text
.
├── .github/
│   └── workflows/
│       ├── daily-vulns.yml
│       └── backfill.yml
├── config/
│   └── watchlist.yml
├── data/
├── docs/
├── reports/
│   └── YYYY/
│       └── MM/
├── scripts/
│   ├── fetch_vulns.py
│   ├── build_reports.py
│   └── notify_watchlist.py
├── requirements.txt
└── README.md
```

## 2. Enable GitHub Pages

Go to:

**Repository → Settings → Pages**

Set:

**Source → GitHub Actions**

The daily workflow publishes the generated `docs` directory.

## 3. Configure the NVD API key

Go to:

**Repository → Settings → Secrets and variables → Actions**

Add:

  -----------------------------------------------------------------------
  Secret                              Purpose
  ----------------------------------- -----------------------------------
  `NVD_API_KEY`                       Optional NVD API key. Without it
                                      the workflow still works, but NVD
                                      requests are slower due to public
                                      rate limits.

  `GH_PAT`                            Optional PAT used by the current
                                      workflow for the report commit. The
                                      workflow uses it when present so
                                      the daily bot commit counts as
                                      repository activity.
  -----------------------------------------------------------------------

`GITHUB_TOKEN` is supplied automatically by GitHub Actions.

Do not put API keys, PATs, webhook URLs or other secrets directly into
the repository files.

------------------------------------------------------------------------

# Watchlist

The watchlist is configured in:

``` text
config/watchlist.yml
```

The current list is focused on technologies relevant to enterprise
environments and Tieto security work, including:

-   Microsoft / Windows / Azure / Entra
-   Atlassian / Jira / Confluence / Bitbucket
-   Xray / Tempo / Appfire / Comala / Jellyfish
-   AWS
-   Databricks
-   Snowflake
-   PostgreSQL / MySQL / MongoDB / Redis / Elasticsearch
-   GitHub / GitLab / Jenkins
-   Docker / Kubernetes / Terraform
-   HashiCorp Vault
-   SonarQube
-   CrowdStrike / Palo Alto / Fortinet / Cisco
-   Zscaler / Okta / CyberArk
-   Qualys / Tenable
-   VMware / Citrix / F5 / Ivanti
-   OpenSSL / OpenSSH
-   Apache / Tomcat / Kafka / ActiveMQ
-   Nginx / PHP / Spring / Log4j / Jackson
-   Oracle / IBM / SAP
-   npm / Node.js
-   Axios / Express / Lodash / React / Vue / Angular / Next.js
-   PyPI / Python
-   Django / Flask / FastAPI / Requests / urllib3 / cryptography
-   Maven
-   Go / gRPC
-   .NET / NuGet
-   Rust / Cargo
-   Red Hat / SUSE / Dell / HP

The list is deliberately made up of specific technologies/products
rather than broad terms such as `cloud`, `database`, `linux`, `api` or
`python` alone.

## Adding a technology

Edit:

``` text
config/watchlist.yml
```

Add a keyword under `keywords:`.

Example:

``` yaml
keywords:
  - databricks
  - atlassian
  - jira
  - my-new-product
```

Matching is case-insensitive.

The current fetcher primarily matches the watchlist against:

1.  NVD vendor/product information
2.  GHSA/OSV package information
3.  The vulnerability description when vendor/product and package
    information are unavailable

The matched keywords are stored in each record as `watchlist_hits`, and
the record is marked with:

``` text
watchlist_match = true
```

The daily snapshot also stores the active watchlist keywords.

### Keep watchlist entries specific

Prefer:

``` yaml
- microsoft:exchange
- apache:tomcat
- atlassian
- databricks
- hashicorp:vault
- axios
```

Avoid overly broad entries such as:

``` yaml
- cloud
- security
- database
- api
```

Broad terms can match a very large percentage of the daily feed and make
the Watchlist filter less useful.

------------------------------------------------------------------------

# Watchlist alerts

After the daily report is built, the workflow runs:

``` text
scripts/notify_watchlist.py
```

It reads the day's JSON snapshot and checks:

``` text
watchlist_match == true
```

If there are no matches:

``` text
No watchlist matches — skipping notification.
```

No alert issue is created.

If matches exist, the workflow:

1.  Generates a Markdown alert.
2.  Adds the alert to the GitHub Actions Summary.
3.  Creates a GitHub Issue labelled:

``` text
vuln-watchlist
```

4.  Closes older open `vuln-watchlist` issues so that the current alert
    remains the active tracker.
5.  Assigns the issue to the usernames configured in the repository
    variable:

``` text
NOTIFY_ASSIGNEES
```

Example:

``` text
santosh-shet,teammate1
```

Configure it under:

**Repository → Settings → Secrets and variables → Actions → Variables**

The alert includes links to:

-   GitHub Pages dashboard
-   Daily Excel report
-   Daily PDF report

GitHub notifications for the issue/assignees depend on the recipients'
GitHub notification settings.

------------------------------------------------------------------------

# Optional webhook notification

`scripts/notify_watchlist.py` also supports sending the watchlist alert
to an external HTTP webhook.

It supports:

``` bash
python scripts/notify_watchlist.py \
  --webhook-url "https://example.com/webhook"
```

Optional HMAC signing is supported with:

``` bash
--webhook-secret
```

The webhook payload contains:

-   Report date
-   Report window
-   Total entries
-   Watchlist match count
-   Critical watchlist matches
-   High watchlist matches
-   KEV watchlist matches
-   Dashboard URL
-   Individual matching CVE/advisory details

This can be used with an approved webhook endpoint such as an enterprise
automation/email workflow.

The current daily workflow uses the **GitHub Issue alert** by default. A
webhook is only used when a webhook URL is explicitly supplied.

------------------------------------------------------------------------

# What counts as a row?

The feed deliberately separates newly published vulnerabilities from
meaningful updates.

  -----------------------------------------------------------------------
  Reason                              Meaning
  ----------------------------------- -----------------------------------
  **New**                             Vulnerability/advisory published
                                      during the report window.

  **Updated - ...**                   An older vulnerability received a
                                      meaningful security-related change
                                      detected in the current window.

  **Added to KEV**                    CISA added an older CVE to the
                                      Known Exploited Vulnerabilities
                                      catalogue.
  -----------------------------------------------------------------------

## New vulnerabilities

For NVD, the **Published Date** determines the daily New bucket.

An older CVE does not become a new CVE just because NVD changed its
`lastModified` timestamp.

This keeps the daily feed tied to the original publication date.

## Significant updates

The modified timestamp is used only to discover possible update
candidates.

An older CVE is included in the current report only when a meaningful
security-related change is detected, such as:

-   CVSS score added
-   CVSS score changed
-   Severity changed
-   CVSS vector changed
-   SSVC exploitation status changed

Routine NVD re-processing or metadata changes should not cause an old
CVE to appear as a new vulnerability.

## Historical behaviour

If:

``` text
CVE-X
Published: 2026-09-16
```

and its score changes on:

``` text
2026-09-18
```

then:

-   It remains in the **September 16** New report.
-   It can appear in the **September 18** Significant Updates section.
-   It is not reclassified as New on September 18.

This is the mechanism used to avoid the previous large daily spikes
caused by NVD `lastModified` processing.

------------------------------------------------------------------------

# Priority rules

Priority is calculated in `fetch_vulns.py`.

  -----------------------------------------------------------------------
  Priority                            Rule
  ----------------------------------- -----------------------------------
  **P1 - Act now**                    In CISA KEV, or EPSS \>= 0.50, or
                                      SSVC exploitation = active

  **P2 - High**                       CVSS \>= 9.0, or CVSS \>= 7.0 with
                                      EPSS \>= 0.10, or SSVC exploitation
                                      = poc

  **P3 - Medium**                     CVSS \>= 7.0

  **P4 - Low / Unscored**             Everything else
  -----------------------------------------------------------------------

A newly published vulnerability can therefore initially be unscored and
become higher priority when additional scoring information becomes
available.

------------------------------------------------------------------------

# Data sources

  ------------------------------------------------------------------------
  Source                  What it adds            Configuration
  ----------------------- ----------------------- ------------------------
  **NVD 2.0**             CVE, description, CVSS, Always
                          CPE vendor/product      

  **CISA KEV**            Exploited flag, due     Always
                          date, ransomware-use    
                          information             

  **FIRST EPSS**          Exploit probability and Always
                          percentile              

  **CISA Vulnrichment**   CVSS and SSVC           `sources.vulnrichment`
                          exploitation            
                          information where       
                          available               

  **GitHub Security       Package ecosystem,      `sources.ghsa`
  Advisories**            package, fixed version  
                          and GHSA advisories     

  **OSV.dev**             Package advisories for  `sources.osv`
                          configured ecosystems   
  ------------------------------------------------------------------------

Current OSV ecosystems:

``` yaml
osv_ecosystems:
  - Go
  - PyPI
  - Maven
  - npm
  - NuGet
```

Additional ecosystems can be added if supported by OSV and if the daily
download volume is acceptable.

------------------------------------------------------------------------

# Daily schedule

The current workflow uses a timezone-aware GitHub Actions schedule:

``` yaml
on:
  schedule:
    - cron: "17 6 * * *"
      timezone: "Asia/Kolkata"
```

This targets:

**06:17 IST every day.**

GitHub Actions scheduled workflows can be delayed, so the cron time
should not be treated as an exact execution alarm.

If the desired target is 07:00 IST, use:

``` yaml
on:
  schedule:
    - cron: "0 7 * * *"
      timezone: "Asia/Kolkata"
```

The schedule is defined in:

``` text
.github/workflows/daily-vulns.yml
```

The workflow also supports manual execution through:

**Actions → Daily vulnerability report → Run workflow**

------------------------------------------------------------------------

# Manual run and backfill

The daily workflow supports two inputs.

## Run for a specific date

Use:

``` text
date: 2026-09-08
```

This fetches the specified UTC calendar day.

## Run a rolling window

Use:

``` text
hours: 72
```

This fetches the previous 72 hours.

The default is:

``` text
hours: 24
```

This is useful when a scheduled run was missed.

------------------------------------------------------------------------

# Backfill

There is a separate workflow:

``` text
.github/workflows/backfill.yml
```

Go to:

**Actions → Backfill last N days → Run workflow**

Enter the number of days, for example:

``` text
10
```

The workflow processes each missing day individually and skips days for
which a JSON snapshot already exists.

It also rebuilds the reports/dashboard and commits the resulting files.

------------------------------------------------------------------------

# Output files

## JSON

Daily snapshots:

``` text
data/YYYY-MM-DD.json
```

These contain:

-   Report date
-   UTC window
-   Source information
-   Counts
-   Watchlist keywords
-   Vulnerability records
-   CVSS
-   EPSS
-   KEV
-   SSVC
-   Watchlist matches
-   Vendor/product/package information
-   Entity information
-   Priority

The JSON snapshots are the source used to build the Excel, PDF and
dashboard.

## Excel

Generated at:

``` text
reports/YYYY/MM/vulns-YYYY-MM-DD.xlsx
```

Sheets include:

-   Summary
-   All CVEs
-   New Today
-   Significant Updates
-   Added to KEV
-   KEV - Exploited
-   Critical & High
-   Watchlist
-   Packages (GHSA-OSV)

## PDF

Generated at:

``` text
reports/YYYY/MM/vulns-YYYY-MM-DD.pdf
```

The PDF contains the daily summary and vulnerability details intended
for quick review.

## Dashboard

Generated at:

``` text
docs/index.html
```

and published through GitHub Pages.

------------------------------------------------------------------------

# Repository activity and scheduled workflows

The daily workflow commits the generated data, reports and dashboard
back to the repository.

The current workflow can use:

``` text
GH_PAT
```

for the report commit.

GitHub scheduled workflows can be disabled after a prolonged period of
repository inactivity. The daily bot commit helps keep the repository
active. If the dashboard becomes stale, first check:

**Actions → Daily vulnerability report**

for failed or missing scheduled runs.

------------------------------------------------------------------------

# Troubleshooting

## No new report

Check:

**Actions → Daily vulnerability report**

Confirm that the run is marked **Scheduled** and inspect any failed
step.

## Scheduled run happens later than expected

GitHub Actions schedules are not guaranteed to start exactly at the cron
minute. GitHub can delay scheduled workflows during periods of high
Actions load.

Use a schedule at a less congested minute and allow sufficient buffer
before the team's review time.

## Too many vulnerabilities

Check:

``` text
config/watchlist.yml
```

for overly broad keywords.

For update volume, check:

``` yaml
include_updated: true
modified_lookback_days: 21
```

The update logic is intentionally based on meaningful security changes
rather than every NVD `lastModified` event.

## Watchlist does not match a technology

Check that the technology is represented in:

``` text
config/watchlist.yml
```

and that the keyword matches the vendor/product/package naming used by
the source.

Remember that the current matcher primarily uses structured
vendor/product and package fields, with description matching as a
fallback when those fields are unavailable.

## NVD is slow

Configure:

``` text
NVD_API_KEY
```

as a GitHub Actions secret.

## NVD is unreachable

If the GitHub-hosted runner cannot reach `nvd.nist.gov` because of
organizational network restrictions, use an approved self-hosted runner.

------------------------------------------------------------------------

# Future integrations

The project can later incorporate internal scanner findings such as:

-   Tenable
-   Qualys
-   Microsoft Defender

A new fetcher should normalize findings into the same record structure
used by `fetch_vulns.py`. The existing report and dashboard generation
can then consume the normalized records.

------------------------------------------------------------------------

# Security and privacy note

GitHub Pages visibility depends on the GitHub plan and organization
configuration.

If the Pages site is publicly accessible, anyone with the URL may be
able to view the dashboard.

Although CVE information itself is public, the **Watchlist reveals
technologies used in the environment**.

Before sharing the Pages URL externally, verify that the repository and
Pages configuration meet your organization's security requirements.

Do not store:

-   API keys
-   PATs
-   webhook secrets
-   passwords
-   other credentials

in the repository. Use GitHub Actions Secrets or approved enterprise
secret-management mechanisms.
