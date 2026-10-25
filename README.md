# sAScan 🐉 — dragon-grade digital footprint intelligence

**sAScan** is a stateless command-line OSINT tool that unifies username, email and phone reconnaissance into a single live footprint model. It combines a fast native engine with optional adapters for [Sherlock](https://github.com/sherlock-project/sherlock), [Holehe](https://github.com/megadose/holehe) and [PhoneInfoga](https://github.com/sundowndev/phoneinfoga), correlates discovered identifiers, and opens an interactive HTML report.

No SQLite. No account history. No scan database. Every run is independent.

> ⚠️ **Legal and ethical notice**
>
> Use sAScan only on your own digital footprint or on data you have **explicit, documented permission** to investigate. Unauthorized profiling can violate privacy laws, harassment laws and platform terms. You are responsible for how you use the output. Correlation is evidence, not identity proof.

---

## Highlights

- 🐉 Animated-ready Rich console with a custom ASCII dragon banner.
- 🔎 **19 native platforms** out of the box, with explicit three-way verdicts: `FOUND`, `ABSENT`, `UNKNOWN`.
- 📧 Email intelligence: MX / SPF / DMARC, Gravatar public profile discovery and exact-author commit evidence from public GitHub commits.
- 📱 Phone intelligence: E.164 validation, region, line type, carrier, timezone and manual lookup leads.
- 🧠 **Correlation Engine**: derives usernames from email local-parts, extracts handles from profile URLs, links Gravatar accounts, builds a graph and calculates an evidence-based confidence score.
- 🌐 **Interactive HTML report**: vis-network identity graph, verdict filters, live table search, JSON export and print layout.
- 🧾 Rich console report with panels, tables, a correlation tree and confidence bar.
- 🧩 Optional external engines, detected safely in `PATH`; no auto-install and no hidden network calls.
- 🗃️ Fully stateless: no SQLite, no sessions, no database, no history.
- 🧪 Pure-logic tests for classification, normalization, correlation, parsers and report rendering.

---

## Installation

Requires **Python 3.10+** (tested on Python 3.14).

Run these commands from the **project root** — the folder that contains `pyproject.toml`. If you already downloaded or copied the project, do not clone it again, and do not run these steps from the inner `sascan/` package folder.

```bash
cd /path/to/sascan          # folder containing pyproject.toml
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

> If you cloned the project from a repository, replace `/path/to/sascan` with your clone directory. There is no placeholder URL to copy.
>
> The only supported environment is `.venv` at the project root (`sascan/.venv`). A virtual environment created inside the package folder (`sascan/sascan/.venv`) does not contain the dependencies and will fail with `ModuleNotFoundError`.

Check the installation:

```bash
sascan --version
sascan version --no-banner
sascan sites --no-banner
```

If `sascan` is not found after `pip install -e .`, use:

```bash
.venv/bin/sascan --help
# or
python -m sascan --help
```

### Optional external engines

sAScan's native engine works immediately. External engines are optional and are used only if their executable is available in `PATH`.

| Engine | Purpose | Install |
|---|---|---|
| Sherlock | Username coverage beyond the native registry | `pipx install sherlock-project` |
| Holehe | Email account registration checks | `pipx install holehe` |
| PhoneInfoga | Additional phone OSINT | [GitHub releases](https://github.com/sundowndev/phoneinfoga/releases) |

Verify detection:

```bash
sascan version --no-banner
```

`auto` mode runs the fast native engine only, even when external tools are installed. External engines are opt-in:

- `--engine both` runs the native engine plus the relevant external engine (it must be installed).
- `--engine sherlock`, `--engine holehe` or `--engine phoneinfoga` runs that adapter alone.

External scans can take minutes because tools such as Sherlock probe hundreds of sites; sAScan applies a 180-second hard cap. `sascan version` always shows which external engines are available. Explicit engine modes fail with a clear error if the tool is missing.

---

## Quick start

```bash
# Auto-detect username, email or phone
sascan scan alice

# Explicit username scan
sascan user alice

# Email scan with bounded deep follow-up on derived usernames
sascan email alice@example.com --deep

# Phone scan (E.164 recommended)
sascan phone +966501234567 --region SA

# Limit native sites
sascan user alice --only GitHub,Telegram,Reddit

# Console only, no HTML
sascan user alice --no-report

# Machine-readable output
sascan user alice --json

# Custom report location
sascan user alice --output ~/reports/alice.html
```

The HTML report is written to `./reports/` by default and opened in the default browser. Use `--no-open` to suppress the browser.

---

## Commands

| Command | Description |
|---|---|
| `sascan scan TARGET` | Auto-detect `TARGET` as username, email or phone. |
| `sascan user USERNAME` | Force a username scan. |
| `sascan email EMAIL` | Force an email scan. |
| `sascan phone PHONE` | Force a phone scan. |
| `sascan sites` | List the native site registry. |
| `sascan version` | Show runtime and external engine availability. |

### Scan options

| Option | Default | Description |
|---|---|---|
| `--deep` | off | Bounded follow-up of derived usernames (email seeds). |
| `--engine [native\|auto\|both\|sherlock\|holehe\|phoneinfoga]` | `auto` | Engine selection. |
| `--region CODE` | `SA` | ISO country code for parsing local phone numbers. |
| `--timeout SECONDS` | `10` | Per-request timeout. |
| `--concurrency N` | `30` | Maximum concurrent HTTP requests. |
| `--only FILTER` | all | Limit native sites; comma-separated or repeatable. |
| `--output PATH` | `./reports/` | HTML file or directory. |
| `--no-open` | off | Do not launch the browser. |
| `--no-report` | off | Skip HTML generation. |
| `--json` | off | JSON to stdout only; implies no report and no browser. |
| `--verbose` | off | Show all inconclusive findings and unexpected tracebacks. |

Global flags: `--no-banner`, `--quiet`, `--no-color`, `--version`, `--help`.

> `--only` applies to native username checks. For email and phone scans the option is ignored (and noted in the report).

---

## How it works

### Three honest verdicts

Every check is classified as one of:

- **FOUND** — a positive signal was observed (HTTP status and/or required marker).
- **ABSENT** — a definitive absence signal (for example HTTP 404 or an explicit “no such user” marker).
- **UNKNOWN** — bot protection, login walls, captchas, rate limits, timeouts or ambiguous responses.

`UNKNOWN` is never converted into `FOUND` to make a report look better. That is deliberate: Instagram login walls, X guest restrictions, TikTok captchas and similar defenses commonly require manual verification.

### Native modules

| Seed | Native checks |
|---|---|
| Username | 19 HTTP site checks with per-site markers and status rules. |
| Email | MX/SPF/DMARC DNS, Gravatar JSON profile and verified accounts, exact-author GitHub commit evidence. |
| Phone | `phonenumbers` validation plus carrier, region, line type, timezone and manual Truecaller/Google/WhatsApp leads. |

GitHub evidence uses the commit search API with `author-email:<email>`. The older `search/users?q=...in:email` endpoint was removed because it returns unrelated accounts for common test addresses. A GitHub account is reported only when a matching commit exposes an `author.login`; otherwise the result is labelled as commit evidence, not an account. Reserved test domains skip the GitHub check entirely, and multiple distinct logins for one address are treated as a shared email with account links withheld.

### Correlation

The correlation engine:

1. Adds the seed as the root identifier.
2. Derives candidate usernames from the email local-part.
3. Extracts handles from known profile URLs.
4. Adds usernames and links discovered through Gravatar.
5. Marks candidates that were actually scanned with `--deep`.
6. Builds a force-directed graph of seed → identifiers → platforms/leads.
7. Assigns a confidence score based on observed evidence, not promises.

A high score means “more evidence was observed”, not “this person is definitely the target”. Always verify identity claims manually.

### Deep mode

`--deep` is intentionally bounded to at most **two** derived usernames. It follows username candidates inferred from an email address and, when external engines are enabled, checks them with the same engine policy. This avoids accidentally turning a scan into a large, noisy crawl.

Deep mode has no automatic follow-up for username or phone seeds because there is no defensible, low-noise next hop.

---

## Reports

### HTML

The report is a single portable HTML file with embedded data and a CDN-loaded vis-network graph. It includes:

- Target, seed kind, engines, duration and confidence.
- Found / inconclusive / absent statistics.
- Force-directed identity graph (drag, zoom, freeze layout, double-click platforms).
- Unified username/email/phone/candidate lists.
- Gravatar profile card when available.
- Filterable, searchable findings table.
- JSON export, copy-target and print actions.
- Engine errors and analyst notes.

Default path:

```text
./reports/sascan_<kind>_<slug>_<timestamp>.html
```

### Console

The Rich console report includes a confidence bar, scan statistics, correlation tree, verified profiles, inconclusive checks, absent summary, engine errors and notes.

### JSON

`--json` prints the complete machine-readable model to stdout:

```bash
sascan email alice@example.com --json > alice.json
```

JSON output is pure: no banner, no progress animation and no HTML report.

---

## Project structure

```text
sascan/
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── README.md
├── reports/                    # generated HTML reports (gitignored)
├── sascan/
│   ├── __main__.py
│   ├── banner.py               # ASCII dragon + Rich banner
│   ├── cli.py                  # Click commands
│   ├── config.py
│   ├── models.py               # Seed, Finding, Correlation, ScanResult
│   ├── ui.py
│   ├── core/
│   │   ├── classify.py         # pure three-way classifier
│   │   ├── correlation.py      # graph + unified identifiers
│   │   ├── engine.py           # orchestration, deep mode
│   │   ├── http.py             # bounded aiohttp client
│   │   ├── progress.py         # Rich progress
│   │   └── sites.py            # sites.json loader/validator
│   ├── data/
│   │   └── sites.json          # 19 native site rules
│   ├── modules/
│   │   ├── email.py
│   │   ├── external.py         # Sherlock/Holehe/PhoneInfoga adapters
│   │   ├── gravatar.py
│   │   ├── phone.py
│   │   └── username.py
│   ├── reports/
│   │   ├── console.py
│   │   ├── html.py
│   │   └── templates/report.html.j2
│   └── utils/
│       ├── text.py
│       └── validators.py
└── tests/
```

---

## Customizing sites

Edit `sascan/data/sites.json`. Each rule supports:

| Field | Purpose |
|---|---|
| `name`, `kind`, `category` | Display metadata. |
| `url` | HTTPS check URL; must contain `{account}`. |
| `link` | Optional human profile URL; must contain `{account}`. |
| `found_status`, `absent_status`, `blocked_status` | HTTP status sets. |
| `present_markers` | Required marker(s) for confirmation. |
| `absent_markers` | Text proving absence despite HTTP 200. |
| `blocked_markers` | Bot-protection markers producing `UNKNOWN`. |
| `missing_is_absent` | Treat missing present markers as absence (only for decisive sites). |
| `enabled` | Disable a rule without deleting it. |

Validate changes without a scan:

```bash
sascan sites --search github
```

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Many `UNKNOWN` results | Bot protection, login walls, captchas, rate limits or network issues. Manual verification is required. |
| `--engine sherlock` says not installed | Install with `pipx install sherlock-project`, or use `--engine auto` / `native`. |
| A scan seems to hang for a minute | Older builds ran installed external tools in `auto` mode. Current builds keep `auto` native-only; external engines run only with `--engine both` or by name and can take minutes. |
| Holehe command exits non-zero | Check `holehe --help`; versions and flags differ. sAScan reports the error without hiding native output. |
| Phone number rejected | Use E.164 (`+966...`) or set the correct `--region`. |
| Report does not auto-open | Headless environment; use `--no-open` and open the printed path manually. |
| Graph is empty | No confirmed account/profile nodes; textual findings are still in the report. |
| `sascan: command not found` | Activate the virtual environment and reinstall with `python -m pip install -e .` from the folder containing `pyproject.toml`. |
| `ModuleNotFoundError: No module named 'click'` (or `rich`, `aiohttp`) | You activated a stray environment, usually `sascan/sascan/.venv`. Run `deactivate`, `cd` to the folder containing `pyproject.toml`, then `source .venv/bin/activate`. |
| `pyproject.toml not found` during `pip install -e .` | You are in the inner package folder. Move up one level to the project root. |
| Colors look wrong | Use `--no-color`, or set `NO_COLOR=1`. |

---

## Testing

```bash
source .venv/bin/activate
pytest -q
```

Tests do **not** require network access or third-party OSINT tools. They cover:

- Classification precedence and marker matching.
- Username/email/phone normalization and seed detection.
- Site registry validation and filters.
- Correlation graph, candidates and confidence.
- Sherlock/Holehe/PhoneInfoga output parsers.
- HTML report rendering and safe JSON embedding.
- CLI help, site listing and version output.

---

## Design boundaries

- **No database** and no scan history.
- **No credential validation** against login systems.
- **No bypassing** captchas, authentication or rate limits.
- **No claim of ownership** for an email or phone number.
- External engines are independent projects with their own licenses and behavior.
- Site rules are best-effort and can age; platform HTML changes frequently.

---

## License

MIT. See [LICENSE](LICENSE). External tools retain their own licenses.
