# Security policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 2.0.x   | ✅        |
| < 2.0   | ❌        |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private vulnerability reporting on this repository
(**Security → Advisories → Report a vulnerability**):

<https://github.com/tOxt-shadow/sAScan-OSINT/security/advisories/new>

Include, when possible:

- affected version and command used;
- a minimal reproduction (seed value, engine, output file);
- the impact you expect (crash, data leak, code execution, network abuse);
- whether the report includes personal data that should be handled carefully.

You can expect an initial reply within 7 days. Please give a reasonable
window to ship a fix before publishing details.

## Scope

In scope:

- remote code execution, command injection or path traversal in the CLI;
- leaks of local files, environment variables or credentials into reports;
- cross-site scripting (XSS) or script injection in generated HTML reports;
- dependency confusion or tampered report assets;
- denial of service caused by a single scan (unbounded memory or CPU).

Out of scope:

- findings that require the target's own platform to be compromised;
- rate limiting or account blocking applied by scanned platforms;
- false positives / false negatives in footprint detection (open a normal issue);
- results obtained by running the optional third-party engines — report those
  upstream to Sherlock, Holehe or PhoneInfoga;
- use of the tool against accounts you do not own, which is outside the
  documented and permitted use.

## Handling of scan data

sAScan is stateless: it writes only the report you ask for and never sends scan
results to any server controlled by this project. Generated reports can contain
personal data — treat them as sensitive local files and never commit them.
