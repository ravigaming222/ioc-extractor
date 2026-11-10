# IOC Extractor

Offline single-file IOC extractor for SOC analysts: paste a report, email or log and get the indicators of compromise. Everything runs locally in the browser. No network requests, no dependencies, no build step.

## Features

- Deduplicated extraction of URLs, domains, IPv4, IPv6, e-mails, MD5, SHA-1, SHA-256 and CVE IDs.
- Automatic refang of the input before parsing: `hxxp/hxxps`, `fxp`, `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)`, `{dot}`, `[@]`, `(at)`, `[at]`, `[://]`, `[:]`.
- "Defang text" and "Refang text" buttons with a separate output field and a copy button.
- Options: hide private IPs (10.x, 127.x, 0.x, 172.16-31.x, 192.168.x, 169.254.x); show results defanged.
- False-domain filter: IP addresses, numeric TLDs and common file extensions (exe, dll, js, php, pdf, zip, png, ...) are not treated as domains.
- Export: CSV (`type,value`), JSON, copy all, copy per category. Exports reflect what is shown on screen (with the options applied).
- "Sample" and "Clear" buttons.

## Live demo

https://ravigaming222.github.io/ioc-extractor/ (runs entirely in your browser, same single file).

## Download

Latest release: https://github.com/ravigaming222/ioc-extractor/releases/latest

The release contains `ioc-extractor.html`, `ioc-extractor-<tag>.zip` and `SHA256SUMS.txt`. To verify the checksums (files in the same folder):

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

## Run locally

Download `ioc-extractor.html` and open it by double-click. No installation, server or internet connection needed.

Tests (Node.js, no dependencies):

```bash
npm test
```

## How it works

- All code lives in one file, `ioc-extractor.html` (HTML + CSS + JS). The pure logic (`refang`, `defangValue`, `extract`, `defangText`) has no DOM access and is delimited by `IOC-LOGIC-START/END` markers; `tests/test.js` extracts it from the HTML and tests it in Node.
- The input is refanged first, then matched with regular expressions. Hashes use lookarounds so they are never cut out of longer hex strings; trailing punctuation is trimmed from URLs.
- Defang text replaces found IOCs from longest to shortest through placeholder markers so replacements never overlap. `refang(defang(x))` equals `refang(x)`.
- Output goes to the DOM via `textContent` only. The page makes no network requests, and a CSP `<meta>` tag forbids them.

## Limitations

- Domains are detected by format only; false positives (and misses, e.g. TLDs that are also in the file-extension list) are possible.
- IPv6 parsing is simplified (no IPv4-mapped addresses or zone IDs).
- No enrichment (WHOIS, reputation, geo): the tool only extracts indicators.

## Ideas

- More types (SHA-512, file names, registry keys).
- STIX/MISP-style export.
- Configurable exclusion lists (domains, IPs).

## Security

The tool is fully offline and sends nothing. To report a problem, use [GitHub Security Advisories](https://github.com/ravigaming222/ioc-extractor/security/advisories/new) or open an [Issue](https://github.com/ravigaming222/ioc-extractor/issues) (without real incident data).

## License

MIT, see [LICENSE](LICENSE).
