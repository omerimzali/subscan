# Subscan

![Subscan Logo](assets/images/subscan.png)

![Go](https://img.shields.io/badge/Go-1.21-blue)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Subscan](https://img.shields.io/github/stars/omerimzali/subscan?style=social)

**Subscan** is a fast and flexible CLI tool for subdomain enumeration.  
Discover subdomains through passive intel & active DNS resolution.  
*Written in Go. Made for bug bounty hunters, red teamers, and automation.*

![Subscan Demo](assets/images/subscan.gif)

---

## 🚀 Features

| Type               | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| 🔍 Passive Recon    | Fetch subdomains from public sources like `crt.sh`, OTX, and ThreatCrowd    |
| 🌐 Active Scanning  | Brute-force with wordlists + concurrent DNS resolution                      |
| 🧠 Smart Wordlists  | Intelligent permutation generation & pattern analysis                       |
| 📊 Subdomain Scoring | HTTP response analysis, TLS cert validation & CNAME detection               |
| 🔬 Misconfiguration | Probe for subdomain takeovers, exposed files & open redirects               |
| 📄 Export Formats   | Output as JSON, CSV, HTML report, Markdown, or plain text                   |
| ⚡ Concurrency       | Built-in goroutine worker pool for speed                                   |
| 💾 Flexible Output  | Save results to file or print to terminal                                   |
| 🛠 Extensible (Soon) | Planned support for plugins and passive source modules                     |

---

## 🧱 Installation

```bash
git clone https://github.com/omerimzali/subscan.git
cd subscan
go build -o subscan
mv subscan /usr/local/bin/  # Optional
```

---

## 🧪 Usage

Basic passive+active scan:

```bash
subscan -d example.com
```

Passive only:

```bash
subscan -d example.com --passive-only
```

Active only (with wordlist):

```bash
subscan -d example.com --active-only -w wordlist.txt
```

Smart wordlist expansion:

```bash
subscan -d example.com --smart-bruteforce --dnstwist
```

Enable subdomain scoring and analysis:

```bash
subscan -d example.com --score
```

Probe for security issues and misconfigurations:

```bash
subscan -d example.com --probe
```

Probe with increased timeout (for slower connections):

```bash
subscan -d example.com --probe --probe-timeout 15
```

Generate a security findings report in HTML:

```bash
subscan -d example.com --probe --format html -o security-report.html
```

Export security findings as JSON for automation:

```bash
subscan -d example.com --probe --format json -o vulns.json
```

Export JSON results:

```bash
subscan -d example.com --score --format json
```

Generate HTML report:

```bash
subscan -d example.com --score --format html -o report.html
```

Complete scan with all features:

```bash
subscan -d example.com --smart-bruteforce --score --probe --verbose-scoring
```

Output to file:

```bash
subscan -d example.com -o out.txt
```

---

## ⚙️ CLI Options

| Flag                   | Description                                          |
|------------------------|------------------------------------------------------|
| `--domain`, `-d`       | Target domain to scan (required)                     |
| `--output`, `-o`       | Output file path                                     |
| `--format`, `-f`       | Output format: plain, json, csv, html, markdown      |
| `--passive-only`       | Only run passive enumeration                         |
| `--active-only`        | Only run active resolution from wordlist             |
| `--wordlist`, `-w`     | Wordlist path for brute-forcing                      |
| `--smart-bruteforce`   | Enable intelligent wordlist expansion                |
| `--commonspeak`        | Path to Commonspeak2 wordlist file                   |
| `--dnstwist`           | Generate typo-based variations                       |
| `--verbose-expansion`  | Show detailed output during wordlist expansion       |
| `--score`              | Enable subdomain analysis and scoring                |
| `--score-concurrency`  | Number of concurrent requests during scoring (10)    |
| `--score-timeout`      | Timeout in seconds for HTTP requests (5)             |
| `--verbose-scoring`    | Show detailed output during scoring process          |
| `--probe`              | Enable probing for misconfigurations                 |
| `--probe-timeout`      | Timeout in seconds for probe requests (10)           |
| `--probe-concurrency`  | Number of concurrent probes (10)                     |
| `--probe-verbose`      | Show detailed output during probing                  |

---

## 📄 Export Formats

Subscan supports multiple output formats for easy integration with other tools:

1. **Plain Text** (default)
   - Simple list of subdomains with basic info
   - Example: `[GitHub-Pages][200] skyline.github.com [200] [Cloud: GitHub-Pages] [CNAME: github.github.io]`

2. **JSON**
   - Structured data for programmatic processing
   - Complete subdomain metadata in JSON format 
   ```json
   [
     {
       "domain": "api.example.com",
       "status": 200,
       "content_length": 1024,
       "cname": "api.cdn.example.com",
       "cloud_provider": "AWS-CloudFront",
       "score": 4.5,
       "tags": ["200", "LARGE"],
       "is_tls": true
     }
   ]
   ```

3. **CSV**
   - Spreadsheet-friendly format with headers
   - Fields: Domain, Status, ContentLength, CNAME, CloudProvider, Score, Tags, IsTLS
   - Easy to import into Excel, Google Sheets, etc.

4. **HTML Report**
   - Beautiful, self-contained HTML page with styled table
   - Colorized status codes and tags
   - Summary statistics and metadata
   - Responsive design for easy viewing

5. **Markdown**
   - GitHub/GitLab-friendly format
   - Includes formatted table with results
   - Preserves all important metadata
   - Perfect for documentation and reports

Use the `--format` flag followed by your desired format (requires either `--score` or `--probe` option).

---

## 📂 Example Reports

Explore real-world output formats generated by Subscan:

### 🧪 HTML Security Report
Visual report showing detected issues with color-coded tags and metadata.

📷 _Preview (add later)_  
[🔗 View example report](./security-report.html)

### 📈 Scoring Report Formats

| Format | Description | Example |
|--------|-------------|---------|
| **JSON** | Structured data for programmatic analysis | [View example](./example/score-results.json) |
| **Markdown** | GitHub-friendly format with tables | [View example](./example/score-results.md) |
| **CSV** | Spreadsheet-compatible for data processing | [View example](./example/score-results.csv) |
| **HTML** | Interactive web report with styling | [View example](./example/score-results.html) |
| **Plain Text** | Simple formatted output | [View example](./example/score-results.txt) |

### 🔍 Probe Report Formats

| Format | Description | Example |
|--------|-------------|---------|
| **JSON** | Complete vulnerability data for automation | [View example](./example/probe-results.json) |
| **Markdown** | Structured reports for documentation | [View example](./example/probe-results.md) |
| **CSV** | Tabular format for tracking findings | [View example](./example/probe-results.csv) |
| **HTML** | Visual dashboard with vulnerability details | [View example](./example/probe-results.html) |
| **Plain Text** | Human-readable summary output | [View example](./example/probe-results.txt) |

---

## 🧠 Smart Brute-Force

The smart brute-force feature analyzes passive enumeration results to generate intelligent wordlist permutations:

1. **Base Wordlist Expansion**
   - Extracts prefixes from discovered subdomains (e.g., "api", "dev", "staging")
   - Generates meaningful permutations and combinations
   
2. **Commonspeak2 Integration**
   - Merges with high-quality wordlists from the Commonspeak2 project
   - Automatically fetches the repository if not present locally
   
3. **DNSTwist Integration**
   - Creates typosquatting variations of discovered domains
   - Uses character substitution, addition, omission, and swapping

This approach dramatically improves discovery rates by creating contextually relevant subdomain candidates.

---

## 📊 Subdomain Scoring & Analysis

The scoring system analyzes each live subdomain to prioritize interesting targets:

1. **HTTP Probing**
   - Checks for both HTTP and HTTPS support
   - Records status codes and response sizes
   - Higher scores for 200 OK and interesting status codes (403, etc.)

2. **TLS Certificate Analysis**
   - Extracts certificate details when HTTPS is available
   - Identifies certificate issuers and Subject Alternative Names (SANs)
   - Validates certificate validity

3. **CNAME Detection**
   - Identifies cloud provider patterns in CNAME records
   - Detects potential cloud misconfigurations (S3 buckets, etc.)
   - Tags results with cloud provider information

4. **Prioritized Output**
   - Results sorted by relevance score
   - Tagged with informative labels like `[200]`, `[AWS-S3]`
   - Detailed output includes status, size, and provider information

Example output:
```
[200][LARGE] admin.example.com [200] (256 KB)
[AWS-S3] backup.example.com [403] (15 KB) [Cloud: AWS-S3]
[301][REDIRECT] www.example.com [301] [CNAME: cdn.example.com]
```

---

## 📚 Wordlists

You can use any standard subdomain wordlists. Recommended:

- [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)
- [jhaddix's all.txt](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)

---

## 🔬 Misconfiguration Detection

The misconfiguration detection module actively probes discovered subdomains for common security issues:

1. **Subdomain Takeover Detection**
   - Identifies dangling CNAMEs pointing to unclaimed services
   - Supports detection for 20+ services (AWS, Heroku, GitHub Pages, etc.)
   - Tags domains with "TAKEOVER-CANDIDATE" for manual verification

2. **S3 Bucket Security Analysis**
   - Detects public, private, and unclaimed S3 buckets
   - Identifies publicly accessible bucket contents
   - Tags with "PUBLIC-S3", "PRIVATE-S3", or "UNCLAIMED-S3"

3. **Sensitive File Exposure**
   - Checks for common sensitive files (.env, .git/config, etc.)
   - Inspects response content for signatures of exposed credentials
   - Tags with file-specific identifiers like "EXPOSED-ENV"

4. **Open Redirect Vulnerability Detection**
   - Tests common redirect endpoints with malicious URLs
   - Identifies unvalidated redirects to untrusted domains
   - Tags with "OPEN-REDIRECT" and provides the vulnerable URL

Example output:
```
=== Probe Summary ===
Total domains probed: 12
Takeover candidates: 1
S3 bucket issues: 2
Exposed sensitive files: 3
Open redirects: 1

=== Vulnerability Details ===
[TAKEOVER-CANDIDATE][Heroku] test.example.com
  CNAME: test.herokuapp.com
  Vulnerabilities:
    - Subdomain Takeover (Heroku)

[PUBLIC-S3] s3.example.com
  CNAME: s3.amazonaws.com
  Vulnerabilities:
    - Public S3 Bucket
  Exposed Files:
    - file1.txt
    - backup.zip

[EXPOSED-ENV] dev.example.com
  Vulnerabilities:
    - Exposed Environment Variables File
  Exposed Files:
    - /.env

[OPEN-REDIRECT] login.example.com
  Vulnerabilities:
    - Open Redirect
  Open Redirect URL: https://login.example.com/redirect?url=https://evil.com
```

Use with `--probe` flag to enable this feature.

### Probe Output Formats

The probe feature supports all output formats for easy integration with your workflow:

1. **Plain Text** (default)
   - Human-readable summary and vulnerability details
   - Great for direct terminal output

2. **JSON**
   - Complete vulnerability data in structured JSON
   - Ideal for programmatic analysis and automation
   ```bash
   subscan -d example.com --probe --format json -o vulns.json
   ```

3. **CSV**
   - Spreadsheet-friendly format with headers
   - Fields include Domain, CNAME, IsTakeover, S3Public, ExposedFiles, etc.
   - Perfect for tracking findings across multiple domains
   ```bash
   subscan -d example.com --probe --format csv -o vulns.csv
   ```

4. **HTML Report**
   - Visual dashboard with statistics and findings
   - Color-coded vulnerability tags
   - Interactive and shareable with team members
   ```bash
   subscan -d example.com --probe --format html -o security-report.html
   ```

5. **Markdown**
   - GitHub/GitLab-friendly format for documentation
   - Well-structured sections with vulnerability details
   - Easy to include in security assessment reports
   ```bash
   subscan -d example.com --probe --format markdown -o findings.md
   ```

---

## 🛣 Roadmap

- [✅] Add intelligent wordlist expansion
- [✅] DNSTwist integration for typosquatting discovery
- [✅] Base wordlist permutation generator
- [✅] Commonspeak2 integration
- [✅] Subdomain scoring and prioritization
- [✅] HTTP response analysis
- [✅] TLS certificate validation
- [✅] CNAME cloud provider detection
- [✅] Multiple export formats (JSON, CSV, HTML, Markdown)
- [✅] Misconfiguration detection and security probing
- [ ] Add more passive sources (e.g. SecurityTrails, URLScan)
- [ ] Plugin support for source modules
- [ ] Subdomain change tracking (diff previous scans)
- [ ] Lightweight API server mode (`--serve`)
- [ ] Browser emulation for dynamic subdomain discovery (via rod/chromedp)

---

## 🤝 Contributing

Pull requests, feature suggestions, and passive source modules are welcome!  
Feel free to open an issue or PR if you'd like to improve Subscan.

---

## 📄 License

MIT

---

> Built with ❤️ in Go by [@omerimzali](https://github.com/omerimzali)