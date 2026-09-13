<div align="center">

#  D4XLEN SECURITY TOOLKIT 

```text
██████╗ ██╗  ██╗██╗  ██╗██╗     ███████╗███╗   ██╗
██╔══██╗██║  ██║╚██╗██╔╝██║     ██╔════╝████╗  ██║
██║  ██║███████║ ╚███╔╝ ██║     █████╗  ██╔██╗ ██║
██║  ██║╚════██║ ██╔██╗ ██║     ██╔══╝  ██║╚██╗██║
██████╔╝     ██║██╔╝ ██╗███████╗███████╗██║ ╚████║
╚═════╝      ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝
```

### Defensive OSINT • Threat Intelligence • IOC Analysis

Python-based defensive cybersecurity toolkit for public intelligence gathering, reputation analysis, IOC investigation, and security research.

![Python](https://img.shields.io/badge/Python-3.x-00ff9c?style=for-the-badge\&logo=python\&logoColor=white)
![Security](https://img.shields.io/badge/Defensive-Security-ff0055?style=for-the-badge)
![OSINT](https://img.shields.io/badge/OSINT-Toolkit-00eaff?style=for-the-badge)
![License](https://img.shields.io/badge/Use-Authorized%20Only-yellow?style=for-the-badge)

</div>

---

## `> SYSTEM OVERVIEW`

**D4xlen Security Toolkit** is a Python-based defensive security toolkit focused on:

* OSINT investigation
* Threat intelligence
* IOC analysis
* Phone reputation research
* Username discovery
* DNS and IP intelligence
* URL security inspection
* TLS certificate analysis
* File hashing and entropy analysis

The toolkit is designed for **security research, blue-team investigation, and authorized analysis**.

---

## `> MODULES`

### ☎ Phone Intelligence

Analyze public numbering metadata including:

* International number format
* Country / region
* Carrier information
* Number type
* Timezone
* Phone reputation data
* Local scam / spam reports

> Carrier and location information is based on numbering-plan metadata and does not provide real-time device location.

---

### ☣ Phone Reputation

Analyze suspicious phone numbers using:

* Local SQLite reports
* Scam / spam categories
* Confidence scoring
* Public evidence input
* Reputation score
* Risk classification

Possible classifications:

```text
[ HIGH RISK ]
[ MEDIUM RISK ]
[ LOW RISK ]
[ UNKNOWN / INSUFFICIENT DATA ]
```

A low score does **not** automatically mean a phone number is safe.

---

### 👤 Username OSINT

Search public username presence across platforms such as:

```text
Instagram
TikTok
X / Twitter
Threads
GitHub
Reddit
Twitch
Pinterest
Medium
YouTube
Telegram
Facebook
Snapchat
SoundCloud
```

Matching usernames across multiple platforms do not necessarily belong to the same person.

---

### 🌐 Domain Intelligence

Inspect domain-related information such as:

* DNS resolution
* A records
* AAAA records
* MX records
* NS records
* TXT records
* Domain-related network information

---

### 📡 IP Intelligence

Analyze IP addresses including:

* IPv4 / IPv6 validation
* Private / public detection
* Reserved address detection
* Reverse DNS lookup
* Network-related information

---

### 🔗 URL Security Analysis

Inspect URLs for:

* HTTP response information
* Redirect behavior
* Security headers
* Server information
* Basic security indicators

Security headers inspected may include:

```text
Content-Security-Policy
Strict-Transport-Security
X-Content-Type-Options
X-Frame-Options
Referrer-Policy
Permissions-Policy
```

---

### 🔐 TLS Certificate Analysis

Analyze HTTPS/TLS certificate information including:

* Certificate issuer
* Subject
* Validity
* Expiration
* TLS-related information

---

### 📁 File Analysis

Analyze local files using:

```text
MD5
SHA-1
SHA-256
SHA-512
Entropy
File Size
```

Useful for malware triage, IOC investigation, and file integrity verification.

---

### 🎯 IOC Analyzer

Automatically identify common Indicators of Compromise such as:

```text
IP Address
Domain
URL
Hash
Phone Number
```

---

## `> INSTALLATION`

Clone the repository:

```bash
git clone https://github.com/Dexlenn/d4xlen-security-toolkit.git
```

Enter the project directory:

```bash
cd d4xlen-security-toolkit
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

---

## `> RUN`

Run the toolkit:

```bash
python d4xlen_analyzer.py
```

On some systems:

```bash
python3 d4xlen_analyzer.py
```

---

## `> DEPENDENCIES`

Main external dependencies:

```text
requests
dnspython
phonenumbers
```

Install them automatically with:

```bash
pip install -r requirements.txt
```

---

## `> PROJECT STRUCTURE`

```text
d4xlen-security-toolkit/
│
├── d4xlen_analyzer.py
├── requirements.txt
├── README.md
├── .gitignore
│
└── reports/
```

Local databases, reports, environment variables, and Python cache files should not be committed to the repository.

---

## `> SECURITY MODEL`

D4xlen is intended primarily for:

```text
[+] Defensive Security
[+] OSINT
[+] Threat Intelligence
[+] Blue Team Investigation
[+] IOC Analysis
[+] Security Research
```

It is **not intended for unauthorized access, exploitation, surveillance, credential attacks, or malicious activity**.

---

## `> DISCLAIMER`

This project is provided for:

* Educational purposes
* Defensive cybersecurity
* Security research
* Authorized investigations

Only analyze systems, files, accounts, domains, URLs, phone numbers, and infrastructure that you are legally authorized to investigate.

Publicly available information may be incomplete, outdated, or inaccurate.

The author is not responsible for misuse of this software.

---

## `> STATUS`

```text
SYSTEM        : ONLINE
PROJECT       : D4XLEN SECURITY TOOLKIT
CATEGORY      : DEFENSIVE SECURITY
MODE          : OSINT / THREAT INTELLIGENCE
LANGUAGE      : PYTHON
```

---

<div align="center">

```text
[ D4XLEN // DEFENSIVE INTELLIGENCE ]
```

**Observe. Analyze. Verify.**

</div>

