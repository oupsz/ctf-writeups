# Operation GhostPrint — Footprinting & Reconnaissance CTF

> **Type notice:** this is not a boot2root. The local file `ghost files.pdf` is a notebook for a passive footprinting/recon CTF with 10 challenges (C01–C10) + 1 bonus (B01), single target `novasec.pt` (fictional entity for educational purposes). The user's template was adapted to this nature: no exploitation, no privesc; "flags" are submitted in `FLAG{...}` format. The concrete answers are not in the local files — only the prompts — so below I record the resolution method, expected format of each flag, and the evidence to collect.

## 1. Identification

| Field              | Value                                                              |
|--------------------|--------------------------------------------------------------------|
| Exercise name      | Operation GhostPrint                                               |
| Category           | Footprinting & Reconnaissance (OSINT CTF)                          |
| Target             | `novasec.pt` (NovaSec Technologies Ltd. — fictional)               |
| Mode               | Passive techniques only — "Ghosts leave no traces."                |
| Challenges         | 10 (C01–C10) + 1 bonus (B01)                                       |
| Score              | 800 pts (without bonus)                                            |
| Flag format        | `FLAG{...}` (case-insensitive)                                     |

> **Ethical notice:** "`novasec.pt` is used as a CTF target for educational purposes — passive/non-intrusive techniques only."

## 2. Initial reconnaissance — approved toolkit

Public sources only:

```
whois · dig / nslookup · crt.sh · Censys · Shodan · Wayback Machine
Hunter.io · LinkedIn · phonebook.cz · exiftool · verifyemailaddress.org
metadata2go.com · theHarvester
```

## 3. Enumeration — challenges C01 to C10

### C01 — Ghost Whois (50 pts)

```bash
whois novasec.pt
# or: https://www.dns.pt/en/whois/
```

| Flag  | Content                                                                            |
|-------|------------------------------------------------------------------------------------|
| C01-A | `FLAG{registrant_organisation}` — registrant organisation (underscores, lowercase) |
| C01-B | `FLAG{expiry_YYYY}` — expiry year                                                  |

> CTF hint: `.pt` is managed by DNS.PT; DomainTools shows limited info — use `dns.pt/whois`.

### C02 — Name Server Secrets (75 pts)

```bash
dig NS novasec.pt +short
dig MX novasec.pt +short
dig TXT novasec.pt +short
```

| Flag  | Content                                                                                       |
|-------|-----------------------------------------------------------------------------------------------|
| C02-A | `FLAG{mx_hostname}` — MX hostname with the lowest priority                                    |
| C02-B | `FLAG{email_provider}` — provider revealed by `include:` in SPF (microsoft/google/sendgrid…)  |

### C03 — Dead Letters (100 pts)

```bash
for s in www mail vpn remote dev staging portal api; do
  echo -n "$s.novasec.pt -> "
  dig +short $s.novasec.pt | tr '\n' ',' ; echo
done
```

| Flag  | Content                                                                  |
|-------|--------------------------------------------------------------------------|
| C03-A | `FLAG{x.x.x.x}` — IP of `www.novasec.pt`                                 |
| C03-B | `FLAG{N_subdomains_active}` — how many of the 8 resolved (not NXDOMAIN) |

### C04 — Dorking for Files (50 pts)

```
filetype:pdf site:novasec.pt
filetype:docx site:novasec.pt
filetype:pptx site:novasec.pt
filetype:xlsx site:novasec.pt
```

| Flag  | Content                                                                |
|-------|------------------------------------------------------------------------|
| C04-A | `FLAG{filetype}` — which filetype returns the most results             |
| C04-B | `FLAG{email_domain}` — email domain seen inside a document             |

### C05 — Hidden Portals (75 pts)

```
inurl:login    site:novasec.pt
inurl:admin    site:novasec.pt
inurl:portal   site:novasec.pt
intitle:"sign in"   site:novasec.pt
intitle:"dashboard" site:novasec.pt
```

| Flag  | Content                                                                  |
|-------|--------------------------------------------------------------------------|
| C05-A | `FLAG{N_login_pages}` — number of distinct login/admin pages             |
| C05-B | `FLAG{cms_name}` — main CMS (look for `<meta name='generator'>`)         |

### C06 — The Exposed Archive (100 pts)

```
intitle:"index of"   site:novasec.pt
intitle:"index of /" site:novasec.pt

https://web.archive.org/web/*/novasec.pt/*
https://web.archive.org/cdx/search/cdx?url=novasec.pt&output=text&limit=5&fl=timestamp
```

| Flag  | Content                                                                                       |
|-------|-----------------------------------------------------------------------------------------------|
| C06-A | `FLAG{yes_or_no}` — is there a directory listing?                                             |
| C06-B | `FLAG{YYYY}` — year of the oldest Wayback snapshot                                            |
| C06-C | `FLAG{technology_name}` — technology visible in old snapshots but gone today                  |

### C07 — Banner Recon (75 pts)

```
Shodan:
  <IP.from.C03>
  org:"NovaSec Technologies"
  hostname:novasec.pt
```

| Flag  | Content                                                |
|-------|--------------------------------------------------------|
| C07-A | `FLAG{webserver_software}` — webserver (nginx/apache/iis) |
| C07-B | `FLAG{version_number}` — exact version                 |

### C08 — Certificate Trail (125 pts)

```bash
curl -s 'https://crt.sh/?q=%.novasec.pt&output=json' \
  | jq -r '.[].name_value' | sort -u
```

Cross-reference in Censys.

| Flag  | Content                                                                            |
|-------|------------------------------------------------------------------------------------|
| C08-A | `FLAG{N_subdomains}` — number rounded to tens                                      |
| C08-B | `FLAG{subdomain.novasec.pt}` — a non-obvious subdomain (not www/mail/webmail)      |
| C08-C | `FLAG{certificate_authority}` — issuing CA (letsencrypt/digicert/sectigo)          |

### C09 — Harvesting Identities (75 pts)

```bash
theHarvester -d novasec.pt -b google,linkedin,bing -l 200
# https://hunter.io/search/novasec.pt
# https://phonebook.cz
```

| Flag  | Content                                                                                  |
|-------|------------------------------------------------------------------------------------------|
| C09-A | `FLAG{{first}.{last}@novasec.pt}` (format exposed by hunter.io)                          |
| C09-B | `FLAG{job_title}` — a job title from LinkedIn (lowercase, underscores)                   |

### C10 — The Phantom Document (75 pts)

```bash
exiftool downloaded_file.pdf
# Online: metadata2go.com / exif.tools
```

Focus: `Author`, `Creator`, `Producer`, `Software`, `Company`, `LastModifiedBy`, `CreateDate`. Check whether `Software` has CVEs in exploit-db.

| Flag  | Content                                                          |
|-------|------------------------------------------------------------------|
| C10-A | `FLAG{firstname_lastname}` — document author                     |
| C10-B | `FLAG{software_version}` — software used                         |
| C10-C | `FLAG{YYYY}` — original creation year                            |

> CTF hint: PDFs can expose the full local path (`C:\Users\john.doe\Desktop\...`) → leak of hostnames and internal structure.

## 4. Exploitation

N/A — fully passive exercise.

## 5. Post-exploitation — B01 Chain of Evidence (bonus)

After solving the 10 challenges, write a one-page Threat Intelligence Summary combining 5+ findings, answering:

1. What is the target's internet exposure? (assets, IPs, subdomains, services)
2. What technologies are running? Any with known CVEs?
3. Email infrastructure — is a phishing campaign feasible?
4. What employee info is public? Who is the highest-value target for social engineering?
5. What is the single highest-risk finding and what attack would it enable?

Scoring criteria:

| Criterion                                  | Weight |
|--------------------------------------------|--------|
| Accuracy of findings                       | 40%    |
| Ability to chain multiple data points      | 30%    |
| Professional clarity of writing            | 20%    |
| Identification of the highest-risk finding | 10%    |

## 6. Privilege escalation

N/A — passive exercise.

## 7. Flags

| Flag                          | Status in local files                                              |
|-------------------------------|--------------------------------------------------------------------|
| C01-A · C01-B · ... · C10-C   | Not preserved — only the prompts exist in the original PDF.        |
| B01 (final report)            | Pending — depends on the answers from C01–C10.                     |

Each flag submission is case-insensitive with a fixed `FLAG{...}` format.

## 8. CTF summary sequence

1. WHOIS of `novasec.pt` (C01).
2. NS/MX/SPF/TXT (C02).
3. Resolve 8 typical subdomains (C03) → baseline.
4. Google `filetype:` dorks (C04) → documents.
5. Google auth dorks (C05) → CMS + login pages.
6. Directory listings + Wayback (C06).
7. Shodan banner of the C03 IP (C07).
8. crt.sh + Censys (C08) → non-obvious subdomains.
9. theHarvester + LinkedIn + Hunter.io (C09).
10. exiftool on the C04 PDF (C10) → author, software, internal paths.
11. B01 — TI summary chaining 5+ findings.

## 9. Technical lessons

- Passive ≠ inferior — for a real pentest, this recon pays for the next 10 hours of exploitation.
- CT logs (crt.sh + Censys) = nearly complete subdomain map of any TLS-using org.
- Wayback Machine preserves configs / technologies removed years ago.
- Shodan indexes banners without being detected by the target.
- PDF metadata still leaks internal paths, authors, and software versions.
- theHarvester + Hunter.io + phonebook.cz combine to map employees by domain.

## 10. References consulted

- crt.sh — Certificate Transparency
- Censys Search
- Shodan
- Wayback Machine — CDX API
- hunter.io
- phonebook.cz
- DNS.PT — official WHOIS
- theHarvester (GitHub)
- verifyemailaddress.org
- metadata2go.com
- OSINT Framework
