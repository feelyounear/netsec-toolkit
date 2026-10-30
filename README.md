# netsec-toolkit

Network security toolkit for reconnaissance, OSINT and exploit utilities.

```
 ███╗   ██╗███████╗████████╗███████╗███████╗ ██████╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔════╝
 ██╔██╗ ██║█████╗     ██║   ███████╗█████╗  ██║
 ██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══╝  ██║
 ██║ ╚████║███████╗   ██║   ███████║███████╗╚██████╗
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝
```

## Tools

**Network**
- Port Scanner — multithreaded TCP connect with banner grabbing
- Ping Sweep — ICMP sweep across a CIDR range
- Traceroute — raw socket hop-by-hop trace
- DNS Lookup — A, AAAA, MX, NS, TXT, CNAME, SOA records
- SSL Checker — certificate details, cipher, expiry warning
- Network Scanner — quick common-port scan across a subnet

**OSINT**
- Whois Lookup — raw whois query via socket
- IP Geolocation — country, ISP, ASN, proxy/hosting detection
- Subdomain Finder — multithreaded DNS bruteforce
- Email Header Analyzer — SPF/DKIM/DMARC + public IP extraction
- Username Lookup — 20 platforms checked in parallel
- Dorking Engine — 10 Google dork templates, opens as search URLs

**Exploit Utils**
- Hash Identifier — MD5, SHA-1/256/512, bcrypt, crypt
- Hash Cracker — wordlist-based, MD5/SHA-1/256/512
- JWT Decoder — header + payload decode, expiry check, alg:none detection
- SQLi Tester — error-based and time-based payloads
- LFI Tester — path traversal and PHP wrapper payloads
- Directory Bruteforcer — status code + size, custom wordlist support
- Header Analyzer — security header audit + server fingerprinting
- Reverse Shell Generator — bash, python, php, perl, ruby, nc, powershell, socat

## Install

```bash
git clone https://github.com/feelyounear/netsec-toolkit
cd netsec-toolkit
pip install requests dnspython
python netsec.py
```

## Requirements

- Python 3.9+
- `requests` — for HTTP-based modules
- `dnspython` — for full DNS record resolution (optional, fallback to socket)

## Notes

- For educational and authorized testing only.
- Traceroute and raw socket features may require root on Linux.
- Hash cracker performance depends on wordlist size and hardware.
