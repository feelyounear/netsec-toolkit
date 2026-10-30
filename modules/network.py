#!/usr/bin/env python3
# modules/network.py — network scanning tools

import os
import sys
import socket
import subprocess
import concurrent.futures
import ipaddress
import ssl
import re
import time
from datetime import datetime

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

from modules.utils import (
    R, DR, W, G, Y, C, GR, RS, B,
    section, ok, info, warn, err, result, pause, get_input, resolve
)


# ─────────────────────────────────────────────
#  01  PORT SCANNER
# ─────────────────────────────────────────────

def _scan_port(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                bnr = ""
                try:
                    s.sendall(b"\r\n")
                    bnr = s.recv(256).decode(errors="replace").strip()[:50]
                except Exception:
                    pass
                return (port, True, bnr)
    except Exception:
        pass
    return (port, False, "")


def port_scanner():
    section("PORT SCANNER")
    host    = get_input("Target (IP/hostname)")
    ports_r = get_input("Ports — range 1-1024, list 22,80,443, or single 80 [default: 1-1024]") or "1-1024"
    timeout = float(get_input("Timeout seconds [0.5]") or "0.5")
    workers = int(get_input("Threads [300]") or "300")

    ip = resolve(host)
    if not ip:
        pause(); return

    ports = []
    for part in ports_r.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    ports = sorted(set(ports))

    info(f"Scanning {ip} — {len(ports)} ports — {workers} threads")
    print()

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_scan_port, ip, p, timeout): p for p in ports}
        done = 0
        for f in concurrent.futures.as_completed(futs):
            port, is_open, bnr = f.result()
            done += 1
            if is_open:
                open_ports.append((port, bnr))
                tag = f"  {G}OPEN{RS}  {W}{port:<7}{RS}"
                if bnr:
                    tag += f" {GR}{bnr}{RS}"
                print(tag)
            if done % 500 == 0:
                print(f"  {GR}... {done}/{len(ports)}{RS}", end="\r")

    print(f"\n  {DR}{'─'*48}{RS}")
    ok(f"{len(open_ports)} open port(s) on {ip}") if open_ports else warn(f"No open ports on {ip}")
    pause()


# ─────────────────────────────────────────────
#  02  PING SWEEP
# ─────────────────────────────────────────────

def _ping(ip):
    flag  = "-n" if os.name == "nt" else "-c"
    wflag = ["-w", "500"] if os.name == "nt" else ["-W", "1"]
    try:
        r = subprocess.run(
            ["ping", flag, "1"] + wflag + [str(ip)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3
        )
        return (str(ip), r.returncode == 0)
    except Exception:
        return (str(ip), False)


def ping_sweep():
    section("PING SWEEP")
    cidr = get_input("Network CIDR (e.g. 192.168.1.0/24)")
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        err(str(e)); pause(); return

    hosts = list(net.hosts())
    if len(hosts) > 1024:
        warn(f"{len(hosts)} hosts — this may take a while")
    info(f"Sweeping {len(hosts)} hosts in {cidr}")
    print()

    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        for ip, up in ex.map(_ping, hosts):
            if up:
                alive.append(ip)
                ok(f"{ip}  UP")

    print(f"\n  {DR}{'─'*48}{RS}")
    ok(f"{len(alive)} host(s) alive") if alive else warn("No hosts responded")
    pause()


# ─────────────────────────────────────────────
#  03  TRACEROUTE
# ─────────────────────────────────────────────

def traceroute():
    section("TRACEROUTE")
    host     = get_input("Target (IP/hostname)")
    max_hops = int(get_input("Max hops [30]") or "30")

    ip = resolve(host)
    if not ip:
        pause(); return

    if os.name == "nt":
        info(f"Tracing route to {host} ({ip})")
        print()
        try:
            proc = subprocess.Popen(
                ["tracert", "-d", "-h", str(max_hops), ip],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                encoding="cp850", errors="replace"
            )
            for line in proc.stdout:
                print(f"  {GR}{line.rstrip()}{RS}")
            proc.wait()
        except Exception as e:
            err(str(e))
        pause()
        return

    info(f"Tracing route to {host} ({ip}), max {max_hops} hops")
    print()
    port = 33434
    for ttl in range(1, max_hops + 1):
        try:
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            recv_sock.settimeout(1.0)
            recv_sock.bind(("", port))
            send_sock.sendto(b"", (ip, port))
            curr = None
            t0 = time.time()
            try:
                _, addr = recv_sock.recvfrom(512)
                curr = addr[0]
                rtt  = (time.time() - t0) * 1000
                try:
                    name = socket.gethostbyaddr(curr)[0]
                except Exception:
                    name = curr
                print(f"  {GR}{ttl:>3}.{RS}  {W}{name:<40}{RS}  {C}{rtt:.1f} ms{RS}")
            except socket.timeout:
                print(f"  {GR}{ttl:>3}.{RS}  {Y}* * *{RS}")
            finally:
                send_sock.close()
                recv_sock.close()
            if curr == ip:
                break
        except PermissionError:
            err("Raw sockets require root on Linux. Run with sudo.")
            pause()
            return

    pause()


# ─────────────────────────────────────────────
#  04  DNS LOOKUP
# ─────────────────────────────────────────────

def dns_lookup():
    section("DNS LOOKUP")
    host = get_input("Domain (e.g. example.com)")
    host = re.sub(r"^https?://", "", host).split("/")[0]

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    found_any    = False

    if HAS_DNS:
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(host, rtype, lifetime=5)
                for rdata in answers:
                    result(rtype, str(rdata))
                    found_any = True
            except Exception:
                pass
    else:
        warn("dnspython not installed — falling back to socket (A/AAAA only)")
        try:
            for info_item in socket.getaddrinfo(host, None):
                fam = "A" if info_item[0] == socket.AF_INET else "AAAA"
                result(fam, info_item[4][0])
                found_any = True
        except Exception as e:
            err(str(e))

    if not found_any:
        warn("No records found")
    pause()


# ─────────────────────────────────────────────
#  05  SSL CHECKER
# ─────────────────────────────────────────────

def ssl_checker():
    section("SSL CHECKER")
    host = get_input("Hostname (e.g. example.com)")
    host = re.sub(r"^https?://", "", host).split("/")[0]
    port = int(get_input("Port [443]") or "443")

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()
                proto  = ssock.version()

        subject   = dict(x[0] for x in cert.get("subject", []))
        issuer    = dict(x[0] for x in cert.get("issuer", []))
        not_after = cert.get("notAfter", "N/A")
        sans      = [v for t, v in cert.get("subjectAltName", [])]

        result("Subject CN",  subject.get("commonName", "N/A"))
        result("Issuer",      issuer.get("organizationName", "N/A"))
        result("Valid From",  cert.get("notBefore", "N/A"))
        result("Valid Until", not_after)
        result("Protocol",    proto)
        result("Cipher",      cipher[0] if cipher else "N/A")
        result("Key Bits",    str(cipher[2]) if cipher else "N/A")
        if sans:
            result("SANs", ", ".join(sans[:6]) + ("..." if len(sans) > 6 else ""))

        try:
            exp       = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp - datetime.utcnow()).days
            if days_left < 30:
                warn(f"Certificate expires in {days_left} days!")
            else:
                ok(f"Certificate valid for {days_left} more days")
        except Exception:
            pass

    except ssl.SSLCertVerificationError as e:
        err(f"SSL verification failed: {e}")
    except ConnectionRefusedError:
        err(f"Connection refused on port {port}")
    except Exception as e:
        err(str(e))

    pause()


# ─────────────────────────────────────────────
#  06  NETWORK SCANNER
# ─────────────────────────────────────────────

def network_scanner():
    section("NETWORK SCANNER")
    cidr = get_input("Network CIDR (e.g. 192.168.1.0/24)")
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        err(str(e)); pause(); return

    hosts     = list(net.hosts())
    com_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080]

    info(f"Scanning {len(hosts)} hosts × {len(com_ports)} common ports")
    print()

    def scan_host(ip):
        open_p = []
        for p in com_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.3)
                    if s.connect_ex((str(ip), p)) == 0:
                        open_p.append(p)
            except Exception:
                pass
        return (str(ip), open_p)

    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
        for ip, ports in ex.map(scan_host, hosts):
            if ports:
                print(f"  {G}UP{RS}  {W}{ip:<18}{RS}  {GR}{' '.join(str(p) for p in ports)}{RS}")

    pause()
